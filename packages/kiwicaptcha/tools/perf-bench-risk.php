<?php

declare(strict_types=1);

/**
 * Risk-enabled controller throughput benchmark.
 *
 * The bundle-level issuance path with the adaptive risk engine wired:
 * each request runs the real ChallengeController, resolves the scope,
 * runs the risk pre-issue assessment (identity keying, signal vector,
 * score, decision), issues the challenge and builds the JSON response.
 * The default workload is 400 controller invocations at 40 warmup
 * iterations against an in-memory risk state store. The storage is
 * ArrayStorage and the risk engine sees a zero signal vector, so the
 * measurement is the pure bundle-path cost of a risk-enabled issuance
 * (the engine, the gateway, the controller mapping), not Redis or
 * solver time.
 *
 * The default state store is an in-memory implementation inside this
 * harness (the RiskStateStoreInterface contract: observe returns a zero
 * vector, outcome registration is a no-op). The benchmark must not
 * depend on the bundle's test fixtures, and the policy is permissive
 * (base_risk 100, minimum allow), so every request ends in a 200
 * challenge response; a denied or escalated response fails the run.
 *
 * Real-Redis mode (--redis): the same risk-enabled controller path, but
 * with the risk state store and the challenge storage both backed by a
 * real Redis through the DSN-built Predis client, exactly the bundle's
 * redis_dsn wiring. The mode is concurrent: 8 worker processes (--workers
 * N and --per-worker M overrides) are forked with proc_open. Each
 * worker opens its own Predis connection, builds its own controller and
 * issues requests through it, so the load is genuinely concurrent at
 * the Redis wire level. Every worker samples each request with hrtime
 * and writes the samples to a per-worker file. The parent aggregates
 * every sample into one distribution and reports p50, p95 and the
 * aggregate throughput in requests per second over the window in which
 * every worker is live. The Redis URL comes from --url, or
 * KC_REDIS_URL, or the local default redis://127.0.0.1:6399. Without a
 * reachable server the mode prints a loud note and exits 0, because the
 * timing signal is non-gating by design, exactly like perf-load.php.
 * The risk keys carry a per-run namespace and the challenge keys a
 * per-run prefix, so repeated runs share no state. Two harness knobs
 * keep the engine's own protections from polluting the latency
 * distribution. The requests rotate through 250 source addresses; a
 * real request stream sees many clients, and the hard sourceFast deny
 * threshold would otherwise trip on a single hot source. The risk
 * store's saturation constants are scaled by 100 so the burst of 800
 * observations stays inside the normal band. Both change only the
 * counters the Lua normalizes, never the script's work or the
 * per-request pipeline; the policy still floors every decision to
 * allow.
 *
 * The percentiles gate on the same generous relative ratchet as the
 * other benchmarks: the run fails only when p95 exceeds 3x its
 * recorded baseline. Noisy-runner-tolerant on purpose; the byte and
 * count budgets in perf-budget.sh remain the gating gate and this
 * timing signal is loud but never a hard merge gate by itself.
 *
 * The recorded baseline values live in tools/perf-baselines.json,
 * the single machine-readable record for the performance-analysis
 * document. The ratchets read them straight from that record
 * (perf_baseline_float), so the JSON is the single baseline authority
 * and no compiled ratchet constants exist to drift. After a
 * deliberate change, run each mode with
 * --baseline-out tools/perf-baselines.json on a clean local machine to
 * merge the fresh measurements into the record, the very file the
 * ratchets read on the next run. --update-baseline prints the fresh
 * values without touching the record.
 */

$autoload = __DIR__.'/../../kiwicaptcha/integrations/symfony/vendor/autoload.php';
if (!is_file($autoload)) {
    fwrite(STDERR, "perf-bench-risk: the Symfony bundle vendor is missing at $autoload (run composer install in packages/kiwicaptcha/integrations/symfony)\n");
    exit(1);
}
require $autoload;
require __DIR__.'/perf-baseline-emit.php';

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\ProcessEmergencyCap;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use Symfony\Component\HttpFoundation\Request;

const WARMUP = 40;
const ITERATIONS = 400;
const RATCHET = 3.0;
const REDIS_WARMUP = 10;
const REDIS_WORKERS = 8;
const REDIS_PER_WORKER = 100;

/** In-memory risk state store: zero signal vectors, outcome no-ops. */
final class BenchRiskStateStore implements RiskStateStoreInterface
{
    public function observe(RiskObservation $observation): SignalVector
    {
        return SignalVector::zero();
    }

    public function registerOutcome(string $decisionId, int $scope, int $decisionHour, int $score): bool
    {
        return true;
    }

    public function confirmOutcome(string $decisionId, bool $legitimate): int
    {
        return 0;
    }

    public function correctOutcome(string $decisionId, bool $legitimate): bool
    {
        return true;
    }
}

function percentile(array $samples, float $q): float
{
    sort($samples, SORT_NUMERIC);
    $index = (int) ceil($q / 100.0 * count($samples)) - 1;

    return $samples[max(0, $index)];
}

function redisUrlFromArgs(array $argv): string
{
    foreach ($argv as $i => $arg) {
        if ($arg === '--url' && isset($argv[$i + 1])) {
            return $argv[$i + 1];
        }
    }
    $url = getenv('KC_REDIS_URL');
    if (is_string($url) && $url !== '') {
        return $url;
    }

    return 'redis://127.0.0.1:6399';
}

/** @return \Predis\Client|null null when no Redis answers */
function redisClientOrNull(string $url): ?\Predis\Client
{
    if (!class_exists(\Predis\Client::class)) {
        return null;
    }
    try {
        $client = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
        $client->ping();

        return $client;
    } catch (\Throwable) {
        return null;
    }
}

/**
 * Build the real-Redis risk-enabled controller path: one DSN-built
 * Predis client drives the challenge storage (RedisStorage) and the
 * risk state store (RedisRiskStateStore), mirroring the bundle's
 * redis_dsn wiring, with the same engine, gateway and controller
 * assembly as the in-memory harness. The store's saturation constants
 * are scaled by 100 so the burst workload stays inside the normal band
 * (see the header).
 *
 * @return list{ChallengeController}
 */
function buildRedisRiskController(string $url, string $prefix, string $namespace): array
{
    $client = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
    $client->ping();
    $storage = new RedisStorage($client, $prefix);
    $issuer = new Issuer(new Config(
        secretKey: '0123456789abcdef0123456789abcdef',
        algorithm: PoWAlgorithm::Sha256,
        targetBits: 8,
        ttlSecs: 120,
    ), $storage);
    $keys = RiskKeys::fromMaster('0123456789abcdef0123456789abcdef');
    $classifier = new CidrNetworkClassifier([]);
    $policy = RiskPolicy::fromConfig([
        'version' => RiskPolicy::CONTRACT_VERSION,
        'weights' => [],
        'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow']],
    ]);
    $saturations = array_map(static fn (int $value): int => $value * 100, RedisRiskStateStore::DEFAULT_SATURATIONS);
    $store = new RedisRiskStateStore($client, $namespace, saturations: $saturations);
    $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
    $gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], emergencyCap: new ProcessEmergencyCap(10000));
    $controller = new ChallengeController($issuer, risk: $gateway, sameOriginOnly: false, storage: $storage);

    return [$controller];
}

/**
 * The real-Redis worker entry point: connects its own Predis client,
 * builds the risk-enabled controller, runs the issuance workload,
 * appends sample lines to the out file and exits 0. A failure writes
 * one error line to stdout and exits 1.
 *
 * @param resource $out
 */
function workerMode(array $argv, $out): int
{
    $id = (int) ($argv[0] ?? 0);
    $outFile = (string) ($argv[1] ?? '');
    $prefix = (string) ($argv[2] ?? '');
    $namespace = (string) ($argv[3] ?? '');
    $perWorker = (int) ($argv[4] ?? REDIS_PER_WORKER);
    $url = (string) ($argv[5] ?? '');

    try {
        [$controller] = buildRedisRiskController($url, $prefix, $namespace);
    } catch (\Throwable $e) {
        fwrite($out, "error\t".str_replace(["\n", "\t"], ' ', $e->getMessage())."\n");
        exit(1);
    }

    $samples = [];
    for ($i = 0; $i < REDIS_WARMUP + $perWorker; $i++) {
        $clientIp = '198.51.100.'.((($id * $perWorker) + $i) % 250 + 1);
        $request = Request::create(
            '/challenge',
            'POST',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json', 'REMOTE_ADDR' => $clientIp],
            '{"scope":"login"}',
        );
        $t0 = hrtime(true);
        $response = $controller->challenge($request);
        $t1 = hrtime(true);
        if ($response->getStatusCode() !== 200) {
            fwrite($out, "error\tworker $id: a risk-enabled issuance did not answer 200 (status ".$response->getStatusCode().")\n");
            exit(1);
        }
        if ($i >= REDIS_WARMUP) {
            $samples[] = ($t1 - $t0) / 1e6;
        }
    }

    $fh = fopen($outFile, 'ab');
    if ($fh === false) {
        fwrite(STDERR, "perf-bench-risk worker $id: cannot write $outFile\n");
        exit(1);
    }
    foreach ($samples as $ms) {
        fwrite($fh, "sample\t".sprintf('%.4f', $ms)."\n");
    }
    fclose($fh);

    return 0;
}

/**
 * Spawn the worker processes, aggregate every sample into one flat
 * distribution and return the errors, the sample count and the window
 * in which every worker was live (spawn end to the last worker exit).
 *
 * @return array{samples: list<float>, errors: list<string>, n: int, windowMs: float}
 */
function runRedisPhase(int $workers, int $perWorker, string $prefix, string $namespace, string $url, string $workDir): array
{
    $outFiles = [];
    $procs = [];
    $t0 = hrtime(true);
    for ($id = 0; $id < $workers; $id++) {
        $outFile = "$workDir/risk-$id.out";
        $outFiles[] = $outFile;
        $cmd = [PHP_BINARY, __FILE__, '--worker', (string) $id, $outFile, $prefix, $namespace, (string) $perWorker, $url];
        $pipes = [];
        $proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($proc)) {
            fwrite(STDERR, "perf-bench-risk: cannot spawn worker $id\n");
            exit(1);
        }
        fclose($pipes[0]);
        $procs[] = ['proc' => $proc, 'pipes' => $pipes];
    }
    $spawnEnd = hrtime(true);
    $stderrAll = '';
    $exitCodes = [];
    foreach ($procs as $entry) {
        $stderr = stream_get_contents($entry['pipes'][2]);
        $stdout = stream_get_contents($entry['pipes'][1]);
        if (is_string($stderr) && $stderr !== '') {
            $stderrAll .= $stderr;
        }
        if (is_string($stdout) && $stdout !== '') {
            $stderrAll .= $stdout;
        }
        fclose($entry['pipes'][1]);
        fclose($entry['pipes'][2]);
        $exitCodes[] = proc_close($entry['proc']);
    }
    $t1 = hrtime(true);
    $windowMs = ($t1 - $spawnEnd) / 1e6;

    $samples = [];
    $errors = [];
    foreach ($outFiles as $i => $outFile) {
        $hadErrorLine = false;
        if (is_file($outFile)) {
            foreach (file($outFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                $parts = explode("\t", $line);
                if (count($parts) >= 2 && $parts[0] === 'error') {
                    $errors[] = $parts[1];
                    $hadErrorLine = true;
                    continue;
                }
                if (count($parts) !== 2 || $parts[0] !== 'sample') {
                    $errors[] = "unparsable worker line: $line";
                    continue;
                }
                $samples[] = (float) $parts[1];
            }
        } else {
            $errors[] = "worker output missing: $outFile";
        }
        if (($exitCodes[$i] ?? 0) !== 0 && !$hadErrorLine && !isset($errors[array_key_last($errors)])) {
            $errors[] = "worker $i exited with code ".($exitCodes[$i] ?? '?');
        }
    }
    if ($stderrAll !== '') {
        $errors[] = trim($stderrAll);
    }

    return ['samples' => $samples, 'errors' => $errors, 'n' => count($samples), 'windowMs' => $windowMs];
}

$workerIndex = array_search('--worker', $argv, true);
if ($workerIndex !== false) {
    $rest = array_values(array_slice($argv, $workerIndex + 1));
    $fh = fopen('php://stdout', 'w');

    return exit(workerMode($rest, $fh));
}

$redisMode = in_array('--redis', $argv, true);
$redisUpdate = $redisMode && in_array('--update-baseline', $argv, true);
$baselineOut = null;
foreach ($argv as $i => $arg) {
    if ($arg === '--baseline-out' && isset($argv[$i + 1])) {
        $baselineOut = $argv[$i + 1];
    }
}
$workers = REDIS_WORKERS;
$perWorker = REDIS_PER_WORKER;
foreach ($argv as $i => $arg) {
    if ($arg === '--workers' && isset($argv[$i + 1])) {
        $workers = max(1, (int) $argv[$i + 1]);
    }
    if ($arg === '--per-worker' && isset($argv[$i + 1])) {
        $perWorker = max(1, (int) $argv[$i + 1]);
    }
}
$baselineFile = $baselineOut ?? __DIR__.'/perf-baselines.json';

if ($redisMode) {
    $url = redisUrlFromArgs($argv);
    $probe = redisClientOrNull($url);
    if ($probe === null) {
        fwrite(STDERR, sprintf("perf-bench-risk NOTE: no Redis answers at %s; the real-Redis mode is skipped — the timing signal is non-gating\n", $url));
        exit(0);
    }
    $prefix = 'perf-bench-risk-'.bin2hex(random_bytes(6)).'-';
    $namespace = 'b'.bin2hex(random_bytes(4));
    $workDir = sys_get_temp_dir().'/perf-bench-risk-'.getmypid();
    if (!mkdir($workDir) && !is_dir($workDir)) {
        fwrite(STDERR, "perf-bench-risk: cannot create $workDir\n");
        exit(1);
    }
    $r = runRedisPhase($workers, $perWorker, $prefix, $namespace, $url, $workDir);
    if ($r['errors'] !== []) {
        foreach ($r['errors'] as $error) {
            fwrite(STDERR, "perf-bench-risk: redis phase error: $error\n");
        }
        exit(1);
    }
    $p50 = percentile($r['samples'], 50);
    $p95 = percentile($r['samples'], 95);
    $ops = $r['windowMs'] > 0 ? (int) round($r['n'] / ($r['windowMs'] / 1000.0)) : 0;
    printf("perf-bench-risk: real-Redis concurrent risk-enabled issuance p50 %.3f ms p95 %.3f ms (n=%d); throughput %d req/s\n", $p50, $p95, $r['n'], $ops);
    if ($baselineOut !== null) {
        try {
            perf_baseline_emit($baselineOut, ['bench_risk', 'redis_concurrent'], [
                'p50_ms' => $p50,
                'p95_ms' => $p95,
                'n' => $r['n'],
                'workers' => $workers,
                'per_worker' => $perWorker,
                'throughput_requests_per_second' => $ops,
            ]);
            printf("perf-bench-risk: baseline record updated in %s\n", $baselineOut);
        } catch (\Throwable $e) {
            fwrite(STDERR, 'perf-bench-risk: cannot write the baseline record: '.$e->getMessage()."\n");
            exit(1);
        }
    }
    if ($redisUpdate) {
        printf("perf-bench-risk: record these values with --baseline-out: p50 %.3f p95 %.3f\n", $p50, $p95);
        exit(0);
    }
    $baselineP95 = perf_baseline_float($baselineFile, ['bench_risk', 'redis_concurrent', 'p95_ms']);
    if ($baselineP95 <= 0.0) {
        if (!perf_baseline_missing('perf-bench-risk', 'real-Redis concurrent risk-enabled issuance')) {
            exit(1);
        }
        exit(0);
    }
    if ($p95 > $baselineP95 * RATCHET) {
        fwrite(STDERR, sprintf("perf-bench-risk FAILED: real-Redis risk-enabled issuance p95 %.3f ms exceeds the ratchet %.3f ms (3x baseline %.3f ms)\n", $p95, $baselineP95 * RATCHET, $baselineP95));
        exit(1);
    }
    echo "perf-bench-risk: OK (real-Redis p95 within the 3x noisy-runner-tolerant ratchet)\n";
    exit(0);
}

$secret = '0123456789abcdef0123456789abcdef';
$storage = new ArrayStorage();
$issuer = new Issuer(new Config(
    secretKey: $secret,
    algorithm: PoWAlgorithm::Sha256,
    targetBits: 8,
    ttlSecs: 120,
), $storage);
$keys = RiskKeys::fromMaster($secret);
$classifier = new CidrNetworkClassifier([]);
$policy = RiskPolicy::fromConfig([
    'version' => RiskPolicy::CONTRACT_VERSION,
    'weights' => [],
    'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow']],
]);
$engine = new AdaptiveRiskEngine(new BenchRiskStateStore(), $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);
$gateway = new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), ['login' => 1], emergencyCap: new ProcessEmergencyCap(10000));
$controller = new ChallengeController($issuer, risk: $gateway, sameOriginOnly: false, storage: $storage);

$samples = [];
for ($i = 0; $i < WARMUP + ITERATIONS; $i++) {
    $request = Request::create(
        '/challenge',
        'POST',
        [],
        [],
        [],
        ['CONTENT_TYPE' => 'application/json', 'REMOTE_ADDR' => '198.51.100.7'],
        '{"scope":"login"}',
    );
    $t0 = hrtime(true);
    $response = $controller->challenge($request);
    $t1 = hrtime(true);
    if ($response->getStatusCode() !== 200) {
        fwrite(STDERR, 'perf-bench-risk: a risk-enabled issuance did not answer 200 (status '.$response->getStatusCode().")\n");
        exit(1);
    }
    if ($i >= WARMUP) {
        $samples[] = ($t1 - $t0) / 1e6;
    }
}

$p50 = percentile($samples, 50);
$p95 = percentile($samples, 95);
printf("perf-bench-risk: risk-enabled controller issuance p50 %.3f ms p95 %.3f ms (n=%d)\n", $p50, $p95, count($samples));

if ($baselineOut !== null) {
    try {
        perf_baseline_emit($baselineOut, ['bench_risk', 'in_memory'], [
            'p50_ms' => $p50,
            'p95_ms' => $p95,
            'n' => count($samples),
        ]);
        printf("perf-bench-risk: baseline record updated in %s\n", $baselineOut);
    } catch (\Throwable $e) {
        fwrite(STDERR, 'perf-bench-risk: cannot write the baseline record: '.$e->getMessage()."\n");
        exit(1);
    }
}

if (in_array('--update-baseline', $argv, true)) {
    printf("perf-bench-risk: record these values with --baseline-out: p50 %.3f p95 %.3f\n", $p50, $p95);
    exit(0);
}

$baselineP95 = perf_baseline_float($baselineFile, ['bench_risk', 'in_memory', 'p95_ms']);
if ($baselineP95 <= 0.0) {
    if (!perf_baseline_missing('perf-bench-risk', 'risk-enabled controller issuance in-memory')) {
        exit(1);
    }
    exit(0);
}
if ($p95 > $baselineP95 * RATCHET) {
    fwrite(STDERR, sprintf("perf-bench-risk FAILED: risk-enabled issuance p95 %.3f ms exceeds the ratchet %.3f ms (3x baseline %.3f ms)\n", $p95, $baselineP95 * RATCHET, $baselineP95));
    exit(1);
}
echo "perf-bench-risk: OK (p95 within the 3x noisy-runner-tolerant ratchet)\n";
