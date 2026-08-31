<?php

declare(strict_types=1);

/**
 * Concurrent-load benchmark for issuance and verification against a real
 * Redis, through the php-core RedisStorage, the Issuer and the Verifier.
 *
 * Methodology. The benchmark spawns worker processes (8 by default)
 * with proc_open, and each worker opens its own Predis connection, so
 * the load is genuinely concurrent at the Redis wire level instead of a
 * serial loop inside one process. Every phase times each operation
 * inside the worker with hrtime and writes the samples to a per-worker
 * file. The parent aggregates every sample into one distribution and
 * reports p50, p95 and the aggregate throughput in operations per
 * second. The parent measures the wall clock around the whole phase.
 * The throughput window runs from the end of the spawn loop to the
 * last worker exit, so the reported throughput excludes the serial PHP
 * startup of the worker processes and covers only the window in which
 * every worker is live. The solve phase of the SHA-256 workload is a
 * local hash loop inside the workers and the parent; it is never a
 * measured phase. The storage prefix is unique per run, and
 * verification consumes every record, so a run leaves no cleanup
 * behind.
 *
 * Modes:
 *  - --issue: 8 workers issue 100 challenges each (800 issuances).
 *  - --verify: the parent pre-issues and solves 800 challenges into a
 *    pool file, then 8 workers verify 100 tokens each (800
 *    verifications). Every token is distinct, so this phase measures
 *    pure concurrent verification throughput. The contended one-shot
 *    path, where several requests race the same token, is the province
 *    of the RedisConcurrencyLoadTest phpunit suite, which asserts the
 *    exactly-one-success invariant under load.
 *  - --mixed: 8 workers each run 100 rounds of issue, solve, verify
 *    through one shared storage prefix, so issuance and verification
 *    interleave on the same Redis instance the way a production request
 *    stream does.
 *  - --risk: the risk-enabled issuance variant. The php-core vendor
 *    carries no KiwiCaptcha\Risk classes today (the risk engine lives
 *    in the separate risk packages and is wired by the Symfony bundle),
 *    so this mode prints a loud note and exits. The bundle's
 *    risk-enabled ChallengeController path is covered by
 *    perf-bench-risk.php, which measures the same per-request cost with
 *    the real bundle wiring. When the php-core vendor gains the risk
 *    classes, this mode runs the same concurrent issuance load through
 *    the core risk engine without any edits to the harness.
 *  - --all (default): issue, verify and mixed in one run, then the risk
 *    variant.
 *
 * Flags: --workers N and --per-worker N override the default 8 x 100.
 * The Redis URL comes from KC_REDIS_URL, or --url, or the local default
 * redis://127.0.0.1:6399. Without a reachable server the script prints
 * a loud note and exits 0, because the timing signal is non-gating by
 * design, exactly like perf-bench.php.
 *
 * Ratchets. Every phase gates on the same generous relative ratchet as
 * the other benchmarks: the run fails only when a p95 exceeds 3x its
 * recorded baseline. The design is noisy-runner-tolerant on purpose,
 * because a shared CI runner can stall a single worker without any code
 * regression. The byte and count budgets in perf-budget.sh gate
 * deterministically; this timing signal is loud but never a hard merge
 * gate by itself.
 *
 * The recorded baseline values live in tools/perf-baselines.json,
 * the single machine-readable record for the performance-analysis
 * document. The ratchets read them straight from that record
 * (perf_baseline_float), so the JSON is the single baseline authority
 * and no compiled ratchet constants exist to drift. After a
 * deliberate change, run each phase with
 * --baseline-out tools/perf-baselines.json on a clean local machine to
 * merge the fresh measurements into the record, the very file the
 * ratchets read on the next run. --update-baseline prints the fresh
 * values without touching the record.
 */

$autoload = __DIR__.'/../../kiwicaptcha-php/vendor/autoload.php';
if (!is_file($autoload)) {
    fwrite(STDERR, "perf-load: kiwicaptcha-php vendor is missing at $autoload\n");
    exit(1);
}
require $autoload;
require __DIR__.'/perf-baseline-emit.php';

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;

const RATCHET = 3.0;

function percentile(array $samples, float $q): float
{
    if ($samples === []) {
        return 0.0;
    }
    sort($samples, SORT_NUMERIC);
    $index = (int) ceil($q / 100.0 * count($samples)) - 1;

    return $samples[max(0, $index)];
}

function shaConfig(): Config
{
    return new Config(
        secretKey: '0123456789abcdef0123456789abcdef',
        algorithm: PoWAlgorithm::Sha256,
        mKib: 0,
        t: 1,
        p: 1,
        targetBits: 8,
        argon2TargetBits: 8,
        ttlSecs: 120,
        minDurationMs: 0,
    );
}

function solveCounter($challenge): int
{
    $counter = 0;
    $saltBytes = base64_decode($challenge->salt, true);
    do {
        $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
        $counter++;
    } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);

    return $counter - 1;
}

function tokenFor($challenge, int $counter): string
{
    return SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
}

/** @return \Predis\Client|null null when no Redis answers */
function redisOrNull(string $url): ?\Predis\Client
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

/**
 * The in-process risk state store of the risk variant, the
 * RiskStateStoreInterface contract with zero signal vectors and
 * outcome no-ops, mirroring the bench harness of perf-bench-risk.
 * The declaration is guarded because the interface lives in the
 * separate risk package, which the php-core vendor does not require.
 */
if (interface_exists(\KiwiCaptcha\Risk\Storage\RiskStateStoreInterface::class)) {
    final class LoadRiskStateStore implements \KiwiCaptcha\Risk\Storage\RiskStateStoreInterface
    {
        public function observe(\KiwiCaptcha\Risk\RiskObservation $observation): \KiwiCaptcha\Risk\SignalVector
        {
            return \KiwiCaptcha\Risk\SignalVector::zero();
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
}

/** Whether every class of the php-core risk path is loadable. */
function riskPathAvailable(): bool
{
    foreach ([
        \KiwiCaptcha\Risk\AdaptiveRiskEngine::class,
        \KiwiCaptcha\Risk\RiskContext::class,
        \KiwiCaptcha\Risk\RiskPolicy::class,
        \KiwiCaptcha\Risk\RiskKeys::class,
        \KiwiCaptcha\Risk\RiskIdentityFactory::class,
        \KiwiCaptcha\Risk\RiskScorer::class,
        \KiwiCaptcha\Risk\Network\CidrNetworkClassifier::class,
        \KiwiCaptcha\Risk\Storage\RiskStateStoreInterface::class,
    ] as $class) {
        if (!class_exists($class)) {
            return false;
        }
    }

    return true;
}

/**
 * The worker entry point: connects its own Redis client, runs the
 * phase workload, appends tab-separated sample lines to the out file
 * and exits 0. A failure writes one error line to stdout and exits 1.
 *
 * @param resource $out
 */
function workerMode(array $argv, $out): int
{
    $id = (int) ($argv[0] ?? 0);
    $phase = (string) ($argv[1] ?? '');
    $outFile = (string) ($argv[2] ?? '');
    $prefix = (string) ($argv[3] ?? '');
    $perWorker = (int) ($argv[4] ?? 100);
    $poolFile = isset($argv[5]) ? (string) $argv[5] : null;

    $client = redisOrNull(redisUrlFromArgs($GLOBALS['argv'] ?? []));
    if ($client === null) {
        fwrite(STDERR, "perf-load worker $id: no Redis answers\n");
        exit(1);
    }

    $config = shaConfig();
    $issuer = new Issuer($config, new RedisStorage($client, $prefix));
    $verifier = new Verifier(new RedisStorage($client, $prefix));
    $samples = [];

    try {
        if ($phase === 'issue') {
            for ($i = 0; $i < $perWorker; $i++) {
                $t0 = hrtime(true);
                $issuer->issue('login', '198.51.100.7');
                $t1 = hrtime(true);
                $samples[] = ['issue', ($t1 - $t0) / 1e6];
            }
        } elseif ($phase === 'verify') {
            if ($poolFile === null || !is_file($poolFile)) {
                throw new \RuntimeException("worker $id: the verify phase needs a pool file");
            }
            $pool = [];
            foreach (file($poolFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                $pool[] = json_decode($line, true, flags: JSON_THROW_ON_ERROR);
            }
            $start = $id * $perWorker;
            foreach (array_slice($pool, $start, $perWorker) as $row) {
                $t0 = hrtime(true);
                $outcome = $verifier->verify($row['token'], $config->secretKey, 'login', '198.51.100.7');
                $t1 = hrtime(true);
                if (!$outcome->isOk()) {
                    throw new \RuntimeException(sprintf("worker %d: a valid token failed verification (%s)", $id, $outcome->code()->name));
                }
                $samples[] = ['verify', ($t1 - $t0) / 1e6];
            }
        } elseif ($phase === 'mixed') {
            for ($i = 0; $i < $perWorker; $i++) {
                $t0 = hrtime(true);
                $challenge = $issuer->issue('login', '198.51.100.7');
                $t1 = hrtime(true);
                $token = tokenFor($challenge, solveCounter($challenge));
                $t2 = hrtime(true);
                $outcome = $verifier->verify($token, $config->secretKey, 'login', '198.51.100.7');
                $t3 = hrtime(true);
                if (!$outcome->isOk()) {
                    throw new \RuntimeException(sprintf("worker %d: a mixed-pipeline verification failed (%s)", $id, $outcome->code()->name));
                }
                $samples[] = ['issue', ($t1 - $t0) / 1e6];
                $samples[] = ['verify', ($t3 - $t2) / 1e6];
            }
        } elseif ($phase === 'risk') {
            if (!riskPathAvailable()) {
                throw new \RuntimeException('worker: the php-core risk path is unavailable');
            }
            $keys = \KiwiCaptcha\Risk\RiskKeys::fromMaster($config->secretKey);
            $policy = \KiwiCaptcha\Risk\RiskPolicy::fromConfig([
                'version' => \KiwiCaptcha\Risk\RiskPolicy::CONTRACT_VERSION,
                'weights' => [],
                'scopes' => [1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow']],
            ]);
            $engine = new \KiwiCaptcha\Risk\AdaptiveRiskEngine(
                new LoadRiskStateStore(),
                new \KiwiCaptcha\Risk\Network\CidrNetworkClassifier([]),
                new \KiwiCaptcha\Risk\RiskIdentityFactory($keys),
                new \KiwiCaptcha\Risk\RiskScorer(),
                $policy,
                $keys,
            );
            for ($i = 0; $i < $perWorker; $i++) {
                $context = new \KiwiCaptcha\Risk\RiskContext(
                    1,
                    '198.51.100.7',
                    null,
                    null,
                    \KiwiCaptcha\Risk\RiskEventKind::PreIssue,
                    new \KiwiCaptcha\Risk\Network\NetworkFlags(),
                    new \KiwiCaptcha\Risk\ResourcePressure(1000, 1000),
                );
                $t0 = hrtime(true);
                $decision = $engine->assessPreIssue($context);
                $issuer->issue('login', '198.51.100.7');
                $t1 = hrtime(true);
                if ($decision->action !== \KiwiCaptcha\Risk\RiskAction::Allow) {
                    throw new \RuntimeException(sprintf('worker %d: the permissive risk policy refused an issuance', $id));
                }
                $samples[] = ['risk-issue', ($t1 - $t0) / 1e6];
            }
        } else {
            throw new \RuntimeException('worker: unknown phase '.$phase);
        }
    } catch (\Throwable $e) {
        fwrite($out, "error\t".str_replace(["\n", "\t"], ' ', $e->getMessage())."\n");
        exit(1);
    }

    $fh = fopen($outFile, 'ab');
    if ($fh === false) {
        fwrite(STDERR, "perf-load worker $id: cannot write $outFile\n");
        exit(1);
    }
    foreach ($samples as [$kind, $ms]) {
        fwrite($fh, "sample\t$kind\t".sprintf('%.4f', $ms)."\n");
    }
    fclose($fh);

    return 0;
}

/** @return array{samples: array<string, list<float>>, errors: list<string>, n: int, wallMs: float, windowMs: float} */
function runPhase(string $phase, int $workers, int $perWorker, string $prefix, string $workDir, ?string $poolFile): array
{
    $outFiles = [];
    $procs = [];
    $t0 = hrtime(true);
    for ($id = 0; $id < $workers; $id++) {
        $outFile = "$workDir/$phase-$id.out";
        $outFiles[] = $outFile;
        $cmd = [PHP_BINARY, __FILE__, '--worker', (string) $id, $phase, $outFile, $prefix, (string) $perWorker];
        if ($poolFile !== null) {
            $cmd[] = $poolFile;
        }
        $pipes = [];
        $proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($proc)) {
            fwrite(STDERR, "perf-load: cannot spawn worker $id\n");
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
    $wallMs = ($t1 - $t0) / 1e6;
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
                if (count($parts) !== 3 || $parts[0] !== 'sample') {
                    $errors[] = "unparsable worker line: $line";
                    continue;
                }
                $samples[$parts[1]][] = (float) $parts[2];
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

    return ['samples' => $samples, 'errors' => $errors, 'n' => array_sum(array_map('count', $samples)), 'wallMs' => $wallMs, 'windowMs' => $windowMs];
}

/** @return array{p50: float, p95: float} the measured percentiles */
function report(string $label, array $samples, float $windowMs, float $baselineP95): array
{
    $n = count($samples);
    $p50 = percentile($samples, 50);
    $p95 = percentile($samples, 95);
    $ops = $windowMs > 0 ? (int) round($n / ($windowMs / 1000.0)) : 0;
    printf(
        "perf-load: %s p50 %.3f ms p95 %.3f ms (n=%d); throughput %d ops/s\n",
        $label,
        $p50,
        $p95,
        $n,
        $ops,
    );
    if ($baselineP95 <= 0.0) {
        // A missing timing-baseline leaf: note degradation by default,
        // a hard failure under $KIWI_STRICT_BASELINE=1 (the manual
        // hard-ratchet job). The flag is remembered so the final exit
        // code reflects it even though no numeric ratchet applies.
        if (!perf_baseline_missing('perf-load', $label)) {
            $GLOBALS['perf_load_strict_missing_baseline'] = true;
        }

        return ['p50' => $p50, 'p95' => $p95, 'n' => $n, 'throughput' => $ops];
    }
    if ($p95 > $baselineP95 * RATCHET) {
        fwrite(STDERR, sprintf("perf-load FAILED: %s p95 %.3f ms exceeds the ratchet %.3f ms (3x baseline %.3f ms)\n", $label, $p95, $baselineP95 * RATCHET, $baselineP95));
    }

    return ['p50' => $p50, 'p95' => $p95, 'n' => $n, 'throughput' => $ops];
}

function usage(): void
{
    fwrite(STDERR, "usage: php perf-load.php [--issue] [--verify] [--mixed] [--risk] [--all] [--workers N] [--per-worker N] [--url redis://host:port] [--update-baseline] [--baseline-out file]\n");
    exit(1);
}

$workerIndex = array_search('--worker', $argv, true);
if ($workerIndex !== false) {
    $rest = array_values(array_slice($argv, $workerIndex + 1));
    $fh = fopen('php://stdout', 'w');

    return exit(workerMode($rest, $fh));
}

set_time_limit(0);

$modeIssue = false;
$modeVerify = false;
$modeMixed = false;
$modeRisk = false;
$modeAll = false;
$workers = 8;
$perWorker = 100;
$update = false;
foreach ($argv as $i => $arg) {
    switch ($arg) {
        case '--issue':
            $modeIssue = true;
            break;
        case '--verify':
            $modeVerify = true;
            break;
        case '--mixed':
            $modeMixed = true;
            break;
        case '--risk':
            $modeRisk = true;
            break;
        case '--all':
            $modeAll = true;
            break;
        case '--workers':
            if (!isset($argv[$i + 1])) {
                usage();
            }
            $workers = (int) $argv[$i + 1];
            break;
        case '--per-worker':
            if (!isset($argv[$i + 1])) {
                usage();
            }
            $perWorker = (int) $argv[$i + 1];
            break;
        case '--update-baseline':
            $update = true;
            break;
        case '--url':
        case '--baseline-out':
            break;
        default:
            if ($i > 0 && !in_array($argv[$i - 1], ['--url', '--workers', '--per-worker', '--baseline-out'], true)) {
                usage();
            }
    }
}
if (!$modeIssue && !$modeVerify && !$modeMixed && !$modeRisk && !$modeAll) {
    $modeAll = true;
}
if ($modeAll) {
    $modeIssue = $modeVerify = $modeMixed = $modeRisk = true;
}
if ($workers < 1 || $perWorker < 1) {
    usage();
}

$baselineOut = null;
foreach ($argv as $i => $arg) {
    if ($arg === '--baseline-out' && isset($argv[$i + 1])) {
        $baselineOut = $argv[$i + 1];
    }
}
$baselineFile = $baselineOut ?? __DIR__.'/perf-baselines.json';

$url = redisUrlFromArgs($argv);
$probe = redisOrNull($url);
if ($probe === null) {
    fwrite(STDERR, sprintf("perf-load NOTE: no Redis answers at %s; the concurrent-load benchmark is skipped — the timing signal is non-gating\n", $url));
    exit(0);
}

$prefix = 'perf-load-'.bin2hex(random_bytes(6)).'-';
$workDir = sys_get_temp_dir().'/perf-load-'.getmypid();
if (!mkdir($workDir) && !is_dir($workDir)) {
    fwrite(STDERR, "perf-load: cannot create $workDir\n");
    exit(1);
}

$poolFile = null;
$allOk = true;
$measured = [];

if ($modeVerify) {
    $prepT0 = hrtime(true);
    $pool = [];
    $issuer = new Issuer(shaConfig(), new RedisStorage($probe, $prefix));
    for ($i = 0; $i < $workers * $perWorker; $i++) {
        $challenge = $issuer->issue('login', '198.51.100.7');
        $pool[] = ['nonce' => $challenge->nonce, 'token' => tokenFor($challenge, solveCounter($challenge))];
    }
    $poolFile = "$workDir/pool.jsonl";
    $fh = fopen($poolFile, 'wb');
    foreach ($pool as $row) {
        fwrite($fh, json_encode($row, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n");
    }
    fclose($fh);
    $prepMs = (hrtime(true) - $prepT0) / 1e6;
    printf("perf-load: verify pool prepared in %.0f ms (%d challenges issued and solved)\n", $prepMs, count($pool));
}

if ($modeIssue) {
    $r = runPhase('issue', $workers, $perWorker, $prefix, $workDir, null);
    if ($r['errors'] !== []) {
        foreach ($r['errors'] as $error) {
            fwrite(STDERR, "perf-load: issue phase error: $error\n");
        }
        $allOk = false;
    } else {
        $measured['issue'] = report('concurrent issue ('.($workers * $perWorker).' challenges)', $r['samples']['issue'] ?? [], $r['windowMs'], perf_baseline_float($baselineFile, ['load', 'issue', 'p95_ms']));
    }
}

if ($modeVerify) {
    $r = runPhase('verify', $workers, $perWorker, $prefix, $workDir, $poolFile);
    if ($r['errors'] !== []) {
        foreach ($r['errors'] as $error) {
            fwrite(STDERR, "perf-load: verify phase error: $error\n");
        }
        $allOk = false;
    } else {
        $measured['verify'] = report('concurrent verify ('.($workers * $perWorker).' tokens)', $r['samples']['verify'] ?? [], $r['windowMs'], perf_baseline_float($baselineFile, ['load', 'verify', 'p95_ms']));
    }
}

if ($modeMixed) {
    $r = runPhase('mixed', $workers, $perWorker, $prefix, $workDir, null);
    if ($r['errors'] !== []) {
        foreach ($r['errors'] as $error) {
            fwrite(STDERR, "perf-load: mixed phase error: $error\n");
        }
        $allOk = false;
    } else {
        $measured['mixed-issue'] = report('mixed-pipeline issue ('.($workers * $perWorker).' challenges)', $r['samples']['issue'] ?? [], $r['windowMs'], perf_baseline_float($baselineFile, ['load', 'mixed-issue', 'p95_ms']));
        $measured['mixed-verify'] = report('mixed-pipeline verify ('.($workers * $perWorker).' tokens)', $r['samples']['verify'] ?? [], $r['windowMs'], perf_baseline_float($baselineFile, ['load', 'mixed-verify', 'p95_ms']));
    }
}

if ($modeRisk) {
    if (!riskPathAvailable()) {
        fwrite(STDERR, "perf-load NOTE: the php-core risk path (KiwiCaptcha\\Risk) is absent from the php-core vendor; the risk-enabled variant is skipped — the bundle's risk-enabled controller path is covered by perf-bench-risk.php\n");
    } else {
        $r = runPhase('risk', $workers, $perWorker, $prefix, $workDir, null);
        if ($r['errors'] !== []) {
            foreach ($r['errors'] as $error) {
                fwrite(STDERR, "perf-load: risk phase error: $error\n");
            }
            $allOk = false;
        } else {
            $measured['risk-issue'] = report('risk-enabled concurrent issue ('.($workers * $perWorker).' challenges)', $r['samples']['risk-issue'] ?? [], $r['windowMs'], perf_baseline_float($baselineFile, ['load', 'risk-issue', 'p95_ms']));
        }
    }
}

if ($baselineOut !== null) {
    if ($measured === []) {
        fwrite(STDERR, "perf-load: --baseline-out given but no phase measured anything; the record was not updated\n");
    } else {
        $record = [];
        foreach ($measured as $key => $values) {
            $record[$key] = [
                'p50_ms' => $values['p50'],
                'p95_ms' => $values['p95'],
                'n' => $values['n'],
                'throughput_ops_per_second' => $values['throughput'],
            ];
        }
        try {
            perf_baseline_emit($baselineOut, ['load'], $record);
            printf("perf-load: baseline record updated in %s\n", $baselineOut);
        } catch (\Throwable $e) {
            fwrite(STDERR, 'perf-load: cannot write the baseline record: '.$e->getMessage()."\n");
            exit(1);
        }
    }
}

if ($update) {
    $fmt = static fn (string $key, string $label): string => isset($measured[$key])
        ? sprintf('%s p95 %.3f', $label, $measured[$key]['p95'])
        : "$label not measured";
    echo 'perf-load: measured p95 values to record: '.implode(', ', [
        $fmt('issue', 'issue'),
        $fmt('verify', 'verify'),
        $fmt('mixed-issue', 'mixed issue'),
        $fmt('mixed-verify', 'mixed verify'),
        $fmt('risk-issue', 'risk issue'),
    ])."\n";
    exit(0);
}

foreach ($measured as $key => $values) {
    $baseline = perf_baseline_float($baselineFile, ['load', $key, 'p95_ms']);
    if ($baseline > 0.0 && $values['p95'] > $baseline * RATCHET) {
        $allOk = false;
    }
}

if (!$allOk || ($GLOBALS['perf_load_strict_missing_baseline'] ?? false)) {
    exit(1);
}
echo "perf-load: OK (every measured p95 within its 3x noisy-runner-tolerant ratchet)\n";
