<?php

declare(strict_types=1);

/**
 * Synthetic-load benchmark for issuance and verification latency.
 *
 * Modes (all timing, all non-gating by design):
 *  - default (no flag): the SHA-256 workload against ArrayStorage, the
 *    original baseline mode. 400 challenges are issued, solved and
 *    verified at 8 target bits with 40 warmup iterations; issuance and
 *    verification are timed per iteration and the solve phase runs
 *    inside the workload without being a measured phase.
 *  - --redis: the same workload against the php-core RedisStorage on a
 *    real Redis. The mode activates only when a URL is available
 *    (KC_REDIS_URL, or --url, or the local default
 *    redis://127.0.0.1:6399) and the server answers ping. Without a
 *    reachable server it prints a loud note and exits 0, because the
 *    byte budgets in perf-budget.sh remain the gating gate and this
 *    timing signal is noisy-runner-tolerant by design. A per-run
 *    storage prefix keeps runs isolated; verification consumes each
 *    record, so no cleanup is needed.
 *  - --argon: Argon2id issuance + verification measured separately,
 *    through the admission gate (VerificationAdmissionGate) exactly as
 *    the verifier consumes it in production. The gate is an
 *    in-process token-set implementation inside this harness; the
 *    iteration count is small (20 + 5 warmup) because each verification
 *    derives a memory-hard hash (64 MiB, t=3, the argon64 production
 *    profile). The solve phase is memory-hard too: an Argon2id
 *    challenge is solved by Argon2id derivations, because the verifier
 *    re-derives the same hash. The harness therefore uses the 2-bit
 *    target (expected 4 derivations per solve) instead of the
 *    production 4-bit target to keep the non-measured solve phase
 *    bounded.
 *
 * Every mode gates on the same generous relative ratchet: the run
 * fails only when a p95 exceeds 3x its recorded baseline. The design is
 * noisy-runner-tolerant on purpose, because a shared CI runner can
 * stall a single iteration without any code regression. The byte and
 * count budgets live in perf-budget.sh, which gates deterministically;
 * this timing signal is loud but never a hard merge gate by itself.
 *
 * Flags. --json-out <path> writes the run's provenance record with the
 * shared schema kiwicaptcha.perf-run/1. The record carries the tool
 * name, the timestamp, every measurement with its n and printed
 * percentiles, and the ratchet verdict for each p95. It also carries
 * the baseline file the ratchet read, the environment and the source
 * commit. The record is written on the pass path, on the
 * ratchet-failure path and on the --baseline-out failure path, and an
 * unwritable path fails the run. --iterations N and --warmup N
 * override the per-lane defaults, which keeps a test run small; the
 * overrides are recorded in each measurement's configuration.
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

$autoload = __DIR__.'/../../kiwicaptcha-php/vendor/autoload.php';
if (!is_file($autoload)) {
    fwrite(STDERR, "perf-bench: kiwicaptcha-php vendor is missing at $autoload\n");
    exit(1);
}
require $autoload;
require __DIR__.'/perf-baseline-emit.php';
require __DIR__.'/perf-record.php';

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\VerificationAdmissionGate;
use KiwiCaptcha\Verifier;

const UPDATE_BASELINE = '--update-baseline';
const WARMUP = 40;
const ITERATIONS = 400;
const ARGON_WARMUP = 5;
const ARGON_ITERATIONS = 20;
const RATCHET = 3.0;

/** The in-process admission gate of the harness: a token-set cap, the
 *  InProcessArgonGate contract without the bundle dependency. */
final class BenchAdmissionGate implements VerificationAdmissionGate
{
    /** @var array<string, true> */
    private array $leases = [];

    public function __construct(private readonly int $maxConcurrent = 8)
    {
    }

    public function acquire(): ?string
    {
        if ($this->maxConcurrent <= 0) {
            return 'disabled';
        }
        if (\count($this->leases) >= $this->maxConcurrent) {
            return null;
        }
        $token = bin2hex(random_bytes(16));
        $this->leases[$token] = true;

        return $token;
    }

    public function release(string $lease): void
    {
        unset($this->leases[$lease]);
    }
}

function percentile(array $samples, float $q): float
{
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

function argonConfig(): Config
{
    return new Config(
        secretKey: '0123456789abcdef0123456789abcdef',
        algorithm: PoWAlgorithm::Argon2id,
        mKib: 65536,
        t: 3,
        p: 1,
        targetBits: 8,
        argon2TargetBits: 2,
        ttlSecs: 120,
        minDurationMs: 0,
    );
}

/** The memory-hard solve: derive Argon2id hashes until the target is met. */
function solveArgon($challenge): int
{
    $counter = 0;
    $saltBytes = base64_decode($challenge->salt, true);
    $memlimit = $challenge->mKib * 1024;
    do {
        $hash = sodium_crypto_pwhash(32, $challenge->prefix.$counter, $saltBytes, $challenge->t, $memlimit, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        $counter++;
    } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);

    return $counter - 1;
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

/** @return array{p50: float, p90: float, p95: float, n: int} */
function runWorkload(callable $issue, callable $solve, callable $verify, int $warmup, int $iterations): array
{
    $issueSamples = [];
    $verifySamples = [];
    for ($i = 0; $i < $warmup + $iterations; $i++) {
        $t0 = hrtime(true);
        $challenge = $issue();
        $t1 = hrtime(true);
        $token = tokenFor($challenge, $solve($challenge));
        $t2 = hrtime(true);
        $ok = $verify($token);
        $t3 = hrtime(true);
        if (!$ok) {
            fwrite(STDERR, "perf-bench: a verification failed in the workload\n");
            exit(1);
        }
        if ($i >= $warmup) {
            $issueSamples[] = ($t1 - $t0) / 1e6;
            $verifySamples[] = ($t3 - $t2) / 1e6;
        }
    }

    return [
        'issue' => ['p50' => percentile($issueSamples, 50), 'p90' => percentile($issueSamples, 90), 'p95' => percentile($issueSamples, 95), 'n' => count($issueSamples)],
        'verify' => ['p50' => percentile($verifySamples, 50), 'p90' => percentile($verifySamples, 90), 'p95' => percentile($verifySamples, 95), 'n' => count($verifySamples)],
    ];
}

/**
 * Print one lane's percentile line and evaluate its ratchet. Returns
 * the lane's pass flag plus the ratchet verdict block per phase, which
 * the --json-out record carries.
 *
 * @return array{ok: bool, ratchet: array{issue: array<string, mixed>, verify: array<string, mixed>}}
 */
function report(string $label, array $r, float $bIssueP95, float $bVerifyP95): array
{
    printf(
        "perf-bench: %s issuance p50 %.3f ms p95 %.3f ms p90 %.3f ms (n=%d); verification p50 %.3f ms p95 %.3f ms p90 %.3f ms (n=%d)\n",
        $label,
        $r['issue']['p50'],
        $r['issue']['p95'],
        $r['issue']['p90'],
        $r['issue']['n'],
        $r['verify']['p50'],
        $r['verify']['p95'],
        $r['verify']['p90'],
        $r['verify']['n'],
    );
    if ($bIssueP95 <= 0.0 || $bVerifyP95 <= 0.0) {
        // A missing timing-baseline leaf: note degradation by default,
        // a hard failure under $KIWI_STRICT_BASELINE=1 (the manual
        // hard-ratchet job), because a hard-ratchet run with no
        // baseline is not a hard ratchet.
        $ok = perf_baseline_missing('perf-bench', $label);
        $verdict = $ok ? 'missing_baseline' : 'missing_baseline_failed';
        $block = perf_record_ratchet(null, null, $verdict);

        return ['ok' => $ok, 'ratchet' => ['issue' => $block, 'verify' => $block]];
    }
    $failed = false;
    $issueRatchet = perf_record_ratchet($bIssueP95, $bIssueP95 * RATCHET, 'ok');
    $verifyRatchet = perf_record_ratchet($bVerifyP95, $bVerifyP95 * RATCHET, 'ok');
    if ($r['issue']['p95'] > $bIssueP95 * RATCHET) {
        fwrite(STDERR, sprintf("perf-bench FAILED: %s issuance p95 %.3f ms exceeds the ratchet %.3f ms (3x baseline %.3f ms)\n", $label, $r['issue']['p95'], $bIssueP95 * RATCHET, $bIssueP95));
        $failed = true;
        $issueRatchet['verdict'] = 'failed';
    }
    if ($r['verify']['p95'] > $bVerifyP95 * RATCHET) {
        fwrite(STDERR, sprintf("perf-bench FAILED: %s verification p95 %.3f ms exceeds the ratchet %.3f ms (3x baseline %.3f ms)\n", $label, $r['verify']['p95'], $bVerifyP95 * RATCHET, $bVerifyP95));
        $failed = true;
        $verifyRatchet['verdict'] = 'failed';
    }

    return ['ok' => !$failed, 'ratchet' => ['issue' => $issueRatchet, 'verify' => $verifyRatchet]];
}

$modeArray = !in_array('--redis', $argv, true) && !in_array('--argon', $argv, true) || in_array('--all', $argv, true);
$modeRedis = in_array('--redis', $argv, true) || in_array('--all', $argv, true);
$modeArgon = in_array('--argon', $argv, true) || in_array('--all', $argv, true);
$update = in_array(UPDATE_BASELINE, $argv, true);
$baselineOut = null;
$jsonOut = null;
$iterations = ITERATIONS;
$warmup = WARMUP;
$argonIterations = ARGON_ITERATIONS;
$argonWarmup = ARGON_WARMUP;
foreach ($argv as $i => $arg) {
    if ($arg === '--baseline-out' && isset($argv[$i + 1])) {
        $baselineOut = $argv[$i + 1];
    }
    if ($arg === '--json-out' && isset($argv[$i + 1])) {
        $jsonOut = $argv[$i + 1];
    }
    if ($arg === '--iterations' && isset($argv[$i + 1])) {
        $iterations = max(1, (int) $argv[$i + 1]);
        $argonIterations = $iterations;
    }
    if ($arg === '--warmup' && isset($argv[$i + 1])) {
        $warmup = max(0, (int) $argv[$i + 1]);
        $argonWarmup = $warmup;
    }
}

$allOk = true;
$record = [];
$measurements = [];
$redisUrl = null;
$phaseFmt = static fn (array $p): array => ['p50_ms' => $p['p50'], 'p90_ms' => $p['p90'], 'p95_ms' => $p['p95'], 'n' => $p['n']];
$baselineFile = $baselineOut ?? __DIR__.'/perf-baselines.json';

if ($modeArray) {
    $storage = new ArrayStorage();
    $issuer = new Issuer(shaConfig(), $storage);
    $verifier = new Verifier($storage);
    $r = runWorkload(
        static fn () => $issuer->issue('login', '198.51.100.7'),
        solveCounter(...),
        static fn (string $token) => $verifier->verify($token, shaConfig()->secretKey, 'login', '198.51.100.7')->isOk(),
        $warmup,
        $iterations,
    );
    $verdict = report(
        'SHA-256 array',
        $r,
        perf_baseline_float($baselineFile, ['bench', 'sha_array', 'issue', 'p95_ms']),
        perf_baseline_float($baselineFile, ['bench', 'sha_array', 'verify', 'p95_ms']),
    );
    $allOk = $verdict['ok'] && $allOk;
    $record['sha_array'] = ['issue' => $phaseFmt($r['issue']), 'verify' => $phaseFmt($r['verify'])];
    $measurements['sha_array'] = [
        'configuration' => ['algorithm' => 'sha256', 'storage' => 'array', 'target_bits' => 8, 'warmup' => $warmup, 'iterations' => $iterations],
        'issue' => perf_record_sample($r['issue']['n'], $r['issue']['p50'], $r['issue']['p90'], $r['issue']['p95'], null, $verdict['ratchet']['issue']),
        'verify' => perf_record_sample($r['verify']['n'], $r['verify']['p50'], $r['verify']['p90'], $r['verify']['p95'], null, $verdict['ratchet']['verify']),
    ];
}

if ($modeRedis) {
    $url = getenv('KC_REDIS_URL');
    if (!is_string($url) || $url === '') {
        $url = 'redis://127.0.0.1:6399';
    }
    $redisUrl = $url;
    if (!class_exists(\Predis\Client::class)) {
        fwrite(STDERR, "perf-bench: --redis requested but predis/predis is not installed; skipping the Redis mode\n");
        exit(1);
    }
    $redis = null;
    try {
        $redis = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
        $redis->ping();
    } catch (\Throwable $e) {
        fwrite(STDERR, sprintf("perf-bench NOTE: --redis requested but no Redis answers at %s (%s); the Redis mode is skipped — the timing signal is non-gating\n", $url, $e->getMessage()));
        $modeRedis = false;
        $measurements['sha_redis'] = null;
    }
    if ($modeRedis) {
        $storage = new RedisStorage($redis, 'perf-bench-'.bin2hex(random_bytes(6)).'-');
        $issuer = new Issuer(shaConfig(), $storage);
        $verifier = new Verifier($storage);
        $r = runWorkload(
            static fn () => $issuer->issue('login', '198.51.100.7'),
            solveCounter(...),
            static fn (string $token) => $verifier->verify($token, shaConfig()->secretKey, 'login', '198.51.100.7')->isOk(),
            $warmup,
            $iterations,
        );
        $verdict = report(
            'SHA-256 redis',
            $r,
            perf_baseline_float($baselineFile, ['bench', 'sha_redis', 'issue', 'p95_ms']),
            perf_baseline_float($baselineFile, ['bench', 'sha_redis', 'verify', 'p95_ms']),
        );
        $allOk = $verdict['ok'] && $allOk;
        $record['sha_redis'] = ['issue' => $phaseFmt($r['issue']), 'verify' => $phaseFmt($r['verify'])];
        $measurements['sha_redis'] = [
            'configuration' => ['algorithm' => 'sha256', 'storage' => 'redis', 'target_bits' => 8, 'warmup' => $warmup, 'iterations' => $iterations],
            'issue' => perf_record_sample($r['issue']['n'], $r['issue']['p50'], $r['issue']['p90'], $r['issue']['p95'], null, $verdict['ratchet']['issue']),
            'verify' => perf_record_sample($r['verify']['n'], $r['verify']['p50'], $r['verify']['p90'], $r['verify']['p95'], null, $verdict['ratchet']['verify']),
        ];
    }
}

if ($modeArgon) {
    $storage = new ArrayStorage();
    $config = argonConfig();
    $issuer = new Issuer($config, $storage);
    $gate = new BenchAdmissionGate();
    $verifier = new Verifier($storage, $gate);
    $r = runWorkload(
        static fn () => $issuer->issue('login', '198.51.100.7'),
        solveArgon(...),
        static fn (string $token) => $verifier->verify($token, $config->secretKey, 'login', '198.51.100.7')->isOk(),
        $argonWarmup,
        $argonIterations,
    );
    $verdict = report(
        'Argon2id admission',
        $r,
        perf_baseline_float($baselineFile, ['bench', 'argon', 'issue', 'p95_ms']),
        perf_baseline_float($baselineFile, ['bench', 'argon', 'verify', 'p95_ms']),
    );
    $allOk = $verdict['ok'] && $allOk;
    $record['argon'] = ['issue' => $phaseFmt($r['issue']), 'verify' => $phaseFmt($r['verify'])];
    $measurements['argon'] = [
        'configuration' => ['algorithm' => 'argon2id', 'm_kib' => 65536, 't' => 3, 'p' => 1, 'target_bits' => 2, 'warmup' => $argonWarmup, 'iterations' => $argonIterations],
        'issue' => perf_record_sample($r['issue']['n'], $r['issue']['p50'], $r['issue']['p90'], $r['issue']['p95'], null, $verdict['ratchet']['issue']),
        'verify' => perf_record_sample($r['verify']['n'], $r['verify']['p50'], $r['verify']['p90'], $r['verify']['p95'], null, $verdict['ratchet']['verify']),
    ];
}

if ($baselineOut !== null) {
    if ($record === []) {
        fwrite(STDERR, "perf-bench: --baseline-out given but no mode measured anything; the record was not updated\n");
    } else {
        try {
            perf_baseline_emit($baselineOut, ['bench'], $record);
            printf("perf-bench: baseline record updated in %s\n", $baselineOut);
        } catch (\Throwable $e) {
            if ($jsonOut !== null) {
                perf_record_write($jsonOut, perf_record_envelope('perf-bench', $argv, $baselineFile, $redisUrl) + [
                    'measurements' => $measurements,
                    'verdict' => 'baseline_write_failed',
                ]);
            }
            fwrite(STDERR, 'perf-bench: cannot write the baseline record: '.$e->getMessage()."\n");
            exit(1);
        }
    }
}

$runVerdict = $allOk ? 'ok' : 'failed';
if ($update) {
    $runVerdict = 'updated_baseline';
}
if ($jsonOut !== null) {
    perf_record_write($jsonOut, perf_record_envelope('perf-bench', $argv, $baselineFile, $redisUrl) + [
        'measurements' => $measurements,
        'verdict' => $runVerdict,
    ]);
}

if ($update) {
    exit(0);
}

if (!$allOk) {
    exit(1);
}
echo "perf-bench: OK (every measured p95 within its 3x noisy-runner-tolerant ratchet)\n";
