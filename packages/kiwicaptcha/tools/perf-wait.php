<?php

declare(strict_types=1);

/**
 * The verified-WAIT durability barrier round-trip fixture.
 *
 * The RedisStorage verified-WAIT barrier (waitReplicas > 0) writes a
 * fresh replication fence and issues a raw WAIT after every
 * durability-critical mutation (issuance, the pending-to-consumed
 * transition, the result commit). On a single Redis authority there are
 * no replicas, so WAIT acknowledges 0 and the barrier fails closed
 * (ReplicaWaitException) once the wait timeout elapses. The round trip
 * is real and fully measurable; the timeout is the worst case because
 * no replica can ever ack. A real replica topology (a primary with the
 * configured replica count) is the full production fixture: there WAIT
 * returns as soon as the replicas ack, in milliseconds. The
 * single-authority delta recorded here is therefore the upper bound of
 * the added latency the barrier inserts between a mutation and its
 * client.
 *
 * Phases, against the same KC_REDIS_URL or --url, or the local default
 * redis://127.0.0.1:6399. A loud note plus exit 0 follows when the
 * server is unreachable.
 *  - pre-issue reference: challenges are issued through the baseline
 *    storage (waitReplicas 0) and timed per issuance, one nonce pool
 *    per phase. The barrier would raise on issuance too, so consume and
 *    commit are measured against pre-issued challenges.
 *  - baseline: RedisStorage with waitReplicas 0; consume and
 *    commitResult are timed per operation.
 *  - barrier: RedisStorage with waitReplicas 1 and the store default
 *    wait timeout of 100 ms; the same two operations are timed to the
 *    ReplicaWaitException every durability-critical write must raise on
 *    a single authority (0 acked replicas, fail closed).
 *  - raw: the bare WAIT 0 and WAIT 1 commands through the same Predis
 *    client, isolating the command-level round trip from the storage
 *    path. WAIT 1 on a replica-less node blocks the full timeout and
 *    replies 0.
 *
 * This single-node run exercises the shortfall/fail-closed path only:
 * on a single authority no replica can ever ack, so the numbers below
 * are the unsatisfied-WAIT upper bound, not the production topology.
 * The successful-acknowledgment numbers (issuance, consume and commit
 * with a real replica acked, plus the replication-lag distribution)
 * live in the sibling fixture perf-wait-replica.php, which boots a
 * local primary plus replica and measures the same barrier on the
 * acked path.
 *
 * The fixture is non-gating on timing by design: it reports p50, p95
 * and the p95 delta of the barrier phase over the baseline, and the
 * recorded values live in tools/perf-baselines.json below. The only
 * hard failure is a correctness invariant: a barrier-phase operation
 * that does not raise ReplicaWaitException proves the barrier was
 * silently downgraded and fails the run.
 *
 * The recorded values live in tools/perf-baselines.json, the single
 * machine-readable record for the performance-analysis document.
 * After a deliberate change, run with
 * --baseline-out tools/perf-baselines.json on a clean local machine to
 * merge the fresh measurements into the record.
 */

$autoload = __DIR__.'/../../kiwicaptcha-php/vendor/autoload.php';
if (!is_file($autoload)) {
    fwrite(STDERR, "perf-wait: kiwicaptcha-php vendor is missing at $autoload\n");
    exit(1);
}
require $autoload;
require __DIR__.'/perf-baseline-emit.php';

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Storage\ReplicaWaitException;

const WARMUP = 10;
const ITERATIONS = 100;
const WAIT_TIMEOUT_MS = 100;

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

/**
 * Pre-issue the challenge pool through the given storage and return the
 * nonces plus the per-issuance timings in milliseconds (the first
 * warmup issuances warm the connection and the script cache; their
 * timings are discarded).
 *
 * @return array{nonces: list<string>, samples: list<float>}
 */
function preIssuePool(RedisStorage $storage, int $count): array
{
    $issuer = new Issuer(shaConfig(), $storage);
    $nonces = [];
    $samples = [];
    for ($i = 0; $i < $count; $i++) {
        $t0 = hrtime(true);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $t1 = hrtime(true);
        $nonces[] = $challenge->nonce;
        if ($i >= WARMUP) {
            $samples[] = ($t1 - $t0) / 1e6;
        }
    }

    return ['nonces' => $nonces, 'samples' => $samples];
}

/**
 * Run the consume and commit loop over one nonce pool and collect the
 * per-operation wall times in milliseconds. The expected barrier
 * outcome is 'raise' (every durability-critical write must raise
 * ReplicaWaitException on a single authority) or 'none' (no barrier
 * configured, plain timings). The first warmup operations warm the
 * connection and the script cache; their timings are discarded.
 *
 * @param list<string> $nonces
 * @return array{samples: array<string, list<float>>, raises: int, missing: list<string>}
 */
function runConsumeCommit(RedisStorage $storage, array $nonces, string $expect): array
{
    $samples = ['consume' => [], 'commit' => []];
    $raises = 0;
    $missing = [];
    foreach ($nonces as $index => $nonce) {
        $consumeRaised = false;
        $commitRaised = false;
        $fresh = false;
        $committed = false;
        $t0 = hrtime(true);
        try {
            $record = $storage->consume($nonce);
            $t1 = hrtime(true);
            $fresh = $record !== null && $record->consumedNow;
        } catch (ReplicaWaitException $e) {
            $consumeRaised = true;
            $t1 = hrtime(true);
            $raises++;
            if ($expect !== 'raise') {
                throw $e;
            }
        }
        if ($expect === 'raise' && !$consumeRaised) {
            $missing[] = 'a consume did not raise ReplicaWaitException on a single authority';
        }
        if ($expect !== 'raise' && !$fresh) {
            $missing[] = 'a fresh issuance did not consume as a fresh transition';
        }
        try {
            $committed = $storage->commitResult($nonce, true, 'perf-wait');
            $t2 = hrtime(true);
        } catch (ReplicaWaitException $e) {
            $commitRaised = true;
            $t2 = hrtime(true);
            $raises++;
            if ($expect !== 'raise') {
                throw $e;
            }
        }
        if ($expect === 'raise' && !$commitRaised) {
            $missing[] = 'a commit did not raise ReplicaWaitException on a single authority';
        }
        if ($expect !== 'raise' && !$committed) {
            $missing[] = 'a fresh commit reported not committed';
        }
        if ($index >= WARMUP) {
            $samples['consume'][] = ($t1 - $t0) / 1e6;
            $samples['commit'][] = ($t2 - $t1) / 1e6;
        }
    }

    return ['samples' => $samples, 'raises' => $raises, 'missing' => array_values(array_unique($missing))];
}

/**
 * Measure the bare WAIT command round trip. WAIT 0 returns immediately;
 * WAIT 1 on a replica-less node blocks the full timeout and replies 0.
 *
 * @return array{ok: bool, detail: string, p50: float, p95: float, n: int}
 */
function runRawWait(\Predis\Client $client, int $count, int $replicas): array
{
    $samples = [];
    $lastReply = null;
    for ($i = 0; $i < $count; $i++) {
        $t0 = hrtime(true);
        $lastReply = $client->executeRaw(['WAIT', (string) $replicas, (string) WAIT_TIMEOUT_MS]);
        $t1 = hrtime(true);
        $samples[] = ($t1 - $t0) / 1e6;
    }
    $measured = array_slice($samples, WARMUP);
    $p50 = percentile($measured, 50);
    $p95 = percentile($measured, 95);
    printf("perf-wait: raw WAIT %d p50 %.3f ms p95 %.3f ms (n=%d; reply %s)\n", $replicas, $p50, $p95, count($measured), var_export($lastReply, true));

    return ['ok' => $replicas === 0 || (string) $lastReply === '0', 'detail' => 'raw WAIT '.$replicas.' reply '.var_export($lastReply, true), 'p50' => $p50, 'p95' => $p95, 'n' => count($measured)];
}

$iterations = ITERATIONS;
$baselineOut = null;
foreach ($argv as $i => $arg) {
    if ($arg === '--iterations' && isset($argv[$i + 1])) {
        $iterations = max(1, (int) $argv[$i + 1]);
    }
    if ($arg === '--baseline-out' && isset($argv[$i + 1])) {
        $baselineOut = $argv[$i + 1];
    }
}

$url = redisUrlFromArgs($argv);
$client = redisClientOrNull($url);
if ($client === null) {
    fwrite(STDERR, sprintf("perf-wait NOTE: no Redis answers at %s; the WAIT fixture is skipped — the timing signal is non-gating\n", $url));
    exit(0);
}

$count = WARMUP + $iterations;
$prefix = 'perf-wait-'.bin2hex(random_bytes(6)).'-';
$baseline = new RedisStorage($client, $prefix);
$barrier = new RedisStorage($client, $prefix, waitReplicas: 1, waitTimeoutMs: WAIT_TIMEOUT_MS);

$preIssue = preIssuePool($baseline, $count * 2);
$baseNonces = array_slice($preIssue['nonces'], 0, $count);
$barrierNonces = array_slice($preIssue['nonces'], $count, $count);

$base = runConsumeCommit($baseline, $baseNonces, 'none');
if ($base['missing'] !== []) {
    foreach ($base['missing'] as $issue) {
        fwrite(STDERR, "perf-wait: baseline invariant failure: $issue\n");
    }
    exit(1);
}

$barr = runConsumeCommit($barrier, $barrierNonces, 'raise');
if ($barr['missing'] !== []) {
    foreach ($barr['missing'] as $issue) {
        fwrite(STDERR, "perf-wait: barrier invariant failure: $issue\n");
    }
    exit(1);
}
if ($barr['raises'] !== $count * 2) {
    fwrite(STDERR, sprintf("perf-wait: barrier invariant failure: %d of %d durability-critical writes raised ReplicaWaitException\n", $barr['raises'], $count * 2));
    exit(1);
}

$raw0 = runRawWait($client, $count, 0);
$raw1 = runRawWait($client, $count, 1);
if (!$raw0['ok'] || !$raw1['ok']) {
    fwrite(STDERR, 'perf-wait: raw WAIT invariant failure: '.($raw0['ok'] ? '' : $raw0['detail'].'; ').($raw1['ok'] ? '' : $raw1['detail'])."\n");
    exit(1);
}

$issueP50 = percentile($preIssue['samples'], 50);
$issueP95 = percentile($preIssue['samples'], 95);
printf("perf-wait: pre-issue reference p50 %.3f ms p95 %.3f ms (n=%d)\n", $issueP50, $issueP95, count($preIssue['samples']));

$deltas = [];
foreach (['consume', 'commit'] as $op) {
    $bp50 = percentile($base['samples'][$op], 50);
    $bp95 = percentile($base['samples'][$op], 95);
    $wp50 = percentile($barr['samples'][$op], 50);
    $wp95 = percentile($barr['samples'][$op], 95);
    printf("perf-wait: baseline %s p50 %.3f ms p95 %.3f ms (n=%d)\n", $op, $bp50, $bp95, count($base['samples'][$op]));
    printf("perf-wait: barrier %s p50 %.3f ms p95 %.3f ms (n=%d)\n", $op, $wp50, $wp95, count($barr['samples'][$op]));
    printf("perf-wait: %s p95 delta (barrier over baseline) %+.3f ms\n", $op, $wp95 - $bp95);
    $deltas[$op] = $wp95 - $bp95;
}
printf("perf-wait: p95 delta consume %+.3f ms, commit %+.3f ms (single authority; a real replica topology is the full production fixture)\n", $deltas['consume'], $deltas['commit']);

if ($baselineOut !== null) {
    $fmtSamples = static fn (array $samples): array => ['p50_ms' => percentile($samples, 50), 'p95_ms' => percentile($samples, 95), 'n' => count($samples)];
    try {
        perf_baseline_emit($baselineOut, ['wait'], [
            'pre_issue' => $fmtSamples($preIssue['samples']),
            'baseline' => ['consume' => $fmtSamples($base['samples']['consume']), 'commit' => $fmtSamples($base['samples']['commit'])],
            'barrier' => ['consume' => $fmtSamples($barr['samples']['consume']), 'commit' => $fmtSamples($barr['samples']['commit'])],
            'raw' => ['wait0' => ['p50_ms' => $raw0['p50'], 'p95_ms' => $raw0['p95'], 'n' => $raw0['n']], 'wait1' => ['p50_ms' => $raw1['p50'], 'p95_ms' => $raw1['p95'], 'n' => $raw1['n']]],
            'p95_delta_ms' => ['consume' => round($deltas['consume'], 3), 'commit' => round($deltas['commit'], 3)],
            'wait_timeout_ms' => WAIT_TIMEOUT_MS,
        ]);
        printf("perf-wait: baseline record updated in %s\n", $baselineOut);
    } catch (\Throwable $e) {
        fwrite(STDERR, 'perf-wait: cannot write the baseline record: '.$e->getMessage()."\n");
        exit(1);
    }
}

echo "perf-wait: OK (barrier invariants held; timing is advisory, non-gating)\n";
