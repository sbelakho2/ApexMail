<?php

declare(strict_types=1);

/**
 * The real primary+replica verified-WAIT fixture.
 *
 * perf-wait.php measures the shortfall path only: on a single Redis
 * authority WAIT acknowledges 0 replicas and every barrier operation
 * fails closed after the wait timeout. That delta is the upper bound
 * of the barrier cost. This fixture boots a real local primary plus
 * replica (replicaof the primary, raw WAIT 1 confirms the initial
 * sync). The same RedisStorage verified-WAIT barrier then runs on
 * the successful-acknowledgment path. Every durability-critical
 * write (issuance, the pending-to-consumed transition, the
 * deterministic result commit) is followed by a WAIT that returns in
 * milliseconds once the replica acked.
 *
 * Phases against the booted local topology. The gate is the same
 * KC_REDIS_URL / --url gate as the other real-Redis tools, with the
 * local default redis://127.0.0.1:6399 as the gate probe. The
 * measured master is a fresh local server on a free port, never the
 * gated one. The phases:
 *  - sync: the replica attaches with replicaof, the initial sync is
 *    confirmed with master_link_status:up, and a raw WAIT 1 must ack
 *    exactly 1 before any phase runs.
 *  - baseline: RedisStorage with waitReplicas 0 over the same master
 *    connection; issuance, consume and commit are timed per operation
 *    as the no-barrier reference.
 *  - ack: RedisStorage with waitReplicas 1 and the 100 ms store
 *    default timeout over the same connection; issuance, consume and
 *    commit are timed per operation, every durability-critical write
 *    must ack 1 replica.
 *  - lag: the replication-lag distribution between the master write
 *    and the replica's acked state, measured two ways: the raw WAIT 1
 *    ack latency after a fence write, and the master-write to
 *    replica-visible delta polled on the replica connection.
 *  - shortfall: the replica is stopped and the same barrier is forced
 *    to fail closed on the same fixture. A raw WAIT 1 answers 0, and
 *    every barrier write (issuance, consume, commit) must raise
 *    ReplicaWaitException once the wait timeout elapses. The
 *    shortfall latency is reported per operation.
 *
 * The fixture is non-gating on timing by design, like the other perf
 * tools: it reports p50, p95 and the p95 delta of the ack phase over
 * the baseline, and the recorded values live in
 * tools/perf-baselines.json below. The only hard failure is a
 * correctness invariant: an ack-phase write that raises
 * ReplicaWaitException, or a shortfall write that does not, proves
 * the barrier was silently downgraded and fails the run. A missing
 * redis-server / redis-cli binary, an unreachable gate Redis, or a
 * topology that never reaches acked sync prints a loud note and exits
 * 0.
 *
 * Teardown is unconditional: both redis-server child processes are
 * terminated (SIGTERM first, a forced kill after a grace period) and
 * the scratch directory is removed. Teardown also runs on failure and
 * on Ctrl-C / SIGTERM when pcntl is available. A shutdown handler
 * runs the same teardown on every exit path and prints the proof
 * line.
 *
 * The recorded values live in tools/perf-baselines.json, the single
 * machine-readable record for the performance-analysis document.
 * After a deliberate change, run with
 * --baseline-out tools/perf-baselines.json on a clean local machine to
 * merge the fresh measurements into the record.
 */

$autoload = __DIR__.'/../../kiwicaptcha-php/vendor/autoload.php';
if (!is_file($autoload)) {
    fwrite(STDERR, "perf-wait-replica: kiwicaptcha-php vendor is missing at $autoload\n");
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
const BOOT_TIMEOUT_SECS = 20;

/**
 * @var array<int, resource> the spawned redis-server proc handles
 */
$procs = [];

/**
 * The scratch directory holding the server logs and RDB state.
 */
$tmpDir = '';

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
 * Issue a nonce pool through the given storage and time every
 * issuance. The first warmup issuances warm the connection and the
 * script cache; their timings are discarded. The pool is pre-issued
 * with waitReplicas 0 storage, so a later shortfall phase can consume
 * and commit against pre-existing records.
 *
 * @return array{nonces: list<string>, samples: list<float>}
 */
function issuePool(RedisStorage $storage, int $count): array
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
 * per-operation wall times in milliseconds. $expect is 'ack' (every
 * durability-critical write must complete with the replica acked) or
 * 'raise' (every write must raise ReplicaWaitException on the forced
 * shortfall). The first warmup operations warm the connection; their
 * timings are discarded.
 *
 * @param list<string> $nonces
 * @return array{samples: array<string, list<float>>, acked: int, raises: int, missing: list<string>}
 */
function runConsumeCommit(RedisStorage $storage, array $nonces, string $expect): array
{
    $samples = ['consume' => [], 'commit' => []];
    $acked = 0;
    $raises = 0;
    $missing = [];
    foreach ($nonces as $index => $nonce) {
        $fresh = false;
        $t0 = hrtime(true);
        try {
            $record = $storage->consume($nonce);
            $t1 = hrtime(true);
            $fresh = $record !== null && $record->consumedNow;
            if ($fresh) {
                $acked++;
            }
        } catch (ReplicaWaitException $e) {
            $t1 = hrtime(true);
            $raises++;
            if ($expect !== 'raise') {
                throw $e;
            }
        }
        if ($expect === 'raise' && $fresh) {
            $missing[] = 'a consume succeeded while the shortfall should force ReplicaWaitException';
        }
        if ($expect === 'ack' && !$fresh) {
            $missing[] = 'a fresh issuance did not consume as a fresh acked transition';
        }
        $committed = false;
        try {
            $committed = $storage->commitResult($nonce, true, 'perf-wait-replica');
            $t2 = hrtime(true);
            if ($committed) {
                $acked++;
            }
        } catch (ReplicaWaitException $e) {
            $t2 = hrtime(true);
            $raises++;
            if ($expect !== 'raise') {
                throw $e;
            }
        }
        if ($expect === 'raise' && $committed) {
            $missing[] = 'a commit succeeded while the shortfall should force ReplicaWaitException';
        }
        if ($expect === 'ack' && !$committed) {
            $missing[] = 'a fresh commit reported not committed';
        }
        if ($index >= WARMUP) {
            $samples['consume'][] = ($t1 - $t0) / 1e6;
            $samples['commit'][] = ($t2 - $t1) / 1e6;
        }
    }

    return ['samples' => $samples, 'acked' => $acked, 'raises' => $raises, 'missing' => array_values(array_unique($missing))];
}

function freePort(): int
{
    for ($attempt = 0; $attempt < 50; $attempt++) {
        $candidate = 20_000 + random_int(0, 25_000);
        $sock = @stream_socket_server('tcp://127.0.0.1:'.$candidate, $errno, $errstr);
        if ($sock !== false) {
            fclose($sock);

            return $candidate;
        }
    }
    fwrite(STDERR, "perf-wait-replica NOTE: no free local port available ($errstr); the replica fixture is skipped\n");
    exit(0);
}

/**
 * @return resource
 */
function spawnRedisServer(array $extraArgs, string $name, string $dir, array &$procs)
{
    $log = $dir.'/'.$name.'.log';
    $args = array_merge(
        ['redis-server'],
        $extraArgs,
        ['--save', '', '--appendonly', 'no', '--logfile', $log],
    );
    $proc = proc_open($args, [
        0 => ['pipe', 'r'],
        1 => ['file', $log, 'a'],
        2 => ['file', $log, 'a'],
    ], $pipes);
    if (!is_resource($proc)) {
        fwrite(STDERR, "perf-wait-replica NOTE: failed to start $name (see $log); the replica fixture is skipped\n");
        exit(0);
    }
    fclose($pipes[0]);
    $procs[] = $proc;

    return $proc;
}

function waitFor(callable $predicate, int $timeoutSecs, string $what): bool
{
    $deadline = microtime(true) + $timeoutSecs;
    while (microtime(true) < $deadline) {
        if ($predicate()) {
            return true;
        }
        usleep(150_000);
    }
    fwrite(STDERR, "perf-wait-replica NOTE: timed out waiting for $what; the replica fixture is skipped\n");

    return false;
}

function removeDir(string $dir): void
{
    $items = @scandir($dir);
    if ($items === false) {
        return;
    }
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $path = $dir.'/'.$item;
        if (is_dir($path)) {
            removeDir($path);
        } else {
            @unlink($path);
        }
    }
    @rmdir($dir);
}

/**
 * Stop a spawned redis-server: SIGTERM, then a forced kill after a
 * short grace period, then reap the handle. Returns true when the
 * process exited.
 */
function stopProcess($proc, int $signalWaitSecs = 3): bool
{
    if (!is_resource($proc)) {
        return true;
    }
    $status = proc_get_status($proc);
    if ($status === false || !$status['running']) {
        proc_close($proc);

        return true;
    }
    proc_terminate($proc, 15);
    $deadline = microtime(true) + $signalWaitSecs;
    while (microtime(true) < $deadline) {
        $status = proc_get_status($proc);
        if ($status === false || !$status['running']) {
            proc_close($proc);

            return true;
        }
        usleep(100_000);
    }
    proc_terminate($proc, 9);
    proc_close($proc);

    return false;
}

/**
 * Stop the replica only (the shortfall phase). The handle is removed
 * from the tracked set so the final teardown never reaps it.
 */
function stopReplica(array &$procs, $replicaProc): void
{
    foreach ($procs as $i => $proc) {
        if ($proc === $replicaProc) {
            unset($procs[$i]);
            break;
        }
    }
    stopProcess($replicaProc);
}

/**
 * The unconditional teardown: stop every tracked server, remove the
 * scratch directory and print the proof line.
 */
function teardown(array &$procs, string &$tmpDir, int $masterPid, int $replicaPid): void
{
    $masterExited = true;
    $replicaExited = true;
    foreach ($procs as $i => $proc) {
        $status = proc_get_status($proc);
        $pid = $status === false ? null : (int) ($status['pid'] ?? 0);
        $exited = stopProcess($proc);
        unset($procs[$i]);
        if ($pid === $masterPid) {
            $masterExited = $exited;
        }
        if ($pid === $replicaPid) {
            $replicaExited = $exited;
        }
    }
    if ($tmpDir !== '' && is_dir($tmpDir)) {
        removeDir($tmpDir);
    }
    $dirState = $tmpDir !== '' && is_dir($tmpDir) ? 'left behind' : 'removed';
    printf(
        "perf-wait-replica: teardown complete (master pid %d %s, replica pid %d %s; scratch dir %s)\n",
        $masterPid,
        $masterExited ? 'stopped' : 'needed SIGKILL',
        $replicaPid,
        $replicaExited ? 'stopped' : 'needed SIGKILL',
        $dirState,
    );
    $tmpDir = '';
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
$gate = redisClientOrNull($url);
if ($gate === null) {
    fwrite(STDERR, sprintf("perf-wait-replica NOTE: no Redis answers at %s; the replica fixture is skipped (the timing signal is non-gating)\n", $url));
    exit(0);
}
foreach (['redis-server', 'redis-cli'] as $binary) {
    if (trim((string) shell_exec('command -v '.$binary.' 2>/dev/null')) === '') {
        fwrite(STDERR, "perf-wait-replica NOTE: $binary not found on PATH; the replica fixture is skipped (install redis-server with replica support)\n");
        exit(0);
    }
}

$tmpDir = sys_get_temp_dir().'/kiwicaptcha-replica-perf-'.bin2hex(random_bytes(6));
if (!mkdir($tmpDir, 0o700, true) && !is_dir($tmpDir)) {
    fwrite(STDERR, "perf-wait-replica NOTE: cannot create the replica scratch directory; the fixture is skipped\n");
    exit(0);
}

register_shutdown_function(static function () use (&$procs, &$tmpDir, &$masterPid, &$replicaPid): void {
    teardown($procs, $tmpDir, $masterPid, $replicaPid);
});
if (function_exists('pcntl_signal')) {
    pcntl_async_signals(true);
    pcntl_signal(SIGINT, static function (): void {
        exit(130);
    });
    pcntl_signal(SIGTERM, static function (): void {
        exit(143);
    });
}

$masterPort = freePort();
$replicaPort = freePort();
$masterProc = spawnRedisServer(['--port', (string) $masterPort, '--dir', $tmpDir], 'master', $tmpDir, $procs);
$replicaProc = spawnRedisServer([
    '--port', (string) $replicaPort,
    '--replicaof', '127.0.0.1', (string) $masterPort,
    '--dir', $tmpDir,
], 'replica', $tmpDir, $procs);
$masterStatus = proc_get_status($masterProc);
$replicaStatus = proc_get_status($replicaProc);
$masterPid = (int) ($masterStatus['pid'] ?? 0);
$replicaPid = (int) ($replicaStatus['pid'] ?? 0);

$ok = waitFor(
    static fn (): bool => str_contains((string) @shell_exec('redis-cli -p '.$masterPort.' ping 2>/dev/null'), 'PONG'),
    BOOT_TIMEOUT_SECS,
    'the master to answer PONG',
);
$ok = $ok && waitFor(
    static fn (): bool => str_contains((string) @shell_exec('redis-cli -p '.$replicaPort.' ping 2>/dev/null'), 'PONG'),
    BOOT_TIMEOUT_SECS,
    'the replica to answer PONG',
);
$ok = $ok && waitFor(
    static fn (): bool => str_contains((string) @shell_exec('redis-cli -p '.$replicaPort.' info replication 2>/dev/null'), 'master_link_status:up'),
    BOOT_TIMEOUT_SECS,
    'the replica to finish its initial sync',
);
if (!$ok) {
    exit(0);
}

$client = new \Predis\Client('tcp://127.0.0.1:'.$masterPort, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$replicaClient = new \Predis\Client('tcp://127.0.0.1:'.$replicaPort, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);

// Sync confirmation: the replica must ack a write on the master
// before any barrier phase can claim the acked path.
$client->set('perf-wait-replica-sync-probe', '1');
$syncAcked = $client->executeRaw(['WAIT', '1', '5000']);
if ((string) $syncAcked !== '1') {
    fwrite(STDERR, sprintf("perf-wait-replica NOTE: the replica never acknowledged the sync probe (WAIT replied %s); the fixture is skipped\n", var_export($syncAcked, true)));
    exit(0);
}
printf("perf-wait-replica: topology up (master 127.0.0.1:%d, replica 127.0.0.1:%d; initial sync acked by WAIT 1)\n", $masterPort, $replicaPort);

$count = WARMUP + $iterations;
$prefix = 'perf-wait-replica-'.bin2hex(random_bytes(6)).'-';
$baseline = new RedisStorage($client, $prefix);
$barrier = new RedisStorage($client, $prefix, waitReplicas: 1, waitTimeoutMs: WAIT_TIMEOUT_MS);

// The baseline reference: issuance, consume and commit without the
// barrier, the honest no-barrier cost the ack delta is measured
// against.
$baseIssue = issuePool($baseline, $count * 2);
$baseNonces = array_slice($baseIssue['nonces'], 0, $count);
$shortfallNonces = array_slice($baseIssue['nonces'], $count, $count);
$baseOps = runConsumeCommit($baseline, $baseNonces, 'ack');
if ($baseOps['missing'] !== []) {
    foreach ($baseOps['missing'] as $issue) {
        fwrite(STDERR, "perf-wait-replica: baseline invariant failure: $issue\n");
    }
    exit(1);
}

// The ack phase: every durability-critical write goes through the
// verified WAIT with the replica acked, on pre-issued nonces for
// consume and commit, and through real issuance for issuance.
$ackIssue = issuePool($barrier, $count);
$ackOps = runConsumeCommit($barrier, $ackIssue['nonces'], 'ack');
if ($ackOps['missing'] !== []) {
    foreach ($ackOps['missing'] as $issue) {
        fwrite(STDERR, "perf-wait-replica: ack-phase invariant failure: $issue\n");
    }
    exit(1);
}
if ($ackOps['acked'] !== $count * 2) {
    fwrite(STDERR, sprintf("perf-wait-replica: ack-phase invariant failure: %d of %d durability-critical writes acked the replica\n", $ackOps['acked'], $count * 2));
    exit(1);
}

// The replication-lag distribution: the raw WAIT 1 ack latency after
// a fence write, and the master-write to replica-visible delta polled
// on the replica connection.
$waitAckSamples = [];
$visibleSamples = [];
for ($i = 0; $i < $count; $i++) {
    $value = bin2hex(random_bytes(8));
    $t0 = hrtime(true);
    $client->set('perf-wait-replica-lag-'.$i, $value);
    $t1 = hrtime(true);
    $acked = $client->executeRaw(['WAIT', '1', (string) WAIT_TIMEOUT_MS]);
    $t2 = hrtime(true);
    if ((string) $acked !== '1') {
        fwrite(STDERR, sprintf("perf-wait-replica: lag invariant failure: WAIT replied %s while the replica is attached\n", var_export($acked, true)));
        exit(1);
    }
    $waitAckSamples[] = ($t2 - $t1) / 1e6;
    $deadline = microtime(true) + 5.0;
    do {
        $seen = $replicaClient->get('perf-wait-replica-lag-'.$i);
    } while ($seen !== $value && microtime(true) < $deadline);
    $t3 = hrtime(true);
    if ($seen !== $value) {
        fwrite(STDERR, "perf-wait-replica: lag invariant failure: the replica never observed a replicated write within 5 s\n");
        exit(1);
    }
    $visibleSamples[] = ($t3 - $t1) / 1e6;
}

// The shortfall phase on the same fixture: the replica is stopped,
// WAIT 1 must answer 0, and every barrier write must fail closed.
printf("perf-wait-replica: stopping the replica (pid %d) to force the shortfall on the same fixture\n", $replicaPid);
stopReplica($procs, $replicaProc);
$shortfallAcked = $client->executeRaw(['WAIT', '1', (string) WAIT_TIMEOUT_MS]);
if ((string) $shortfallAcked !== '0') {
    fwrite(STDERR, sprintf("perf-wait-replica: shortfall invariant failure: raw WAIT replied %s after the replica was stopped\n", var_export($shortfallAcked, true)));
    exit(1);
}

$shortfallOps = runConsumeCommit($barrier, $shortfallNonces, 'raise');
if ($shortfallOps['missing'] !== []) {
    foreach ($shortfallOps['missing'] as $issue) {
        fwrite(STDERR, "perf-wait-replica: shortfall invariant failure: $issue\n");
    }
    exit(1);
}
$shortfallIssueRaised = 0;
$record = new \KiwiCaptcha\ChallengeRecord(
    nonce: 'shortfall-'.bin2hex(random_bytes(8)),
    scope: 'login',
    bindingTag: 'abc123',
    issuedAt: time(),
    expiresAt: time() + 120,
    algorithm: PoWAlgorithm::Sha256,
    mKib: 0,
    t: 1,
    p: 1,
    targetBits: 8,
    salt: 'c2FsdA==',
    prefix: 'prefix',
    challenge: 'challenge',
    minDurationMs: 0,
    issuedAtNs: 123_456_789,
);
try {
    $barrier->store($record);
    fwrite(STDERR, "perf-wait-replica: shortfall invariant failure: an issuance did not raise ReplicaWaitException with the replica gone\n");
    exit(1);
} catch (ReplicaWaitException) {
    $shortfallIssueRaised = 1;
}
$expectedRaises = $count * 2 + 1;
if ($shortfallOps['raises'] + $shortfallIssueRaised !== $expectedRaises) {
    fwrite(STDERR, sprintf("perf-wait-replica: shortfall invariant failure: %d of %d durability-critical writes raised ReplicaWaitException\n", $shortfallOps['raises'] + $shortfallIssueRaised, $expectedRaises));
    exit(1);
}

$measured = fn (array $samples): array => [percentile($samples, 50), percentile($samples, 95)];

printf("perf-wait-replica: baseline issuance p50 %.3f ms p95 %.3f ms (n=%d)\n", ...array_merge($measured($baseIssue['samples']), [$count]));
printf("perf-wait-replica: ack issuance p50 %.3f ms p95 %.3f ms (n=%d; every write acked 1 replica)\n", ...array_merge($measured($ackIssue['samples']), [$count]));
foreach (['consume', 'commit'] as $op) {
    $bp50 = percentile($baseOps['samples'][$op], 50);
    $bp95 = percentile($baseOps['samples'][$op], 95);
    $wp50 = percentile($ackOps['samples'][$op], 50);
    $wp95 = percentile($ackOps['samples'][$op], 95);
    printf("perf-wait-replica: baseline %s p50 %.3f ms p95 %.3f ms (n=%d)\n", $op, $bp50, $bp95, count($baseOps['samples'][$op]));
    printf("perf-wait-replica: ack %s p50 %.3f ms p95 %.3f ms (n=%d; every write acked 1 replica)\n", $op, $wp50, $wp95, count($ackOps['samples'][$op]));
    printf("perf-wait-replica: %s p95 delta (ack over baseline) %+.3f ms\n", $op, $wp95 - $bp95);
    if ($op === 'consume') {
        $consumeDelta = $wp95 - $bp95;
    } else {
        $commitDelta = $wp95 - $bp95;
    }
}
$issueDelta = $measured($ackIssue['samples'])[1] - $measured($baseIssue['samples'])[1];
printf("perf-wait-replica: issuance p95 delta (ack over baseline) %+.3f ms\n", $issueDelta);
printf("perf-wait-replica: p95 delta consume %+.3f ms, commit %+.3f ms (primary+replica; the acked path is the production topology)\n", $consumeDelta, $commitDelta);

[$waitP50, $waitP95] = $measured($waitAckSamples);
[$visibleP50, $visibleP95] = $measured($visibleSamples);
printf("perf-wait-replica: lag raw WAIT 1 after a fence write p50 %.3f ms p95 %.3f ms (n=%d)\n", $waitP50, $waitP95, $count);
printf("perf-wait-replica: lag master-write to replica-visible p50 %.3f ms p95 %.3f ms (n=%d)\n", $visibleP50, $visibleP95, $count);

$shortP50 = percentile($shortfallOps['samples']['consume'], 50);
$shortP95 = percentile($shortfallOps['samples']['consume'], 95);
printf("perf-wait-replica: shortfall consume p50 %.3f ms p95 %.3f ms (n=%d; every write raised ReplicaWaitException)\n", $shortP50, $shortP95, count($shortfallOps['samples']['consume']));
$shortP50 = percentile($shortfallOps['samples']['commit'], 50);
$shortP95 = percentile($shortfallOps['samples']['commit'], 95);
printf("perf-wait-replica: shortfall commit p50 %.3f ms p95 %.3f ms (n=%d; every write raised ReplicaWaitException)\n", $shortP50, $shortP95, count($shortfallOps['samples']['commit']));
printf("perf-wait-replica: shortfall issuance raised ReplicaWaitException after the replica was stopped\n");

if ($baselineOut !== null) {
    $fmtSamples = static fn (array $samples): array => ['p50_ms' => percentile($samples, 50), 'p95_ms' => percentile($samples, 95), 'n' => count($samples)];
    try {
        perf_baseline_emit($baselineOut, ['wait_replica'], [
            'baseline' => [
                'issuance' => $fmtSamples($baseIssue['samples']),
                'consume' => $fmtSamples($baseOps['samples']['consume']),
                'commit' => $fmtSamples($baseOps['samples']['commit']),
            ],
            'ack' => [
                'issuance' => $fmtSamples($ackIssue['samples']),
                'consume' => $fmtSamples($ackOps['samples']['consume']),
                'commit' => $fmtSamples($ackOps['samples']['commit']),
            ],
            'p95_delta_ms' => ['issuance' => round($issueDelta, 3), 'consume' => round($consumeDelta, 3), 'commit' => round($commitDelta, 3)],
            'lag' => ['wait_ack' => $fmtSamples($waitAckSamples), 'replica_visible' => $fmtSamples($visibleSamples)],
            'shortfall' => [
                'consume' => $fmtSamples($shortfallOps['samples']['consume']),
                'commit' => $fmtSamples($shortfallOps['samples']['commit']),
            ],
            'wait_timeout_ms' => WAIT_TIMEOUT_MS,
        ]);
        printf("perf-wait-replica: baseline record updated in %s\n", $baselineOut);
    } catch (\Throwable $e) {
        fwrite(STDERR, 'perf-wait-replica: cannot write the baseline record: '.$e->getMessage()."\n");
        exit(1);
    }
}

echo "perf-wait-replica: OK (ack and shortfall invariants held; timing is advisory, non-gating)\n";
