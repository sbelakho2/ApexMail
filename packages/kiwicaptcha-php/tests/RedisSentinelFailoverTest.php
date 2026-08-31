<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Tests\Fixtures\RealRedisTestEnv;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * Redis Sentinel failover contract against a real master, replica and
 * sentinel that this suite boots itself.
 *
 * The documented topology contract: the verified-WAIT barrier is
 * refused on a Predis Sentinel aggregate, so waitReplicas must stay 0.
 * A store pointed at the primary fails closed with typed connection
 * errors when the primary dies. It never fabricates a success and
 * never silently accepts a stale view. After a promotion, records
 * that were consumed on the former primary may legitimately reappear
 * as pending on the promoted stale replica; that is the documented
 * async replication boundary. The observable contract of that
 * boundary is what this suite asserts: a vanished or rolled-back
 * record resolves as missing or pending-fresh, and a committed
 * verification result is never replayed from a replica that never
 * received it.
 *
 * The stale-promotion window is manufactured deterministically: local
 * writes on the replica (replica-read-only off, then restored)
 * roll the consumed record back to its issued pending envelope and
 * delete the committed record, exactly the state a lagging replica
 * presents after promotion. Real async lag is normally microseconds
 * on a loopback topology, so the stale view cannot be raced; it is
 * placed on the replica deliberately, then the sentinel promotes it.
 *
 * Runs in the dedicated "PHP core real-Redis fault/topology" CI lane,
 * which publishes `KC_REDIS_URL` and `TEST_REDIS_URL` and sets
 * `KIWI_REQUIRE_REAL_REDIS_TESTS=1`; with the flag on, a missing or
 * unreachable Redis, or missing redis-server/redis-cli binaries, fails
 * the suite instead of skipping. With the flag off the suite skips
 * like every other real-Redis suite.
 */
final class RedisSentinelFailoverTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const ISSUED_AT = 1_800_000_000;

    private const MASTER_NAME = 'mymaster';

    /** @var array<int, resource> */
    private array $procs = [];

    private string $tmpDir = '';

    private int $masterPort = 0;

    private int $replicaPort = 0;

    private int $sentinelPort = 0;

    private $masterProc = null;

    protected function tearDown(): void
    {
        foreach ($this->procs as $proc) {
            $status = proc_get_status($proc);
            if ($status !== false && $status['running']) {
                proc_terminate($proc, 9);
                proc_close($proc);
            }
        }
        $this->procs = [];
        if ($this->tmpDir !== '' && is_dir($this->tmpDir)) {
            $this->removeDir($this->tmpDir);
        }
        $this->tmpDir = '';
        $this->masterPort = 0;
        $this->replicaPort = 0;
        $this->sentinelPort = 0;
        $this->masterProc = null;
    }

    private function removeDir(string $dir): void
    {
        $items = scandir($dir);
        if ($items === false) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir.'/'.$item;
            if (is_dir($path)) {
                $this->removeDir($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    private function envRedisOrSkip(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $url = RealRedisTestEnv::requireRedis('the Redis Sentinel failover suite');
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis topology suites run in the dedicated real-Redis CI lane');
        }
        try {
            $probe = new \Predis\Client($url, ['timeout' => 3.0]);
            $probe->ping();
        } catch (\Throwable) {
            RealRedisTestEnv::failWhenRequired('no Redis is reachable at the configured KC_REDIS_URL/TEST_REDIS_URL', 'the Redis Sentinel failover suite');
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }
    }

    private function binariesOrSkip(): void
    {
        foreach (['redis-server', 'redis-cli'] as $binary) {
            if (RealRedisTestEnv::requireBinary($binary, 'the Redis Sentinel failover suite')) {
                continue;
            }
            self::markTestSkipped("{$binary} not found on PATH — the sentinel topology suite needs a local redis-server build with sentinel support");
        }
    }

    private function freePort(): int
    {
        for ($attempt = 0; $attempt < 50; $attempt++) {
            $candidate = 20_000 + random_int(0, 25_000);
            $sock = @stream_socket_server('tcp://127.0.0.1:'.$candidate, $errno, $errstr);
            if ($sock !== false) {
                fclose($sock);

                return $candidate;
            }
        }
        self::markTestSkipped('no free local port available for the sentinel suite: '.$errstr);
    }

    /**
     * Boot a redis-server as a tracked child process (never daemonized,
     * so the PID is known for the failover kill), with logs on disk.
     *
     * @param list<string> $extraArgs
     *
     * @return resource the proc handle
     */
    private function spawnRedisServer(array $extraArgs, string $name)
    {
        $log = $this->tmpDir.'/'.$name.'.log';
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
        if (!\is_resource($proc)) {
            self::markTestSkipped('failed to start '.$name.' (see '.$log.')');
        }
        fclose($pipes[0]);
        $this->procs[] = $proc;

        return $proc;
    }

    private function waitFor(callable $predicate, int $timeoutSecs, string $what): void
    {
        $deadline = microtime(true) + $timeoutSecs;
        while (microtime(true) < $deadline) {
            if ($predicate()) {
                return;
            }
            usleep(150_000);
        }
        self::fail('timed out waiting for: '.$what);
    }

    /** @return list<int> [masterPort, replicaPort, sentinelPort] */
    private function startTopologyOrSkip(): array
    {
        if ($this->masterPort !== 0) {
            return [$this->masterPort, $this->replicaPort, $this->sentinelPort];
        }
        $this->envRedisOrSkip();
        $this->binariesOrSkip();
        $this->tmpDir = sys_get_temp_dir().'/kiwicaptcha-sentinel-'.bin2hex(random_bytes(6));
        if (!mkdir($this->tmpDir, 0o700, true) && !is_dir($this->tmpDir)) {
            self::markTestSkipped('cannot create the sentinel scratch directory');
        }
        $lastFailure = '';
        for ($attempt = 0; $attempt < 3; $attempt++) {
            $candidates = [$this->freePort(), $this->freePort(), $this->freePort()];
            try {
                $this->masterPort = $candidates[0];
                $this->replicaPort = $candidates[1];
                $this->sentinelPort = $candidates[2];
                $master = $this->spawnRedisServer(['--port', (string) $this->masterPort, '--dir', $this->tmpDir], 'master');
                $this->masterProc = $master;
                $this->spawnRedisServer([
                    '--port', (string) $this->replicaPort,
                    '--replicaof', '127.0.0.1', (string) $this->masterPort,
                    '--dir', $this->tmpDir,
                ], 'replica');
                $this->waitFor(
                    fn (): bool => str_contains((string) @shell_exec('redis-cli -p '.$this->masterPort.' ping 2>/dev/null'), 'PONG'),
                    10,
                    'the master to answer PONG',
                );
                $this->waitFor(
                    fn (): bool => str_contains((string) @shell_exec('redis-cli -p '.$this->replicaPort.' ping 2>/dev/null'), 'PONG'),
                    10,
                    'the replica to answer PONG',
                );
                $sentinelConf = $this->tmpDir.'/sentinel.conf';
                $conf = "port {$this->sentinelPort}\n"
                    ."logfile \"{$this->tmpDir}/sentinel.log\"\n"
                    ."dir {$this->tmpDir}\n"
                    ."sentinel monitor ".self::MASTER_NAME.' 127.0.0.1 '.$this->masterPort." 1\n"
                    ."sentinel down-after-milliseconds ".self::MASTER_NAME." 500\n"
                    ."sentinel failover-timeout ".self::MASTER_NAME." 4000\n"
                    ."sentinel parallel-syncs ".self::MASTER_NAME." 1\n";
                file_put_contents($sentinelConf, $conf);
                $this->spawnRedisServer([$sentinelConf, '--sentinel'], 'sentinel');
                $sentinel = new \Predis\Client('tcp://127.0.0.1:'.$this->sentinelPort, ['timeout' => 2.0]);
                $this->waitFor(
                    fn (): bool => $this->sentinelSeesTheMaster($sentinel),
                    15,
                    'the sentinel to observe the master',
                );
                $this->waitFor(
                    fn (): bool => str_contains((string) @shell_exec('redis-cli -p '.$this->replicaPort.' info replication 2>/dev/null'), 'master_link_status:up'),
                    15,
                    'the replica to finish its initial sync',
                );
                $probe = new \Predis\Client('tcp://127.0.0.1:'.$this->masterPort, ['timeout' => 2.0]);
                $probe->set('sentinel-probe', '1');
                $acked = $probe->executeRaw(['WAIT', '1', '5000']);
                if ($acked !== 1) {
                    throw new \RuntimeException('the replica never acknowledged a write (WAIT returned '.var_export($acked, true).')');
                }

                return [$this->masterPort, $this->replicaPort, $this->sentinelPort];
            } catch (\Throwable $e) {
                $lastFailure = $e->getMessage();
                $this->tearDownTopologyProcs();
                $this->masterPort = 0;
                $this->replicaPort = 0;
                $this->sentinelPort = 0;
            }
        }
        self::markTestSkipped('sentinel topology boot was attempted but failed: '.$lastFailure);
    }

    private function sentinelSeesTheMaster(\Predis\Client $sentinel): bool
    {
        try {
            return $this->masterAddressOf($sentinel) === [$this->masterPort, '127.0.0.1'];
        } catch (\Predis\PredisException $e) {
            if (!$this->isConnectionFailure($e)) {
                throw $e;
            }

            return false;
        }
    }

    /** Whether a Predis exception is a typed connection failure. */
    private function isConnectionFailure(\Predis\PredisException $e): bool
    {
        return $e instanceof \Predis\Connection\ConnectionException
            || $e instanceof \Predis\Connection\Resource\Exception\StreamInitException;
    }

    private function tearDownTopologyProcs(): void
    {
        foreach ($this->procs as $proc) {
            $status = proc_get_status($proc);
            if ($status !== false && $status['running']) {
                proc_terminate($proc, 9);
            }
            proc_close($proc);
        }
        $this->procs = [];
        $this->masterProc = null;
    }

    /** @return list{0: int, 1: string} [port, host] */
    private function masterAddressOf(\Predis\Client $sentinel): array
    {
        $reply = $sentinel->executeRaw(['SENTINEL', 'get-master-addr-by-name', self::MASTER_NAME]);
        if (!\is_array($reply) || \count($reply) !== 2) {
            return [0, ''];
        }

        return [(int) $reply[1], (string) $reply[0]];
    }

    private function makeRecord(string $nonce): ChallengeRecord
    {
        return new ChallengeRecord(
            nonce: $nonce,
            scope: 'login',
            bindingTag: 'abc123',
            issuedAt: self::ISSUED_AT,
            expiresAt: self::ISSUED_AT + 120,
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
    }

    public function testFailClosedDuringTheOutageAndTheStalePromotionBoundary(): void
    {
        [$masterPort, $replicaPort, $sentinelPort] = $this->startTopologyOrSkip();
        $prefix = 'sentinel-test-'.bin2hex(random_bytes(4)).'-';
        $masterClient = new \Predis\Client('tcp://127.0.0.1:'.$masterPort, ['timeout' => 2.0, 'read_write_timeout' => 2.0]);
        $storage = new RedisStorage($masterClient, $prefix);

        $c1 = 'c1-'.bin2hex(random_bytes(8));
        $c2 = 'c2-'.bin2hex(random_bytes(8));
        $c3 = 'c3-'.bin2hex(random_bytes(8));
        $storage->store($this->makeRecord($c1));
        $pendingJson = $masterClient->get($prefix.$c1);
        self::assertIsString($pendingJson, 'the issued envelope must exist before the consume');
        $consumed1 = $storage->consume($c1);
        self::assertNotNull($consumed1);
        self::assertTrue($consumed1->consumedNow);
        $storage->store($this->makeRecord($c2));
        self::assertNotNull($storage->consume($c2));
        self::assertTrue($storage->commitResult($c2, true, 'txn-committed'));
        $storage->store($this->makeRecord($c3));

        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
        $baseline = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT))->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($baseline->isOk(), 'the baseline issue and verify must succeed against the master, got '.$baseline->code());

        $acked = $masterClient->executeRaw(['WAIT', '1', '3000']);
        self::assertSame(1, $acked, 'the replica must hold every baseline write before the failover');

        $replicaClient = new \Predis\Client('tcp://127.0.0.1:'.$replicaPort, ['timeout' => 2.0, 'read_write_timeout' => 2.0]);
        $replicaClient->config('set', 'replica-read-only', 'no');
        $replicaClient->set($prefix.$c1, $pendingJson, 'EX', 120);
        $replicaClient->del($prefix.$c2);
        $replicaClient->config('set', 'replica-read-only', 'yes');
        $staleC1 = $replicaClient->get($prefix.$c1);
        self::assertIsString($staleC1);
        self::assertStringContainsString('"state":"pending"', $staleC1, 'the manufactured stale view must present the record as pending');
        self::assertNull($replicaClient->get($prefix.$c2), 'the manufactured stale view must have lost the committed record');

        $masterProc = $this->masterProc;
        self::assertNotNull($masterProc);
        proc_terminate($masterProc, 9);
        $this->masterProc = null;

        $failingOps = [
            static fn (): mixed => $storage->find('sentinel-nonce'),
            static fn (): mixed => $storage->consume($c1),
            static fn (): mixed => $storage->commitResult($c1, true, null),
            static fn (): mixed => $storage->deleteIfPending($c3),
            static fn (): mixed => $storage->claimResumeDerivation($c1),
        ];
        foreach ($failingOps as $op) {
            $threw = false;
            for ($attempt = 0; $attempt < 10; $attempt++) {
                try {
                    $value = $op();
                    if ($value !== null) {
                        self::fail('an operation returned a value while the primary was down: '.var_export($value, true));
                    }
                } catch (\Predis\PredisException $e) {
                    if (!$this->isConnectionFailure($e)) {
                        throw $e;
                    }
                    $threw = true;
                    break;
                }
                usleep(100_000);
            }
            self::assertTrue($threw, 'every operation must fail closed with a typed connection error while the primary is down');
        }

        $sentinel = new \Predis\Client('tcp://127.0.0.1:'.$sentinelPort, ['timeout' => 2.0]);
        $this->waitFor(
            fn (): bool => $this->masterAddressOf($sentinel) === [$replicaPort, '127.0.0.1'],
            25,
            'the sentinel to promote the replica',
        );
        $role = trim((string) @shell_exec('redis-cli -p '.$replicaPort.' info replication 2>/dev/null'));
        self::assertStringContainsString('role:master', $role, 'the promoted node must be a master');

        $promoted = new \Predis\Client('tcp://127.0.0.1:'.$replicaPort, ['timeout' => 2.0, 'read_write_timeout' => 2.0]);
        $freshStorage = new RedisStorage($promoted, $prefix);

        $c1Raw = $promoted->get($prefix.$c1);
        self::assertIsString($c1Raw, 'the stale promoted replica must still hold the rolled-back record');
        self::assertStringContainsString('"state":"pending"', $c1Raw, 'the rolled-back record resolves pending, never a fabricated consumed view');
        self::assertStringContainsString('"consumed_result":null', $c1Raw, 'a consumed record whose result commit never replicated resolves without a result');
        self::assertStringNotContainsString('"valid":true', $c1Raw, 'a committed authorization is never replayed from the stale promoted replica');
        self::assertNull($freshStorage->consumedState($c1), 'the vanished consume resolves as not-consumed, never a replayed authorization');
        $fresh = $freshStorage->consume($c1);
        self::assertNotNull($fresh, 'the pending-fresh record is consumable on the new authority');
        self::assertTrue($fresh->consumedNow);
        self::assertFalse($fresh->consumedBefore);
        self::assertNull($fresh->consumedResult, 'the fresh consume carries no replayed result');

        self::assertNull($freshStorage->find($c2), 'a record that vanished with the former primary resolves as missing, never a replayed authorization');
        self::assertNull($promoted->get($prefix.$c2), 'the committed record is absent on the promoted replica');
        $c3After = $freshStorage->find($c3);
        self::assertNotNull($c3After, 'an untouched pending record survives the promotion');
        self::assertSame($c3, $c3After->nonce);
    }

    public function testVerifiedWaitGuardRefusesWaitReplicasOnTheRealSentinelAggregate(): void
    {
        $this->startTopologyOrSkip();
        $sentinel = new \Predis\Connection\Replication\SentinelReplication(
            self::MASTER_NAME,
            ['tcp://127.0.0.1:'.$this->sentinelPort],
            new \Predis\Connection\Factory(),
        );
        $client = new \Predis\Client($sentinel);

        try {
            new RedisStorage($client, waitReplicas: 1);
            self::fail('a Predis Sentinel aggregate must be refused when waitReplicas > 0');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('replication aggregate', $e->getMessage());
            self::assertStringContainsString('write offset is empty', $e->getMessage());
        }
        $storage = new RedisStorage($client);
        self::assertInstanceOf(RedisStorage::class, $storage, 'waitReplicas 0 must construct on a sentinel aggregate');
    }
}
