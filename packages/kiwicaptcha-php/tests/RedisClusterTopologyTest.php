<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Tests\Fixtures\RealRedisTestEnv;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * Redis Cluster routing/atomicity compatibility against a real
 * three-master cluster that this suite boots and tears down itself.
 *
 * This fixture is deliberately NOT a "Cluster HA verification": it
 * boots masters with no replicas, so no failover, promotion or
 * replica-side durability is exercised. Redis Cluster's
 * high-availability behavior is a separate deployment concern (see
 * docs/redis-topologies.md); what this fixture verifies is routing
 * and per-record atomicity.
 *
 * The documented topology contract: every storage Lua script touches
 * exactly one key. The record key is the one key, and the resume
 * claim is embedded in the record envelope, never a second key. The
 * argon admission semaphore's auxiliary keys are deliberately
 * co-slotted with the lease key ({K}:sem:waiters and {K}:<scope-hash>
 * hash to the lease key's slot because the tag inside the braces is
 * the lease key string itself). A cluster deployment therefore runs
 * every transition without a cross-slot error, and the
 * VerifiedWaitGuard refuses waitReplicas > 0 on a cluster client,
 * because a keyless WAIT has no slot to route by.
 *
 * Boots three cluster-enabled redis-server masters on free ports and
 * joins them with redis-cli --cluster create. It then drives the
 * php-core RedisStorage through the full lifecycle (issuance,
 * verification, consume, result commit, resume-claim, release,
 * delete-if-pending, cancel) over a Predis cluster client, with the
 * script bodies pre-loaded on every master. A Predis cluster
 * aggregate refuses the keyless warm-up command, so the warm-up runs
 * on each node's plain connection first; the actual transitions are
 * the single-key evalsha calls the storage performs.
 *
 * Runs in the dedicated "PHP core real-Redis fault/topology" CI lane,
 * which publishes `KC_REDIS_URL` and `TEST_REDIS_URL` and sets
 * `KIWI_REQUIRE_REAL_REDIS_TESTS=1`; with the flag on, a missing or
 * unreachable Redis, or missing redis-server/redis-cli binaries, fails
 * the suite instead of skipping. With the flag off the suite skips
 * like every other real-Redis suite. When the cluster cannot be
 * booted, the slot invariants are still asserted on the composed key
 * strings through the environment Redis (server keyslot where served,
 * the canonical CRC-16 computation otherwise).
 */
final class RedisClusterTopologyTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const ISSUED_AT = 1_800_000_000;

    /** @var array<int, resource> */
    private array $procs = [];

    private string $tmpDir = '';

    /** @var array<int, int> */
    private array $ports = [];

    private ?\Predis\Client $clusterClient = null;

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
        $this->ports = [];
        $this->clusterClient = null;
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

    /** @return \Predis\Client the environment Redis client (never null) */
    private function envRedisOrSkip(): \Predis\Client
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $url = RealRedisTestEnv::requireRedis('the Redis Cluster topology suite');
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis topology suites run in the dedicated real-Redis CI lane');
        }
        try {
            $client = new \Predis\Client($url, ['timeout' => 3.0, 'read_write_timeout' => 3.0]);
            $client->ping();

            return $client;
        } catch (\Throwable) {
            RealRedisTestEnv::failWhenRequired('no Redis is reachable at the configured KC_REDIS_URL/TEST_REDIS_URL', 'the Redis Cluster topology suite');
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }
    }

    private function binariesOrSkip(): void
    {
        foreach (['redis-server', 'redis-cli'] as $binary) {
            if (RealRedisTestEnv::requireBinary($binary, 'the Redis Cluster topology suite')) {
                continue;
            }
            self::markTestSkipped("{$binary} not found on PATH — the cluster topology suite needs a local redis-server build with cluster support");
        }
    }

    private function freePort(): int
    {
        // Cluster mode derives the bus port as the Redis port plus
        // 10000, so the port must stay below 55536; the macOS ephemeral
        // range (49152+) would overflow it. The scan stays inside the
        // 20000..45000 window, well away from the ephemeral range.
        for ($attempt = 0; $attempt < 50; $attempt++) {
            $candidate = 20_000 + random_int(0, 25_000);
            $sock = @stream_socket_server('tcp://127.0.0.1:'.$candidate, $errno, $errstr);
            if ($sock !== false) {
                fclose($sock);

                return $candidate;
            }
        }
        self::markTestSkipped('no free local port available for the topology suite: '.$errstr);
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

    /**
     * Wait until a predicate holds, bounded in seconds; the failure
     * message names the wait so a broken local build is diagnosable.
     */
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

    /** @return list<int> */
    private function startClusterOrSkip(): array
    {
        if ($this->ports !== []) {
            return $this->ports;
        }
        $this->envRedisOrSkip();
        $this->binariesOrSkip();
        $this->tmpDir = sys_get_temp_dir().'/kiwicaptcha-cluster-'.bin2hex(random_bytes(6));
        if (!mkdir($this->tmpDir, 0o700, true) && !is_dir($this->tmpDir)) {
            self::markTestSkipped('cannot create the topology scratch directory');
        }
        $ports = [$this->freePort(), $this->freePort(), $this->freePort()];
        $this->ports = $ports;
        $booted = 0;
        try {
            foreach ($ports as $port) {
                $this->spawnRedisServer([
                    '--port', (string) $port,
                    '--cluster-enabled', 'yes',
                    '--cluster-config-file', 'nodes-'.$port.'.conf',
                    '--dir', $this->tmpDir,
                ], 'master-'.$port);
                $booted++;
            }
            foreach ($ports as $port) {
                $this->waitFor(
                    static function () use ($port): bool {
                        $reply = @shell_exec('redis-cli -p '.$port.' ping 2>/dev/null');

                        return is_string($reply) && str_contains($reply, 'PONG');
                    },
                    10,
                    'cluster master '.$port.' to answer PONG',
                );
            }
            $this->createCluster($ports);
            $this->waitFor(
                static fn (): bool => str_contains((string) @shell_exec('redis-cli -p '.$ports[0].' cluster info 2>/dev/null'), 'cluster_state:ok'),
                20,
                'the cluster to reach cluster_state:ok',
            );
        } catch (\Throwable $e) {
            self::markTestSkipped('cluster boot was attempted but failed: '.$e->getMessage());
        }
        $nodes = array_map(static fn (int $port): string => 'tcp://127.0.0.1:'.$port, $ports);
        $this->clusterClient = new \Predis\Client($nodes, [
            'cluster' => 'redis',
            'parameters' => ['timeout' => 3.0, 'read_write_timeout' => 3.0],
        ]);

        return $ports;
    }

    /** @param list<int> $ports */
    private function createCluster(array $ports): void
    {
        $args = array_merge(
            ['redis-cli', '--cluster', 'create'],
            array_map(static fn (int $port): string => '127.0.0.1:'.$port, $ports),
            ['--cluster-replicas', '0', '--cluster-yes'],
        );
        $proc = proc_open($args, [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ], $pipes);
        if (!\is_resource($proc)) {
            throw new \RuntimeException('redis-cli --cluster create could not start');
        }
        fclose($pipes[0]);
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($proc);
        if ($exit !== 0) {
            throw new \RuntimeException('redis-cli --cluster create exited '.$exit.' ('.trim($out.' '.$err).')');
        }
    }

    /**
     * Pre-load every storage Lua body on each master over a plain
     * connection and seed the storage's sha cache. The Predis cluster
     * aggregate refuses the keyless warm-up command (it has no slot),
     * so the warm-up runs per node and the cache is pre-populated with
     * the server's sha (sha1 of the body). The transitions themselves
     * are the single-key evalsha calls the storage performs; a
     * deployment on a cluster warms the scripts per node the same way
     * (or uses a client whose warm-up is routable).
     */
    private function preloadScripts(array $ports, RedisStorage $storage): void
    {
        $reflection = new \ReflectionClass(RedisStorage::class);
        $names = [
            'CONSUME_SCRIPT',
            'DELETE_IF_PENDING_SCRIPT',
            'CANCEL_SCRIPT',
            'CLAIM_RESUME_SCRIPT',
            'RELEASE_RESUME_SCRIPT',
            'COMMIT_SCRIPT',
        ];
        $cache = [];
        foreach ($names as $name) {
            $body = (string) $reflection->getConstant($name);
            $cache[$body] = sha1($body);
        }
        foreach ($ports as $port) {
            $plain = new \Predis\Client('tcp://127.0.0.1:'.$port, ['timeout' => 3.0]);
            foreach ($names as $name) {
                $body = (string) $reflection->getConstant($name);
                $sha = $plain->script('LOAD', $body);
                if (!\is_string($sha) || $sha === '' || $sha !== $cache[$body]) {
                    throw new \RuntimeException('script pre-load failed on port '.$port);
                }
            }
            $plain->disconnect();
        }
        $cacheProperty = new \ReflectionProperty(RedisStorage::class, 'scriptShas');
        $cacheProperty->setValue($storage, $cache);
    }

    private function makeRecord(string $nonce): \KiwiCaptcha\ChallengeRecord
    {
        return new \KiwiCaptcha\ChallengeRecord(
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

    public function testRedisStorageLifecycleIsSingleSlotOnTheRealCluster(): void
    {
        $ports = $this->startClusterOrSkip();
        $prefix = 'cluster-test-'.bin2hex(random_bytes(4)).'-';
        $storage = new RedisStorage($this->clusterClient, $prefix);
        $this->preloadScripts($ports, $storage);

        $nonce = bin2hex(random_bytes(16));
        $storage->store($this->makeRecord($nonce));
        $record = $storage->find($nonce);
        self::assertNotNull($record, 'the record must round-trip through the cluster');
        self::assertSame($nonce, $record->nonce);

        $consumed = $storage->consume($nonce);
        self::assertNotNull($consumed, 'the consume transition must run on the cluster');
        self::assertTrue($consumed->consumedNow);
        self::assertNull($consumed->consumedResult);
        self::assertTrue($storage->commitResult($nonce, true, 'txn-cluster'));
        $after = $storage->consumedState($nonce);
        self::assertNotNull($after?->consumedResult);
        self::assertTrue($after->consumedResult->valid);
        self::assertSame('txn-cluster', $after->consumedResult->binding);

        $claimNonce = bin2hex(random_bytes(16));
        $storage->store($this->makeRecord($claimNonce));
        self::assertNull($storage->claimResumeDerivation($claimNonce), 'a pending record is not claimable');
        self::assertNotNull($storage->consume($claimNonce));
        $owner = $storage->claimResumeDerivation($claimNonce);
        self::assertIsString($owner, 'the resume claim lives inside the record envelope, one key');
        self::assertNull($storage->claimResumeDerivation($claimNonce), 'a second claim while the first is held is refused');
        self::assertTrue($storage->commitResultResume($claimNonce, true, 'txn-claim', $owner), 'the claim-bearing commit is one key');
        self::assertFalse($storage->releaseResumeDerivation($claimNonce, $owner), 'the commit already cleared the claim');

        $pendingNonce = bin2hex(random_bytes(16));
        $storage->store($this->makeRecord($pendingNonce));
        $deleted = $storage->deleteIfPending($pendingNonce);
        self::assertSame('deleted-pending', $deleted->state);
        self::assertNull($storage->find($pendingNonce));

        $cancelNonce = bin2hex(random_bytes(16));
        $storage->store($this->makeRecord($cancelNonce));
        self::assertNotNull($storage->cancel($cancelNonce));
        self::assertSame(\KiwiCaptcha\ChallengeRuntimeStateKind::Cancelled, $storage->runtimeState($cancelNonce)->kind);

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
        $outcome = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT))->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), 'issuance and verification must run on the cluster, got '.$outcome->code());
    }

    public function testVerifiedWaitGuardRefusesWaitReplicasOnTheRealClusterClient(): void
    {
        $ports = $this->startClusterOrSkip();
        $nodes = array_map(static fn (int $port): string => 'tcp://127.0.0.1:'.$port, $ports);
        $cluster = new \Predis\Client($nodes, [
            'cluster' => 'redis',
            'parameters' => ['timeout' => 3.0],
        ]);
        try {
            new RedisStorage($cluster, waitReplicas: 1);
            self::fail('a Predis cluster client must be refused when waitReplicas > 0');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('Predis Redis Cluster', $e->getMessage());
            self::assertStringContainsString('WAIT', $e->getMessage());
        }
        $storage = new RedisStorage($cluster, 'guard-test-');
        self::assertInstanceOf(RedisStorage::class, $storage, 'waitReplicas 0 must construct on a cluster client');
    }

    public function testArgonSemaphoreKeysShareTheLeaseSlotOnTheCluster(): void
    {
        $ports = $this->startClusterOrSkip();
        $leaseKey = 'kiwicaptcha:argon2:leases:'.bin2hex(random_bytes(4));
        $scopeHash = hash('sha256', 'tenant:alpha');
        $keys = [
            $leaseKey,
            '{'.$leaseKey.'}:sem:waiters',
            '{'.$leaseKey.'}:'.$scopeHash,
        ];
        $slots = [];
        foreach ($keys as $key) {
            $slots[] = $this->keyslotOnCluster($ports, $key);
        }
        self::assertSame(1, \count(array_unique($slots)), 'the semaphore keys must share one slot: '.json_encode(array_combine($keys, $slots)));
        $local = array_map(static fn (string $key): int => self::crc16Slot($key), $keys);
        self::assertSame($slots, $local, 'the local CRC-16 slot computation must agree with the server on every composed key');
    }

    /** @param list<int> $ports */
    private function keyslotOnCluster(array $ports, string $key): int
    {
        foreach ($ports as $port) {
            $reply = trim((string) @shell_exec('redis-cli -p '.$port.' cluster keyslot '.escapeshellarg($key).' 2>/dev/null'));
            if (ctype_digit($reply)) {
                return (int) $reply;
            }
        }
        self::fail('CLUSTER KEYSLOT refused on every node for key '.$key);
    }

    public function testArgonSemaphoreAcquireAndReleaseRunsOnTheRealCluster(): void
    {
        $ports = $this->startClusterOrSkip();
        $bundleAutoload = \dirname(__DIR__, 3).'/packages/kiwicaptcha/integrations/symfony/vendor/autoload.php';
        if (!is_file($bundleAutoload)) {
            self::markTestSkipped('the bundle vendor is not installed locally; the semaphore key shapes are asserted via the keyslot tests instead');
        }
        require_once $bundleAutoload;
        if (!\class_exists(\BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore::class)) {
            self::markTestSkipped('the RedisAdmissionSemaphore class is not loadable');
        }
        $namespace = 'cluster-'.bin2hex(random_bytes(4));
        $semaphore = new \BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore(
            $this->clusterClient,
            4,
            $namespace,
        );
        $lease = $semaphore->acquire('tenant:alpha');
        self::assertIsString($lease, 'the scoped acquire must run the three-key script without a cross-slot error');
        self::assertSame(1, $semaphore->usage());
        $unscoped = $semaphore->acquire();
        self::assertIsString($unscoped, 'the unscoped acquire re-declares the lease key in the scope position');
        self::assertSame(2, $semaphore->usage());
        $semaphore->release($lease);
        $semaphore->release($unscoped);
        self::assertSame(0, $semaphore->usage());
    }

    public function testComposedKeysShareOneSlotOnTheEnvRedis(): void
    {
        $client = $this->envRedisOrSkip();
        $leaseKey = 'kiwicaptcha:argon2:leases:'.bin2hex(random_bytes(4));
        $keys = [
            $leaseKey,
            '{'.$leaseKey.'}:sem:waiters',
            '{'.$leaseKey.'}:'.hash('sha256', 'tenant:beta'),
        ];
        $slots = array_map(fn (string $key): int => $this->slotOf($client, $key), $keys);
        self::assertSame(1, \count(array_unique($slots)), 'the semaphore keys must share one slot: '.json_encode(array_combine($keys, $slots)));

        $recordKey = 'kiwicaptcha:'.bin2hex(random_bytes(16));
        $recordSlot = $this->slotOf($client, $recordKey);
        self::assertGreaterThanOrEqual(0, $recordSlot, 'a record key has a well-defined slot');
        self::assertLessThanOrEqual(0x3FFF, $recordSlot, 'a record key has a well-defined slot');
        self::assertSame(
            $this->slotOf($client, $recordKey),
            $recordSlot,
            'the slot of a record key is stable; the resume claim is embedded in the record envelope, so every claim transition stays single-key',
        );
    }

    private function slotOf(\Predis\Client $client, string $key): int
    {
        try {
            $reply = $client->executeRaw(['CLUSTER', 'KEYSLOT', $key]);
            if (\is_int($reply)) {
                return $reply;
            }
            $message = (string) $reply;
            if (str_contains($message, 'cluster support disabled')) {
                return self::crc16Slot($key);
            }
            throw new \RuntimeException('CLUSTER KEYSLOT returned: '.$message);
        } catch (\Predis\Exception\ServerException $e) {
            if (str_contains($e->getMessage(), 'cluster support disabled')) {
                return self::crc16Slot($key);
            }
            throw $e;
        }
    }

    private static function hashTag(string $key): string
    {
        $open = strpos($key, '{');
        if ($open === false) {
            return $key;
        }
        $close = strpos($key, '}', $open);
        if ($close === false) {
            return $key;
        }

        return substr($key, $open + 1, $close - $open - 1);
    }

    /** slot = crc16(tag) & 0x3FFF — the Redis Cluster hash-tag algorithm. */
    private static function crc16Slot(string $key): int
    {
        return self::crc16(self::hashTag($key)) & 0x3FFF;
    }

    /** The canonical CRC-16 with the xmodem polynomial (0x1021, init 0) over ASCII bytes. */
    private static function crc16(string $data): int
    {
        $crc = 0;
        $length = \strlen($data);
        for ($i = 0; $i < $length; $i++) {
            $crc ^= \ord($data[$i]) << 8;
            for ($j = 0; $j < 8; $j++) {
                $crc = (($crc & 0x8000) !== 0) ? (($crc << 1) ^ 0x1021) & 0xFFFF : ($crc << 1) & 0xFFFF;
            }
        }

        return $crc;
    }

    public function testCrc16MatchesThePinnedReferenceVector(): void
    {
        // The standard CRC-16 check value ("123456789" to 0x31C3)
        // pins the implementation used for the hash-tag slot fallback.
        self::assertSame(0x31C3, self::crc16('123456789'));
        self::assertSame(0x0000, self::crc16(''));
    }
}
