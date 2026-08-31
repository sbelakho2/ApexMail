<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\Authority\AuthorityGuardedPredisClient;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedAuthorityRefusalException;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedPrimaryAuthorityGuard;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use KiwiCaptcha\Storage\RedisStorage;
use PHPUnit\Framework\TestCase;

/**
 * The adversarial authority-safety scenarios for the pinned-primary
 * authority guard (docs/ha-authority.md), on real Redis servers.
 *
 * - per-authority pins: a distinct risk authority changes while the
 *   storage authority stays, and the reverse, each refusing only its
 *   own authority.
 * - a restart on the same port within the verification window: a
 *   security-final transition refuses immediately, an ordinary read
 *   serves from the cache until the window expires or the connection
 *   is replaced, then refuses too.
 * - a retry-enabled direct client is refused for pinned_primary.
 * - an endpoint re-point to a different server is refused.
 * - a fresh process after an authority event refuses both a changed
 *   pin and an absent pin, with the initialize message, never
 *   auto-pinning.
 * - an initial migration with pre-existing state refuses until the
 *   operator runs the explicit bootstrap.
 * - a lost pin is refused and never re-pinned.
 * - the verified-WAIT durability session (M1): a restart of the
 *   authority between the security-final mutation and the WAIT
 *   barrier refuses the barrier before the fence write or the WAIT
 *   executes. The WAIT never runs on the changed authority and the
 *   stored state stays unchanged. Without the restart the barrier
 *   succeeds with the acked causal fence.
 *
 * The suite boots its own redis-server instances, never the shared CI
 * Redis service, following the promotion suite's convention: gated on
 * the shared real-Redis env variables and the redis-server binary;
 * skips cleanly otherwise. Every server is flushed before use and
 * runs on a fresh free port.
 */
final class HaAuthorityAdversarialRealRedisTest extends TestCase
{
    private const NS = 'ha-adversarial';

    /** @var array<int, resource> */
    private array $procs = [];

    /** @var array<int, int> port => index into $procs */
    private array $procIndexByPort = [];

    private string $tmpDir = '';

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
        $this->procIndexByPort = [];
        if ($this->tmpDir !== '' && is_dir($this->tmpDir)) {
            $this->removeDir($this->tmpDir);
        }
        $this->tmpDir = '';
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
        if (RedisTestUrl::resolve() === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the dedicated real-Redis CI lane');
        }
    }

    private function binaryOrSkip(): void
    {
        if (@shell_exec('command -v redis-server 2>/dev/null') === null) {
            self::markTestSkipped('redis-server not found on PATH — the adversarial simulations need a local redis-server build');
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
        self::markTestSkipped('no free local port available for the adversarial simulation: '.$errstr);
    }

    private function setupTmpDir(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/kiwicaptcha-ha-adversarial-'.bin2hex(random_bytes(6));
        if (!mkdir($this->tmpDir, 0o700, true) && !is_dir($this->tmpDir)) {
            self::markTestSkipped('cannot create the adversarial scratch directory');
        }
    }

    /**
     * Start a redis-server on the given port (a fresh free port when
     * null) with append-only persistence, so a pin written before a
     * restart survives the restart and the identity change becomes a
     * refusal instead of a silent re-pin.
     *
     * @param list<string> $extraArgs
     */
    private function bootRedis(int $port, string $name, array $extraArgs = []): void
    {
        $args = array_merge([
            '--port', (string) $port,
            '--dir', $this->tmpDir,
            '--appendonly', 'yes',
            '--save', '',
            '--appendfsync', 'always',
        ], $extraArgs);
        $this->spawnRedisServer($args, $name, $port);
        $this->waitForPong($port, 10);
        // Flush before every run: an adversarial scenario must never
        // observe a leftover key from a prior scenario.
        $this->client($port)->flushall();
    }

    private function spawnRedisServer(array $args, string $name, int $port): void
    {
        $log = $this->tmpDir.'/'.$name.'.log';
        $args = array_merge(['redis-server'], $args, ['--logfile', $log]);
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
        $this->procIndexByPort[$port] = \count($this->procs) - 1;
    }

    private function restartRedis(int $port, string $name): void
    {
        $index = $this->procIndexByPort[$port] ?? null;
        if ($index !== null && isset($this->procs[$index])) {
            proc_terminate($this->procs[$index], 15);
            usleep(500_000);
        }
        $this->spawnRedisServer([
            '--port', (string) $port,
            '--dir', $this->tmpDir,
            '--appendonly', 'yes',
            '--save', '',
        ], $name, $port);
        $this->waitForPong($port, 10);
    }

    /**
     * Boot a redis-server in its OWN scratch directory (the master +
     * replica topology of the WAIT-boundary suite must not share one
     * append-only file) with append-only persistence, flushed before
     * use. A replica (extraArgs containing `--replicaof`) is
     * read-only and cannot be flushed; pass $flush false for it.
     *
     * @param list<string> $extraArgs
     */
    private function bootRedisIsolated(int $port, string $name, string $dir, array $extraArgs = [], bool $flush = true): void
    {
        $args = array_merge([
            '--port', (string) $port,
            '--dir', $dir,
            '--appendonly', 'yes',
            '--save', '',
            '--appendfsync', 'always',
        ], $extraArgs);
        $this->spawnRedisServer($args, $name, $port);
        $this->waitForPong($port, 10);
        if ($flush) {
            $this->client($port)->flushall();
        }
    }

    /**
     * Restart a redis-server on the same port from its own scratch
     * directory: a graceful SIGTERM shutdown (the append-only file is
     * fully flushed), then a fresh boot with a new run_id and the
     * persisted state. The outgoing process is awaited to actually
     * exit before the replacement spawns, so the port is never lost
     * to a race (a master with attached replicas may take a moment
     * to shut down).
     */
    private function restartRedisIsolated(int $port, string $name, string $dir): void
    {
        $index = $this->procIndexByPort[$port] ?? null;
        if ($index !== null && isset($this->procs[$index])) {
            proc_terminate($this->procs[$index], 15);
            $deadline = microtime(true) + 5;
            while (microtime(true) < $deadline) {
                $status = proc_get_status($this->procs[$index]);
                if ($status !== false && !$status['running']) {
                    break;
                }
                usleep(100_000);
            }
        }
        $this->spawnRedisServer([
            '--port', (string) $port,
            '--dir', $dir,
            '--appendonly', 'yes',
            '--save', '',
            '--appendfsync', 'always',
        ], $name, $port);
        $this->waitForPong($port, 10);
    }

    /**
     * Wait until a real replica acknowledged a write on the master
     * (WAIT 1 returns 1): the acked-barrier control needs a replica
     * that is actually caught up.
     */
    private function waitForReplicaSync(int $masterPort): void
    {
        $probe = $this->client($masterPort);
        $deadline = microtime(true) + 20;
        while (microtime(true) < $deadline) {
            try {
                $probe->set('replica-sync-probe', '1');
                if ($probe->executeRaw(['WAIT', '1', '1000']) === 1) {
                    return;
                }
            } catch (\Throwable) {
                // the master may still be booting
            }
            usleep(150_000);
        }
        self::fail('the replica never acknowledged a write (WAIT never returned 1)');
    }

    private function waitForPong(int $port, int $timeoutSecs): void
    {
        $deadline = microtime(true) + $timeoutSecs;
        while (microtime(true) < $deadline) {
            if (str_contains((string) @shell_exec('redis-cli -p '.$port.' ping 2>/dev/null'), 'PONG')) {
                return;
            }
            usleep(150_000);
        }
        self::fail('timed out waiting for redis-server on port '.$port.' to answer PONG');
    }

    private function client(int $port): \Predis\Client
    {
        return new \Predis\Client('tcp://127.0.0.1:'.$port, ['timeout' => 3.0]);
    }

    private function guard(\Predis\Client $client, string $suffix, int $reverifySecs = 0): PinnedPrimaryAuthorityGuard
    {
        return new PinnedPrimaryAuthorityGuard($client, self::NS, $reverifySecs, $suffix);
    }

    private function pinKey(string $suffix): string
    {
        return '{kiwi:'.self::NS.'}:authority:pin:'.$suffix;
    }

    private function identityOf(\Predis\Client $client): array
    {
        $replication = $client->info('replication');
        $role = $replication['role'] ?? $replication['Replication']['role'] ?? '?';
        $runId = $replication['run_id'] ?? $replication['Replication']['run_id'] ?? null;
        if (!\is_string($runId) || $runId === '') {
            $server = $client->info('server');
            $runId = $server['run_id'] ?? $server['Server']['run_id'] ?? '?';
        }

        return ['role' => $role, 'run_id' => $runId];
    }

    private function runIdOf(\Predis\Client $client): string
    {
        return (string) $this->identityOf($client)['run_id'];
    }

    public function testDistinctRiskAuthorityChangeRefusesOnlyTheRiskGuard(): void
    {
        $this->envRedisOrSkip();
        $this->binaryOrSkip();
        $this->setupTmpDir();
        $storagePort = $this->freePort();
        $riskPort = $this->freePort();
        $this->bootRedis($storagePort, 'storage');
        $this->bootRedis($riskPort, 'risk');

        $storageClient = $this->client($storagePort);
        $riskClient = $this->client($riskPort);
        $storageGuard = $this->guard($storageClient, 'storage');
        $riskGuard = $this->guard($riskClient, 'risk');
        $storageGuard->initializePin();
        $riskGuard->initializePin();
        $pinnedRiskRunId = $this->runIdOf($riskClient);
        self::assertSame('master|'.$this->runIdOf($storageClient), $storageClient->get($this->pinKey('storage')));
        self::assertSame('master|'.$pinnedRiskRunId, $riskClient->get($this->pinKey('risk')));
        $storageGuard->assertServeEligible($storageClient);
        $riskGuard->assertServeEligible($riskClient);

        // Change only the risk authority: a restart on the risk port
        // regenerates its run_id; the storage authority is untouched.
        $this->restartRedis($riskPort, 'risk-restarted');
        $riskClient->disconnect();
        $riskClient->set('warmup', '1');
        $newRiskRunId = $this->runIdOf($riskClient);
        self::assertNotSame($pinnedRiskRunId, $newRiskRunId, 'a restarted Redis always regenerates its run_id');
        self::assertSame('master|'.$pinnedRiskRunId, $riskClient->get($this->pinKey('risk')), 'the risk pin survives the restart through the append-only file');

        try {
            $riskGuard->assertServeEligible($riskClient);
            self::fail('the risk guard must refuse its own changed authority');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('pinned master|'.$pinnedRiskRunId, $e->getMessage());
            self::assertStringContainsString('observed master|'.$newRiskRunId, $e->getMessage());
        }

        // The storage authority is independent: its guard still serves.
        $storageGuard->assertServeEligible($storageClient);
        self::assertSame('OK', (string) $storageClient->set('storage-still-serving', '1'), 'the storage authority is untouched by the risk restart');
    }

    public function testDistinctStorageAuthorityChangeRefusesOnlyTheStorageGuard(): void
    {
        $this->envRedisOrSkip();
        $this->binaryOrSkip();
        $this->setupTmpDir();
        $storagePort = $this->freePort();
        $riskPort = $this->freePort();
        $this->bootRedis($storagePort, 'storage');
        $this->bootRedis($riskPort, 'risk');

        $storageClient = $this->client($storagePort);
        $riskClient = $this->client($riskPort);
        $storageGuard = $this->guard($storageClient, 'storage');
        $riskGuard = $this->guard($riskClient, 'risk');
        $storageGuard->initializePin();
        $riskGuard->initializePin();
        $pinnedStorageRunId = $this->runIdOf($storageClient);
        $storageGuard->assertServeEligible($storageClient);
        $riskGuard->assertServeEligible($riskClient);

        // Change only the storage authority: the storage guard refuses,
        // the risk authority keeps serving.
        $this->restartRedis($storagePort, 'storage-restarted');
        $storageClient->disconnect();
        $storageClient->set('warmup', '1');
        $newStorageRunId = $this->runIdOf($storageClient);
        self::assertNotSame($pinnedStorageRunId, $newStorageRunId);

        try {
            $storageGuard->assertServeEligible($storageClient);
            self::fail('the storage guard must refuse its own changed authority');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('pinned master|'.$pinnedStorageRunId, $e->getMessage());
            self::assertStringContainsString('observed master|'.$newStorageRunId, $e->getMessage());
        }

        $riskGuard->assertServeEligible($riskClient);
        self::assertSame('OK', (string) $riskClient->set('risk-still-serving', '1'), 'the risk authority is untouched by the storage restart');
    }

    public function testARestartWithinTheWindowRefusesSecurityFinalImmediatelyButServesOrdinaryUntilInvalidated(): void
    {
        $this->envRedisOrSkip();
        $this->binaryOrSkip();
        $this->setupTmpDir();
        $port = $this->freePort();
        $this->bootRedis($port, 'primary');

        $clientA = $this->client($port);
        $guard = new PinnedPrimaryAuthorityGuard($clientA, self::NS, 3, 'storage');
        $guard->initializePin();
        $pinnedRunId = $this->runIdOf($clientA);

        // The guarded storage rides the zero-stale security-final lane.
        $wrapped = new AuthorityGuardedPredisClient($guard, $clientA);
        $storage = new RedisStorage($wrapped, 'adv:', waitReplicas: 0);
        $this->storePendingRecord($storage, 'within-window-nonce');

        // An ordinary read serves inside the window.
        self::assertSame('OK', (string) $wrapped->set('ordinary-read', '1'));

        // Restart the server on the same port within the window: the
        // run_id changes but the pin (AOF) survives.
        $this->restartRedis($port, 'primary-restarted');
        $clientA->disconnect();
        $clientA->set('warmup', '1');
        self::assertNotSame($pinnedRunId, $this->runIdOf($clientA));

        // A security-final transition refuses immediately, inside the
        // window: the wrapper bypasses the cache for the consume.
        try {
            $storage->consume('within-window-nonce');
            self::fail('a security-final transition must refuse immediately after the authority changed, inside the window');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('pinned master|'.$pinnedRunId, $e->getMessage());
            self::assertStringContainsString('observed master|'.$this->runIdOf($clientA), $e->getMessage());
        }

        // An ordinary read still serves from the cached verification
        // inside the window (the restart did not replace the connection
        // object, and the window has not expired).
        self::assertSame('1', $wrapped->get('ordinary-read'), 'an ordinary read serves within the verification window');

        // After the window expires, the ordinary lane re-verifies and
        // refuses too (the changed authority is no longer masked).
        usleep(3_300_000);
        try {
            $wrapped->get('ordinary-read');
            self::fail('an ordinary read must refuse once the verification window has expired and the authority is changed');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('the serving authority changed', $e->getMessage());
        }

        // A fresh client is a NEW connection object: its first ordinary
        // read is a cache miss (connection-generation invalidation) and
        // refuses immediately, even inside the window.
        $freshGuard = new PinnedPrimaryAuthorityGuard($this->client($port), self::NS, 60, 'storage');
        try {
            $freshGuard->assertServeEligible($this->client($port));
            self::fail('a fresh connection object must re-verify on its first check: connection-generation invalidation');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('the serving authority changed', $e->getMessage());
        }
    }

    public function testARetryEnabledDirectClientIsRefusedForPinnedPrimary(): void
    {
        $this->envRedisOrSkip();
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $retryEnabled = new \Predis\Client([
            'host' => '127.0.0.1',
            'retry' => new \Predis\Retry\Retry(new \Predis\Retry\Strategy\ExponentialBackoff(), 3),
        ]);
        self::assertFalse($retryEnabled->getConnection()->getParameters()->isDisabledRetry());

        try {
            new PinnedPrimaryAuthorityGuard($retryEnabled, self::NS, 0, 'storage');
            self::fail('a retry-enabled direct client must be refused for pinned_primary');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('retry-enabled', $e->getMessage());
            self::assertStringContainsString('replacement connection', $e->getMessage());
        }
    }

    public function testAnEndpointRepointIsRefused(): void
    {
        $this->envRedisOrSkip();
        $this->binaryOrSkip();
        $this->setupTmpDir();
        $portA = $this->freePort();
        $portB = $this->freePort();
        $this->bootRedis($portA, 'a');
        $this->bootRedis($portB, 'b');

        $clientA = $this->client($portA);
        $guardA = $this->guard($clientA, 'storage');
        $guardA->initializePin();
        $pinnedRunId = $this->runIdOf($clientA);

        // The deployment re-points its endpoint at server B, whose state
        // carried the pin across (the replicated deployment state
        // includes the pin key). The observed authority is B, the pin
        // says A: the re-point is refused.
        $clientB = $this->client($portB);
        $clientB->set($this->pinKey('storage'), 'master|'.$pinnedRunId);
        $guardB = $this->guard($clientB, 'storage');
        self::assertSame('master|'.$pinnedRunId, $clientB->get($this->pinKey('storage')), 'the pin traveled with the re-pointed state');
        $observedRunId = $this->runIdOf($clientB);
        self::assertNotSame($pinnedRunId, $observedRunId);

        try {
            $guardB->assertServeEligible($clientB);
            self::fail('a re-pointed endpoint must be refused');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('pinned master|'.$pinnedRunId, $e->getMessage());
            self::assertStringContainsString('observed master|'.$observedRunId, $e->getMessage());
        }
    }

    public function testAFreshProcessRefusesAChangedPinNeverAutoPinning(): void
    {
        $this->envRedisOrSkip();
        $this->binaryOrSkip();
        $this->setupTmpDir();
        $port = $this->freePort();
        $this->bootRedis($port, 'primary');

        $clientA = $this->client($port);
        $guardA = $this->guard($clientA, 'storage');
        $guardA->initializePin();
        $pinnedRunId = $this->runIdOf($clientA);

        // An authority event: the primary restarts with a new run_id,
        // the pin (AOF) survives.
        $this->restartRedis($port, 'primary-restarted');

        // A fresh process (new client, new guard) observes the new
        // authority against the surviving pin: refusal, never a
        // re-pin to the new identity.
        $freshClient = $this->client($port);
        $freshGuard = $this->guard($freshClient, 'storage');
        self::assertSame('master|'.$pinnedRunId, $freshClient->get($this->pinKey('storage')));
        try {
            $freshGuard->assertServeEligible($freshClient);
            self::fail('a fresh process after an authority event with a surviving pin must refuse the changed identity');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('pinned master|'.$pinnedRunId, $e->getMessage());
            self::assertStringContainsString('observed master|'.$this->runIdOf($freshClient), $e->getMessage());
        }
        self::assertSame('master|'.$pinnedRunId, $freshClient->get($this->pinKey('storage')), 'the pin is never rewritten to the new authority');
    }

    public function testAFreshProcessWithNoPinRefusesAndNeverAutoPins(): void
    {
        $this->envRedisOrSkip();
        $this->binaryOrSkip();
        $this->setupTmpDir();
        $port = $this->freePort();
        $this->bootRedis($port, 'primary');

        $client = $this->client($port);
        $guard = $this->guard($client, 'storage');
        self::assertNull($client->get($this->pinKey('storage')), 'a fresh server carries no pin');

        try {
            $guard->assertServeEligible($client);
            self::fail('an uninitialized guard must refuse: the production runtime never auto-pins');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('never auto-pins', $e->getMessage());
            self::assertStringContainsString('kiwicaptcha:ha-initialize', $e->getMessage(), 'the refusal names the explicit bootstrap command');
        }
        self::assertNull($client->get($this->pinKey('storage')), 'the guard must never auto-pin a fresh authority');
    }

    public function testInitialMigrationWithPreExistingStateRefusesWithoutInitialize(): void
    {
        $this->envRedisOrSkip();
        $this->binaryOrSkip();
        $this->setupTmpDir();
        $port = $this->freePort();
        $this->bootRedis($port, 'primary');

        // The deployment already serves: a pre-existing challenge record
        // and pin-less state.
        $client = $this->client($port);
        $client->set('kiwi:preexisting:challenge', '{"state":"pending"}');

        // Adopting pinned_primary without the explicit bootstrap is
        // refused: the migration must not silently pin the first
        // authority it sees.
        $guard = $this->guard($client, 'storage');
        try {
            $guard->assertServeEligible($client);
            self::fail('a pinned_primary migration with pre-existing state must refuse until the operator initializes');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('never auto-pins', $e->getMessage());
            self::assertStringContainsString('kiwicaptcha:ha-initialize', $e->getMessage());
        }
        self::assertNull($client->get($this->pinKey('storage')), 'no pin is written by the refusal');

        // The explicit bootstrap arms the deployment and the
        // pre-existing state is untouched.
        $guard->initializePin();
        $guard->assertServeEligible($client);
        self::assertSame('{"state":"pending"}', $client->get('kiwi:preexisting:challenge'), 'the pre-existing state survives the migration');
    }

    public function testPinLossIsRefusedAndNeverRepinned(): void
    {
        $this->envRedisOrSkip();
        $this->binaryOrSkip();
        $this->setupTmpDir();
        $port = $this->freePort();
        $this->bootRedis($port, 'primary');

        $client = $this->client($port);
        $guard = $this->guard($client, 'storage');
        $guard->initializePin();
        $pinnedRunId = $this->runIdOf($client);
        $guard->assertServeEligible($client);

        // A promotion to a node that never received the pin: the key is
        // gone. The guard refuses and never re-pins.
        $client->del($this->pinKey('storage'));
        self::assertNull($client->get($this->pinKey('storage')));

        try {
            $guard->assertServeEligible($client);
            self::fail('a lost pin must be a refusal, never a silent re-pin');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('the pinned identity is missing', $e->getMessage());
            self::assertStringContainsString('was pinned to master|'.$pinnedRunId, $e->getMessage());
        }
        self::assertNull($client->get($this->pinKey('storage')), 'the guard must never re-pin after a pin loss');
    }

    /**
     * M1: the verified WAIT must compose with the authority fence. A
     * restart of the authority between the security-final mutation and
     * the WAIT barrier is observed by the barrier's own zero-stale
     * verification. The round trip reconnects to the restarted server
     * and reads the new run_id, and the refusal happens before the
     * fence write or the WAIT executes. The WAIT never runs on the
     * changed authority, and the stored security state is
     * byte-identical.
     */
    public function testWaitBarrierRefusesWhenTheAuthorityRestartsBetweenTheMutationAndTheWait(): void
    {
        $this->envRedisOrSkip();
        $this->binaryOrSkip();
        $this->setupTmpDir();
        $masterDir = $this->tmpDir.'/master';
        $replicaDir = $this->tmpDir.'/replica';
        if (!mkdir($masterDir, 0o700, true) && !is_dir($masterDir)) {
            self::markTestSkipped('cannot create the WAIT-boundary master directory');
        }
        if (!mkdir($replicaDir, 0o700, true) && !is_dir($replicaDir)) {
            self::markTestSkipped('cannot create the WAIT-boundary replica directory');
        }
        $masterPort = $this->freePort();
        $replicaPort = $this->freePort();
        $this->bootRedisIsolated($masterPort, 'master', $masterDir);
        $this->bootRedisIsolated($replicaPort, 'replica', $replicaDir, ['--replicaof', '127.0.0.1', (string) $masterPort], flush: false);
        $this->waitForReplicaSync($masterPort);

        $raw = $this->client($masterPort);
        $guard = new PinnedPrimaryAuthorityGuard($raw, self::NS, 5, 'storage');
        $guard->initializePin();
        $pinnedRunId = $this->runIdOf($raw);
        $wrapped = new AuthorityGuardedPredisClient($guard, $raw);

        // The security-final mutation on A: the pending→consumed
        // transition through the wait-free storage (no barrier yet).
        $waitFree = new RedisStorage($wrapped, 'wait-boundary:', waitReplicas: 0);
        $record = $this->storePendingRecord($waitFree, 'boundary-nonce');
        $consumed = $waitFree->consume($record->nonce);
        self::assertNotNull($consumed, 'the security-final consume transition lands on A');
        self::assertTrue($consumed->consumedNow, 'the consume is a fresh pending→consumed transition');
        $recordKey = 'wait-boundary:'.$record->nonce;
        $before = $raw->get($recordKey);
        self::assertIsString($before, 'the consumed envelope exists on A');
        self::assertStringContainsString('"state":"consumed"', $before, 'the mutation on A is the consumed envelope');

        // The authority restarts between the mutation and the WAIT
        // barrier: a new run_id on the same endpoint, the state (the
        // append-only file) preserved.
        $this->restartRedisIsolated($masterPort, 'master-restarted', $masterDir);
        $raw->disconnect();
        $newRunId = $this->runIdOf($raw);
        self::assertNotSame($pinnedRunId, $newRunId, 'a restarted Redis always regenerates its run_id');
        self::assertSame('master|'.$pinnedRunId, $raw->get($this->pinKey('storage')), 'the pin survives the restart through the append-only file');

        // The WAIT barrier refuses before executing: the durability
        // session observes the changed authority and refuses before
        // the fence write or the WAIT.
        $barriered = new RedisStorage($wrapped, 'wait-boundary:', waitReplicas: 1, waitTimeoutMs: 100);
        try {
            $barriered->establishReplicationFence('the WAIT-boundary test');
            self::fail('the WAIT barrier must refuse when the authority changed between the mutation and the WAIT');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('pinned master|'.$pinnedRunId, $e->getMessage());
            self::assertStringContainsString('observed master|'.$newRunId, $e->getMessage());
        }

        // The stored state is unchanged: the refused barrier wrote
        // nothing — the record holds the exact mutation bytes and no
        // fence token exists on the changed authority (the WAIT never
        // executed on B).
        self::assertSame($before, $raw->get($recordKey), 'the stored security state is unchanged by the refused barrier');
        self::assertNull($raw->get('wait-boundary:replication-fence'), 'the refused barrier never wrote its fence: the WAIT never executed on the changed authority');
    }

    /**
     * M1 control: with no authority change between the mutation and
     * the WAIT, the durability session succeeds with the acked
     * barrier. Every durability-critical mutation (store, the
     * pending→consumed transition, the result commit) writes its
     * causal fence and the replica acknowledges it.
     */
    public function testWaitBarrierSucceedsWithTheAckedFenceOnThePinnedAuthority(): void
    {
        $this->envRedisOrSkip();
        $this->binaryOrSkip();
        $this->setupTmpDir();
        $masterDir = $this->tmpDir.'/master';
        $replicaDir = $this->tmpDir.'/replica';
        if (!mkdir($masterDir, 0o700, true) && !is_dir($masterDir)) {
            self::markTestSkipped('cannot create the WAIT-boundary master directory');
        }
        if (!mkdir($replicaDir, 0o700, true) && !is_dir($replicaDir)) {
            self::markTestSkipped('cannot create the WAIT-boundary replica directory');
        }
        $masterPort = $this->freePort();
        $replicaPort = $this->freePort();
        $this->bootRedisIsolated($masterPort, 'master', $masterDir);
        $this->bootRedisIsolated($replicaPort, 'replica', $replicaDir, ['--replicaof', '127.0.0.1', (string) $masterPort], flush: false);
        $this->waitForReplicaSync($masterPort);

        $raw = $this->client($masterPort);
        $guard = new PinnedPrimaryAuthorityGuard($raw, self::NS, 5, 'storage');
        $guard->initializePin();
        $wrapped = new AuthorityGuardedPredisClient($guard, $raw);
        $storage = new RedisStorage($wrapped, 'wait-control:', waitReplicas: 1, waitTimeoutMs: 2000);

        // Every durability-critical mutation rides the barrier: each
        // one writes its causal fence and WAITs for the replica ack.
        $record = $this->storePendingRecord($storage, 'control-nonce');
        $consumed = $storage->consume($record->nonce);
        self::assertNotNull($consumed, 'the barriered consume succeeds on the pinned authority');
        self::assertTrue($consumed->consumedNow);
        self::assertTrue($storage->commitResult($record->nonce, true, 'txn-boundary'), 'the barriered result commit succeeds');
        $state = $storage->consumedState($record->nonce);
        self::assertNotNull($state?->consumedResult, 'the committed result is retained');
        self::assertTrue($state->consumedResult->valid);

        // The acked barrier left its causal fence on the pinned
        // authority.
        $fence = $raw->get('wait-control:replication-fence');
        self::assertIsString($fence, 'the verified WAIT succeeds with the acked barrier');
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', $fence, 'the fence is the fresh random token of the last barrier');

        // The pinned authority is still serving.
        $guard->assertServeEligible($raw);
    }

    /**
     * Store a fresh pending challenge record through the guarded
     * storage and return it for later consumption.
     */
    private function storePendingRecord(RedisStorage $storage, string $nonce): \KiwiCaptcha\ChallengeRecord
    {
        $record = \KiwiCaptcha\ChallengeRecord::fromArray([
            'nonce' => $nonce,
            'scope' => 'login',
            'binding_tag' => 'b',
            'issued_at' => time(),
            'expires_at' => time() + 120,
            'algorithm' => 'sha256',
            'm_kib' => 0,
            't' => 0,
            'p' => 0,
            'target_bits' => 8,
            'salt' => '00',
            'prefix' => '0000',
            'challenge' => '0',
            'min_duration_ms' => 0,
            'issued_at_ns' => 1234567890123456,
            'protocol_version' => 2,
            'attempts_used' => 0,
            'region' => null,
            'policy_version' => 1,
            'request_binding' => null,
            'issuer' => 'test',
            'kid' => 1,
            'hostname' => 'test',
        ]);
        $storage->store($record);

        return $record;
    }
}
