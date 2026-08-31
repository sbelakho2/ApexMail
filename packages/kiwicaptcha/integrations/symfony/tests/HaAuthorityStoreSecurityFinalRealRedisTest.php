<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\AuthorityGuardedPredisClient;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedAuthorityRefusalException;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedPrimaryAuthorityGuard;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use PHPUnit\Framework\TestCase;

/**
 * The adversarial zero-stale scenarios for the real bundle stores under
 * the pinned-primary authority guard (docs/ha-authority.md), on real
 * Redis servers.
 *
 * The stores execute their Lua transitions through the typed
 * {@see \BelConsulting\KiwiCaptchaBundle\Security\Authority\RedisSecurityCommandExecutor}
 * seam. Every scenario warms the authority verification cache, changes
 * the authority (a restart regenerates the run_id; the pin survives
 * through the append-only file), then calls the real final transition
 * inside the verification window. The transition must refuse before
 * the mutation. The record is byte-identical afterwards:
 *
 *  - the siteverify idempotency finalize (the security-final
 *    transition of {@see RedisSiteVerifyIdempotencyStore});
 *  - a chain terminal transition (markVerified, the security-final
 *    lane of {@see RedisChainedChallengeStateStore});
 *  - the post-solve final disposition (finalize, the security-final
 *    transition of {@see RedisPostSolveDispositionStore}).
 *
 * The suite boots its own redis-server instances, never the shared CI
 * Redis service, following the promotion suite's convention: gated on
 * the shared real-Redis env variables and the redis-server binary;
 * skips cleanly otherwise. Every server is flushed before use and
 * runs on a fresh free port.
 */
final class HaAuthorityStoreSecurityFinalRealRedisTest extends TestCase
{
    private const NS = 'ha-store-final';

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
        $this->tmpDir = sys_get_temp_dir().'/kiwicaptcha-ha-store-final-'.bin2hex(random_bytes(6));
        if (!mkdir($this->tmpDir, 0o700, true) && !is_dir($this->tmpDir)) {
            self::markTestSkipped('cannot create the adversarial scratch directory');
        }
    }

    /**
     * Start a redis-server on the given port with append-only
     * persistence, so a pin written before a restart survives the
     * restart and the identity change becomes a refusal instead of a
     * silent re-pin.
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

    private function runIdOf(\Predis\Client $client): string
    {
        $replication = $client->info('replication');
        $runId = $replication['run_id'] ?? $replication['Replication']['run_id'] ?? null;
        if (!\is_string($runId) || $runId === '') {
            $server = $client->info('server');
            $runId = $server['run_id'] ?? $server['Server']['run_id'] ?? '';
        }

        return (string) $runId;
    }

    private function stageNonce(string $seed): string
    {
        return base64_encode(hash('sha256', 'stage2:'.$seed, true));
    }

    /**
     * Restart the server on the same port within the verification
     * window and reconnect the guarded client without replacing the
     * connection object. The ordinary lane keeps serving from the
     * cache (the window is still warm); a security-final transition
     * must refuse immediately.
     */
    private function restartWithinWindow(int $port, string $name, \Predis\Client $client): void
    {
        $this->restartRedis($port, $name);
        $client->disconnect();
        $client->set('warmup', '1');
    }

    public function testSiteVerifyFinalizeRefusesInsideTheWindowAndLeavesTheRecordUnchanged(): void
    {
        $this->envRedisOrSkip();
        $this->binaryOrSkip();
        $this->setupTmpDir();
        $port = $this->freePort();
        $this->bootRedis($port, 'primary');

        $client = $this->client($port);
        $guard = new PinnedPrimaryAuthorityGuard($client, self::NS, 30, 'storage');
        $guard->initializePin();
        $pinnedRunId = $this->runIdOf($client);
        $wrapped = new AuthorityGuardedPredisClient($guard, $client);
        $store = new RedisSiteVerifyIdempotencyStore($wrapped, self::NS, 1);

        // the store (the claim
        // rides the mutation lane; the guard verification warms the
        // window) and warm the ordinary lane too.
        [$claim, $owner] = $store->claim('backend', 'idem-1', 'response-hash', 300, 'fp', null, 'binding');
        self::assertSame(IdempotencyClaim::Claimed, $claim);
        self::assertIsString($owner);
        $wrapped->set('warm', '1');

        // Change the authority inside the window: the run_id changes
        // the pin survives through the append-only file, and the
        // connection object is unchanged (the ordinary lane still
        // serves from the cache).
        $this->restartWithinWindow($port, 'primary-restarted', $client);
        self::assertNotSame($pinnedRunId, $this->runIdOf($client));
        self::assertSame('1', $wrapped->get('warm'), 'the ordinary lane serves inside the window: the cache is warm, not invalidated');

        $recordKey = '{'.self::NS.'}:siteverify-idem:backend:idem-1';
        $raw = $this->client($port);
        $before = json_decode((string) $raw->get($recordKey), true, 8, JSON_THROW_ON_ERROR);
        self::assertSame('pending', $before['state'], 'the claim is pending before the finalize attempt');

        try {
            $store->finalize('backend', 'idem-1', 'response-hash', $owner, ['valid' => true]);
            self::fail('the siteverify finalize must refuse inside the window after the authority changed');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('pinned master|'.$pinnedRunId, $e->getMessage());
            self::assertStringContainsString('observed master|'.$this->runIdOf($client), $e->getMessage());
        }

        $after = json_decode((string) $raw->get($recordKey), true, 8, JSON_THROW_ON_ERROR);
        self::assertSame('pending', $after['state'], 'the refused finalize never mutated the record');
        self::assertSame($before, $after, 'the record is byte-identical: the refusal happened before the mutation');
    }

    public function testACleanAuthorizedFinalizeStillSucceedsOnTheWarmedAuthority(): void
    {
        // The refusal above is authority-driven, not a broken lane: the
        // same finalize on the unchanged authority succeeds, so the
        // seam's security-final lane still lets the legitimate write
        // through.
        $this->envRedisOrSkip();
        $this->binaryOrSkip();
        $this->setupTmpDir();
        $port = $this->freePort();
        $this->bootRedis($port, 'primary');

        $client = $this->client($port);
        $guard = new PinnedPrimaryAuthorityGuard($client, self::NS, 30, 'storage');
        $guard->initializePin();
        $wrapped = new AuthorityGuardedPredisClient($guard, $client);
        $store = new RedisSiteVerifyIdempotencyStore($wrapped, self::NS, 1);

        [$claim, $owner] = $store->claim('backend', 'idem-ok', 'response-hash', 300, 'fp', null, 'binding');
        self::assertSame(IdempotencyClaim::Claimed, $claim);

        self::assertTrue($store->finalize('backend', 'idem-ok', 'response-hash', $owner, ['valid' => true]));
        $record = json_decode((string) $this->client($port)->get('{'.self::NS.'}:siteverify-idem:backend:idem-ok'), true, 8, JSON_THROW_ON_ERROR);
        self::assertSame('complete', $record['state'], 'a legitimate finalize still succeeds on the pinned authority');
    }

    public function testChainTerminalTransitionRefusesInsideTheWindowAndLeavesTheRecordUnchanged(): void
    {
        $this->envRedisOrSkip();
        $this->binaryOrSkip();
        $this->setupTmpDir();
        $port = $this->freePort();
        $this->bootRedis($port, 'primary');

        $client = $this->client($port);
        $guard = new PinnedPrimaryAuthorityGuard($client, self::NS, 30, 'storage');
        $guard->initializePin();
        $pinnedRunId = $this->runIdOf($client);
        $wrapped = new AuthorityGuardedPredisClient($guard, $client);
        $store = new RedisChainedChallengeStateStore($wrapped, self::NS);

        // Build a live chain through the store: obligation
        // create-or-get, reservation, stage-2 issuance (all security-
        // final lanes, all before the authority change).
        $chainId = base64_encode(random_bytes(32));
        $obligationId = str_repeat('a', 64);
        $stage2 = $this->stageNonce('stage2');
        $resolved = $store->createOrGetObligation($obligationId, $chainId, $this->stageNonce('stage1'), 'login', '', 'sha16', 1, 1, time() + 300, 300);
        self::assertSame($chainId, $resolved);
        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        self::assertSame('issued_new', $store->markIssued($chainId, 'owner-a', $stage2));
        $wrapped->set('warm', '1');

        $this->restartWithinWindow($port, 'primary-restarted', $client);
        self::assertNotSame($pinnedRunId, $this->runIdOf($client));
        self::assertSame('1', $wrapped->get('warm'), 'the ordinary lane serves inside the window: the cache is warm, not invalidated');

        $recordKey = '{kiwi:'.self::NS.'}:chain:'.$chainId;
        $raw = $this->client($port);
        $before = json_decode((string) $raw->get($recordKey), true, 8, JSON_THROW_ON_ERROR);
        self::assertSame('issued', $before['state'], 'the chain is issued before the terminal attempt');

        try {
            $store->markVerified($chainId, $stage2);
            self::fail('the chain terminal transition must refuse inside the window after the authority changed');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('pinned master|'.$pinnedRunId, $e->getMessage());
            self::assertStringContainsString('observed master|'.$this->runIdOf($client), $e->getMessage());
        }

        $after = json_decode((string) $raw->get($recordKey), true, 8, JSON_THROW_ON_ERROR);
        self::assertSame('issued', $after['state'], 'the refused terminal transition never mutated the chain record');
        self::assertSame($before, $after, 'the chain record is byte-identical: the refusal happened before the mutation');
        self::assertSame($chainId, (string) $raw->get('{kiwi:'.self::NS.'}:chain-obligation:'.$obligationId), 'the obligation mapping is untouched too');
    }

    public function testPostSolveFinalDispositionRefusesInsideTheWindowAndLeavesTheRecordUnchanged(): void
    {
        $this->envRedisOrSkip();
        $this->binaryOrSkip();
        $this->setupTmpDir();
        $port = $this->freePort();
        $this->bootRedis($port, 'primary');

        $client = $this->client($port);
        $guard = new PinnedPrimaryAuthorityGuard($client, self::NS, 30, 'storage');
        $guard->initializePin();
        $pinnedRunId = $this->runIdOf($client);
        $wrapped = new AuthorityGuardedPredisClient($guard, $client);
        $store = new RedisPostSolveDispositionStore($wrapped, self::NS, 300);

        // A pending disposition claim through the store, then warm
        // the ordinary lane.
        $nonce = bin2hex(random_bytes(16));
        [$status] = $store->claim($nonce, 'owner-p', 300);
        self::assertSame('claimed', $status);
        $wrapped->set('warm', '1');

        $this->restartWithinWindow($port, 'primary-restarted', $client);
        self::assertNotSame($pinnedRunId, $this->runIdOf($client));
        self::assertSame('1', $wrapped->get('warm'), 'the ordinary lane serves inside the window: the cache is warm, not invalidated');

        $recordKey = '{kiwi:'.self::NS.'}:postsolve:'.$nonce;
        $raw = $this->client($port);
        $before = json_decode((string) $raw->get($recordKey), true, 8, JSON_THROW_ON_ERROR);
        self::assertSame('pending', $before['state'], 'the disposition is pending before the finalize attempt');

        try {
            $store->finalize($nonce, 'owner-p', new PostSolveDisposition(PostSolveDispositionKind::Deny, 'decision-1'));
            self::fail('the post-solve final disposition must refuse inside the window after the authority changed');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('pinned master|'.$pinnedRunId, $e->getMessage());
            self::assertStringContainsString('observed master|'.$this->runIdOf($client), $e->getMessage());
        }

        $after = json_decode((string) $raw->get($recordKey), true, 8, JSON_THROW_ON_ERROR);
        self::assertSame('pending', $after['state'], 'the refused final disposition never mutated the record');
        self::assertSame($before, $after, 'the record is byte-identical: the refusal happened before the mutation');
    }
}
