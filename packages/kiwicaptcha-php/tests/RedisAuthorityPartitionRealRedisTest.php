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
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * The split-authority partition contract against two real Redis
 * instances this suite boots itself.
 *
 * A network partition can leave two nodes serving one logical
 * deployment, each with its own view of the challenge state. The
 * documented contract (redis-topologies.md) is that one-shot
 * verification is atomic on the current Redis authority but is not
 * guaranteed across stale-replica promotion. This suite pins that
 * boundary deterministically: a second authority is seeded with a
 * byte-identical stale copy of an issued envelope, exactly the state
 * a lagging replica presents after promotion. The Sentinel suite
 * places that stale view on a real replica; here the second authority
 * is an independent server, so the split view needs no failover at
 * all.
 *
 * Within each authority the atomic single-use holds: one consume
 * wins, the next consume reports consumed-before, and a verification
 * never replays. Across the authorities the views diverge on the same
 * nonce: the second authority still holds the pending envelope, it
 * accepts a fresh consume with no replayed result, and a committed
 * verification result never crosses the split. That divergence is the
 * documented deployment boundary, not a code defect.
 *
 * Runs in the dedicated "PHP core real-Redis fault/topology" CI lane
 * contract: with `KIWI_REQUIRE_REAL_REDIS_TESTS=1` a missing or
 * unreachable Redis, or missing redis-server/redis-cli binaries,
 * fails the suite instead of skipping. With the flag off the suite
 * skips like every other real-Redis suite.
 */
final class RedisAuthorityPartitionRealRedisTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const ISSUED_AT = 1_800_000_000;

    private const PREFIX = 'partition:';

    /** @var array<int, resource> */
    private array $procs = [];

    private string $tmpDir = '';

    private int $portA = 0;

    private int $portB = 0;

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
        $this->portA = 0;
        $this->portB = 0;
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
        $url = RealRedisTestEnv::requireRedis('the Redis authority partition suite');
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis topology suites run in the dedicated real-Redis CI lane');
        }
        try {
            $probe = new \Predis\Client($url, ['timeout' => 3.0]);
            $probe->ping();
        } catch (\Throwable) {
            RealRedisTestEnv::failWhenRequired('no Redis is reachable at the configured KC_REDIS_URL/TEST_REDIS_URL', 'the Redis authority partition suite');
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }
    }

    private function binariesOrSkip(): void
    {
        foreach (['redis-server', 'redis-cli'] as $binary) {
            if (RealRedisTestEnv::requireBinary($binary, 'the Redis authority partition suite')) {
                continue;
            }
            self::markTestSkipped("{$binary} not found on PATH — the authority partition suite needs a local redis-server build");
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
        self::markTestSkipped('no free local port available for the authority partition suite: '.$errstr);
    }

    /** @param list<string> $extraArgs */
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

    /** @return list<int> [portA, portB] */
    private function startAuthoritiesOrSkip(): array
    {
        if ($this->portA !== 0) {
            return [$this->portA, $this->portB];
        }
        $this->envRedisOrSkip();
        $this->binariesOrSkip();
        $this->tmpDir = sys_get_temp_dir().'/kiwicaptcha-partition-'.bin2hex(random_bytes(6));
        if (!mkdir($this->tmpDir, 0o700, true) && !is_dir($this->tmpDir)) {
            self::markTestSkipped('cannot create the partition scratch directory');
        }
        $lastFailure = '';
        for ($attempt = 0; $attempt < 3; $attempt++) {
            $candidates = [$this->freePort(), $this->freePort()];
            try {
                $this->portA = $candidates[0];
                $this->portB = $candidates[1];
                $this->spawnRedisServer(['--port', (string) $this->portA, '--dir', $this->tmpDir], 'authority-a');
                $this->spawnRedisServer(['--port', (string) $this->portB, '--dir', $this->tmpDir], 'authority-b');
                $this->waitFor(
                    fn (): bool => str_contains((string) @shell_exec('redis-cli -p '.$this->portA.' ping 2>/dev/null'), 'PONG'),
                    10,
                    'authority A to answer PONG',
                );
                $this->waitFor(
                    fn (): bool => str_contains((string) @shell_exec('redis-cli -p '.$this->portB.' ping 2>/dev/null'), 'PONG'),
                    10,
                    'authority B to answer PONG',
                );

                return [$this->portA, $this->portB];
            } catch (\Throwable $e) {
                $lastFailure = $e->getMessage();
                foreach ($this->procs as $proc) {
                    $status = proc_get_status($proc);
                    if ($status !== false && $status['running']) {
                        proc_terminate($proc, 9);
                    }
                    proc_close($proc);
                }
                $this->procs = [];
                $this->portA = 0;
                $this->portB = 0;
            }
        }
        self::markTestSkipped('authority partition boot was attempted but failed: '.$lastFailure);
    }

    /** @return array{0: RedisStorage, 1: \KiwiCaptcha\ChallengeRecord, 2: string} */
    private function issueAndSolve(\Predis\Client $client): array
    {
        $storage = new RedisStorage($client, self::PREFIX);
        $challenge = (new Issuer(
            new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120, minDurationMs: 0),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        ))->issue('login', '198.51.100.7');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $record->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        return [$storage, $record, $token];
    }

    /**
     * Each authority grants the nonce exactly once, on the pending
     * envelope each side holds. Authority B is seeded with the pending
     * bytes authority A issued, so both sides grant the same nonce
     * once. The divergence is deterministic: each grant is a fresh
     * pending-to-consumed transition on its own server, and the
     * re-verification on each side is refused.
     */
    public function testTheSplitAuthoritiesGrantTheSameNonceOnceEach(): void
    {
        [$portA, $portB] = $this->startAuthoritiesOrSkip();
        $clientA = new \Predis\Client('tcp://127.0.0.1:'.$portA, ['timeout' => 2.0]);
        $clientB = new \Predis\Client('tcp://127.0.0.1:'.$portB, ['timeout' => 2.0]);
        [$storageA, $record, $token] = $this->issueAndSolve($clientA);
        $nonce = $record->nonce;

        // The second authority receives a byte-identical copy of the
        // pending envelope, the stale view a lagging replica presents.
        $pendingJson = $clientA->get(self::PREFIX.$nonce);
        self::assertIsString($pendingJson, 'the issued envelope must exist before the split');
        self::assertStringContainsString('"state":"pending"', $pendingJson);
        $clientB->set(self::PREFIX.$nonce, $pendingJson, 'EX', 300);
        self::assertSame($pendingJson, $clientB->get(self::PREFIX.$nonce), 'the seeded copy must be byte-identical');

        // Authority B grants the token first: the same token verifies
        // on the second authority, the documented promotion boundary.
        $verifierB = new Verifier(new RedisStorage($clientB, self::PREFIX), null, static fn (): int => self::ISSUED_AT);
        $grantB = $verifierB->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($grantB->isOk(), sprintf('authority B must grant the pending nonce once, got %s', $grantB->code()));
        self::assertSame(
            VerifyError::AlreadyConsumed,
            $verifierB->verify($token, self::SECRET, 'login', '198.51.100.7')->error,
            'the second grant on the same authority must be refused'
        );

        // Authority A never saw the grant on B: its envelope still
        // reads pending while B already holds a consumed envelope. The
        // views diverge on purpose.
        $aRaw = $clientA->get(self::PREFIX.$nonce);
        $bRaw = $clientB->get(self::PREFIX.$nonce);
        self::assertIsString($aRaw);
        self::assertIsString($bRaw);
        self::assertStringContainsString('"state":"pending"', $aRaw, 'authority A never saw the grant on B');
        self::assertStringContainsString('"state":"consumed"', $bRaw, 'authority B consumed its own envelope');

        // Authority A still holds the untouched pending envelope and
        // grants the same token once too.
        $verifierA = new Verifier($storageA, null, static fn (): int => self::ISSUED_AT);
        $grantA = $verifierA->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertTrue($grantA->isOk(), sprintf('authority A must grant the still-pending nonce once, got %s', $grantA->code()));
        self::assertSame(
            VerifyError::AlreadyConsumed,
            $verifierA->verify($token, self::SECRET, 'login', '198.51.100.7')->error,
            'the second grant on authority A must be refused too'
        );
    }

    /**
     * The committed-result divergence: authority A consumes and
     * commits a valid result, and authority B never sees either
     * transition. B still holds the pending envelope, its consume is
     * fresh with no replayed result, and its retry of the same token
     * resolves the indeterminate retryable outcome, never a replayed
     * authorization.
     */
    public function testTheCommittedResultNeverCrossesTheSplit(): void
    {
        [$portA, $portB] = $this->startAuthoritiesOrSkip();
        $clientA = new \Predis\Client('tcp://127.0.0.1:'.$portA, ['timeout' => 2.0]);
        $clientB = new \Predis\Client('tcp://127.0.0.1:'.$portB, ['timeout' => 2.0]);
        [$storageA, $record, $token] = $this->issueAndSolve($clientA);
        $nonce = $record->nonce;
        $pendingJson = $clientA->get(self::PREFIX.$nonce);
        self::assertIsString($pendingJson);
        $clientB->set(self::PREFIX.$nonce, $pendingJson, 'EX', 300);

        // Authority A: the atomic single-use holds at the storage level.
        $first = $storageA->consume($nonce);
        self::assertNotNull($first);
        self::assertTrue($first->consumedNow, 'the first consume wins the transition');
        self::assertFalse($first->consumedBefore);
        $second = $storageA->consume($nonce);
        self::assertNotNull($second);
        self::assertFalse($second->consumedNow);
        self::assertTrue($second->consumedBefore, 'the second consume on the same authority reports consumed-before');

        // The commit lands on authority A and stays there.
        self::assertTrue($storageA->commitResult($nonce, true, 'txn-a'));
        $stateA = $storageA->consumedState($nonce);
        self::assertNotNull($stateA);
        self::assertNotNull($stateA?->consumedResult, 'the committed result is readable back on authority A');
        self::assertTrue($stateA->consumedResult->valid);
        $aRaw = $clientA->get(self::PREFIX.$nonce);
        self::assertIsString($aRaw);
        self::assertStringContainsString('"valid":true', $aRaw, 'authority A holds the committed authorization');

        // Authority B: the stale copy never advanced.
        $bRaw = $clientB->get(self::PREFIX.$nonce);
        self::assertIsString($bRaw, 'the second authority still holds its copy');
        self::assertStringContainsString('"state":"pending"', $bRaw, 'the consume never crossed the split');
        self::assertStringNotContainsString('"valid":true', $bRaw, 'the committed result never crossed the split');

        // The fresh consume on B carries no replayed result.
        $storageB = new RedisStorage($clientB, self::PREFIX);
        $fresh = $storageB->consume($nonce);
        self::assertNotNull($fresh, 'the split authority still sees a pending record');
        self::assertTrue($fresh->consumedNow);
        self::assertFalse($fresh->consumedBefore);
        self::assertNull($fresh->consumedResult, 'the fresh consume carries no replayed result');
        self::assertNull($storageB->consumedState($nonce)?->consumedResult, 'the committed result of authority A is absent on authority B');

        // The retry of the same token on B resolves the indeterminate
        // retryable outcome, never a replayed authorization.
        $verifierB = new Verifier($storageB, null, static fn (): int => self::ISSUED_AT);
        $retry = $verifierB->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::ConsumeIndeterminate, $retry->error, 'without a stored result on B the retry is indeterminate, never a replay');
    }
}
