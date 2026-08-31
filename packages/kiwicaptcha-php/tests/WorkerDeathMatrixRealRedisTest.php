<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\ConsumedOutcomeRecovery;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Tests\Fixtures\RealRedisTestEnv;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * The worker-death matrix against a real Redis.
 *
 * Every scenario forks a real worker process that performs the steps of
 * a verification up to one transition boundary and then dies, and the
 * parent runs the recovery and asserts the deterministic contract. The
 * lifecycle runs from issuance through the submit, the runtime-state
 * read, the atomic consume, the derivation, the result commit and the
 * stored-result replay. A death before the consume leaves the record
 * pending for a fresh verification. A death between the consume and the
 * commit leaves a resultless consumed record that recovers through the
 * re-derivation claim with exactly one derivation. A death between the
 * commit and the reply leaves a committed record that replays behind
 * the identity gate. A death inside the recovery claim leaves only the
 * short lease, which expires into the next recovery. No scenario may
 * produce a second success, a lost authorization, a surviving claim
 * field, or an envelope that blocks a legitimate retry beyond the claim
 * TTL.
 *
 * Runs in the dedicated "PHP core real-Redis fault/topology" CI lane,
 * which publishes `KC_REDIS_URL` and `TEST_REDIS_URL` and sets
 * `KIWI_REQUIRE_REAL_REDIS_TESTS=1`; with the flag on, a missing or
 * unreachable Redis, or missing pcntl/posix extensions, fails the
 * suite instead of skipping. With the flag off the suite skips like
 * every other real-Redis suite. The matrix stays bounded: one record
 * per boundary, a short claim TTL where the test needs expiry inside
 * the window, and a bounded wait for the worker markers.
 */
final class WorkerDeathMatrixRealRedisTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const ISSUED_AT = 1_800_000_000;

    private const CLAIM_TTL_SECS = 1;

    /** @return \Predis\Client|null null when Redis is unreachable */
    private function redisOrSkip(): ?\Predis\Client
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        if (!RealRedisTestEnv::requireExtensions(['pcntl', 'posix'], 'the real-Redis worker-death matrix')) {
            self::markTestSkipped('the pcntl and posix extensions are required for the forked workers');
        }
        $url = RealRedisTestEnv::requireRedis('the real-Redis worker-death matrix');
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis death matrix runs in the dedicated real-Redis CI lane');
        }
        try {
            $probe = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();

            return $probe;
        } catch (\Throwable) {
            RealRedisTestEnv::failWhenRequired('no Redis is reachable at the configured KC_REDIS_URL/TEST_REDIS_URL', 'the real-Redis worker-death matrix');
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }
    }

    private function redisUrl(): string
    {
        $url = getenv('KC_REDIS_URL');
        if (!\is_string($url) || $url === '') {
            $url = getenv('TEST_REDIS_URL');
        }

        return (string) $url;
    }

    private function identity(string $seed): string
    {
        return 'op-'.hash('sha256', $seed);
    }

    private function makeIssuer(\Predis\Client $client, string $prefix): Issuer
    {
        return new Issuer(
            new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0),
            new RedisStorage($client, $prefix),
            now: static fn (): int => self::ISSUED_AT,
        );
    }

    private function solveToken(string $nonce, string $powPrefix, string $salt, int $targetBits): string
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $powPrefix.$counter.$saltBytes, true);
            ++$counter;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);
        --$counter;

        return SolutionToken::create($nonce, $counter, 5000, [])->encode();
    }

    /**
     * @return array<string, mixed>
     */
    private function envelope(\Predis\Client $client, string $prefix, string $nonce): array
    {
        $raw = $client->get($prefix.$nonce);
        self::assertIsString($raw, 'the record must still be stored');
        $data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($data);

        return $data;
    }

    /**
     * The claim lives inside the record envelope, never a second key:
     * after a settled recovery the storage prefix must hold exactly the
     * record key and nothing else.
     */
    private function assertSingleKey(\Predis\Client $client, string $prefix, string $nonce, string $label): void
    {
        $keys = $client->keys($prefix.'*');
        sort($keys);
        self::assertSame([$prefix.$nonce], $keys, $label.': the record envelope is the only key under the prefix');
    }

    /**
     * Fork one worker that performs the role steps up to its death
     * boundary. The child opens its own Redis connection, writes its
     * result as JSON, and exits; it never runs PHPUnit.
     *
     * @param array<string, mixed> $extra
     *
     * @return array{0: int, 1: string, 2: string} [pid, result path, tmp dir]
     */
    private function spawnChild(string $role, string $prefix, array $extra): array
    {
        $tmp = sys_get_temp_dir().'/kiwicaptcha-death-'.bin2hex(random_bytes(4));
        self::assertTrue(mkdir($tmp));
        $jobPath = "$tmp/job.json";
        $resultPath = "$tmp/result.json";
        $job = array_merge(['role' => $role, 'prefix' => $prefix], $extra);
        file_put_contents($jobPath, json_encode($job, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        $pid = pcntl_fork();
        self::assertNotSame(-1, $pid, 'the worker fork must succeed');
        if ($pid === 0) {
            $this->workerMain($jobPath, $resultPath);
        }

        return [$pid, $resultPath, $tmp];
    }

    /**
     * Wait for the worker to exit and decode its result file, asserting
     * the clean status.
     *
     * @return array<string, mixed>
     */
    private function reapChild(int $pid, string $resultPath): array
    {
        pcntl_waitpid($pid, $status);
        self::assertTrue(pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0, "worker $pid must exit with status 0");
        $raw = file_get_contents($resultPath);
        self::assertIsString($raw, 'the worker result file must exist');
        $result = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($result);
        self::assertArrayNotHasKey('error', $result, 'the worker must not report an error');

        return $result;
    }

    private function waitForMarker(string $path): void
    {
        $deadline = microtime(true) + 15.0;
        while (!file_exists($path)) {
            self::assertLessThan($deadline, microtime(true), 'the worker marker must appear within the deadline');
            usleep(100000);
        }
    }

    /**
     * Kill a parked worker with the kill signal and reap it, used when
     * the scenario models the worker vanishing mid-claim.
     */
    private function killAndReap(int $pid): void
    {
        @posix_kill($pid, 9);
        pcntl_waitpid($pid, $status);
    }

    /**
     * The forked worker entry point: dispatch on the job role, write the
     * result file, and exit. Every worker opens a fresh Redis connection
     * because the parent's connection is not safe to share across fork.
     */
    private function workerMain(string $jobPath, string $resultPath): void
    {
        try {
            $raw = file_get_contents($jobPath);
            $job = json_decode((string) $raw, true, flags: JSON_THROW_ON_ERROR);
            self::assertIsArray($job);
            $result = match ($job['role'] ?? null) {
                'issue' => $this->workerIssue($job),
                'submit' => $this->workerSubmit($job),
                'runtime-read' => $this->workerRuntimeRead($job),
                'consume' => $this->workerConsume($job),
                'commit' => $this->workerCommit($job),
                'resume' => $this->workerResume($job),
                'claim-park' => $this->workerClaimPark($job),
                default => throw new \RuntimeException('unknown worker role'),
            };
            file_put_contents($resultPath, json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            exit(0);
        } catch (\Throwable $e) {
            file_put_contents($resultPath, json_encode(['error' => $e->getMessage()], JSON_THROW_ON_ERROR));
            exit(2);
        }
    }

    private function workerClient(): \Predis\Client
    {
        return new \Predis\Client($this->redisUrl(), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
    }

    /** @param array<string, mixed> $job */
    private function workerIssue(array $job): array
    {
        $issuer = new Issuer(
            new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0),
            new RedisStorage($this->workerClient(), (string) $job['prefix']),
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', '198.51.100.7');

        return [
            'nonce' => $challenge->nonce,
            'salt' => $challenge->salt,
            'prefix' => $challenge->prefix,
            'target_bits' => $challenge->targetBits,
        ];
    }

    /** @param array<string, mixed> $job */
    private function workerSubmit(array $job): array
    {
        $token = SolutionToken::decode((string) $job['token']);

        return ['nonce' => $token->nonce, 'counter' => $token->counter];
    }

    /** @param array<string, mixed> $job */
    private function workerRuntimeRead(array $job): array
    {
        $storage = new RedisStorage($this->workerClient(), (string) $job['prefix']);
        $state = $storage->runtimeState((string) $job['nonce']);

        return ['kind' => $state->kind->value, 'has_record' => $state->record !== null, 'nonce' => (string) $job['nonce']];
    }

    /** @param array<string, mixed> $job */
    private function workerConsume(array $job): array
    {
        $storage = new RedisStorage($this->workerClient(), (string) $job['prefix']);
        $consumed = $storage->consumeWithOperationIdentity((string) $job['nonce'], (string) $job['identity']);
        if ($consumed === null) {
            throw new \RuntimeException('the consume returned no record');
        }

        return ['consumed_now' => $consumed->consumedNow, 'consumed_before' => $consumed->consumedBefore];
    }

    /**
     * The worker that dies between the commit and the reply: it consumes
     * with the identity, re-derives the proof, commits the deterministic
     * outcome, and then exits before any reply could reach the client.
     *
     * @param array<string, mixed> $job
     */
    private function workerCommit(array $job): array
    {
        $storage = new RedisStorage($this->workerClient(), (string) $job['prefix']);
        $nonce = (string) $job['nonce'];
        $token = SolutionToken::decode((string) $job['token']);
        $consumed = $storage->consumeWithOperationIdentity($nonce, (string) $job['identity']);
        if ($consumed === null || !$consumed->consumedNow) {
            throw new \RuntimeException('the worker lost the atomic consume');
        }
        $record = $consumed->record;
        $saltBytes = base64_decode($record->salt, true);
        $hash = hash('sha256', $record->prefix.$token->counter.$saltBytes, true);
        $valid = Verifier::leadingZeroBits($hash) >= $record->targetBits;
        $committed = $storage->commitResult($nonce, $valid, $record->requestBinding);

        return ['committed' => $committed, 'valid' => $valid];
    }

    /** @param array<string, mixed> $job */
    private function workerResume(array $job): array
    {
        $verifier = new Verifier(
            new RedisStorage($this->workerClient(), (string) $job['prefix']),
            now: static fn (): int => self::ISSUED_AT,
            resumeClaimTtlSecs: self::CLAIM_TTL_SECS,
        );
        $outcome = $verifier->resumeConsumedOperation(
            (string) $job['token'],
            self::SECRET,
            (string) $job['identity'],
            'login',
            '198.51.100.7',
        );

        return [
            'ok' => $outcome->isOk(),
            'code' => $outcome->code(),
            'from_stored_result' => $outcome->fromStoredResult,
            'solve_duration_ms' => $outcome->solveDurationMs(),
        ];
    }

    /**
     * The worker that dies inside the recovery claim: it acquires the
     * re-derivation claim with the short TTL, signals the parent, and
     * then parks until the parent kills it. The claim survives the
     * process death with no release and no commit.
     *
     * @param array<string, mixed> $job
     *
     * @return never
     */
    private function workerClaimPark(array $job): array
    {
        $storage = new RedisStorage($this->workerClient(), (string) $job['prefix']);
        $ttl = isset($job['claim_ttl']) ? (int) $job['claim_ttl'] : self::CLAIM_TTL_SECS;
        $owner = $storage->claimResumeDerivation((string) $job['nonce'], $ttl);
        if ($owner === null) {
            throw new \RuntimeException('the claim was refused');
        }
        file_put_contents((string) $job['marker'], $owner);
        while (true) {
            usleep(100000);
        }
    }

    public function testDeathBeforeTheConsumeLeavesTheRecordPendingForAFreshVerification(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);

        foreach (['issue', 'submit', 'runtime-read'] as $boundary) {
            $prefix = 'death-a-'.$boundary.'-'.bin2hex(random_bytes(4)).'-';
            if ($boundary === 'issue') {
                [$pid, $resultPath, $tmp] = $this->spawnChild('issue', $prefix, []);
                $result = $this->reapChild($pid, $resultPath);
                $nonce = (string) $result['nonce'];
                $token = $this->solveToken($nonce, (string) $result['prefix'], (string) $result['salt'], (int) $result['target_bits']);
            } else {
                $challenge = $this->makeIssuer($client, $prefix)->issue('login', '198.51.100.7');
                $nonce = $challenge->nonce;
                $token = $this->solveToken($nonce, $challenge->prefix, $challenge->salt, $challenge->targetBits);
                $extra = $boundary === 'submit' ? ['token' => $token] : ['nonce' => $nonce];
                [$pid, $resultPath, $tmp] = $this->spawnChild($boundary, $prefix, $extra);
                $result = $this->reapChild($pid, $resultPath);
                self::assertSame($nonce, $result['nonce'] ?? null, 'the dead worker must have handled this record');
                if ($boundary === 'runtime-read') {
                    self::assertSame('pending', $result['kind'] ?? null, 'the snapshot read by the dead worker still sees the pending record');
                }
            }
            $this->assertPendingRecoveryContract($client, $prefix, $nonce, $token, $boundary);
        }
    }

    /**
     * The contract of a death before the consume: the record stayed
     * pending, a fresh verification completes it exactly once, and the
     * replay paths behind the identity gate serve the committed outcome
     * with no surviving claim fields.
     */
    private function assertPendingRecoveryContract(\Predis\Client $client, string $prefix, string $nonce, string $token, string $boundary): void
    {
        $label = 'death before the consume at the '.$boundary.' boundary';
        $storage = new RedisStorage($client, $prefix);
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT, resumeClaimTtlSecs: self::CLAIM_TTL_SECS);
        $recovery = new ConsumedOutcomeRecovery($storage);
        $identity = $this->identity('death-a');

        $data = $this->envelope($client, $prefix, $nonce);
        self::assertSame('pending', $data['state'] ?? null, $label.': the record must still be pending');
        self::assertNull($data['consumed_result'] ?? null, $label.': nothing may be committed');
        self::assertArrayNotHasKey('resume_owner', $data, $label.': no claim may exist');
        self::assertArrayNotHasKey('resume_until', $data, $label.': no claim expiry may exist');
        self::assertNull($recovery->recover($token, $identity), $label.': a pending record recovers nothing');

        $fresh = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7', operationIdentity: $identity);
        self::assertTrue($fresh->isOk(), $label.': the fresh verification must succeed, got '.$fresh->code());
        self::assertFalse($fresh->fromStoredResult, $label.': the completion is a fresh derivation');
        self::assertNotNull($fresh->solveDurationMs(), $label.': a fresh derivation exposes the measured solve duration');
        self::assertSame($nonce, $fresh->nonce(), $label.': the success names the exact challenge');

        $data = $this->envelope($client, $prefix, $nonce);
        self::assertSame('consumed', $data['state'] ?? null, $label.': the record is consumed after the fresh verification');
        self::assertTrue($data['consumed_result']['valid'] ?? false, $label.': the committed outcome is valid');
        self::assertArrayNotHasKey('resume_owner', $data, $label.': no claim may survive the completion');
        self::assertArrayNotHasKey('resume_until', $data, $label.': no claim expiry may survive the completion');
        $this->assertSingleKey($client, $prefix, $nonce, $label);

        $replay = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7', operationIdentity: $identity);
        self::assertTrue($replay->isOk(), $label.': the identity-proven replay resolves the stored success');
        self::assertTrue($replay->fromStoredResult, $label.': the replay is the stored result, never a second derivation');
        self::assertNull($replay->solveDurationMs(), $label.': the stored replay carries no fresh solve duration');
        $refused = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::AlreadyConsumed, $refused->error, $label.': a replay without the identity proof is refused');
        $recovered = $recovery->recover($token, $identity);
        self::assertNotNull($recovered, $label.': the recovery API answers the proven identity');
        self::assertTrue($recovered->isOk(), $label.': the recovery API returns the stored grant');
        self::assertTrue($recovered->fromStoredResult, $label.': the recovery API is a stored-result replay');
    }

    public function testDeathBetweenConsumeAndCommitRecoversThroughTheClaimWithOneDerivation(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);

        $prefix = 'death-b-'.bin2hex(random_bytes(4)).'-';
        $challenge = $this->makeIssuer($client, $prefix)->issue('login', '198.51.100.7');
        $nonce = $challenge->nonce;
        $token = $this->solveToken($nonce, $challenge->prefix, $challenge->salt, $challenge->targetBits);
        $identity = $this->identity('death-b');

        [$pid, $resultPath, $tmp] = $this->spawnChild('consume', $prefix, ['nonce' => $nonce, 'identity' => $identity]);
        $result = $this->reapChild($pid, $resultPath);
        self::assertTrue($result['consumed_now'] ?? false, 'the dead worker must have won the atomic consume');

        $storage = new RedisStorage($client, $prefix);
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT, resumeClaimTtlSecs: self::CLAIM_TTL_SECS);
        $recovery = new ConsumedOutcomeRecovery($storage);

        $data = $this->envelope($client, $prefix, $nonce);
        self::assertSame('consumed', $data['state'] ?? null, 'the record is consumed when the worker dies');
        self::assertNull($data['consumed_result'] ?? null, 'the worker died before the result commit');
        self::assertSame($identity, $data['operation_identity'] ?? null, 'the identity rode the atomic transition');
        self::assertArrayNotHasKey('resume_owner', $data, 'no claim exists right after the death');
        self::assertArrayNotHasKey('resume_until', $data, 'no claim expiry exists right after the death');
        self::assertNull($recovery->recover($token, $identity), 'a resultless consumed record is ambiguous for the recovery API');

        [$pid2, $resultPath2, $tmp2] = $this->spawnChild('resume', $prefix, ['token' => $token, 'identity' => $identity]);
        $parentOutcome = $verifier->resumeConsumedOperation($token, self::SECRET, $identity, 'login', '198.51.100.7');
        $childResult = $this->reapChild($pid2, $resultPath2);

        $parentFresh = $parentOutcome->isOk() && $parentOutcome->solveDurationMs() !== null;
        $childFresh = (bool) ($childResult['ok'] ?? false) && ($childResult['solve_duration_ms'] ?? null) !== null;
        self::assertSame(1, ($parentFresh ? 1 : 0) + ($childFresh ? 1 : 0), 'the claim deduplicates the derivation: exactly one recovery derives');
        if (!$parentOutcome->isOk()) {
            self::assertSame(VerifyError::ConsumeIndeterminate, $parentOutcome->error, 'a claim loser answers the retryable verdict');
        }
        if (!($childResult['ok'] ?? false)) {
            self::assertSame('consume_indeterminate', $childResult['code'] ?? null, 'a claim loser answers the retryable verdict');
        }
        self::assertTrue($parentOutcome->isOk() || ($childResult['ok'] ?? false), 'at least one recovery must complete the derivation');

        $data = $this->envelope($client, $prefix, $nonce);
        self::assertTrue($data['consumed_result']['valid'] ?? false, 'the winner committed the deterministic valid outcome');
        self::assertArrayNotHasKey('resume_owner', $data, 'no claim may survive the settled recovery');
        self::assertArrayNotHasKey('resume_until', $data, 'no claim expiry may survive the settled recovery');
        $this->assertSingleKey($client, $prefix, $nonce, 'the settled recovery');

        $retry = $verifier->resumeConsumedOperation($token, self::SECRET, $identity, 'login', '198.51.100.7');
        self::assertTrue($retry->isOk(), 'a retry after the settled recovery resolves the committed outcome');
        self::assertTrue($retry->fromStoredResult, 'the retry is the stored result, never a second derivation');

        $recovered = $recovery->recover($token, $identity);
        self::assertNotNull($recovered, 'the committed grant is recoverable');
        self::assertTrue($recovered->isOk(), 'the proven identity receives the stored grant');
        $refused = $recovery->recover($token, $this->identity('death-b-other'));
        self::assertNotNull($refused, 'the recovery API answers a mismatched identity too');
        self::assertSame(VerifyError::AlreadyConsumed, $refused->error, 'a different identity never receives the grant');
        $replay = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7', operationIdentity: $identity);
        self::assertTrue($replay->isOk(), 'the ordinary verify path replays the stored success to the proven identity');
        self::assertTrue($replay->fromStoredResult, 'the ordinary replay is the stored result');
        $noIdentity = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::AlreadyConsumed, $noIdentity->error, 'a replay without the identity proof is refused');
    }

    public function testDeathBetweenCommitAndReplyReplaysBehindTheIdentityGate(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);

        $prefix = 'death-c-'.bin2hex(random_bytes(4)).'-';
        $challenge = $this->makeIssuer($client, $prefix)->issue('login', '198.51.100.7');
        $nonce = $challenge->nonce;
        $token = $this->solveToken($nonce, $challenge->prefix, $challenge->salt, $challenge->targetBits);
        $identity = $this->identity('death-c');

        [$pid, $resultPath, $tmp] = $this->spawnChild('commit', $prefix, ['nonce' => $nonce, 'token' => $token, 'identity' => $identity]);
        $result = $this->reapChild($pid, $resultPath);
        self::assertTrue($result['committed'] ?? false, 'the worker must have committed before dying');
        self::assertTrue($result['valid'] ?? false, 'the worker committed the valid outcome');

        $storage = new RedisStorage($client, $prefix);
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT, resumeClaimTtlSecs: self::CLAIM_TTL_SECS);
        $recovery = new ConsumedOutcomeRecovery($storage);

        $data = $this->envelope($client, $prefix, $nonce);
        self::assertSame('consumed', $data['state'] ?? null, 'the record is consumed when the worker dies');
        self::assertTrue($data['consumed_result']['valid'] ?? false, 'the committed outcome landed before the death');
        self::assertSame($identity, $data['operation_identity'] ?? null, 'the identity survived the commit');
        self::assertArrayNotHasKey('resume_owner', $data, 'no claim may exist on the committed record');
        self::assertArrayNotHasKey('resume_until', $data, 'no claim expiry may exist on the committed record');

        $outcome = $verifier->resumeConsumedOperation($token, self::SECRET, $identity, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), 'the committed record resolves on the resume path');
        self::assertTrue($outcome->fromStoredResult, 'the committed record replays, never a re-derivation');
        self::assertNull($outcome->solveDurationMs(), 'a stored-result replay carries no fresh solve duration');

        $wrong = $verifier->resumeConsumedOperation($token, self::SECRET, $this->identity('death-c-other'), 'login', '198.51.100.7');
        self::assertSame(VerifyError::ConsumeIndeterminate, $wrong->error, 'a different identity cannot resume the operation');

        $recovered = $recovery->recover($token, $identity);
        self::assertNotNull($recovered, 'the recovery API answers the proven identity');
        self::assertTrue($recovered->isOk(), 'the stored grant replays to the proven identity');
        self::assertTrue($recovered->fromStoredResult, 'the recovery API is a stored-result replay');
        $refused = $recovery->recover($token, $this->identity('death-c-other'));
        self::assertNotNull($refused, 'the recovery API answers a mismatched identity too');
        self::assertSame(VerifyError::AlreadyConsumed, $refused->error, 'a different identity never receives the grant');

        $replay = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7', operationIdentity: $identity);
        self::assertTrue($replay->isOk(), 'the ordinary verify path replays the stored success to the proven identity');
        self::assertTrue($replay->fromStoredResult, 'the ordinary replay is the stored result');
        $noIdentity = $verifier->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::AlreadyConsumed, $noIdentity->error, 'a replay without the identity proof is refused');

        $data = $this->envelope($client, $prefix, $nonce);
        self::assertArrayNotHasKey('resume_owner', $data, 'no claim may survive the replay');
        self::assertArrayNotHasKey('resume_until', $data, 'no claim expiry may survive the replay');
        $this->assertSingleKey($client, $prefix, $nonce, 'the committed replay');
    }

    public function testDeathInsideTheRecoveryClaimExpiresIntoTheNextRecovery(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);

        // The parked claim uses a 3-second lease: long enough that the
        // loser probe below always runs while the claim is live even
        // under CI load, short enough that the expiry wait stays
        // bounded.
        $claimTtlSecs = 3;
        $prefix = 'death-d-'.bin2hex(random_bytes(4)).'-';
        $challenge = $this->makeIssuer($client, $prefix)->issue('login', '198.51.100.7');
        $nonce = $challenge->nonce;
        $token = $this->solveToken($nonce, $challenge->prefix, $challenge->salt, $challenge->targetBits);
        $identity = $this->identity('death-d');

        [$pid1, $resultPath1, $tmp1] = $this->spawnChild('consume', $prefix, ['nonce' => $nonce, 'identity' => $identity]);
        $result1 = $this->reapChild($pid1, $resultPath1);
        self::assertTrue($result1['consumed_now'] ?? false, 'the setup worker must win the atomic consume');

        $markerTmp = sys_get_temp_dir().'/kiwicaptcha-death-'.bin2hex(random_bytes(4));
        self::assertTrue(mkdir($markerTmp));
        $marker = "$markerTmp/claimed.marker";
        [$pid2, $resultPath2, $tmp2] = $this->spawnChild('claim-park', $prefix, ['nonce' => $nonce, 'marker' => $marker, 'claim_ttl' => $claimTtlSecs]);

        $verifier = new Verifier(new RedisStorage($client, $prefix), now: static fn (): int => self::ISSUED_AT, resumeClaimTtlSecs: self::CLAIM_TTL_SECS);
        try {
            $this->waitForMarker($marker);

            $data = $this->envelope($client, $prefix, $nonce);
            $owner = $data['resume_owner'] ?? null;
            self::assertIsString($owner, 'the dead recovery left its owner token inside the envelope');
            self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', $owner, 'the owner token follows the 32-hex contract');
            $until = (int) ($data['resume_until'] ?? 0);
            self::assertGreaterThan(time() + 1, $until, 'the claim must still be live for the loser probe');
            self::assertLessThanOrEqual(time() + $claimTtlSecs + 2, $until, 'the claim is the short configured lease');
            self::assertNull($data['consumed_result'] ?? null, 'the claiming worker committed nothing');

            $loser = $verifier->resumeConsumedOperation($token, self::SECRET, $identity, 'login', '198.51.100.7');
            self::assertSame(VerifyError::ConsumeIndeterminate, $loser->error, 'a recovery attempt while the dead claim is live answers the retryable verdict');

            $data = $this->envelope($client, $prefix, $nonce);
            self::assertSame($owner, $data['resume_owner'] ?? null, 'the refused attempt left the dead owner in place');
            self::assertNull($data['consumed_result'] ?? null, 'the refused attempt committed nothing');
        } finally {
            $this->killAndReap($pid2);
        }

        // Wait out the remaining lease with a bounded poll, so the
        // stale claim is dead regardless of how long the probe took.
        $deadline = microtime(true) + $claimTtlSecs + 3.0;
        while ((int) ($this->envelope($client, $prefix, $nonce)['resume_until'] ?? 0) > time()) {
            self::assertLessThan($deadline, microtime(true), 'the claim lease must expire within its TTL');
            usleep(250000);
        }
        $data = $this->envelope($client, $prefix, $nonce);
        self::assertLessThanOrEqual(time(), (int) ($data['resume_until'] ?? 0), 'the lease expired while the owner process was gone');
        self::assertNull($data['consumed_result'] ?? null, 'no result was committed while the claim was dead');

        $outcome = $verifier->resumeConsumedOperation($token, self::SECRET, $identity, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), 'the next recovery re-claims and completes the derivation');
        self::assertNotNull($outcome->solveDurationMs(), 'the completing recovery is a fresh derivation');

        $data = $this->envelope($client, $prefix, $nonce);
        self::assertTrue($data['consumed_result']['valid'] ?? false, 'the completing recovery committed the valid outcome');
        self::assertArrayNotHasKey('resume_owner', $data, 'the claim-bearing commit cleared the claim in the same transition');
        self::assertArrayNotHasKey('resume_until', $data, 'the claim-bearing commit cleared the claim expiry in the same transition');
        $this->assertSingleKey($client, $prefix, $nonce, 'the completed claim recovery');

        $retry = $verifier->resumeConsumedOperation($token, self::SECRET, $identity, 'login', '198.51.100.7');
        self::assertTrue($retry->isOk(), 'the retry after the claim expiry resolves the committed outcome');
        self::assertTrue($retry->fromStoredResult, 'the retry is the stored result, never a second derivation');
    }
}
