<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\VerificationAdmissionGate;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * Real-Redis regression for the resume re-derivation claim
 * ({@see \KiwiCaptcha\ResumeDerivationClaimInterface}): the atomic
 * claim, the compare-and-delete release, the claim-clearing commit and
 * the verifier's loser semantics, all against the real RedisStorage
 * Lua scripts (the Rust `claim_resume_derivation` /
 * `release_resume_derivation` / `commit_result_clearing_claim` mirror).
 *
 * Runs when `KC_REDIS_URL` or `TEST_REDIS_URL` is set (the shared
 * real-Redis env of the monorepo CI); skips otherwise, like every other
 * real-Redis suite.
 */
final class VerifierResumeClaimRealRedisTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const ISSUED_AT = 1_800_000_000;

    /** @return \Predis\Client|null null when Redis is unreachable */
    private function redisOrSkip(): ?\Predis\Client
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $url = getenv('KC_REDIS_URL');
        if (!\is_string($url) || $url === '') {
            $url = getenv('TEST_REDIS_URL');
        }
        if (!\is_string($url) || $url === '') {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis claim suite runs in the CI Redis-service job');
        }
        try {
            $probe = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();

            return $probe;
        } catch (\Throwable) {
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }
    }

    /**
     * The storage prefix, so the test can read the stored envelope
     * bytes (the claim is embedded in the record envelope, never a
     * second key).
     */
    private function storagePrefix(RedisStorage $storage): string
    {
        $property = new \ReflectionProperty(RedisStorage::class, 'prefix');

        return (string) $property->getValue($storage);
    }

    /** @return array{0: RedisStorage, 1: string} [storage, prefix] */
    private function makeStorage(\Predis\Client $client): array
    {
        $storage = new RedisStorage($client, 'claim-test-'.bin2hex(random_bytes(4)).'-');

        return [$storage, $this->storagePrefix($storage)];
    }

    /**
     * The envelope of the stored record, decoded from the raw bytes the
     * client holds (the claim is embedded in the record envelope, never
     * a second key).
     *
     * @return array<string, mixed>
     */
    private function envelope(\Predis\Client $client, RedisStorage $storage, string $nonce): array
    {
        $raw = $client->get($this->storagePrefix($storage).$nonce);
        self::assertIsString($raw, 'the record must still be stored');

        $data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($data);

        return $data;
    }

    /** @return array{0: RedisStorage, 1: ChallengeRecord, 2: string} */
    private function issueAndSolveConsumed(\Predis\Client $client, string $identity): array
    {
        $storage = new RedisStorage($client, 'claim-test-'.bin2hex(random_bytes(4)).'-');
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
        $storage->consumeWithOperationIdentity($challenge->nonce, $identity);

        return [$storage, $record, $token];
    }

    public function testClaimReleaseAndCommitLifecycleOnRealRedis(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        [$storage, $prefix] = $this->makeStorage($client);
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $storage->consume($challenge->nonce);

        $owner = $storage->claimResumeDerivation($challenge->nonce);
        self::assertIsString($owner, 'a consumed, resultless record is claimable');

        // The claim is embedded in the record envelope with a bounded
        // expiry (epoch seconds, server clock).
        $data = $this->envelope($client, $storage, $challenge->nonce);
        self::assertSame($owner, $data['resume_owner'] ?? null, 'the claim owner is embedded in the record envelope');
        self::assertGreaterThan(time(), $data['resume_until'] ?? 0, 'the claim must carry a live expiry');
        self::assertLessThanOrEqual(time() + 60, $data['resume_until'] ?? 0, 'the claim expiry must be the 60s lease');

        self::assertNull($storage->claimResumeDerivation($challenge->nonce), 'a second claim while the first is held must be refused');
        self::assertFalse($storage->releaseResumeDerivation($challenge->nonce, 'not-the-owner'), 'a stale owner can never release');
        $data = $this->envelope($client, $storage, $challenge->nonce);
        self::assertSame($owner, $data['resume_owner'] ?? null, 'the refused release leaves the claim with its true owner');
        self::assertTrue($storage->releaseResumeDerivation($challenge->nonce, $owner), 'the true owner releases');
        $data = $this->envelope($client, $storage, $challenge->nonce);
        self::assertArrayNotHasKey('resume_owner', $data, 'the release cleared the claim from the envelope');
        self::assertArrayNotHasKey('resume_until', $data, 'the release cleared the claim expiry from the envelope');

        // Commit through the claim: the result lands and the claim is
        // cleared in the same Lua script run.
        $owner = $storage->claimResumeDerivation($challenge->nonce);
        self::assertIsString($owner);
        self::assertFalse($storage->commitResultResume($challenge->nonce, true, 'txn-1', 'not-the-owner'), 'a stale owner can never commit');
        $data = $this->envelope($client, $storage, $challenge->nonce);
        self::assertNull($data['consumed_result'], 'the refused commit writes nothing');
        self::assertSame($owner, $data['resume_owner'] ?? null, 'the true owner still holds the claim after the refused commit');
        self::assertTrue($storage->commitResultResume($challenge->nonce, true, 'txn-1', $owner), 'the true owner commits through the claim');
        $data = $this->envelope($client, $storage, $challenge->nonce);
        self::assertArrayNotHasKey('resume_owner', $data, 'the successful commit cleared the claim in the same transition');
        self::assertArrayNotHasKey('resume_until', $data, 'the successful commit cleared the claim expiry in the same transition');
        self::assertNull($storage->claimResumeDerivation($challenge->nonce), 'a committed record is no longer claimable');
        $after = $storage->consumedState($challenge->nonce);
        self::assertNotNull($after?->consumedResult);
        self::assertTrue($after->consumedResult->valid);
        self::assertSame('txn-1', $after->consumedResult->binding);
    }

    public function testClaimExpiryAllowsReclaimOnRealRedis(): void
    {
        // The bounded lease: a claim whose resume_until has passed is
        // dead and re-claimable — a crashed recovery leaves only the
        // short lease, never a poison marker. The 1-second lease is
        // claimed, the clock moves past it, and the same nonce is
        // claimable again without any release.
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        [$storage, $prefix] = $this->makeStorage($client);
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $storage->consume($challenge->nonce);

        $first = $storage->claimResumeDerivation($challenge->nonce, 1);
        self::assertIsString($first, 'the 1-second lease is claimable');
        self::assertNull($storage->claimResumeDerivation($challenge->nonce), 'the live lease is refused');
        $data = $this->envelope($client, $storage, $challenge->nonce);
        self::assertLessThanOrEqual(time() + 1, $data['resume_until'] ?? 0, 'the lease expiry must be now + 1s');

        // No release (the crashed-recovery path); the lease expires.
        sleep(2);
        $reclaimed = $storage->claimResumeDerivation($challenge->nonce);
        self::assertIsString($reclaimed, 'an expired claim is re-claimable without any release');
        self::assertNotSame($first, $reclaimed, 'the re-claim mints a fresh owner token');
        $data = $this->envelope($client, $storage, $challenge->nonce);
        self::assertSame($reclaimed, $data['resume_owner'] ?? null, 'the re-claim replaced the expired owner');
        $storage->releaseResumeDerivation($challenge->nonce, $reclaimed);
    }

    public function testClaimIsRefusedForNonResultlessRecordsOnRealRedis(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        [$storage, $prefix] = $this->makeStorage($client);

        self::assertNull($storage->claimResumeDerivation('claim-nonce'), 'a missing record is not claimable');

        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $nonce = $challenge->nonce;
        self::assertNull($storage->claimResumeDerivation($nonce), 'a pending record is not claimable');

        $storage->consume($nonce);
        self::assertTrue($storage->commitResult($nonce, true, null));
        self::assertNull($storage->claimResumeDerivation($nonce), 'a committed record is not claimable');

        $challenge2 = $issuer->issue('login', '198.51.100.7');
        $storage->cancel($challenge2->nonce);
        self::assertNull($storage->claimResumeDerivation($challenge2->nonce), 'a cancelled record is not claimable');

        $data = $this->envelope($client, $storage, $nonce);
        self::assertArrayNotHasKey('resume_owner', $data, 'a refused claim on a committed record may not leave a claim behind');
        $data2 = $this->envelope($client, $storage, $challenge2->nonce);
        self::assertArrayNotHasKey('resume_owner', $data2, 'a refused claim on a cancelled record may not leave a claim behind');
    }

    public function testTheVerifierResumeClaimsAndCommitsOnRealRedis(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $identity = 'op-'.hash('sha256', 'backend|uuid|response');
        [$storage, $record, $token] = $this->issueAndSolveConsumed($client, $identity);
        $verifier = new Verifier($storage, now: static fn (): int => self::ISSUED_AT);

        $outcome = $verifier->resumeConsumedOperation($token, self::SECRET, $identity, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), sprintf('the identity-proven resume must derive and commit, got %s', $outcome->code()));
        self::assertNotNull($storage->consumedState($record->nonce)?->consumedResult, 'the resume committed the deterministic outcome');
        $data = $this->envelope($client, $storage, $record->nonce);
        self::assertArrayNotHasKey('resume_owner', $data, 'the commit cleared the claim in the same transition');
        self::assertArrayNotHasKey('resume_until', $data, 'the commit cleared the claim expiry in the same transition');

        // The committed-result recovery stays the fast path.
        $replay = $verifier->resumeConsumedOperation($token, self::SECRET, $identity, 'login', '198.51.100.7');
        self::assertTrue($replay->isOk(), 'the retry resolves the committed outcome');
        self::assertTrue($replay->fromStoredResult);
    }

    public function testTheVerifierLoserAnswersIndeterminateWhileTheClaimIsHeldOnRealRedis(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $identity = 'op-'.hash('sha256', 'loser');
        [$storage, $record, $token] = $this->issueAndSolveConsumed($client, $identity);

        $winner = $storage->claimResumeDerivation($record->nonce);
        self::assertIsString($winner);

        $outcome = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT))->resumeConsumedOperation($token, self::SECRET, $identity, 'login', '198.51.100.7');
        self::assertSame(VerifyError::ConsumeIndeterminate, $outcome->error, 'the loser must not derive while the claim is held');
        self::assertNull($storage->consumedState($record->nonce)?->consumedResult, 'the loser must not commit anything');

        $storage->releaseResumeDerivation($record->nonce, $winner);
        $outcome = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT))->resumeConsumedOperation($token, self::SECRET, $identity, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), 'after the release the retry derives and commits');
    }

    public function testClaimRefusedLoserResolvesTheWinnersCommittedOutcomeOnRealRedis(): void
    {
        // The winner commits through its claim while the loser is
        // mid-resume: the loser's claim attempt is refused, the reread
        // sees the winner's committed result, and the loser resolves it
        // behind the fence — never a second derivation. This is the
        // Verifier-side of the commit-returns-2 contract: the stale
        // path cannot commit, and the loser resolves via reread.
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $identity = 'op-'.hash('sha256', 'loser-committed');
        [$storage, $record, $token] = $this->issueAndSolveConsumed($client, $identity);

        $winner = $storage->claimResumeDerivation($record->nonce);
        self::assertIsString($winner);
        self::assertTrue($storage->commitResultResume($record->nonce, true, $record->requestBinding, $winner), 'the winner commits while holding the claim');

        $outcome = (new Verifier($storage, now: static fn (): int => self::ISSUED_AT))->resumeConsumedOperation($token, self::SECRET, $identity, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), sprintf('the loser must resolve the winner\'s committed outcome, got %s', $outcome->code()));
        self::assertTrue($outcome->fromStoredResult, 'the resolved outcome is the stored result, not a derivation');
        self::assertSame($record->nonce, $outcome->nonce());
    }

    public function testAnEarlyVerifierReturnReleasesTheClaimOnRealRedis(): void
    {
        // The claim is released on an early return after acquisition: a
        // resume that fails the post-derive revalidation (the policy
        // epoch rotates mid-derivation, driven by the admission gate)
        // must release its claim, so a fresh claim succeeds immediately.
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $storage = new RedisStorage($client, 'claim-test-'.bin2hex(random_bytes(4)).'-');
        $issuer = new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Argon2id,
            mKib: 64,
            t: 3,
            p: 1,
            argon2TargetBits: 4,
            ttlSecs: 120,
            minDurationMs: 0,
            policyVersion: 2,
        ), $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = sodium_crypto_pwhash(32, $challenge->prefix.$counter, $saltBytes, 3, 64 * 1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
        $identity = 'op-'.hash('sha256', 'claim-release');
        $storage->consumeWithOperationIdentity($challenge->nonce, $identity);

        $gate = new class() implements VerificationAdmissionGate {
            public ?Verifier $verifier = null;

            public function acquire(): ?string
            {
                $this->verifier?->rotateDeploymentExpectations(policyVersion: 3, region: null, issuer: null);

                return 'lease-rotate';
            }

            public function release(string $lease): void
            {
            }
        };
        $verifier = new Verifier($storage, $gate, now: static fn (): int => self::ISSUED_AT, expectedPolicyVersion: 2);
        $gate->verifier = $verifier;

        $outcome = $verifier->resumeConsumedOperation($token, self::SECRET, $identity, 'login', '198.51.100.7');
        self::assertSame(VerifyError::WrongPolicyVersion, $outcome->error, 'the rotation must fail the post-derive re-check');
        self::assertNull($storage->consumedState($challenge->nonce)?->consumedResult, 'the rotated resume must NOT commit anything');

        // The early return released the claim: a fresh claim succeeds
        // immediately, nothing blocks the next retry.
        $reclaimed = $storage->claimResumeDerivation($challenge->nonce);
        self::assertIsString($reclaimed, 'a fresh claim must succeed right after the released early return');
        $storage->releaseResumeDerivation($challenge->nonce, $reclaimed);
    }
}
