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
     * The storage prefix, so the test can inspect the claim key it
     * created (the claim key is `{prefix}resume-claim:<nonce>`).
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

    private function claimKey(RedisStorage $storage, string $nonce): string
    {
        return $this->storagePrefix($storage).'resume-claim:'.$nonce;
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
        $claimKey = $this->claimKey($storage, $challenge->nonce);

        $owner = $storage->claimResumeDerivation($challenge->nonce);
        self::assertIsString($owner, 'a consumed, resultless record is claimable');

        $ttl = $client->ttl($claimKey);
        self::assertGreaterThan(0, $ttl, 'the claim must carry a live TTL');
        self::assertLessThanOrEqual(60, $ttl, 'the claim TTL must be the 60s lease');

        self::assertNull($storage->claimResumeDerivation($challenge->nonce), 'a second claim while the first is held must be refused');
        self::assertFalse($storage->releaseResumeDerivation($challenge->nonce, 'not-the-owner'), 'a stale owner can never release');
        self::assertSame($owner, $client->get($claimKey), 'the refused release leaves the claim with its true owner');
        self::assertTrue($storage->releaseResumeDerivation($challenge->nonce, $owner), 'the true owner releases');
        self::assertNull($client->get($claimKey), 'the release deleted the claim key');

        // Commit through the claim: the result lands and the claim is
        // cleared in the same Lua script run.
        $owner = $storage->claimResumeDerivation($challenge->nonce);
        self::assertIsString($owner);
        self::assertFalse($storage->commitResultResume($challenge->nonce, true, 'txn-1', 'not-the-owner'), 'a stale owner can never commit');
        self::assertNull($storage->consumedState($challenge->nonce)?->consumedResult, 'the refused commit writes nothing');
        self::assertSame($owner, $client->get($claimKey), 'the true owner still holds the claim after the refused commit');
        self::assertTrue($storage->commitResultResume($challenge->nonce, true, 'txn-1', $owner), 'the true owner commits through the claim');
        self::assertNull($client->get($claimKey), 'the successful commit cleared the claim in the same transition');
        self::assertNull($storage->claimResumeDerivation($challenge->nonce), 'a committed record is no longer claimable');
        $after = $storage->consumedState($challenge->nonce);
        self::assertNotNull($after?->consumedResult);
        self::assertTrue($after->consumedResult->valid);
        self::assertSame('txn-1', $after->consumedResult->binding);
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

        self::assertNull($client->get($this->claimKey($storage, $nonce)), 'a refused claim on a committed record may not leave a claim key behind');
        self::assertNull($client->get($this->claimKey($storage, $challenge2->nonce)), 'a refused claim on a cancelled record may not leave a claim key behind');
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
        self::assertNull($client->get($this->storagePrefix($storage).'resume-claim:'.$record->nonce), 'the commit cleared the claim in the same transition');

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
