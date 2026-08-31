<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Tests\Fixtures\RealRedisTestEnv;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * Region clock skew against one shared Redis authority.
 *
 * Two verifier instances, each with its own clock closure, operate on
 * the same records in the same Redis. The resume-claim lease expiry is
 * stamped from Redis TIME inside the Lua script, so a region with a
 * skew sees the same lease liveness as every other region. The
 * minimum-duration floor uses the local receipt instant while the
 * floor value stays the record's signed one. The expiry verdict is
 * authoritative per region, and the committed shared state dominates
 * every later retry. The signing-key ring resolves by kid, so a skew
 * region still reads the historical secret during the rotation grace.
 *
 * Runs when `KC_REDIS_URL` or `TEST_REDIS_URL` is set; skips otherwise,
 * like every other real-Redis suite. The dedicated CI lane publishes
 * the URLs and the `KIWI_REQUIRE_REAL_REDIS_TESTS` flag, which turns a
 * missing Redis into a hard failure instead of a skip.
 */
final class RegionClockSkewSharedRedisAuthorityRealRedisTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const SECRET_2 = 'fedcba9876543210fedcba9876543210';

    private const SECRET_3 = 'a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8';

    private const ISSUED_AT = 1_800_000_000;

    /** @return \Predis\Client|null null when Redis is unreachable */
    private function redisOrSkip(): ?\Predis\Client
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $url = RealRedisTestEnv::requireRedis('the region clock skew suite');
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the region clock skew suite runs in the dedicated real-Redis CI lane');
        }
        try {
            $probe = new \Predis\Client($url, ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
            $probe->ping();

            return $probe;
        } catch (\Throwable) {
            RealRedisTestEnv::failWhenRequired('no Redis is reachable at the configured KC_REDIS_URL/TEST_REDIS_URL', 'the region clock skew suite');
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }
    }

    /**
     * The storage prefix, so the test can read the stored envelope
     * bytes (the resume claim lives in the record envelope).
     */
    private function storagePrefix(RedisStorage $storage): string
    {
        $property = new \ReflectionProperty(RedisStorage::class, 'prefix');

        return (string) $property->getValue($storage);
    }

    /**
     * @return array{0: RedisStorage, 1: string} [storage, prefix]
     */
    private function makeStorage(\Predis\Client $client, string $tag): array
    {
        $storage = new RedisStorage($client, 'skew-'.$tag.'-'.bin2hex(random_bytes(4)).'-');

        return [$storage, $this->storagePrefix($storage)];
    }

    /**
     * @return array<string, mixed> the decoded envelope of the stored record
     */
    private function envelope(\Predis\Client $client, string $prefix, string $nonce): array
    {
        $raw = $client->get($prefix.$nonce);
        self::assertIsString($raw, 'the record must still be stored');
        $data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($data);

        return $data;
    }

    private function solve(string $prefix, string $salt, int $targetBits): int
    {
        $saltBytes = base64_decode($salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.$saltBytes, true);
            ++$counter;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);

        return $counter - 1;
    }

    private function tokenFor(\KiwiCaptcha\Challenge $challenge): string
    {
        $counter = $this->solve($challenge->prefix, $challenge->salt, $challenge->targetBits);

        return SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
    }

    /**
     * @return array{0: RedisStorage, 1: \KiwiCaptcha\ChallengeRecord, 2: string, 3: string}
     */
    private function issueAndSolve(\Predis\Client $client, string $tag, int $minDurationMs = 0, int $kid = 1, string $secret = self::SECRET): array
    {
        [$storage, $prefix] = $this->makeStorage($client, $tag);
        $issuer = new Issuer(
            new Config(secretKey: $secret, targetBits: 8, ttlSecs: 120, minDurationMs: $minDurationMs, kid: $kid),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', '198.51.100.7');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        return [$storage, $record, $this->tokenFor($challenge), $challenge->nonce];
    }

    public function testResumeClaimLeaseIsServerClockEvaluatedAcrossSkewedRegions(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        [$storage, $prefix] = $this->makeStorage($client, 'claim');
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage, now: static fn (): int => self::ISSUED_AT);
        $challenge = $issuer->issue('login', '198.51.100.7');
        $storage->consume($challenge->nonce);

        // Region A claims with a 2-second lease. The claim liveness is
        // decided inside the Lua script on Redis TIME alone.
        $ownerA = $storage->claimResumeDerivation($challenge->nonce, 2);
        self::assertIsString($ownerA, 'a consumed resultless record is claimable');

        // The expiry is stamped from the server clock: resume_until tracks
        // the Redis TIME command plus the TTL, not any region clock.
        $data = $this->envelope($client, $prefix, $challenge->nonce);
        $serverTime = $client->time();
        $serverSecs = (int) $serverTime[0];
        self::assertLessThanOrEqual($serverSecs + 3, (int) ($data['resume_until'] ?? 0), 'the lease expiry must be the server clock plus the TTL');
        self::assertGreaterThanOrEqual($serverSecs + 1, (int) ($data['resume_until'] ?? 0), 'the lease expiry must be the server clock plus the TTL');

        // Both region clocks sit far past the deadline: the pinned
        // issuance instant plus or minus five seconds is roughly a year
        // ahead of the server clock, while resume_until is only seconds
        // past it. A local-clock lease would already be dead for both
        // regions. The shared authority still sees it as live, so the
        // second region is refused exactly like the first.
        self::assertLessThan(self::ISSUED_AT - 5, (int) ($data['resume_until'] ?? 0), 'both region clocks are past the lease deadline');
        self::assertNull($storage->claimResumeDerivation($challenge->nonce, 2), 'the live lease is refused for the other region too');

        // Once Redis TIME passes the deadline the lease dies for every
        // region at the same moment; the behind region re-claims.
        sleep(3);
        $ownerB = $storage->claimResumeDerivation($challenge->nonce, 2);
        self::assertIsString($ownerB, 'an expired claim is re-claimable');
        self::assertNotSame($ownerA, $ownerB, 'the re-claim mints a fresh owner token');
        $storage->releaseResumeDerivation($challenge->nonce, $ownerB);
    }

    public function testResumePathCompletesIdenticallyForBothRegionClocks(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        $identity = 'op-'.hash('sha256', 'region-skew-resume');
        [$storage, $record, $token] = $this->issueAndSolve($client, 'resume');
        $storage->consumeWithOperationIdentity($record->nonce, $identity);

        // Region A runs five seconds ahead of the shared authority; its
        // clock is still inside the signed lifetime, so the resumed
        // derivation commits.
        $ahead = new Verifier($storage, now: static fn (): int => self::ISSUED_AT + 5);
        $outcome = $ahead->resumeConsumedOperation($token, self::SECRET, $identity, 'login', '198.51.100.7');
        self::assertTrue($outcome->isOk(), sprintf('the identity-proven resume must derive and commit, got %s', $outcome->code()));

        // Region B runs five seconds behind. The shared committed state
        // answers identically: the retry replays the stored outcome.
        $behind = new Verifier($storage, now: static fn (): int => self::ISSUED_AT - 5);
        $replay = $behind->resumeConsumedOperation($token, self::SECRET, $identity, 'login', '198.51.100.7');
        self::assertTrue($replay->isOk(), 'the behind region resolves the committed outcome');
        self::assertTrue($replay->fromStoredResult, 'the behind region replays the stored result');
    }

    public function testMinimumDurationFloorIsReceiptAnchoredAndIdenticalAcrossRegions(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);

        // The receipt preceding issuance within the skew tolerance is
        // unmeasurable: the floor is skipped and the duration is null.
        // The behind clock cannot shorten the floor to a measured value.
        [$storageA, $recordA, $tokenA] = $this->issueAndSolve($client, 'floor-1', 3000);
        $aheadA = new Verifier($storageA, now: static fn (): int => self::ISSUED_AT + 5);
        $unmeasurable = $aheadA->verify($tokenA, self::SECRET, 'login', '198.51.100.7', nowNs: $recordA->issuedAtNs - 2_000_000);
        self::assertTrue($unmeasurable->isOk(), 'a receipt just before issuance falls inside the skew tolerance');
        self::assertNull($unmeasurable->solveDurationMs(), 'an unmeasurable elapsed time yields a null duration');

        // A receipt preceding issuance beyond the skew bound is
        // physically impossible and fails closed as TooFast.
        [$storageB, $recordB, $tokenB] = $this->issueAndSolve($client, 'floor-2', 3000);
        $aheadB = new Verifier($storageB, now: static fn (): int => self::ISSUED_AT + 5);
        $impossible = $aheadB->verify($tokenB, self::SECRET, 'login', '198.51.100.7', nowNs: $recordB->issuedAtNs - 6_000_000);
        self::assertSame(VerifyError::TooFast, $impossible->error, 'a receipt more than the skew bound before issuance is TooFast');

        // At a measurable receipt the floor is the record's signed value,
        // identical for both regions. The client-reported duration never
        // shortens it.
        [$storageC, $recordC, $tokenC] = $this->issueAndSolve($client, 'floor-3', 3000);
        $aheadC = new Verifier($storageC, now: static fn (): int => self::ISSUED_AT + 5);
        $fastA = $aheadC->verify($tokenC, self::SECRET, 'login', '198.51.100.7', nowNs: $recordC->issuedAtNs + 1_000_000);
        self::assertSame(VerifyError::TooFast, $fastA->error, 'a sub-floor receipt is TooFast for the ahead region');
        [$storageD, $recordD, $tokenD] = $this->issueAndSolve($client, 'floor-4', 3000);
        $behindD = new Verifier($storageD, now: static fn (): int => self::ISSUED_AT - 5);
        $fastB = $behindD->verify($tokenD, self::SECRET, 'login', '198.51.100.7', nowNs: $recordD->issuedAtNs + 1_000_000);
        self::assertSame(VerifyError::TooFast, $fastB->error, 'a sub-floor receipt is TooFast for the behind region');

        // The receipt exactly at the floor passes, and the measured
        // duration is anchored at the record's signed issuance clock.
        [$storageE, $recordE, $tokenE] = $this->issueAndSolve($client, 'floor-5', 3000);
        $behindE = new Verifier($storageE, now: static fn (): int => self::ISSUED_AT - 5);
        $atFloor = $behindE->verify($tokenE, self::SECRET, 'login', '198.51.100.7', nowNs: $recordE->issuedAtNs + 3_000_000);
        self::assertTrue($atFloor->isOk(), 'a receipt at the floor clears it');
        self::assertSame(3000, $atFloor->solveDurationMs(), 'the duration is the receipt minus the signed issuance');

        // An ahead receipt cannot extend the floor: the floor value stays
        // the record's 3000ms and the verdict depends only on the receipt.
        [$storageF, $recordF, $tokenF] = $this->issueAndSolve($client, 'floor-6', 3000);
        $aheadF = new Verifier($storageF, now: static fn (): int => self::ISSUED_AT + 5);
        $aheadOk = $aheadF->verify($tokenF, self::SECRET, 'login', '198.51.100.7', nowNs: $recordF->issuedAtNs + 8_000_000);
        self::assertTrue($aheadOk->isOk(), 'a receipt well past the floor clears it');
        self::assertSame(8000, $aheadOk->solveDurationMs(), 'the measured span follows the receipt, the floor does not');
        self::assertSame(3000, $recordF->minDurationMs, 'the floor is the signed record value');
    }

    public function testExpiryVerdictIsPerRegionAuthoritativeAndSharedStateDominates(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);
        [$storage, $prefix] = $this->makeStorage($client, 'expiry');
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage, now: static fn (): int => self::ISSUED_AT);

        // The record expires at the pinned issuance instant plus 120.
        // The ahead region clock sits past that deadline; the behind
        // region clock sits before it.
        $ahead = new Verifier($storage, now: static fn (): int => self::ISSUED_AT + 125);
        $behind = new Verifier($storage, now: static fn (): int => self::ISSUED_AT + 115);

        // The behind region verifies the near-expiry record first. Its own
        // clock governs its own verification, so the grant lands.
        $challenge = $issuer->issue('login', '198.51.100.7');
        $token = $this->tokenFor($challenge);
        $granted = $behind->verify($token, self::SECRET, 'login', '198.51.100.7', operationIdentity: 'op-grant');
        self::assertTrue($granted->isOk(), 'the behind region clock is inside the lifetime, so it verifies');

        // The ahead region retries the same record. Its expiry opinion is
        // irrelevant: the committed shared state answers with the stored
        // grant, never a fresh expiry verdict and never a second live
        // grant for a different identity.
        $retry = $ahead->verify($token, self::SECRET, 'login', '198.51.100.7', operationIdentity: 'op-grant');
        self::assertTrue($retry->isOk(), 'the shared committed state dominates the ahead expiry opinion');
        self::assertTrue($retry->fromStoredResult, 'the retry replays the stored grant');
        $otherIdentity = $ahead->verify($token, self::SECRET, 'login', '198.51.100.7', operationIdentity: 'op-other');
        self::assertSame(VerifyError::AlreadyConsumed, $otherIdentity->error, 'a different identity never gets a second grant');

        // A second record verified by the ahead region first fails closed
        // on its own clock: Expired, and the shared authority erases the
        // pending record. The behind region then sees the authoritative
        // absence.
        $challenge2 = $issuer->issue('login', '198.51.100.7');
        $token2 = $this->tokenFor($challenge2);
        $denied = $ahead->verify($token2, self::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::Expired, $denied->error, 'the ahead region expires the record on its own clock');
        self::assertNull($storage->find($challenge2->nonce), 'the expired pending record is erased by the shared authority');
        $afterErase = $behind->verify($token2, self::SECRET, 'login', '198.51.100.7');
        self::assertSame(VerifyError::RecordNotFound, $afterErase->error, 'the behind region sees the authoritative absence');
    }

    public function testKidRotationGraceResolvesByKidNotByClock(): void
    {
        $client = $this->redisOrSkip();
        self::assertNotNull($client);

        // The rotation moves the newest kid to 3; the ring keeps the
        // historical secrets during the grace window.
        $ring = [1 => self::SECRET, 2 => self::SECRET_2, 3 => self::SECRET_3];
        [$storageOldA, , $oldTokenA] = $this->issueAndSolve($client, 'kid-1a', 0, 1, self::SECRET);
        [$storageOldB, , $oldTokenB] = $this->issueAndSolve($client, 'kid-1b', 0, 1, self::SECRET);
        [$storageNew, , $newToken] = $this->issueAndSolve($client, 'kid-2', 0, 2, self::SECRET_2);

        $ahead = new Verifier($storageOldA, now: static fn (): int => self::ISSUED_AT + 5, secretsByKid: $ring);
        $behind = new Verifier($storageOldB, now: static fn (): int => self::ISSUED_AT - 5, secretsByKid: $ring);
        $aheadNew = new Verifier($storageNew, now: static fn (): int => self::ISSUED_AT + 5, secretsByKid: $ring);
        self::assertTrue($ahead->verify($oldTokenA, self::SECRET, 'login', '198.51.100.7')->isOk(), 'the ahead region resolves the prior kid via the historical secret');
        self::assertTrue($behind->verify($oldTokenB, self::SECRET, 'login', '198.51.100.7')->isOk(), 'the behind region resolves the prior kid via the historical secret');
        self::assertTrue($aheadNew->verify($newToken, self::SECRET, 'login', '198.51.100.7')->isOk(), 'the current kid resolves under skew too');

        // The grace window closes: the ring drops kid 1. The kid-selected
        // secret is the only selector, so the clock cannot rescue the
        // old-kid record on either region.
        $dropped = [2 => self::SECRET_2, 3 => self::SECRET_3];
        [$storageOldC, , $oldTokenC] = $this->issueAndSolve($client, 'kid-1c', 0, 1, self::SECRET);
        [$storageOldD, , $oldTokenD] = $this->issueAndSolve($client, 'kid-1d', 0, 1, self::SECRET);
        $aheadDropped = new Verifier($storageOldC, now: static fn (): int => self::ISSUED_AT + 5, secretsByKid: $dropped);
        $behindDropped = new Verifier($storageOldD, now: static fn (): int => self::ISSUED_AT - 5, secretsByKid: $dropped);
        self::assertSame(VerifyError::UnknownKid, $aheadDropped->verify($oldTokenC, self::SECRET, 'login', '198.51.100.7')->error, 'a dropped kid fails UnknownKid after the grace window');
        self::assertSame(VerifyError::UnknownKid, $behindDropped->verify($oldTokenD, self::SECRET, 'login', '198.51.100.7')->error, 'the behind clock cannot rescue the dropped kid');

        // The rollback/forward guard: a record signed by a kid beyond the
        // newest configured kid fails UnknownKid under skew as well.
        [$storageFuture, , $futureToken] = $this->issueAndSolve($client, 'kid-3', 0, 3, self::SECRET_3);
        $olderRing = [1 => self::SECRET, 2 => self::SECRET_2];
        $aheadOlder = new Verifier($storageFuture, now: static fn (): int => self::ISSUED_AT + 5, secretsByKid: $olderRing);
        self::assertSame(VerifyError::UnknownKid, $aheadOlder->verify($futureToken, self::SECRET, 'login', '198.51.100.7')->error, 'a future kid fails the rollback guard under skew');
    }
}
