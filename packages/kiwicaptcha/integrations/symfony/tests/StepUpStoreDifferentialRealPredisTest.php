<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandSendLease;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandSendSettlement;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\StepUpStoreDifferentialHarness;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The randomized differential lane of the two step-up stores over a
 * real Predis client against a live redis-server (KC_REDIS_URL), the
 * exact deployment reply surface. The property code is the shared
 * harness fixture, identical to the emulated lane
 * (StepUpStoreDifferentialTest); only the store wiring and the clock
 * strategy differ. The harness clock resynchronizes to the wall clock
 * before every action, and the randomized time-dependent parameters
 * stay far from their boundaries, so no decision can flip between the
 * two calls of one action.
 *
 * The store-owned time boundaries whose acceptance needs a window to
 * pass (the send-lease spacing, the crashed-claim recovery, the
 * finalization claim retake) get their own dedicated sequences here.
 * Each walks the boundary with one real sleep of two seconds, runs the
 * same steps on both stores, and asserts the answers agree, whichever
 * side of the boundary the shared wall clock lands on.
 */
final class StepUpStoreDifferentialRealPredisTest extends TestCase
{
    private const PREFIX = '{kiwi:diffreal}:stepup:';

    private \Predis\Client $client;

    private ArrayStepUpChallengeStore $arrayStore;

    private RedisStepUpChallengeStore $redisStore;

    private \stdClass $clock;

    protected function setUp(): void
    {
        $url = getenv('KC_REDIS_URL');
        if ($url === false || $url === '') {
            self::markTestSkipped('KC_REDIS_URL not set — real-Predis differential lane skipped');
        }
        if (!class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $this->client = new \Predis\Client($url, ['timeout' => 2.0]);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis unreachable: '.$e->getMessage());
        }
        $this->clock = new \stdClass();
        $this->clock->now = time();
        $this->arrayStore = new ArrayStepUpChallengeStore(fn (): int => $this->clock->now);
        $this->redisStore = new RedisStepUpChallengeStore($this->client, self::PREFIX);
        $this->sweep();
    }

    protected function tearDown(): void
    {
        // The leg owns only its hash-tagged family; the sweep never
        // reaches another suite's keys on the shared instance.
        if (!isset($this->client)) {
            return;
        }
        try {
            $this->sweep();
        } catch (\Throwable) {
            // a dead instance must not fail the shutdown path
        }
    }

    private function sweep(): void
    {
        $keys = $this->client->keys(self::PREFIX.'*');
        if ($keys !== []) {
            $this->client->del(...$keys);
        }
    }

    public static function providerSeeds(): \Generator
    {
        foreach ([101, 102, 103] as $seed) {
            yield 'seed '.$seed => [$seed];
        }
    }

    /**
     * The randomized property on the real server: the same seeded
     * legal sequence answers identically on both stores, after every
     * action, with the Redis clock owning every store-side timing
     * decision.
     */
    #[DataProvider('providerSeeds')]
    public function testBothStoresAnswerTheSameObservableSequenceOnTheRealServer(int $seed): void
    {
        $harness = new StepUpStoreDifferentialHarness(
            $this->arrayStore,
            $this->redisStore,
            $this->client,
            $this->clock,
            StepUpStoreDifferentialHarness::LANE_REAL,
            self::PREFIX,
            static function (bool $condition, string $message): void {
                self::assertTrue($condition, $message);
            },
        );

        $harness->runSequence($seed, 40);
    }

    /**
     * The send-lease boundary walk on the shared wall clock: the
     * spacing refusal holds while the window runs and crosses after
     * the sleep. A crashed claim is recovered without a second credit
     * and its holder's late settlement turns worthless.
     */
    public function testTheSendLeaseSpacingAndRecoveryAgreeOnTheRealClock(): void
    {
        $first = $this->mintBoth('difreal00sendparent001');
        $leaseA = $this->arrayStore->claimDemandSendLease($first, 2, 60);
        $leaseR = $this->redisStore->claimDemandSendLease($first, 2, 60);
        self::assertNotNull($leaseA, 'the array store funds the initial delivery');
        self::assertNotNull($leaseR, 'the Redis store funds the initial delivery');
        self::assertFalse($leaseA->recovered, 'an initial claim recovers nothing on the array store');
        self::assertFalse($leaseR->recovered, 'an initial claim recovers nothing on the Redis store');
        self::assertSame($leaseA->demand->sends, $leaseR->demand->sends, 'the initial credit agrees');

        // A live lease refuses the second claim on both stores.
        $this->sync();
        self::assertNull($this->arrayStore->claimDemandSendLease($first, 2, 60), 'the array store refuses a claim inside a live lease');
        self::assertNull($this->redisStore->claimDemandSendLease($first, 2, 60), 'the Redis store refuses a claim inside a live lease');

        // The delivery commits; the spacing window of two seconds holds
        // right now and crosses after the sleep, on both stores alike.
        $settledA = $this->arrayStore->settleDemandSendLease($this->settlement($first, $leaseA, true));
        $settledR = $this->redisStore->settleDemandSendLease($this->settlement($first, $leaseR, true));
        self::assertTrue($settledA, 'the array store accepts the settlement of its own claim');
        self::assertTrue($settledR, 'the Redis store accepts the settlement of its own claim');
        $this->sync();
        self::assertNull($this->arrayStore->claimDemandSendLease($first, 2, 60), 'the array store enforces the resend spacing');
        self::assertNull($this->redisStore->claimDemandSendLease($first, 2, 60), 'the Redis store enforces the resend spacing on the server clock');
        sleep(2);
        $this->sync();
        $resendA = $this->arrayStore->claimDemandSendLease($first, 2, 60);
        $resendR = $this->redisStore->claimDemandSendLease($first, 2, 60);
        self::assertNotNull($resendA, 'the array store opens the resend after the spacing window');
        self::assertNotNull($resendR, 'the Redis store opens the resend after the spacing window');
        self::assertSame(2, $resendA->demand->sends, 'the resend charges the second credit on the array store');
        self::assertSame($resendA->demand->sends, $resendR->demand->sends, 'the resend credit agrees across the stores');

        // A crashed claim: the holder never settles, the window of two
        // seconds passes, the slot is re-leased without a second
        // credit, and the crashed stamp settles nothing.
        $second = $this->mintBoth('difreal00sendparent002');
        $crashA = $this->arrayStore->claimDemandSendLease($second, 60, 2);
        $crashR = $this->redisStore->claimDemandSendLease($second, 60, 2);
        self::assertNotNull($crashA, 'the array store funds the crashed claim');
        self::assertNotNull($crashR, 'the Redis store funds the crashed claim');
        sleep(2);
        $this->sync();
        $recovA = $this->arrayStore->claimDemandSendLease($second, 60, 2);
        $recovR = $this->redisStore->claimDemandSendLease($second, 60, 2);
        self::assertNotNull($recovA, 'the array store recovers the expired lease');
        self::assertNotNull($recovR, 'the Redis store recovers the expired lease');
        self::assertTrue($recovA->recovered, 'the array store marks the claim as a recovery');
        self::assertTrue($recovR->recovered, 'the Redis store marks the claim as a recovery');
        self::assertSame($recovA->demand->sends, $recovR->demand->sends, 'the recovered slot pays no second credit on either store');
        self::assertFalse($this->arrayStore->settleDemandSendLease($this->settlement($second, $crashA, false)), 'the crashed array stamp settles nothing');
        self::assertFalse($this->redisStore->settleDemandSendLease($this->settlement($second, $crashR, false)), 'the crashed Redis stamp settles nothing');
    }

    /**
     * The finalization claim boundary on the shared wall clock: the
     * claim window of one second holds immediately after the claim and
     * passes after the sleep, so the retake lands on both stores
     * alike.
     */
    public function testTheFinalizationClaimRetakeAgreesOnTheRealClock(): void
    {
        $id = $this->mintBoth('difreal00claimparent01');
        self::assertNotNull($this->arrayStore->completeDemand($id, $this->clock->now, 600));
        self::assertNotNull($this->redisStore->completeDemand($id, $this->clock->now, 600));
        $claimA = $this->arrayStore->claimDemandFinalization($id, $this->clock->now, 1);
        $claimR = $this->redisStore->claimDemandFinalization($id, $this->clock->now, 1);
        self::assertNotNull($claimA, 'the array store grants the fresh finalization claim');
        self::assertNotNull($claimR, 'the Redis store grants the fresh finalization claim');

        // Inside the window the retake refuses on both stores.
        $this->sync();
        self::assertNull($this->arrayStore->claimDemandFinalization($id, $this->clock->now, 1), 'the array store refuses the retake inside the claim window');
        self::assertNull($this->redisStore->claimDemandFinalization($id, $this->clock->now, 1), 'the Redis store refuses the retake inside the claim window');

        sleep(2);
        $this->sync();
        $retakeA = $this->arrayStore->claimDemandFinalization($id, $this->clock->now, 1);
        $retakeR = $this->redisStore->claimDemandFinalization($id, $this->clock->now, 1);
        self::assertNotNull($retakeA, 'the array store retakes the stale claim after the window');
        self::assertNotNull($retakeR, 'the Redis store retakes the stale claim after the window');
        self::assertSame(StepUpDemandState::Finalizing, $retakeA->state, 'the retaken record stays finalizing on the array store');
        self::assertSame(StepUpDemandState::Finalizing, $retakeR->state, 'the retaken record stays finalizing on the Redis store');
        self::assertNull($retakeA->supersededByDemandId, 'the array store marked no supersession on the retaken demand');
        self::assertNull($retakeR->supersededByDemandId, 'the Redis store marked no supersession on the retaken demand');
    }

    /**
     * Parity pin: the lockout deadline unit. Both stores arm the
     * deadline in epoch seconds, the unit the interface contract
     * names, and both answer the same value past an arm. The one
     * consumer (StepUpLockoutGuard::retryAfterSecs) subtracts the
     * clock second from the deadline directly, so a millisecond value
     * on either lane would overstate the wait a thousandfold.
     */
    public function testTheLockoutDeadlineAnswersEpochSecondsOnBothStores(): void
    {
        $dimension = 'principal';
        $pseudonym = 'aabbccddeeff00112233445566778899';
        $this->sync();

        $this->arrayStore->armLockout($dimension, $pseudonym, $this->clock->now, 600);
        $this->redisStore->armLockout($dimension, $pseudonym, $this->clock->now, 600);

        $a = $this->arrayStore->lockoutUntil($dimension, $pseudonym, $this->clock->now);
        $r = $this->redisStore->lockoutUntil($dimension, $pseudonym, $this->clock->now);
        self::assertSame($this->clock->now + 600, $a, 'the array store answers the epoch-second deadline the interface documents');
        self::assertSame($a, $r, 'the Redis store answers the same epoch-second deadline: the consumer subtracts the current second, so a millisecond value would overstate the wait a thousandfold');
    }

    private function mintBoth(string $id): string
    {
        $this->sync();
        $demand = StepUpDemand::mint($id, 'login', null, null, 'decision-1', $this->clock->now, 600);
        $a = $this->arrayStore->createDemand($demand, 600);
        $r = $this->redisStore->createDemand($demand, 600);
        self::assertSame($a, $r, 'the demand persists under the same id on both stores');

        return $id;
    }

    /** Resynchronize the harness clock with the shared wall clock. */
    private function sync(): void
    {
        $this->clock->now = max($this->clock->now, time());
    }

    private function settlement(string $id, StepUpDemandSendLease $lease, bool $delivered): StepUpDemandSendSettlement
    {
        return new StepUpDemandSendSettlement($id, $lease->leaseUntilMs, $lease->claimAt, $lease->priorSends, $lease->priorLastSentAt, $delivered);
    }
}
