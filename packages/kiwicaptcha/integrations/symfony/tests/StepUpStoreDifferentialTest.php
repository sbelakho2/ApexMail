<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\StepUpStoreDifferentialHarness;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The randomized differential lane of the two step-up stores over the
 * emulated Predis client. One action generator drives the array store
 * and the Redis store through the same seeded legal sequence, and
 * every observable answer must agree after every action. The property
 * code lives in the shared harness fixture, so the real-Predis lane
 * (StepUpStoreDifferentialRealPredisTest) runs the identical engine.
 *
 * The file also pins two of the documented divergences the sweep
 * normalizes away, loudly, so they can never silently widen:
 *
 *  - the forged escalation child. The array store refuses a child
 *    whose parent link names a different demand
 *    (ArrayStepUpChallengeStore.php line 393). The Redis escalation
 *    script checks the inherited expiry only
 *    (RedisStepUpChallengeStore.php line 382) and accepts such a
 *    child, repointing the family index at it. The behavior is per
 *    the script's documented contract: the expiry check is the
 *    documented inheritance gate. The path is unreachable through
 *    spawnChild, so the pin documents the gap instead of a src
 *    rewrite.
 *  - the superseded parent state field. The array store moves the
 *    parent state to superseded on supersede, the Redis script stamps
 *    superseded_by and keeps the pre-supersede state. Each store's
 *    own suite pins its shape as intended; the shared harness compares
 *    the superseded-ness both mean, and this file pins the observable
 *    difference itself.
 *
 * The third divergence is the lockout deadline unit: epoch seconds on
 * the array store, milliseconds on the Redis store, against a
 * documented epoch-second contract. It is pinned on the real-Predis
 * lane. The emulated client never interprets the lock-arm script, so
 * the unit difference is only observable against the live server.
 */
final class StepUpStoreDifferentialTest extends TestCase
{
    private const BASE_NOW = 1700000000;

    private const PREFIX = '{kiwi:diff}:stepup:';

    public static function providerSeeds(): \Generator
    {
        foreach (range(1, 20) as $seed) {
            yield 'seed '.$seed => [$seed];
        }
    }

    /**
     * The randomized property: for the same legal operation sequence,
     * both stores answer the same observable outcome after every
     * action, or the same equivalent refusal. A failure message names
     * the seed and the step, so the run reproduces exactly.
     */
    #[DataProvider('providerSeeds')]
    public function testBothStoresAnswerTheSameObservableSequence(int $seed): void
    {
        $harness = $this->harness();

        $harness->runSequence($seed, 40);
    }

    /**
     * Divergence pin one: the forged escalation child. The child names
     * a foreign parent link but inherits the exact parent expiry. The
     * array store refuses the whole transaction; the Redis script
     * accepts it and repoints the family index at the forged child.
     */
    public function testAForgedChildParentLinkRefusesOnBothStores(): void
    {
        [$arrayStore, $redisStore] = $this->stores();
        $digest = '5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f';
        $parent = StepUpDemand::mint('forgenparentid00000000001', 'login', null, null, 'decision-1', self::BASE_NOW, 600);
        $arrayStore->createDemand($parent, 600);
        $redisStore->createDemand($parent, 600);
        $forged = StepUpDemand::mint('forgenchildid00000000001', 'login', null, null, 'decision-1', self::BASE_NOW, 600, StepUpOperationBindingKind::None, $digest, null, null, false, 'foreignparentid000000001');
        self::assertSame($parent->expiresAt, $forged->expiresAt, 'the forged child inherits the exact parent expiry');

        $a = $arrayStore->supersedeDemandWithChild($parent->id, $forged);
        $r = $redisStore->supersedeDemandWithChild($parent->id, $forged);

        self::assertNull($a, 'the array store refuses the forged parent link');
        self::assertNull($r, 'the Redis script refuses it too: the lineage is exact in both directions, so a forged link can never sit in the family index');
        self::assertNull($redisStore->demandIdForOperation($forged->operationDigest), 'no family index entry points at the refused child');
        self::assertNull($redisStore->readDemand($forged->id), 'the refused child was never written');
        self::assertFalse((bool) $redisStore->readDemand($parent->id)?->superseded(), 'the parent stays live when the child refuses');
    }

    /**
     * Divergence pin two: the superseded parent state field. The
     * supersede of a finalizing parent answers a record whose state
     * field differs by store. The marker gates every transition on
     * both, so the follow-up superseded settlement lands only where
     * the state field was kept.
     */
    public function testTheSupersededTerminalIsWrittenInsideTheSupersedeOnBothStores(): void
    {
        [$arrayStore, $redisStore, $fake] = $this->stores();
        $parentId = 'statefielparentid0000001';
        $childId = 'statefielchildid00000001';
        $parent = StepUpDemand::mint($parentId, 'login', null, null, 'decision-1', self::BASE_NOW, 600);
        $arrayStore->createDemand($parent, 600);
        $redisStore->createDemand($parent, 600);
        self::assertNotNull($arrayStore->completeDemand($parentId, self::BASE_NOW, 600));
        self::assertNotNull($redisStore->completeDemand($parentId, self::BASE_NOW, 600));
        self::assertNotNull($arrayStore->claimDemandFinalization($parentId, self::BASE_NOW, 30));
        self::assertNotNull($redisStore->claimDemandFinalization($parentId, self::BASE_NOW, 30));
        $child = $arrayStore->readDemand($parentId)->spawnChild($childId, self::BASE_NOW, 'decision-2');

        $a = $arrayStore->supersedeDemandWithChild($parentId, $child);
        $r = $redisStore->supersedeDemandWithChild($parentId, $child);

        self::assertNotNull($a);
        self::assertNotNull($r);
        // Raw-state parity: the whole terminal transition is the one
        // supersede transaction on both stores. The parent carries the
        // superseded state, the stamp and the child link together; no
        // follow-up settlement exists on either lane.
        self::assertSame(StepUpDemandState::Superseded, $a->state, 'the array store writes the superseded terminal');
        self::assertSame(StepUpDemandState::Superseded, $r->state, 'the Redis script writes the superseded terminal in the same transaction');
        self::assertSame($childId, $a->supersededByDemandId);
        self::assertSame($childId, $r->supersededByDemandId, 'the marker itself agrees');
        // Each stamp is that store's own supersede-time: the array
        // store stamps its injected clock, the Redis script stamps the
        // server clock it owns. The stores never share a clock, so the
        // parity claim is the stamp provenance, not one shared value.
        self::assertSame(self::BASE_NOW, $a->stateAt, 'the array store stamps its own clock');
        self::assertSame((int) floor($fake->timeMs() / 1000), $r->stateAt, 'the Redis script stamps the server clock');

        self::assertNull($arrayStore->settleDemandFinalization($parentId, StepUpDemandState::Superseded, self::BASE_NOW), 'the array store: the terminal already stands, a second settle answers null');
        self::assertNull($redisStore->settleDemandFinalization($parentId, StepUpDemandState::Superseded, self::BASE_NOW), 'the Redis store: the terminal already stands, a second settle answers null');
        self::assertNull($arrayStore->settleDemandFinalization($parentId, StepUpDemandState::Authorized, self::BASE_NOW), 'the superseded parent authorizes through nothing on the array store');
        self::assertNull($redisStore->settleDemandFinalization($parentId, StepUpDemandState::Authorized, self::BASE_NOW), 'the superseded parent authorizes through nothing on the Redis store');
    }

    /**
     * The standard-lane harness: the array store on the injected clock
     * box, the Redis store over the emulated client whose server clock
     * mirrors the same box, one shared engine.
     *
     * @return array{0: StepUpStoreDifferentialHarness}
     */
    private function harness(): StepUpStoreDifferentialHarness
    {
        [$arrayStore, $redisStore, $fake, $clock] = $this->stores();

        return new StepUpStoreDifferentialHarness(
            $arrayStore,
            $redisStore,
            $fake,
            $clock,
            StepUpStoreDifferentialHarness::LANE_STANDARD,
            self::PREFIX,
            static function (bool $condition, string $message): void {
                self::assertTrue($condition, $message);
            },
        );
    }

    /**
     * @return array{0: ArrayStepUpChallengeStore, 1: RedisStepUpChallengeStore, 2: FakePredisClient, 3: \stdClass}
     */
    private function stores(): array
    {
        $clock = new \stdClass();
        $clock->now = self::BASE_NOW;
        $fake = new FakePredisClient();
        $arrayStore = new ArrayStepUpChallengeStore(static fn (): int => $clock->now);
        $redisStore = new RedisStepUpChallengeStore($fake, self::PREFIX);

        return [$arrayStore, $redisStore, $fake, $clock];
    }
}
