<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\FactorRequirement;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandFinalizer;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpEffectsJournal;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorAssurance;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorResolver;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFinalization;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationDigest;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationMaterial;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResult;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use PHPUnit\Framework\TestCase;

/**
 * Model checking of the step-up demand state machine, run in lockstep
 * against both store implementations (the ArrayStepUpChallengeStore and
 * the RedisStepUpChallengeStore over the emulated Predis client), in
 * one process, with no Redis server: the standard lane runs it green.
 *
 * The machine, spelled by StepUpDemandState, the stores' Lua scripts
 * and their comments:
 *
 *  - States: open -> completed (the factor+demand completion).
 *    completed -> finalizing (exactly one owner's claim, a stale
 *    claim retaken past its window).
 *    finalizing -> authorized | denied (the terminal
 *    compare-and-set, exactly once).
 *    open|finalizing -> superseded (the escalation child took over;
 *    the marker is checked on every later transition).
 *  - Guards: the demand id identity of every transition, the single-use
 *    challenge consumption, the presented binding hash, the stored
 *    required factor rank, the supersede marker, the claim window, the
 *    operation-family index and the child's inherited expiry.
 *
 * The invariants asserted after every action of every walk:
 *
 *  I1 denied never becomes authorized (no path through any public
 *     store method).
 *  I2 superseded never becomes authorized and never completes a factor.
 *  I3 a consumed challenge or demand never becomes live again.
 *  I4 a challenge completes at most one demand; one demand completes at
 *     most once.
 *  I5 at most one finalization lease holder; a stale lease is retaken,
 *     a live foreign lease refuses, and exactly one settle wins the
 *     terminal compare-and-set.
 *  I6 an authorized demand's binding is immutable; a supersede of an
 *     authorized demand refuses.
 *  I7 a completion below a record's demanded rank is refused: the
 *     enforcement is the completion gate on the record the finalizer
 *     (or the mint) stored, never a caller argument.
 *  I8 a child never extends the root authorization window (the child
 *     expiry equals the parent expiry; a foreign expiry refuses).
 *  I9 a family never exceeds MAX_GENERATION (spawnChild throws at the
 *     cap; the capped escalation settles denied).
 *  I10 a demand never switches principals or session/browser binding
 *     through any public method.
 *  I11 a login restoration names the authorized family demand only
 *     (superseded, denied and absent tips restore nothing).
 *  I12 a demandless challenge authorizes nothing.
 *  I13 every visible authorization sits on a durable authorized
 *     terminal (settle to authorized only from finalizing, exactly
 *     once, second settle answers null).
 *
 * Each randomized scenario seeds mt_srand with its own fixed seed. The
 * failure messages carry the seed, the step and the action. A walk runs
 * 5-30 actions whose legality the clean-room model decides, and both
 * stores' observable state is compared against the model after every
 * action. The documented lane asymmetry (the Redis supersede leaves the
 * parent state field untouched behind the marker, the array store writes
 * the superseded terminal, so only from a claimed parent does the
 * escalator follow-up land) is modeled per lane, never weakened.
 */
final class StepUpDemandStateMachineModelPropertyTest extends TestCase
{
    private const MASTER = 'kiwi-stepup-prop-master-0123456789ab';

    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    private const SCOPE = 'login';

    private const START = 1700000000;

    /** The scenario TTL: no record ever expires inside a walk. */
    private const TTL = 600;

    /** The randomized scenario count (the seeds 1..240). */
    private const SEEDS = 240;

    /** The deterministic record id counter of the process. */
    private static int $seq = 0;

    // ── the randomized suite ─────────────────────────────────────────

    public function testRandomizedWalksHoldTheInvariantsOnBothStores(): void
    {
        $actions = 0;
        for ($seed = 1; $seed <= self::SEEDS; $seed++) {
            mt_srand($seed);
            $h = new StepUpDemandWalkHarness(self::START);
            $m = new StepUpDemandWalkModel();
            $steps = mt_rand(5, 30);
            for ($step = 1; $step <= $steps; $step++) {
                $ctx = 'seed='.$seed.' step='.$step;
                $h->setNow($h->now + mt_rand(0, 4));
                $name = $this->pickAction($m);
                $actions++;
                $this->runAction($name, $h, $m, $ctx);
                $this->assertStateMatches($h, $m, $ctx.' after '.$name);
                $this->probeInvariants($h, $m, $ctx.' after '.$name, $step);
            }
        }
        self::assertSame(self::SEEDS, $seed - 1, 'every scenario ran');
        self::assertGreaterThan(200 * 5, $actions, 'the scenarios ran a non-trivial action count');
    }

    // ── item 1: the denied terminal is absorbing ─────────────────────

    public function testDeniedNeverBecomesAuthorizedOnEitherStore(): void
    {
        $this->onBothLanes(function (StepUpDemandWalkHarness $h): void {
            $id = $this->mintRootOn($h, $h->array, 'denied');
            foreach (['array' => $h->array, 'redis' => $h->redis] as $store) {
                self::assertNotNull($store->completeDemand($id, $h->now, self::TTL));
                self::assertNotNull($store->claimDemandFinalization($id, $h->now, 30));
                $denied = $store->settleDemandFinalization($id, StepUpDemandState::Denied, $h->now);
                self::assertNotNull($denied);
                self::assertTrue($denied->state === StepUpDemandState::Denied);

                // Every authorizing path refuses past the denied
                // terminal, on this store.
                self::assertNull($store->settleDemandFinalization($id, StepUpDemandState::Authorized, $h->now, 'email_otp'), 'a denied demand never settles authorized');
                self::assertNull($store->settleDemandFinalization($id, StepUpDemandState::Superseded, $h->now), 'a denied demand never leaves its terminal');
                self::assertNull($store->claimDemandFinalization($id, $h->now, 30), 'a denied demand is never claimed');
                self::assertNull($store->completeDemand($id, $h->now, self::TTL), 'a denied demand never completes');

                // A fresh challenge bound to the denied demand completes
                // nothing, and the refusal consumes nothing.
                $challenge = $this->mintChallengeOn($h, $id, 'denied', StepUpChallengeKind::EmailOtp);
                $secret = (string) $store->read($challenge)?->clientSecretHash;
                self::assertNull($store->completeFactor($challenge, $id, $secret, $h->now), 'a denied demand completes no factor');
                self::assertNotNull($store->read($challenge), 'the refusal consumed no challenge');
                self::assertTrue($store->readDemand($id)->state === StepUpDemandState::Denied, 'the denied terminal is durable');

                // The supersede of a denied demand refuses: history is
                // not a family head.
                $child = $this->handMintChild($h, $id, $id.'childddddddddd', null, 0);
                self::assertNull($store->supersedeDemandWithChild($id, $child), 'a denied demand never supersedes');
                self::assertNull($store->readDemand($id.'childddddddddd'), 'the refused child was never written');
            }

            // The non-terminal settle argument: the documented refusal
            // shape differs per lane. The array store throws from a
            // finalizing demand; the Redis script answers nil through
            // its own terminal vocabulary gate.
            $mid = $this->mintRootOn($h, $h->array, 'deniedmid');
            self::assertNotNull($h->array->completeDemand($mid, $h->now, self::TTL));
            self::assertNotNull($h->array->claimDemandFinalization($mid, $h->now, 30));
            try {
                $h->array->settleDemandFinalization($mid, StepUpDemandState::Open, $h->now);
                self::fail('a non-terminal settlement is refused');
            } catch (\InvalidArgumentException) {
                // the documented refusal shape of the array store
            }
            self::assertNotNull($h->redis->completeDemand($mid, $h->now, self::TTL));
            self::assertNotNull($h->redis->claimDemandFinalization($mid, $h->now, 30));
            self::assertNull($h->redis->settleDemandFinalization($mid, StepUpDemandState::Open, $h->now), 'the script vocabulary gate answers nil');
        });
    }

    // ── item 2: the superseded demand authorizes nothing ─────────────

    public function testSupersededNeverAuthorizesThroughAnyPublicMethod(): void
    {
        $this->onBothLanes(function (StepUpDemandWalkHarness $h): void {
            // An open parent superseded in place: the marker rides the
            // record, the escalation child stands. Each lane drives its
            // own copy of the same root.
            $parent = $this->mintRootOn($h, $h->array, 'supopen');
            foreach (['array' => $h->array, 'redis' => $h->redis] as $store) {
                $child = $store->readDemand($parent)->spawnChild($parent.'cccccccccccccc', $h->now, 'decision-sup');
                self::assertNotNull($store->supersedeDemandWithChild($parent, $child), 'the escalation replaces the open parent');
                self::assertTrue($store->readDemand($parent)->superseded());

                self::assertNull($store->settleDemandFinalization($parent, StepUpDemandState::Authorized, $h->now, 'email_otp'), 'a superseded demand never settles authorized');
                self::assertNull($store->settleDemandFinalization($parent, StepUpDemandState::Superseded, $h->now), 'superseded from open, no terminal settle lands (the state gate)');
                self::assertNull($store->claimDemandFinalization($parent, $h->now + 31, 30), 'a superseded demand is never claimed');
                self::assertNull($store->completeDemand($parent, $h->now, self::TTL), 'a superseded demand never completes');
                $challenge = $this->mintChallengeOn($h, $parent, 'supopen', StepUpChallengeKind::EmailOtp);
                $secret = (string) $store->read($challenge)?->clientSecretHash;
                self::assertNull($store->completeFactor($challenge, $parent, $secret, $h->now), 'a superseded demand completes no factor');
                self::assertNotNull($store->read($challenge), 'the refusal consumed no challenge');
                $second = $store->readDemand($parent.'cccccccccccccc')->spawnChild($parent.'dddddddddddddd', $h->now, 'decision-sup');
                self::assertNull($store->supersedeDemandWithChild($parent, $second), 'a superseded parent never supersedes twice');
                self::assertNull($store->readDemand($parent.'dddddddddddddd'), 'the refused child was never written');
            }
        });
    }

    public function testASupersededFinalizingParentAuthorizesThroughNothing(): void
    {
        $this->onBothLanes(function (StepUpDemandWalkHarness $h): void {
            // The claimed parent: the escalator holds its own claim,
            // and both lanes are driven to the claim so the supersede
            // happens from the claimed state on each of them.
            $parent = $this->mintRootOn($h, $h->array, 'supfin');
            self::assertNotNull($h->array->completeDemand($parent, $h->now, self::TTL));
            self::assertNotNull($h->array->claimDemandFinalization($parent, $h->now, 30));
            self::assertNotNull($h->redis->completeDemand($parent, $h->now, self::TTL));
            self::assertNotNull($h->redis->claimDemandFinalization($parent, $h->now, 30));
            $child = $h->array->readDemand($parent)->spawnChild($parent.'cccccccccccccc', $h->now, 'decision-sup');
            $arraySuperseded = $h->array->supersedeDemandWithChild($parent, $child);
            $redisSuperseded = $h->redis->supersedeDemandWithChild($parent, $child);
            self::assertNotNull($arraySuperseded);
            self::assertNotNull($redisSuperseded);

            foreach ([$h->array, $h->redis] as $store) {
                self::assertNull($store->settleDemandFinalization($parent, StepUpDemandState::Authorized, $h->now, 'email_otp'), 'the stale claimant never drives the parent past the child');
                self::assertNull($store->claimDemandFinalization($parent, $h->now + 31, 30), 'a stale claimant never retakes a superseded demand');
            }

            // The superseded terminal is absorbing on both stores: the
            // supersede transaction wrote it (state, stamp and child
            // link together), so no later settlement of any kind lands,
            // and the parent authorizes through nothing.
            self::assertNull($h->array->settleDemandFinalization($parent, StepUpDemandState::Denied, $h->now));
            self::assertNull($h->redis->settleDemandFinalization($parent, StepUpDemandState::Denied, $h->now));
            self::assertTrue($h->array->readDemand($parent)->state === StepUpDemandState::Superseded);
            self::assertTrue($h->redis->readDemand($parent)->state === StepUpDemandState::Superseded);
            self::assertNull($h->array->settleDemandFinalization($parent, StepUpDemandState::Authorized, $h->now, 'email_otp'), 'the superseded terminal is absorbing');
            self::assertNull($h->redis->settleDemandFinalization($parent, StepUpDemandState::Authorized, $h->now, 'email_otp'), 'the superseded terminal is absorbing');

            // The escalator follow-up from the claimed parent: only the
            // Redis lane still lands it, exactly once.
            $parent2 = $this->mintRootOn($h, $h->array, 'supfin2');
            self::assertNotNull($h->array->completeDemand($parent2, $h->now, self::TTL));
            self::assertNotNull($h->array->claimDemandFinalization($parent2, $h->now, 30));
            self::assertNotNull($h->redis->completeDemand($parent2, $h->now, self::TTL));
            self::assertNotNull($h->redis->claimDemandFinalization($parent2, $h->now, 30));
            $child2 = $h->array->readDemand($parent2)->spawnChild($parent2.'cccccccccccccc', $h->now, 'decision-sup');
            self::assertNotNull($h->array->supersedeDemandWithChild($parent2, $child2));
            self::assertNotNull($h->redis->supersedeDemandWithChild($parent2, $child2));
            self::assertNull($h->array->settleDemandFinalization($parent2, StepUpDemandState::Superseded, $h->now), 'both stores wrote the terminal inside the supersede');
            self::assertNull($h->redis->settleDemandFinalization($parent2, StepUpDemandState::Superseded, $h->now), 'both stores wrote the terminal inside the supersede');
            self::assertNull($h->array->settleDemandFinalization($parent2, StepUpDemandState::Authorized, $h->now, 'email_otp'));
            self::assertNull($h->redis->settleDemandFinalization($parent2, StepUpDemandState::Authorized, $h->now, 'email_otp'));
        });
    }

    // ── item 3 + 12: consumed records never come back ────────────────

    public function testAConsumedChallengeAndDemandNeverBecomeLiveAgain(): void
    {
        $this->onBothLanes(function (StepUpDemandWalkHarness $h): void {
            $id = $this->mintRootOn($h, $h->array, 'consume');
            foreach (['array' => $h->array, 'redis' => $h->redis] as $store) {

                // The demand consumption is the destructive send-credit
                // claim: the record is gone after it.
                self::assertNotNull($store->consumeDemand($id)?->id);
                self::assertNull($store->consumeDemand($id), 'a second consumption answers null');
                self::assertNull($store->readDemand($id));
                self::assertNull($store->completeDemand($id, $h->now, self::TTL));
                self::assertNull($store->claimDemandFinalization($id, $h->now, 30));
                self::assertNull($store->settleDemandFinalization($id, StepUpDemandState::Authorized, $h->now, 'email_otp'));
                self::assertNull($store->recordDemandEffect($id, StepUpEffectsJournal::SETTLED, $h->now));

                // A challenge naming the missing demand completes
                // nothing and stays: nothing settles behind a consumed
                // demand.
                $challenge = $this->mintChallengeOn($h, $id, 'consume', StepUpChallengeKind::EmailOtp);
                $secret = (string) $store->read($challenge)?->clientSecretHash;
                self::assertNull($store->completeFactor($challenge, $id, $secret, $h->now), 'a demandless challenge completes nothing');
                self::assertNotNull($store->read($challenge), 'the demandless refusal consumed no challenge');

                // The challenge consumption: single-use.
                self::assertNotNull($store->consume($challenge)?->id);
                self::assertNull($store->consume($challenge));
                self::assertNull($store->read($challenge));
                self::assertNull($store->completeFactor($challenge, $id, $secret, $h->now), 'a consumed challenge completes nothing');
            }
        });
    }

    // ── item 4: one completion per challenge, per demand ─────────────

    public function testAChallengeCompletesOneDemandAndOneDemandCompletesOnce(): void
    {
        $this->onBothLanes(function (StepUpDemandWalkHarness $h): void {
            $id = $this->mintRootOn($h, $h->array, 'once');
            foreach (['array' => $h->array, 'redis' => $h->redis] as $store) {
                $first = $this->mintChallengeOn($h, $id, 'once', StepUpChallengeKind::EmailOtp);
                $second = $this->mintChallengeOn($h, $id, 'once', StepUpChallengeKind::EmailOtp);
                $firstSecret = (string) $store->read($first)?->clientSecretHash;
                $secondSecret = (string) $store->read($second)?->clientSecretHash;

                self::assertNotNull($store->completeFactor($first, $id, $firstSecret, $h->now), 'the first completion lands');
                self::assertNull($store->completeFactor($first, $id, $firstSecret, $h->now), 'the consumed challenge completes nothing twice');
                self::assertNull($store->completeFactor($second, $id, $secondSecret, $h->now), 'a completed demand answers no second completion');
                self::assertNotNull($store->read($second), 'the refusal consumed no challenge');
                self::assertNull($store->completeDemand($id, $h->now, self::TTL), 'the completed demand completes once');
                self::assertTrue($store->readDemand($id)->state === StepUpDemandState::Completed);
                self::assertNull($store->recordDemandEffect($id, StepUpEffectsJournal::SETTLED, $h->now), 'a completed demand journals nothing');
            }
        });
    }

    // ── item 5: the finalization lease race, both interleavings ──────

    public function testTheFinalizationLeaseRaceMirrorsBothInterleavings(): void
    {
        $this->onBothLanes(function (StepUpDemandWalkHarness $h): void {
            $a = $this->mintRootOn($h, $h->array, 'racea');
            $rootsB = ['raceb1' => $this->mintRootOn($h, $h->array, 'raceb1'), 'raceb2' => $this->mintRootOn($h, $h->array, 'raceb2')];
            foreach (['array' => $h->array, 'redis' => $h->redis] as $store) {
                // Interleaving A: the first claimant settles inside its
                // window; the second claimant is refused while the
                // foreign lease lives and after the terminal landed.
                self::assertNotNull($store->completeDemand($a, $h->now, self::TTL));
                self::assertNotNull($store->claimDemandFinalization($a, $h->now, 30), 'the first owner holds the claim');
                self::assertNull($store->claimDemandFinalization($a, $h->now + 1, 30), 'a live foreign lease refuses');
                self::assertNotNull($store->settleDemandFinalization($a, StepUpDemandState::Authorized, $h->now, 'email_otp'));
                self::assertNull($store->settleDemandFinalization($a, StepUpDemandState::Authorized, $h->now, 'email_otp'), 'the second settle answers null');
                self::assertNull($store->claimDemandFinalization($a, $h->now + 31, 30), 'the terminal claimant is gone');
                self::assertNull($store->settleDemandFinalization($a, StepUpDemandState::Denied, $h->now));

                // Interleaving B: the first owner dies inside its
                // window, the second retakes past the deadline and
                // settles; the first claimant's late settle loses the
                // terminal compare-and-set either way (its finalizing
                // state was overwritten), whichever of the two settles
                // first.
                foreach (['raceb1', 'raceb2'] as $i => $tag) {
                    $b = $rootsB[$tag];
                    self::assertNotNull($store->completeDemand($b, $h->now, self::TTL));
                    self::assertNotNull($store->claimDemandFinalization($b, $h->now, 30));
                    self::assertNull($store->claimDemandFinalization($b, $h->now + 29, 30), 'inside the window the retake refuses');
                    $retaken = $store->claimDemandFinalization($b, $h->now + 30, 30);
                    self::assertNotNull($retaken, 'past the window the stale claim is retaken');
                    self::assertSame($h->now + 30, $retaken->stateAt, 'the retake re-stamps the claim');
                    $winner = $i === 0 ? 'the retaker' : 'the revived first claimant';
                    $loser = $i === 0 ? 'the first claimant' : 'the retaker';
                    self::assertNotNull($store->settleDemandFinalization($b, StepUpDemandState::Authorized, $h->now + 31, 'email_otp'), $winner.' settles');
                    self::assertNull($store->settleDemandFinalization($b, StepUpDemandState::Authorized, $h->now + 32, 'email_otp'), $loser.' settles nothing');
                    self::assertTrue($store->readDemand($b)->state === StepUpDemandState::Authorized);
                }
            }
        });
    }

    // ── item 6 + 10: the binding is immutable past the terminal ──────

    public function testAnAuthorizedDemandKeepsItsBindingThroughEveryPublicMethod(): void
    {
        $this->onBothLanes(function (StepUpDemandWalkHarness $h): void {
            $session = str_repeat('7', 64);
            $digest = StepUpOperationDigest::none('binding');
            $demand = StepUpDemand::mint('bindingdemandid0000000000001', 'binding', $session, null, 'decision-bind', $h->now, self::TTL, StepUpOperationBindingKind::None, $digest);
            self::assertSame('bindingdemandid0000000000001', $h->array->createRootDemand($demand, self::TTL));
            self::assertSame('bindingdemandid0000000000001', $h->redis->createRootDemand($demand, self::TTL));

            foreach (['array' => $h->array, 'redis' => $h->redis] as $store) {
                $before = $store->readDemand('bindingdemandid0000000000001');
                self::assertNotNull($before);

                self::assertNotNull($store->completeDemand('bindingdemandid0000000000001', $h->now, self::TTL));
                self::assertNotNull($store->claimDemandFinalization('bindingdemandid0000000000001', $h->now, 30));
                self::assertNotNull($store->settleDemandFinalization('bindingdemandid0000000000001', StepUpDemandState::Authorized, $h->now, 'email_otp'));

                // Hammer every public method; nothing may move the
                // principal binding, the operation binding or the
                // family shape of the terminal.
                $challenge = $this->mintChallengeOn($h, 'bindingdemandid0000000000001', 'binding', StepUpChallengeKind::EmailOtp);
                $secret = (string) $store->read($challenge)?->clientSecretHash;
                self::assertNull($store->completeFactor($challenge, 'bindingdemandid0000000000001', $secret, $h->now));
                self::assertNull($store->completeDemand('bindingdemandid0000000000001', $h->now, self::TTL));
                self::assertNull($store->claimDemandFinalization('bindingdemandid0000000000001', $h->now, 30));
                self::assertNull($store->settleDemandFinalization('bindingdemandid0000000000001', StepUpDemandState::Denied, $h->now));
                self::assertNull($store->settleDemandFinalization('bindingdemandid0000000000001', StepUpDemandState::Superseded, $h->now));
                self::assertNull($store->settleDemandFinalization('bindingdemandid0000000000001', StepUpDemandState::Authorized, $h->now, 'totp'));
                self::assertNotNull($store->recordDemandEffect('bindingdemandid0000000000001', StepUpEffectsJournal::SETTLED, $h->now), 'the journal lands on the terminal');
                self::assertNull($store->recordDemandEffect('bindingdemandid0000000000001', 'not_an_effect', $h->now));

                // A supersede of the authorized demand refuses: the
                // terminal is history, not a family head.
                $child = $before->spawnChild('bindingchildid00000000001', $h->now, 'decision-child');
                self::assertNull($store->supersedeDemandWithChild('bindingdemandid0000000000001', $child));
                self::assertNull($store->readDemand('bindingchildid00000000001'), 'the refused child was never written');

                // The family answers the standing tip, never a refresh.
                $again = StepUpDemand::mint('bindingotherid000000000001', 'binding', $session, null, 'decision-other', $h->now, self::TTL, StepUpOperationBindingKind::None, $digest);
                self::assertSame('bindingdemandid0000000000001', $store->createRootDemand($again, self::TTL), 'one demand per operation: the standing tip serves');

                $after = $store->readDemand('bindingdemandid0000000000001');
                self::assertNotNull($after);
                self::assertSame($before->scope, $after->scope, 'a demand never switches scope');
                self::assertSame($before->sessionHash, $after->sessionHash, 'the browser binding never moves');
                self::assertSame($before->chainId, $after->chainId);
                self::assertSame($before->decisionId, $after->decisionId);
                self::assertSame($before->operationDigest, $after->operationDigest);
                self::assertSame($before->operationIdentityDigest, $after->operationIdentityDigest);
                self::assertSame($before->operationContentDigest, $after->operationContentDigest);
                self::assertSame($before->expiresAt, $after->expiresAt);
                self::assertSame($before->parentDemandId, $after->parentDemandId);
                self::assertSame($before->generation, $after->generation);
                self::assertTrue($after->state === StepUpDemandState::Authorized);
                self::assertSame('email_otp', $after->factor, 'the completed factor stays the settlement one');
                self::assertSame($h->now, $after->authorizedAt);
            }
        });
    }

    // ── item 7: the demanded rank is enforced on the record ──────────

    public function testAWeakMintedChildStillCannotAuthorizeBelowItsDemandedRank(): void
    {
        $this->onBothLanes(function (StepUpDemandWalkHarness $h): void {
            $weakParent = $this->mintRootOn($h, $h->array, 'weaka');
            $strongParent = $this->mintRootOn($h, $h->array, 'weakb');
            foreach (['array' => $h->array, 'redis' => $h->redis] as $store) {
                // The store-level supersede gate judges the expiry and
                // the parent link, never the rank: a hand-minted child
                // with a weaker (or absent) requirement is written
                // as-is. The enforcement the ladder relies on is the
                // completion gate on the child's own record, the record
                // the finalizer mints through strongerRequirement.
                $weakChild = $this->handMintChild($h, $weakParent, 'weakchilddddddddda1', null, 0);
                self::assertNotNull($store->supersedeDemandWithChild($weakParent, $weakChild), 'the supersede judges shape, not rank');
                self::assertNull($store->readDemand('weakchilddddddddda1')?->requiredFactor, 'the weak child carries no demanded rank');

                $weakChallenge = $this->mintChallengeOn($h, 'weakchilddddddddda1', 'weaka', StepUpChallengeKind::EmailOtp);
                $weakSecret = (string) $store->read($weakChallenge)?->clientSecretHash;
                self::assertNotNull($store->completeFactor($weakChallenge, 'weakchilddddddddda1', $weakSecret, $h->now), 'a child with no demanded rank is answered at its face value');

                // The same hand-mint with a demanded rank: the
                // completion gate refuses below it and a completion at
                // the rank lands.
                $strongChild = $this->handMintChild($h, $strongParent, 'weakchildddddddddb2', new FactorRequirement(FactorRequirement::TOTP, FactorRequirement::TOTP, 2), 0);
                self::assertNotNull($store->supersedeDemandWithChild($strongParent, $strongChild));
                $emailChallenge = $this->mintChallengeOn($h, 'weakchildddddddddb2', 'weakb', StepUpChallengeKind::EmailOtp);
                $emailSecret = (string) $store->read($emailChallenge)?->clientSecretHash;
                self::assertNull($store->completeFactor($emailChallenge, 'weakchildddddddddb2', $emailSecret, $h->now), 'the weak factor never completes below the demanded rank');
                self::assertNotNull($store->read($emailChallenge), 'the weaker-factor refusal consumed no challenge');
                self::assertTrue($store->readDemand('weakchildddddddddb2')->state->isOpen(), 'the refusal moved no demand');

                $totpChallenge = $this->mintChallengeOn($h, 'weakchildddddddddb2', 'weakb', StepUpChallengeKind::Totp);
                $totpSecret = (string) $store->read($totpChallenge)?->clientSecretHash;
                self::assertNotNull($store->completeFactor($totpChallenge, 'weakchildddddddddb2', $totpSecret, $h->now), 'a completion at the demanded rank lands');
            }
        });
    }

    public function testTheFinalizerMintedChildDemandsStrictlyMoreOnBothStores(): void
    {
        foreach (['array', 'redis'] as $lane) {
            $h = new StepUpDemandWalkHarness(self::START);
            $reporter = new SpyOutcomeReporter();
            $store = $lane === 'array' ? $h->array : $h->redis;
            $finalizer = $this->finalizer($store, $h, 'step_up', $reporter);

            $demandId = (string) $finalizer->mintLoginDemand(self::SCOPE, self::PRINCIPAL, null, self::TTL);
            self::assertNotNull($store->completeDemand($demandId, $h->now, self::TTL), 'the email otp factor completed the demand');
            $finalization = $finalizer->finalizeLogin($this->proof($demandId, StepUpChallengeKind::EmailOtp, $h), self::SCOPE);
            self::assertSame(StepUpFinalization::ESCALATED, $finalization->reason);
            $child = $finalization->demand;
            self::assertNotNull($child);
            self::assertSame(2, $child->requiredFactor?->assuranceRank, 'the finalizer minted the strictly stronger rung');
            self::assertTrue($store->readDemand($child->id)->state->isOpen());

            // The enforcement rides the child's own record: the same
            // weak rung the parent completed answers the child never.
            $weak = $this->mintChallengeOn($h, $child->id, self::SCOPE, StepUpChallengeKind::EmailOtp);
            $weakSecret = (string) $store->read($weak)?->clientSecretHash;
            self::assertNull($store->completeFactor($weak, $child->id, $weakSecret, $h->now), 'the escalated child refuses the rung it escalated past');
            self::assertNotNull($store->read($weak), 'the refusal consumed no challenge');

            $strong = $this->mintChallengeOn($h, $child->id, self::SCOPE, StepUpChallengeKind::Totp);
            $strongSecret = (string) $store->read($strong)?->clientSecretHash;
            self::assertNotNull($store->completeFactor($strong, $child->id, $strongSecret, $h->now), 'the demanded rung answers the child');
            self::assertTrue($store->readDemand($child->id)->state === StepUpDemandState::Completed);
        }
    }

    // ── item 8: the child inherits the window, never extends it ──────

    public function testAChildNeverExtendsTheRootAuthorizationWindow(): void
    {
        $this->onBothLanes(function (StepUpDemandWalkHarness $h): void {
            $root = $this->mintRootOn($h, $h->array, 'window');
            foreach (['array' => $h->array, 'redis' => $h->redis] as $store) {
                $expiresAt = $store->readDemand($root)?->expiresAt;
                self::assertNotNull($expiresAt);
                $tip = $root;
                for ($generation = 1; $generation <= 3; $generation++) {
                    $childId = 'windowgen00000'.$generation.'cccccc';
                    $child = $store->readDemand($tip)->spawnChild($childId, $h->now, 'decision-window');
                    self::assertNotNull($store->supersedeDemandWithChild($tip, $child), "generation $generation escalates");
                    self::assertSame($expiresAt, $store->readDemand($childId)->expiresAt, "generation $generation carries the root deadline");
                    $tip = $childId;
                }

                // A mint with a foreign expiry refuses in supersede: the
                // child can never outlive (or shorten) what it inherits.
                $forged = $this->handMintChild($h, $tip, 'windowforgedid000001', null, 90);
                self::assertNull($store->supersedeDemandWithChild($tip, $forged), 'a child with a foreign expiry refuses');
                self::assertNull($store->readDemand('windowforgedid000001'), 'the forged child was never written');
                self::assertFalse($store->readDemand($tip)->superseded(), 'the parent stays live when the child refuses');
            }
        });
    }

    // ── item 9: the family cap ───────────────────────────────────────

    public function testAFamilyNeverExceedsTheGenerationCapAndTheCappedEscalationSettlesDenied(): void
    {
        foreach (['array', 'redis'] as $lane) {
            $h = new StepUpDemandWalkHarness(self::START);
            $reporter = new SpyOutcomeReporter();
            $store = $lane === 'array' ? $h->array : $h->redis;

            $finalizer = $this->finalizer($store, $h, 'step_up', $reporter);
            $tip = (string) $finalizer->mintLoginDemand(self::SCOPE, self::PRINCIPAL, null, self::TTL);
            self::assertNotNull($tip);
            // Escalate to the cap: MAX_GENERATION children.
            for ($generation = 1; $generation <= StepUpDemand::MAX_GENERATION; $generation++) {
                $record = $store->readDemand($tip);
                self::assertNotNull($record);
                $child = $record->spawnChild('capgen'.str_pad((string) $generation, 4, '0', STR_PAD_LEFT).$lane.'cccccccc', $h->now, 'decision-cap');
                self::assertNotNull($store->supersedeDemandWithChild($tip, $child), "generation $generation escalates");
                $tip = $child->id;
            }
            $capped = $store->readDemand($tip);
            self::assertNotNull($capped);
            self::assertSame(StepUpDemand::MAX_GENERATION, $capped->generation);
            self::assertFalse($capped->canEscalate(), 'the family cap stops the escalation');
            try {
                $capped->spawnChild('capgenpast00000000000000'.$lane, $h->now, 'decision-past');
                self::fail('a family past its depth spawns no children');
            } catch (\LogicException) {
                // the documented refusal
            }

            // The capped escalation of the finalizer settles denied,
            // never authorized on the weaker proof.
            self::assertNotNull($store->completeDemand($tip, $h->now, self::TTL));
            $cappedFinalization = $this->finalizer($store, $h, 'step_up', $reporter)->finalizeLogin($this->proof($tip, StepUpChallengeKind::EmailOtp, $h), self::SCOPE);
            self::assertFalse($cappedFinalization->authorized);
            self::assertSame(StepUpFinalization::REFUSED_DENIED, $cappedFinalization->reason);
            self::assertTrue($store->readDemand($tip)->state === StepUpDemandState::Denied, 'the capped escalation fails closed');
            self::assertCount(0, $reporter->reports, 'a denied settlement books no credit');
        }
    }

    // ── item 11: the restoration names the authorized family demand ──

    public function testALoginRestorationNamesOnlyTheAuthorizedFamilyDemand(): void
    {
        foreach (['array', 'redis'] as $lane) {
            $h = new StepUpDemandWalkHarness(self::START);
            $store = $lane === 'array' ? $h->array : $h->redis;
            $finalizer = $this->finalizer($store, $h, 'allow', new SpyOutcomeReporter());

            // The named demand while it stands.
            $root = (string) $finalizer->mintLoginDemand(self::SCOPE, self::PRINCIPAL, null, self::TTL);
            self::assertSame($root, $finalizer->loginDemandIdForBegin(self::SCOPE, self::PRINCIPAL, null, $root), 'the open named demand answers its begin');
            self::assertNull($finalizer->retryAuthorizedEffects($root, self::PRINCIPAL), 'an open demand restores nothing');

            // A superseded tip is never the answer: the begin follows
            // the family to the live open child; the restore names the
            // authorized terminal only.
            $child = $store->readDemand($root)->spawnChild('restorechildid000000001', $h->now, 'decision-rest');
            self::assertNotNull($store->supersedeDemandWithChild($root, $child));
            self::assertSame($child->id, $finalizer->loginDemandIdForBegin(self::SCOPE, self::PRINCIPAL, null, $root), 'the begin follows the supersede link to the open tip');
            self::assertNull($finalizer->retryAuthorizedEffects($root, self::PRINCIPAL), 'a superseded demand restores nothing');
            self::assertNull($finalizer->retryAuthorizedEffects($child->id, self::PRINCIPAL), 'an open child restores nothing');

            // Only the Authorized terminal of the family restores.
            self::assertNotNull($store->completeDemand($child->id, $h->now, self::TTL));
            $finalization = $finalizer->finalizeLogin($this->proof($child->id, StepUpChallengeKind::EmailOtp, $h), self::SCOPE);
            self::assertTrue($finalization->authorized);
            self::assertNull($finalizer->loginDemandIdForBegin(self::SCOPE, self::PRINCIPAL, null, $root), 'an authorized tip is not a begin target');
            $restored = $finalizer->retryAuthorizedEffects($child->id, self::PRINCIPAL);
            self::assertNotNull($restored, 'the authorized family terminal restores');
            self::assertTrue($restored->authorized);
            self::assertNotNull($restored->effects);
            self::assertTrue($restored->effects->sessionRestored(), 'the restore journaled on the demand');

            // A denied demand, a foreign principal and an absent id
            // restore nothing.
            $denied = (string) $finalizer->mintLoginDemand(self::SCOPE, self::PRINCIPAL, null, self::TTL);
            self::assertNotNull($store->completeDemand($denied, $h->now, self::TTL));
            self::assertNotNull($store->claimDemandFinalization($denied, $h->now, 30));
            self::assertNotNull($store->settleDemandFinalization($denied, StepUpDemandState::Denied, $h->now));
            self::assertNull($finalizer->retryAuthorizedEffects($denied, self::PRINCIPAL), 'a denied demand restores nothing');
            self::assertNull($finalizer->loginDemandIdForBegin(self::SCOPE, self::PRINCIPAL, null, $denied), 'a denied tip answers no begin');
            self::assertNull($finalizer->retryAuthorizedEffects($child->id, 'ffffffffffffffffffffffffffffffff'), 'another principal restores nothing');
            self::assertNull($finalizer->retryAuthorizedEffects('absentdemandid000000001', self::PRINCIPAL), 'an absent demand restores nothing');
        }
    }

    // ── item 13: every visible authorization has its terminal ───────

    public function testEveryVisibleAuthorizationSitsOnADurableAuthorizedTerminal(): void
    {
        foreach (['array', 'redis'] as $lane) {
            $h = new StepUpDemandWalkHarness(self::START);
            $store = $lane === 'array' ? $h->array : $h->redis;
            $reporter = new SpyOutcomeReporter();
            $finalizer = $this->finalizer($store, $h, 'allow', $reporter);

            $digest = StepUpOperationDigest::none(self::SCOPE);
            $demand = StepUpDemand::mint('grantdemandid0000000000001', self::SCOPE, null, null, null, $h->now, self::TTL, StepUpOperationBindingKind::None, $digest);
            self::assertSame('grantdemandid0000000000001', $store->createRootDemand($demand, self::TTL));
            self::assertNotNull($store->completeDemand('grantdemandid0000000000001', $h->now, self::TTL));

            $finalization = $finalizer->finalizeGrant('grantdemandid0000000000001', StepUpOperationMaterial::login(self::PRINCIPAL));
            self::assertTrue($finalization->authorized, 'the grant lane authorizes through the finalizer only');

            $terminal = $store->readDemand('grantdemandid0000000000001');
            self::assertNotNull($terminal);
            self::assertTrue($terminal->state === StepUpDemandState::Authorized, 'the durable terminal stands');
            self::assertNotNull($terminal->effects, 'the effect journal rides the terminal');
            self::assertTrue($terminal->effects->settled(), 'the settlement is journaled');
            self::assertTrue($terminal->effects->complete(), 'every effect of the journal landed');
            self::assertCount(1, $reporter->reports, 'the credit booked exactly once');

            // The replay is idempotent: no second credit, no second
            // settlement.
            $replay = $finalizer->finalizeGrant('grantdemandid0000000000001', StepUpOperationMaterial::login(self::PRINCIPAL));
            self::assertTrue($replay->authorized, 'the authorized terminal replays idempotently');
            self::assertCount(1, $reporter->reports, 'the replay booked no second credit');
            self::assertNull($store->settleDemandFinalization('grantdemandid0000000000001', StepUpDemandState::Authorized, $h->now, 'email_otp'), 'the terminal settles exactly once');
            self::assertSame($terminal->toArray(), $store->readDemand('grantdemandid0000000000001')?->toArray(), 'the terminal record is untouched by the replay');
        }
    }

    // ── the randomized driver ────────────────────────────────────────

    /** The weighted random choice of one walk action. */
    private function pickAction(StepUpDemandWalkModel $m): string
    {
        $weighted = [
            'mintRoot' => 10,
            'doubleRoot' => 4,
            'completeFactor' => 16,
            'completeDemand' => 8,
            'claim' => 10,
            'settle' => 12,
            'supersede' => 9,
            'supersedeForeignExpiry' => 3,
            'supersedeWeakChild' => 4,
            'consumeDemand' => 5,
            'consumeChallenge' => 4,
            'mintChallenge' => 6,
            'recordEffect' => 9,
        ];
        $pool = [];
        foreach ($weighted as $name => $weight) {
            $pool = [...$pool, ...array_fill(0, $weight, $name)];
        }
        $name = $pool[mt_rand(0, \count($pool) - 1)];
        if ($m->liveDemandIds() === [] && $name !== 'mintRoot') {
            return 'mintRoot';
        }

        return $name;
    }

    private function runAction(string $name, StepUpDemandWalkHarness $h, StepUpDemandWalkModel $m, string $ctx): void
    {
        switch ($name) {
            case 'doubleRoot':
                $this->actCreateRoot($h, $m, $ctx, $m->randomLiveDemandId());
                break;
            case 'completeFactor':
                $this->actCompleteFactor($h, $m, $ctx);
                break;
            case 'completeDemand':
                $this->actCompleteDemand($h, $m, $ctx);
                break;
            case 'claim':
                $this->actClaim($h, $m, $ctx);
                break;
            case 'settle':
                $this->actSettle($h, $m, $ctx);
                break;
            case 'supersede':
                $this->actSupersede($h, $m, $ctx, 'legal');
                break;
            case 'supersedeForeignExpiry':
                $this->actSupersede($h, $m, $ctx, 'foreignExpiry');
                break;
            case 'supersedeWeakChild':
                $this->actSupersede($h, $m, $ctx, 'weakChild');
                break;
            case 'consumeDemand':
                $this->actConsumeDemand($h, $m, $ctx);
                break;
            case 'consumeChallenge':
                $this->actConsumeChallenge($h, $m, $ctx);
                break;
            case 'mintChallenge':
                $this->actMintChallenge($h, $m, $ctx);
                break;
            case 'recordEffect':
                $this->actRecordEffect($h, $m, $ctx);
                break;
            case 'mintRoot':
            default:
                $this->actCreateRoot($h, $m, $ctx, null);
                break;
        }
    }

    /** Mints a root demand of a fresh family, or re-mints one family. */
    private function actCreateRoot(StepUpDemandWalkHarness $h, StepUpDemandWalkModel $m, string $ctx, ?string $reuseDemandId): void
    {
        $scope = $reuseDemandId !== null
            ? $m->demands[$reuseDemandId]->scope
            : 'w'.preg_replace('/[^A-Za-z0-9]/', '', $ctx).mt_rand(0, 999999);
        $digest = StepUpOperationDigest::none($scope);
        $required = match (mt_rand(0, 2)) {
            1 => new FactorRequirement(FactorRequirement::EMAIL_OTP, FactorRequirement::EMAIL_OTP, 1),
            2 => new FactorRequirement(FactorRequirement::TOTP, FactorRequirement::TOTP, 2),
            default => null,
        };
        $id = $m->nextDemandId();
        $decision = 'decision-'.preg_replace('/[^A-Za-z0-9]/', '', $ctx);
        $demand = StepUpDemand::mint($id, $scope, null, null, $decision, $h->now, self::TTL, StepUpOperationBindingKind::None, $digest, null, null, false, null, $required);

        $tip = $m->familyTip[$digest] ?? null;
        $tipLive = $tip !== null && $m->demands[$tip]->present;
        $expected = $tipLive ? $tip : $id;

        $arrayAnswer = $h->array->createRootDemand($demand, self::TTL);
        $redisAnswer = $h->redis->createRootDemand($demand, self::TTL);
        self::assertSame($expected, $arrayAnswer, $ctx.' createRootDemand answer');
        self::assertSame($expected, $redisAnswer, $ctx.' createRootDemand answer');

        if (!$tipLive) {
            $m->familyTip[$digest] = $id;
            $m->demands[$id] = ModelDemand::fromMint($demand, $h->now);
        } else {
            // A standing tip never mints the second root, and the
            // window is never refreshed: the standing tip keeps its
            // exact authorization deadline.
            self::assertNull($h->array->readDemand($id), $ctx.' a standing tip never mints the second root');
            self::assertNull($h->redis->readDemand($id), $ctx.' a standing tip never mints the second root');
            self::assertSame($m->demands[$tip]->expiresAt, $h->array->readDemand($tip)?->expiresAt, $ctx.' the standing window never refreshes');
            self::assertSame($m->demands[$tip]->expiresAt, $h->redis->readDemand($tip)?->expiresAt, $ctx.' the standing window never refreshes');
        }
    }

    private function actCompleteFactor(StepUpDemandWalkHarness $h, StepUpDemandWalkModel $m, string $ctx): void
    {
        $challengeId = $m->randomChallengeId();
        if ($challengeId === null || !$m->challenges[$challengeId]->present) {
            $this->actMintChallenge($h, $m, $ctx);

            return;
        }
        $challenge = $m->challenges[$challengeId];
        $demandId = $challenge->demandId;
        if (mt_rand(0, 3) === 0) {
            $demandId = $m->randomLiveDemandId() ?? $demandId;
        }
        $demand = $m->demands[$demandId] ?? null;
        $wrongBinding = mt_rand(0, 3) === 0;
        $presented = $wrongBinding ? str_repeat('b', 64) : $challenge->binding;
        $hint = $challenge->sessionHash !== null && mt_rand(0, 1) === 0 ? $challenge->sessionHash : null;

        $crossed = $demand === null || $challenge->demandId !== $demandId;
        $rankOk = $demand === null
            || $demand->requiredFactor === null
            || $challenge->rank >= $demand->requiredFactor->assuranceRank;
        $ok = !$crossed
            && $challenge->present
            && $demand->present
            && $demand->supersededBy === null
            && $demand->lanes['array']->state === StepUpDemandState::Open
            && $demand->lanes['redis']->state === StepUpDemandState::Open
            && !$wrongBinding
            && $rankOk;

        $arrayAnswer = $h->array->completeFactor($challengeId, $demandId, $presented, $h->now, $hint);
        $redisAnswer = $h->redis->completeFactor($challengeId, $demandId, $presented, $h->now, $hint);

        if ($ok) {
            self::assertNotNull($arrayAnswer, $ctx.' completeFactor');
            self::assertNotNull($redisAnswer, $ctx.' completeFactor (redis)');
            self::assertSame($challengeId, $arrayAnswer->challengeId, $ctx);
            self::assertSame($demandId, $arrayAnswer->demandId, $ctx);
            self::assertSame($challenge->family, $arrayAnswer->completedFactor, $ctx.' the completed factor is the record one');
            $challenge->present = false;
            foreach (['array', 'redis'] as $lane) {
                $demand->lanes[$lane]->state = StepUpDemandState::Completed;
                $demand->lanes[$lane]->stateAt = $h->now;
            }
            if ($challenge->sessionHash !== null && $hint === $challenge->sessionHash) {
                $m->completedIndex[$challenge->sessionHash] = ['scope' => $challenge->scope, 'family' => $challenge->family, 'expiresAt' => $demand->expiresAt];
            }
        } else {
            self::assertNull($arrayAnswer, $ctx.' completeFactor refusal');
            self::assertNull($redisAnswer, $ctx.' completeFactor refusal (redis)');
        }
    }

    private function actCompleteDemand(StepUpDemandWalkHarness $h, StepUpDemandWalkModel $m, string $ctx): void
    {
        $id = $m->randomLiveDemandId() ?? $m->anyDemandId();
        $demand = $m->demands[$id];
        $arrayAnswer = $h->array->completeDemand($id, $h->now, self::TTL);
        $redisAnswer = $h->redis->completeDemand($id, $h->now, self::TTL);
        foreach (['array' => $arrayAnswer, 'redis' => $redisAnswer] as $lane => $answer) {
            $ok = $demand->present
                && $demand->supersededBy === null
                && $demand->lanes[$lane]->state === StepUpDemandState::Open;
            if ($ok) {
                self::assertNotNull($answer, $ctx.' completeDemand ('.$lane.')');
                self::assertTrue($answer->state === StepUpDemandState::Completed, $ctx);
                $demand->lanes[$lane]->state = StepUpDemandState::Completed;
                $demand->lanes[$lane]->stateAt = $h->now;
            } else {
                self::assertNull($answer, $ctx.' completeDemand refusal ('.$lane.')');
            }
        }
    }

    private function actClaim(StepUpDemandWalkHarness $h, StepUpDemandWalkModel $m, string $ctx): void
    {
        $id = $m->randomLiveDemandId() ?? $m->anyDemandId();
        $demand = $m->demands[$id];
        $claimSecs = [5, 10, 30][mt_rand(0, 2)];
        $arrayAnswer = $h->array->claimDemandFinalization($id, $h->now, $claimSecs);
        $redisAnswer = $h->redis->claimDemandFinalization($id, $h->now, $claimSecs);
        foreach (['array' => $arrayAnswer, 'redis' => $redisAnswer] as $lane => $answer) {
            $ok = $this->laneClaim($demand, $lane, $h->now, $claimSecs);
            if ($ok) {
                self::assertNotNull($answer, $ctx.' claim ('.$lane.')');
                self::assertTrue($answer->state === StepUpDemandState::Finalizing, $ctx);
                $demand->lanes[$lane]->state = StepUpDemandState::Finalizing;
                $demand->lanes[$lane]->stateAt = $h->now;
            } else {
                self::assertNull($answer, $ctx.' claim refusal ('.$lane.')');
            }
        }
    }

    private function actSettle(StepUpDemandWalkHarness $h, StepUpDemandWalkModel $m, string $ctx): void
    {
        $id = $m->randomLiveDemandId() ?? $m->anyDemandId();
        $demand = $m->demands[$id];
        $terminal = [StepUpDemandState::Authorized, StepUpDemandState::Denied, StepUpDemandState::Superseded][mt_rand(0, 2)];
        $factor = $terminal === StepUpDemandState::Authorized ? 'email_otp' : null;
        $arrayAnswer = $h->array->settleDemandFinalization($id, $terminal, $h->now, $factor);
        $redisAnswer = $h->redis->settleDemandFinalization($id, $terminal, $h->now, $factor);
        foreach (['array' => $arrayAnswer, 'redis' => $redisAnswer] as $lane => $answer) {
            $ok = $this->laneSettle($demand, $lane, $terminal);
            if ($ok) {
                self::assertNotNull($answer, $ctx.' settle '.$terminal->value.' ('.$lane.')');
                $demand->lanes[$lane]->state = $terminal;
                $demand->lanes[$lane]->stateAt = $h->now;
                if ($terminal === StepUpDemandState::Authorized) {
                    $demand->factor = 'email_otp';
                    $demand->authorizedAt = $demand->authorizedAt ?? $h->now;
                }
            } else {
                self::assertNull($answer, $ctx.' settle '.$terminal->value.' refusal ('.$lane.')');
            }
        }
    }

    private function actSupersede(StepUpDemandWalkHarness $h, StepUpDemandWalkModel $m, string $ctx, string $mode): void
    {
        $parentId = $m->randomLiveDemandId();
        if ($parentId === null) {
            $this->actCreateRoot($h, $m, $ctx, null);

            return;
        }
        $parent = $m->demands[$parentId];
        $childId = $m->nextDemandId();
        if ($mode === 'legal') {
            // The escalation path of the finalizer: the child is spawned
            // from the standing record (it inherits the requirement and
            // the next generation), so a walk can chain to the cap.
            $parentRecord = $h->array->readDemand($parentId);
            $child = $parentRecord !== null && $parentRecord->canEscalate()
                ? $parentRecord->spawnChild($childId, $h->now, 'decision-'.preg_replace('/[^A-Za-z0-9]/', '', $ctx))
                : $this->handMintChild($h, $parentId, $childId, null, 0, $m);
        } else {
            $extraTtl = $mode === 'foreignExpiry' ? 90 : 0;
            $required = $mode === 'weakChild' && mt_rand(0, 1) === 0
                ? new FactorRequirement(FactorRequirement::EMAIL_OTP, FactorRequirement::EMAIL_OTP, 1)
                : null;
            $child = $this->handMintChild($h, $parentId, $childId, $required, $extraTtl, $m);
        }

        $childOccupied = isset($m->demands[$childId]) && $m->demands[$childId]->present;
        $arrayAnswer = $h->array->supersedeDemandWithChild($parentId, $child);
        $redisAnswer = $h->redis->supersedeDemandWithChild($parentId, $child);

        $landed = false;
        foreach (['array' => $arrayAnswer, 'redis' => $redisAnswer] as $lane => $answer) {
            $ok = $parent->present
                && $parent->supersededBy === null
                && \in_array($parent->lanes[$lane]->state, [StepUpDemandState::Open, StepUpDemandState::Finalizing], true)
                && !$childOccupied
                && $child->expiresAt === $parent->expiresAt;
            if ($ok) {
                self::assertNotNull($answer, $ctx.' supersede ('.$lane.')');
                self::assertSame($childId, $answer->supersededByDemandId, $ctx);
                $landed = true;
                // Both stores write the terminal inside the supersede
                // transaction: state superseded, stamped at the
                // supersede time, child link and index in the same step.
                $parent->lanes[$lane]->state = StepUpDemandState::Superseded;
                $parent->lanes[$lane]->stateAt = $h->now;
            } else {
                self::assertNull($answer, $ctx.' supersede refusal ('.$lane.')');
            }
        }
        if ($landed) {
            $parent->supersededBy = $childId;
            $m->demands[$childId] = ModelDemand::fromChild($child, $parentId, $parent, $h->now);
            $m->familyTip[$child->operationDigest] = $childId;
        } else {
            self::assertNull($h->array->readDemand($childId), $ctx.' the refused child was never written');
            self::assertNull($h->redis->readDemand($childId), $ctx.' the refused child was never written');
        }
    }

    private function actConsumeDemand(StepUpDemandWalkHarness $h, StepUpDemandWalkModel $m, string $ctx): void
    {
        $id = $m->randomLiveDemandId() ?? $m->anyDemandId();
        $demand = $m->demands[$id];
        $arrayAnswer = $h->array->consumeDemand($id);
        $redisAnswer = $h->redis->consumeDemand($id);
        if ($demand->present) {
            self::assertNotNull($arrayAnswer, $ctx.' consumeDemand');
            self::assertNotNull($redisAnswer, $ctx.' consumeDemand (redis)');
            $demand->present = false;
        } else {
            self::assertNull($arrayAnswer, $ctx.' consumeDemand refusal');
            self::assertNull($redisAnswer, $ctx.' consumeDemand refusal (redis)');
        }
    }

    private function actConsumeChallenge(StepUpDemandWalkHarness $h, StepUpDemandWalkModel $m, string $ctx): void
    {
        $id = $m->randomChallengeId();
        if ($id === null || !$m->challenges[$id]->present) {
            $this->actMintChallenge($h, $m, $ctx);

            return;
        }
        $challenge = $m->challenges[$id];
        $arrayAnswer = $h->array->consume($id);
        $redisAnswer = $h->redis->consume($id);
        self::assertNotNull($arrayAnswer, $ctx.' consume');
        self::assertNotNull($redisAnswer, $ctx.' consume (redis)');
        $challenge->present = false;
    }

    private function actMintChallenge(StepUpDemandWalkHarness $h, StepUpDemandWalkModel $m, string $ctx): void
    {
        $demandId = $m->randomLiveDemandId();
        if ($demandId === null) {
            return;
        }
        $scope = $m->demands[$demandId]->scope;
        $kind = mt_rand(0, 2) === 0 ? StepUpChallengeKind::Totp : StepUpChallengeKind::EmailOtp;
        $sessionBound = mt_rand(0, 1) === 0;
        $id = $m->nextChallengeId();
        $challenge = StepUpChallenge::begin(
            $id,
            $kind,
            self::PRINCIPAL,
            null,
            $scope,
            null,
            'post_solve_step_up_required',
            $h->now,
            self::TTL,
            5,
            $kind === StepUpChallengeKind::Totp ? null : str_repeat('a', 64),
            null,
            $sessionBound ? 'session-'.$id : null,
            false,
            false,
            null,
            $demandId,
        );
        $h->array->create($challenge, self::TTL);
        $h->redis->create($challenge, self::TTL);
        $stored = $h->array->read($id);
        self::assertNotNull($stored, $ctx.' the challenge record stands');
        $m->challenges[$id] = new ModelChallenge(
            $id,
            $demandId,
            $stored->scope,
            $stored->sessionHash,
            (string) ($stored->clientSecretHash ?? $stored->sessionHash),
            FactorRequirement::rankOf($stored->factor->family),
            $stored->factor->family,
        );
    }

    private function actRecordEffect(StepUpDemandWalkHarness $h, StepUpDemandWalkModel $m, string $ctx): void
    {
        $id = $m->randomLiveDemandId() ?? $m->anyDemandId();
        $demand = $m->demands[$id];
        $effects = [
            StepUpEffectsJournal::SETTLED,
            StepUpEffectsJournal::OUTCOME_CREDITED,
            StepUpEffectsJournal::SESSION_RESTORED,
            StepUpEffectsJournal::TRUST_WRITTEN,
            'not_an_effect',
        ];
        $effect = $effects[mt_rand(0, 4)];
        $arrayAnswer = $h->array->recordDemandEffect($id, $effect, $h->now);
        $redisAnswer = $h->redis->recordDemandEffect($id, $effect, $h->now);
        foreach (['array' => $arrayAnswer, 'redis' => $redisAnswer] as $lane => $answer) {
            $ok = $demand->present && $demand->lanes[$lane]->state === StepUpDemandState::Authorized && StepUpEffectsJournal::isEffect($effect);
            if ($ok) {
                self::assertNotNull($answer, $ctx.' recordEffect '.$effect.' ('.$lane.')');
                $demand->effects[$effect] = $h->now;
            } else {
                self::assertNull($answer, $ctx.' recordEffect refusal ('.$lane.')');
            }
        }
    }

    // ── the model comparison and the invariant probes ────────────────

    /**
     * Both stores' full observable state against the model, after one
     * action: presence, per-lane lifecycle state, the supersede marker
     * and every immutable binding field of every record, the challenge
     * presence, the escalation markers and the family tips.
     */
    private function assertStateMatches(StepUpDemandWalkHarness $h, StepUpDemandWalkModel $m, string $ctx): void
    {
        foreach ($m->demands as $id => $demand) {
            foreach (['array' => $h->array, 'redis' => $h->redis] as $lane => $store) {
                $record = $store->readDemand($id);
                if (!$demand->present) {
                    self::assertNull($record, $ctx.' the consumed demand '.$id.' reads as absent ('.$lane.')');
                    continue;
                }
                self::assertNotNull($record, $ctx.' the live demand '.$id.' stands ('.$lane.')');
                self::assertTrue($record->state === $demand->lanes[$lane]->state, $ctx.' state of '.$id.' ('.$lane.'): '.$record->state->value.' vs '.$demand->lanes[$lane]->state->value);
                self::assertSame($demand->lanes[$lane]->stateAt, $record->stateAt, $ctx.' stateAt of '.$id.' ('.$lane.')');
                self::assertSame($demand->supersededBy, $record->supersededByDemandId, $ctx.' marker of '.$id);
                self::assertSame($demand->parentDemandId, $record->parentDemandId, $ctx.' parent of '.$id);
                self::assertSame($demand->generation, $record->generation, $ctx.' generation of '.$id);
                self::assertSame($demand->createdAt, $record->createdAt, $ctx.' createdAt of '.$id);
                self::assertSame($demand->expiresAt, $record->expiresAt, $ctx.' expiry of '.$id);
                self::assertSame($demand->scope, $record->scope, $ctx.' scope of '.$id.' (a demand never switches scope)');
                self::assertSame($demand->sessionHash, $record->sessionHash, $ctx.' session binding of '.$id.' (a demand never switches browser)');
                self::assertSame($demand->decisionId, $record->decisionId, $ctx.' decision of '.$id);
                self::assertSame($demand->operationDigest, $record->operationDigest, $ctx.' operation binding of '.$id);
                self::assertNull($record->operationIdentityDigest, $ctx.' unsplit binding of '.$id);
                self::assertNull($record->operationContentDigest, $ctx.' unsplit binding of '.$id);
                self::assertSame($demand->factor, $record->factor, $ctx.' factor of '.$id);
                self::assertSame($demand->authorizedAt, $record->authorizedAt, $ctx.' authorizedAt of '.$id);
                self::assertSame($demand->requiredFactor?->family, $record->requiredFactor?->family, $ctx.' required family of '.$id);
                self::assertSame($demand->requiredFactor?->factorId, $record->requiredFactor?->factorId, $ctx.' required factor id of '.$id);
                self::assertSame($demand->requiredFactor?->assuranceRank, $record->requiredFactor?->assuranceRank, $ctx.' required rank of '.$id);
                self::assertSame(0, $record->sends, $ctx.' no send credit moved in the walk');
                self::assertNull($record->leaseUntilMs, $ctx.' no send lease held in the walk');
                $expectedFx = $demand->effects;
                ksort($expectedFx);
                $actualFx = $record->effects?->toArray() ?? [];
                ksort($actualFx);
                self::assertSame($expectedFx, $actualFx, $ctx.' effects journal of '.$id.' ('.$lane.')');

                // I8 + I9 on the stored records: a child inherits the
                // parent expiry exactly, and no family passes the cap.
                self::assertLessThanOrEqual(StepUpDemand::MAX_GENERATION, $record->generation, $ctx.' the generation cap holds');
                if ($record->parentDemandId !== null) {
                    $parentRecord = $store->readDemand($record->parentDemandId);
                    if ($parentRecord !== null) {
                        self::assertSame($parentRecord->expiresAt, $record->expiresAt, $ctx.' the child carries the parent deadline');
                        self::assertSame($parentRecord->scope, $record->scope, $ctx.' the child keeps the family scope');
                    }
                }
            }
        }
        foreach ($m->challenges as $id => $challenge) {
            foreach (['array' => $h->array, 'redis' => $h->redis] as $lane => $store) {
                $record = $store->read($id);
                if ($challenge->present) {
                    self::assertNotNull($record, $ctx.' the live challenge '.$id.' stands ('.$lane.')');
                    self::assertSame($challenge->demandId, $record->demandId, $ctx.' challenge binding of '.$id);
                } else {
                    self::assertNull($record, $ctx.' the consumed challenge '.$id.' reads as absent ('.$lane.')');
                }
            }
        }
        foreach ($m->familyTip as $digest => $tipId) {
            $expected = $m->demands[$tipId]->present ? $tipId : null;
            self::assertSame($expected, $h->array->demandIdForOperation($digest), $ctx.' family tip (array)');
            self::assertSame($expected, $h->redis->demandIdForOperation($digest), $ctx.' family tip (redis)');
        }
        foreach ($m->completedIndex as $sessionHash => $entry) {
            $expected = $h->now < $entry['expiresAt'] ? $entry['family'] : null;
            self::assertSame($expected, $h->array->completedFactorOf($sessionHash, $entry['scope'], $h->now), $ctx.' escalation marker (array)');
            self::assertSame($expected, $h->redis->completedFactorOf($sessionHash, $entry['scope'], $h->now), $ctx.' escalation marker (redis)');
        }
    }

    /**
     * The invariant probes: every refusal the model predicts is answered
     * by both stores, probed for real. Nothing here mutates a record the
     * model still expects to move: a predicted refusal moves nothing.
     */
    private function probeInvariants(StepUpDemandWalkHarness $h, StepUpDemandWalkModel $m, string $ctx, int $step): void
    {
        $ids = array_keys($m->demands);
        if ($ids !== []) {
            $id = $ids[$step % \count($ids)];
            $demand = $m->demands[$id];

            // I1 + I2 + I13: a settle to authorized is refused for every
            // demand the model predicts it refused, on both stores.
            if (!$this->laneSettle($demand, 'array', StepUpDemandState::Authorized) && !$this->laneSettle($demand, 'redis', StepUpDemandState::Authorized)) {
                self::assertNull($h->array->settleDemandFinalization($id, StepUpDemandState::Authorized, $h->now, 'email_otp'), $ctx.' I1/I2/I13 settle authorized refused (array)');
                self::assertNull($h->redis->settleDemandFinalization($id, StepUpDemandState::Authorized, $h->now, 'email_otp'), $ctx.' I1/I2/I13 settle authorized refused (redis)');
            }

            // I2 + I5: a non-open or superseded demand completes and
            // claims nothing.
            if (!$demand->present || $demand->supersededBy !== null || $demand->lanes['array']->state !== StepUpDemandState::Open) {
                self::assertNull($h->array->completeDemand($id, $h->now, self::TTL), $ctx.' I2 completeDemand refused (array)');
                self::assertNull($h->redis->completeDemand($id, $h->now, self::TTL), $ctx.' I2 completeDemand refused (redis)');
            }

            // I2 + I6 + I8: a supersede attempt answers null whenever
            // the model predicts it (terminal parent, marker, absent
            // parent) and for a supersede-able parent the expiry gate
            // refuses the foreign child; nothing is written either way.
            if ($demand->present) {
                $probeChildId = 'probe'.$step.str_pad((string) $id, 6, '0', STR_PAD_LEFT).'aaaa';
                $probeChild = $this->handMintChild($h, $id, $probeChildId, null, 60, $m);
                self::assertNull($h->array->supersedeDemandWithChild($id, $probeChild), $ctx.' I2/I6/I8 supersede probe refused (array)');
                self::assertNull($h->redis->supersedeDemandWithChild($id, $probeChild), $ctx.' I2/I6/I8 supersede probe refused (redis)');
                self::assertNull($h->array->readDemand($probeChildId), $ctx.' I2/I6/I8 the probed child was never written');
                self::assertNull($h->redis->readDemand($probeChildId), $ctx.' I2/I6/I8 the probed child was never written');
            }

            // I9: a family at the cap spawns no child.
            if ($demand->present && $demand->generation >= StepUpDemand::MAX_GENERATION) {
                $record = $h->array->readDemand($id);
                self::assertNotNull($record);
                try {
                    $record->spawnChild('cappedspawnid0000000000001', $h->now, 'decision-probe');
                    self::fail($ctx.' I9 spawnChild past the cap must throw');
                } catch (\LogicException) {
                    // the documented refusal
                }
            }
        }

        // I3 + I4: consumed challenges and demands answer null forever.
        if ($step % 3 === 0) {
            foreach ($m->challenges as $id => $challenge) {
                if ($challenge->present) {
                    continue;
                }
                self::assertNull($h->array->consume($id), $ctx.' I3 consume of a spent challenge (array)');
                self::assertNull($h->redis->consume($id), $ctx.' I3 consume of a spent challenge (redis)');
                self::assertNull($h->array->completeFactor($id, $challenge->demandId, $challenge->binding, $h->now, null), $ctx.' I3/I4 a spent challenge completes nothing');
                self::assertNull($h->redis->completeFactor($id, $challenge->demandId, $challenge->binding, $h->now, null), $ctx.' I3/I4 a spent challenge completes nothing');
            }
        }
        if ($step % 3 === 1) {
            foreach ($m->demands as $id => $demand) {
                if ($demand->present) {
                    continue;
                }
                self::assertNull($h->array->consumeDemand($id), $ctx.' I3 consume of a spent demand (array)');
                self::assertNull($h->redis->consumeDemand($id), $ctx.' I3 consume of a spent demand (redis)');
            }
        }
    }

    // ── helpers: the records, the lanes and the finalizer ────────────

    /**
     * Runs one deterministic scenario on a fresh pair of stores sharing
     * one explicit clock.
     *
     * @param \Closure(StepUpDemandWalkHarness): void $scenario
     */
    private function onBothLanes(\Closure $scenario): void
    {
        $scenario(new StepUpDemandWalkHarness(self::START));
    }

    /**
     * Mints one root demand on both stores (the same record, the same
     * family) and returns its id.
     */
    private function mintRootOn(StepUpDemandWalkHarness $h, StepUpChallengeStore $store, string $tag): string
    {
        $digest = StepUpOperationDigest::none($tag);
        $demand = StepUpDemand::mint($tag.'demandid00000000000001', $tag, null, null, 'decision-'.$tag, $h->now, self::TTL, StepUpOperationBindingKind::None, $digest);
        $id = $store->createRootDemand($demand, self::TTL);
        $other = $store === $h->array ? $h->redis : $h->array;
        self::assertSame($id, $other->createRootDemand($demand, self::TTL), 'the same root lands on both stores');

        return $id;
    }

    /** A challenge of one kind bound to one demand, on both stores. */
    private function mintChallengeOn(StepUpDemandWalkHarness $h, string $demandId, string $scope, StepUpChallengeKind $kind): string
    {
        $id = 'chal'.str_pad((string) ++self::$seq, 16, '0', STR_PAD_LEFT).'aaaaaaaaaa';
        $challenge = StepUpChallenge::begin(
            $id,
            $kind,
            self::PRINCIPAL,
            null,
            $scope,
            null,
            'post_solve_step_up_required',
            $h->now,
            self::TTL,
            5,
            $kind === StepUpChallengeKind::Totp ? null : str_repeat('a', 64),
            null,
            null,
            false,
            false,
            null,
            $demandId,
        );
        $h->array->create($challenge, self::TTL);
        $h->redis->create($challenge, self::TTL);

        return $id;
    }

    /** A hand-minted escalation child with an explicit requirement. */
    private function handMintChild(StepUpDemandWalkHarness $h, string $parentId, string $childId, ?FactorRequirement $required, int $extraTtl, ?StepUpDemandWalkModel $m = null): StepUpDemand
    {
        $scope = $m !== null
            ? $m->demands[$parentId]->scope
            : (string) $h->array->readDemand($parentId)?->scope;
        $expiresAt = $m !== null
            ? $m->demands[$parentId]->expiresAt
            : (int) $h->array->readDemand($parentId)?->expiresAt;

        return StepUpDemand::mint(
            $childId,
            $scope,
            null,
            null,
            'decision-child',
            $h->now,
            $expiresAt + $extraTtl - $h->now,
            StepUpOperationBindingKind::None,
            StepUpOperationDigest::none($scope),
            null,
            null,
            false,
            $parentId,
            $required,
        );
    }

    /** The verified proof of one rung, for the finalizer lanes. */
    private function proof(string $demandId, StepUpChallengeKind $kind, StepUpDemandWalkHarness $h): StepUpResult
    {
        $assurance = match ($kind) {
            StepUpChallengeKind::EmailOtp => StepUpFactorAssurance::emailOtp(),
            StepUpChallengeKind::Totp => StepUpFactorAssurance::totp(),
            StepUpChallengeKind::WebAuthn => StepUpFactorAssurance::webauthn(),
            StepUpChallengeKind::EmailOwnership => StepUpFactorAssurance::emailOwnership(),
        };
        $challenge = StepUpChallenge::begin(
            'proof'.str_pad((string) ++self::$seq, 16, '0', STR_PAD_LEFT).'aaaaa',
            $kind,
            self::PRINCIPAL,
            null,
            self::SCOPE,
            null,
            'post_solve_step_up_required',
            $h->now,
            300,
            5,
            str_repeat('a', 64),
            null,
            null,
            false,
            false,
            null,
            $demandId,
        );

        return StepUpResult::proved($challenge, $assurance);
    }

    /**
     * The finalizer over one lane: the risk gateway answers exactly the
     * minimum action under test, the outcome reporter is a spy.
     */
    private function finalizer(StepUpChallengeStore $store, StepUpDemandWalkHarness $h, string $minimum, SpyOutcomeReporter $reporter): StepUpDemandFinalizer
    {
        return new StepUpDemandFinalizer(
            $store,
            new StepUpCompletionCredit($reporter, self::MASTER),
            null,
            self::gateway($minimum),
            null,
            null,
            null,
            null,
            fn (): int => $h->now,
            self::MASTER,
            new StepUpFactorResolver('email_otp'),
        );
    }

    /**
     * The risk gateway of the reassessment: the scope minimum is the
     * one knob the test moves, so the fresh decision answers exactly
     * the action under test.
     */
    private static function gateway(string $minimum): RiskGateway
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => $minimum, 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $engine = new AdaptiveRiskEngine(new FakeRiskStateStore(), $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);

        return new RiskGateway($engine, $classifier, new RiskProfileResolver(PoWAlgorithm::Sha256, 8), [self::SCOPE => 1], policy: $policy);
    }

    /** The lane legality of a finalization claim, per the model. */
    private function laneClaim(ModelDemand $demand, string $lane, int $now, int $claimSecs): bool
    {
        if (!$demand->present || $demand->supersededBy !== null) {
            return false;
        }
        $state = $demand->lanes[$lane];
        if ($state->state === StepUpDemandState::Completed) {
            return true;
        }
        if ($state->state === StepUpDemandState::Finalizing) {
            return ($now - ($state->stateAt ?? 0)) >= $claimSecs;
        }

        return false;
    }

    /** The lane legality of a terminal settlement, per the model. */
    private function laneSettle(ModelDemand $demand, string $lane, StepUpDemandState $terminal): bool
    {
        if (!$demand->present || $demand->lanes[$lane]->state !== StepUpDemandState::Finalizing) {
            return false;
        }
        if ($terminal === StepUpDemandState::Authorized && $demand->supersededBy !== null) {
            return false;
        }

        return true;
    }
}

/**
 * The two stores of one scenario on one explicit clock. The array
 * store's injected closure and the fake Redis server time advance
 * together, so every clock decision (the claim window, the expiry
 * judgement of the escalation script) is identical on both lanes.
 */
final class StepUpDemandWalkHarness
{
    public int $now;

    public readonly ArrayStepUpChallengeStore $array;

    public readonly RedisStepUpChallengeStore $redis;

    public readonly FakePredisClient $fake;

    public function __construct(int $now)
    {
        $this->now = $now;
        $this->fake = new FakePredisClient();
        $this->fake->setTimeMs($now * 1000);
        $this->array = new ArrayStepUpChallengeStore(fn (): int => $this->now);
        $this->redis = new RedisStepUpChallengeStore($this->fake, '{kiwi:prop-ns}:stepup:');
    }

    /** Advances the shared clock (both lanes see the same second). */
    public function setNow(int $now): void
    {
        $this->now = $now;
        $this->fake->setTimeMs($now * 1000);
    }
}

/**
 * The clean-room reference model of the demand state machine. It holds
 * the lifecycle state per lane, the supersede marker, the family tips,
 * the escalation markers and every immutable binding field the stores
 * must never move. The lane split models the documented asymmetry: the
 * Redis supersede leaves the parent state field behind the marker, the
 * array store writes the superseded terminal.
 */
final class StepUpDemandWalkModel
{
    /** @var array<string, ModelDemand> */
    public array $demands = [];

    /** @var array<string, ModelChallenge> */
    public array $challenges = [];

    /** @var array<string, string> operation digest -> family tip id */
    public array $familyTip = [];

    /** @var array<string, array{scope: string, family: string, expiresAt: int}> session hash -> escalation marker */
    public array $completedIndex = [];

    private int $counter = 0;

    private int $challengeCounter = 0;

    /** @return list<string> */
    public function liveDemandIds(): array
    {
        $ids = [];
        foreach ($this->demands as $id => $demand) {
            if ($demand->present) {
                $ids[] = $id;
            }
        }

        return $ids;
    }

    public function randomLiveDemandId(): ?string
    {
        $ids = $this->liveDemandIds();

        return $ids === [] ? null : $ids[mt_rand(0, \count($ids) - 1)];
    }

    public function anyDemandId(): string
    {
        $ids = array_keys($this->demands);
        if ($ids === []) {
            throw new \LogicException('the model has no demand to act on');
        }

        return $ids[mt_rand(0, \count($ids) - 1)];
    }

    public function randomChallengeId(): ?string
    {
        $ids = array_keys($this->challenges);
        if ($ids === []) {
            return null;
        }

        return $ids[mt_rand(0, \count($ids) - 1)];
    }

    /** The deterministic record id of the walk (the base64url shape). */
    public function nextDemandId(): string
    {
        return 'd'.str_pad((string) ++$this->counter, 6, '0', STR_PAD_LEFT).'aaaaaaaaaaaaaaaa';
    }

    /** The deterministic challenge id of the walk (the base64url shape). */
    public function nextChallengeId(): string
    {
        return 'c'.str_pad((string) ++$this->challengeCounter, 6, '0', STR_PAD_LEFT).'bbbbbbbbbbbbbbbb';
    }
}

/** The model projection of one demand record. */
final class ModelDemand
{
    /** @var array<string, ModelLaneState> the per-lane lifecycle state */
    public array $lanes;

    /**
     * @param array<string, int> $effects
     */
    public function __construct(
        public readonly string $id,
        public readonly string $scope,
        public readonly ?string $sessionHash,
        public readonly ?string $decisionId,
        public readonly int $createdAt,
        public readonly int $expiresAt,
        public readonly string $operationDigest,
        public readonly ?string $parentDemandId,
        public readonly int $generation,
        public readonly ?FactorRequirement $requiredFactor,
        public bool $present = true,
        public ?string $supersededBy = null,
        public ?string $factor = null,
        public ?int $authorizedAt = null,
        public array $effects = [],
    ) {
        $this->lanes = [
            'array' => new ModelLaneState(),
            'redis' => new ModelLaneState(),
        ];
    }

    /** The model of a minted root. */
    public static function fromMint(StepUpDemand $demand, int $now): self
    {
        return new self(
            $demand->id,
            $demand->scope,
            $demand->sessionHash,
            $demand->decisionId,
            $now,
            $demand->expiresAt,
            $demand->operationDigest,
            null,
            0,
            $demand->requiredFactor,
        );
    }

    /** The model of a minted escalation child. */
    public static function fromChild(StepUpDemand $child, string $parentId, self $parent, int $now): self
    {
        return new self(
            $child->id,
            $parent->scope,
            $parent->sessionHash,
            $child->decisionId,
            $now,
            $parent->expiresAt,
            $parent->operationDigest,
            $parentId,
            $child->generation,
            $child->requiredFactor,
        );
    }
}

/** The per-lane lifecycle state of one model demand. */
final class ModelLaneState
{
    public StepUpDemandState $state = StepUpDemandState::Open;

    public ?int $stateAt = null;
}

/** The model projection of one challenge record. */
final class ModelChallenge
{
    public bool $present = true;

    public function __construct(
        public readonly string $id,
        public readonly string $demandId,
        public readonly string $scope,
        public readonly ?string $sessionHash,
        public readonly string $binding,
        public readonly int $rank,
        public readonly string $family,
    ) {
    }
}
