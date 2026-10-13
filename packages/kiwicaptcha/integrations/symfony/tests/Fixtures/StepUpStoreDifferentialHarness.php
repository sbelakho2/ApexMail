<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandSendSettlement;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpEffectsJournal;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationDigest;

/**
 * The randomized differential engine of the two step-up stores. The
 * emulated-client lane (StepUpStoreDifferentialTest) and the
 * real-Predis lane (StepUpStoreDifferentialRealPredisTest) share this
 * class verbatim. One seeded generator emits a legal operation
 * sequence and executes every action on both stores. After every
 * action the engine asserts the full observable projection of the two
 * stores agrees. The projection covers: record presence, lifecycle
 * state, supersession links, generation, send counters, lease
 * presence, the inherited authorization deadline, operation family
 * tips, completion markers, the raw quota counters, and the
 * replay-guard, begin-window, marker and enrollment answers.
 *
 * The clock asymmetry the engine is built around: the array store
 * judges its internal expiries on the injected clock this harness
 * owns, while the Redis scripts judge liveness on the Redis server
 * time. The server clock cannot be fast-forwarded, so the harness
 * never models expiry through TTL passage. Every record carries a
 * generous TTL (about a day) that outlives any sequence. Expiry is
 * modeled as an explicit harness action that removes the record from
 * both stores by the equivalent external action (consumeDemand or
 * consume). The equivalence argument: once a record is gone, both
 * stores answer the same observable shape an expired record answers
 * (null reads, -1 attempt accounting, a dead family tip), because
 * both judge absence before every other gate. Record ids are never
 * reused after removal, so no store ever sees a stale key behind a
 * reused id.
 *
 * On the real lane the harness clock resynchronizes to the wall clock
 * before every action. The array store then judges the same seconds
 * the Redis server does. Every randomized time-dependent parameter
 * (the resend spacing, the claim window) is chosen large enough that
 * no boundary can flip between the two calls of one action.
 * Store-owned time boundaries whose acceptance needs a window to pass
 * (the finalization claim retake, the send-lease recovery) are
 * deterministic on the emulated lane, where both clocks advance
 * together via the tick action. On the real lane those boundaries
 * belong to the dedicated sleep-bound sequences of the companion
 * test, never to the randomized runs.
 *
 * Documented normalizations of the comparison surface:
 *
 *  - stateAt, leaseUntilMs and lastSentAt are compared for presence,
 *    never for value. The array store stamps its own clock second
 *    while the Redis scripts stamp the server second plus its
 *    sub-second millisecond remainder.
 *  - The lifecycle state compares raw. Both stores write the
 *    superseded terminal inside the supersede transaction itself
 *    (state, stamp and child link together), so no projection is
 *    needed and the raw states must agree. Every transition gate judges
 *    the marker, so both stores refuse the same operations; the raw
 *    state field itself differs, and each store suite pins its own
 *    shape. The projection treats marker and state as the one
 *    superseded-ness they both mean. StepUpStoreDifferentialTest pins
 *    the divergence loudly.
 *  - The quota counters have no array-side accessor. Their projection
 *    is the harness model, asserted against the raw Redis counter on
 *    every step, and against the array store behaviorally through the
 *    reserve and release answers that built the model.
 *  - lockoutUntil stays out of the projection sweep: armLockout
 *    writes and the pool never reads the deadline back. The deadline
 *    contract itself is parity. Both stores answer epoch seconds,
 *    the unit the interface contract names, and the fake emulates
 *    the lock-arm script, so the emulated lane arms the deadline
 *    exactly like the real one. The dedicated pins in the store
 *    suites carry that parity.
 *  - The emulated client never lazily expires an armed key, so a
 *    reservation release is only emitted inside its lease window.
 *    Past the window the fake would answer true while the array store
 *    refuses. The real server expires the marker and agrees with the
 *    array store; the past-lease behavior is pinned by the dedicated
 *    suites.
 */
final class StepUpStoreDifferentialHarness
{
    public const LANE_STANDARD = 'standard';

    public const LANE_REAL = 'real';

    private const SCOPES = ['login', 'signup', 'signup_confirm', 'signup_email'];

    private const EFFECTS = [
        StepUpEffectsJournal::SETTLED,
        StepUpEffectsJournal::OUTCOME_CREDITED,
        StepUpEffectsJournal::SESSION_RESTORED,
        StepUpEffectsJournal::TRUST_WRITTEN,
    ];

    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    private const LOCKOUT_PSEUDONYM = 'aabbccddeeff00112233445566778899';

    private const LOCKOUT_DIMENSION = 'principal';

    /** The record TTL: hours, so nothing expires while a sequence runs. */
    private const RECORD_TTL = 100000;

    /** The quota budget window: it outlives any sequence, like every TTL here. */
    private const QUOTA_WINDOW = 100000;

    private const QUOTA_LEASE = 30;

    /** @var \Closure fn(bool $condition, string $message): void */
    private readonly \Closure $assert;

    /** The shared clock box: a \stdClass with one public int $now. */
    private readonly \stdClass $clock;

    /** @var array<string, array{state: StepUpDemandState, supersededBy: ?string, generation: int, live: bool, lease: ?array{leaseA: StepUpDemandSendLease, leaseR: StepUpDemandSendLease}}> */
    private array $demands = [];

    /** @var array<string, array{record: StepUpChallenge, demandId: ?string, live: bool, binding: string}> */
    private array $challenges = [];

    /** @var array<string, string> family digest -> the family tip the model tracks */
    private array $families = [];

    /** @var list<string> every demand id ever minted (the sweep order) */
    private array $demandOrder = [];

    /** @var list<string> every challenge id ever minted */
    private array $challengeOrder = [];

    /** @var list<string> every budget key ever touched */
    private array $budgetOrder = [];

    /** @var array<string, int> budget key -> the model count both stores must agree on */
    private array $quotaCounts = [];

    /** @var array<string, array{keys: list<string>, leaseUntil: int, releasable: bool}> */
    private array $reservations = [];

    /** @var list<array{0: string, 1: string}> the (session hash, scope) pairs a completion may have marked */
    private array $sessionMarks = [];

    private int $demandSeq = 0;

    private int $challengeSeq = 0;

    private int $reservationSeq = 0;

    private int $totpMarked = 0;

    private int $beginCount = 0;

    private int $lockFails = 0;

    private int $seedTag = 0;

    public function __construct(
        private readonly StepUpChallengeStore $arrayStore,
        private readonly StepUpChallengeStore $redisStore,
        private readonly ?\Predis\Client $rawRedis,
        \stdClass $clock,
        private readonly string $lane,
        private readonly string $redisPrefix,
        ?\Closure $assert = null,
    ) {
        $this->clock = $clock;
        $this->assert = $assert ?? static function (bool $condition, string $message): void {
            if (!$condition) {
                throw new \RuntimeException($message);
            }
        };
    }

    /**
     * Run one seeded sequence of $steps actions. Deterministic: the
     * generator is seeded per call, so a failure message naming the
     * seed and the step reproduces exactly.
     */
    public function runSequence(int $seed, int $steps): void
    {
        $this->seedTag = $seed;
        mt_srand($seed);
        for ($step = 1; $step <= $steps; ++$step) {
            $this->syncClocks();
            $candidates = $this->candidateActions();
            $index = mt_rand(0, \count($candidates) - 1);
            $action = $candidates[$index];
            $ctx = 'seed '.$seed.' step '.$step.' '.$action['label'];
            try {
                ($action['run'])($ctx);
            } catch (\Throwable $e) {
                ($this->assert)(false, $ctx.' raised '.$e::class.': '.$e->getMessage());
            }
            $this->compareProjection($ctx);
        }
    }

    /** Keep the harness clock and the fake server clock in lockstep. */
    private function syncClocks(): void
    {
        if ($this->lane === self::LANE_REAL) {
            $this->clock->now = max($this->clock->now, time());

            return;
        }
        if ($this->rawRedis instanceof FakePredisClient) {
            $this->rawRedis->setTimeMs($this->clock->now * 1000);
        }
    }

    // ── the candidate pool ──────────────────────────────────────────

    /**
     * The legal action pool: every candidate is legal for the current
     * model state, or is an explicit refusal probe whose expected
     * outcome is that both stores refuse equivalently. The tick action
     * advances both clocks together and exists on the emulated lane
     * only. The real server clock cannot be fast-forwarded.
     *
     * @return list<array{label: string, run: \Closure}>
     */
    private function candidateActions(): array
    {
        $candidates = [];

        $candidates[] = ['label' => 'createRootDemand', 'run' => $this->actionCreateRootDemand()];
        $candidates[] = ['label' => 'createDemand', 'run' => $this->actionCreateDemand()];
        if ($this->demandOrder !== []) {
            $candidates[] = ['label' => 'readDemand', 'run' => $this->actionReadDemand()];
        }
        if ($this->families !== []) {
            $candidates[] = ['label' => 'probeFamilyTip', 'run' => $this->actionProbeFamilyTip()];
        }
        if ($this->liveDemandIds() !== []) {
            $candidates[] = ['label' => 'consumeDemand', 'run' => $this->actionConsumeDemand(false)];
            $candidates[] = ['label' => 'expireDemand', 'run' => $this->actionConsumeDemand(true)];
            $candidates[] = ['label' => 'completeDemand', 'run' => $this->actionCompleteDemand()];
            $candidates[] = ['label' => 'supersedeDemandWithChild', 'run' => $this->actionSupersede()];
            $candidates[] = ['label' => 'claimDemandSendLease', 'run' => $this->actionClaimSendLease()];
        }
        if ($this->claimableDemandIds() !== []) {
            $candidates[] = ['label' => 'claimDemandFinalization', 'run' => $this->actionClaimFinalization()];
        }
        if ($this->finalizableDemandIds() !== []) {
            $candidates[] = ['label' => 'settleDemandFinalization', 'run' => $this->actionSettleFinalization()];
        }
        if ($this->authorizedDemandIds() !== []) {
            $candidates[] = ['label' => 'recordDemandEffect', 'run' => $this->actionRecordEffect()];
        }
        if ($this->settleableLeases() !== []) {
            $candidates[] = ['label' => 'settleDemandSendLease', 'run' => $this->actionSettleSendLease()];
        }
        $candidates[] = ['label' => 'createChallenge', 'run' => $this->actionCreateChallenge()];
        if ($this->challengeOrder !== []) {
            $candidates[] = ['label' => 'readChallenge', 'run' => $this->actionReadChallenge()];
        }
        if ($this->liveChallengeIds() !== []) {
            $candidates[] = ['label' => 'consumeChallenge', 'run' => $this->actionConsumeChallenge(false)];
            $candidates[] = ['label' => 'expireChallenge', 'run' => $this->actionConsumeChallenge(true)];
            $candidates[] = ['label' => 'recordFailure', 'run' => $this->actionRecordFailure()];
            $candidates[] = ['label' => 'completeFactor', 'run' => $this->actionCompleteFactor()];
        }
        if ($this->sessionMarks !== []) {
            $candidates[] = ['label' => 'probeCompletedFactor', 'run' => $this->actionProbeCompletedFactor()];
        }
        $candidates[] = ['label' => 'reserveMailQuota', 'run' => $this->actionReserveQuota()];
        if ($this->releasableReservations() !== []) {
            $candidates[] = ['label' => 'releaseMailQuota', 'run' => $this->actionReleaseQuota()];
        }
        if ($this->liveReservationIds() !== []) {
            $candidates[] = ['label' => 'commitMailQuota', 'run' => $this->actionCommitQuota()];
        }
        $candidates[] = ['label' => 'countBegin', 'run' => $this->actionCountBegin()];
        $candidates[] = ['label' => 'markTotpStep', 'run' => $this->actionMarkTotpStep()];
        $candidates[] = ['label' => 'totpSecret', 'run' => $this->actionTotpSecret()];
        $candidates[] = ['label' => 'stepUpMarker', 'run' => $this->actionStepUpMarker()];
        $candidates[] = ['label' => 'sessionStepUpMarker', 'run' => $this->actionSessionMarker()];
        $candidates[] = ['label' => 'lockout', 'run' => $this->actionLockout()];
        if ($this->lane === self::LANE_STANDARD) {
            $candidates[] = ['label' => 'tick', 'run' => $this->actionTick()];
            $candidates[] = ['label' => 'tick', 'run' => $this->actionTick()];
        }

        return $candidates;
    }

    // ── demand actions ──────────────────────────────────────────────

    private function actionCreateRootDemand(): \Closure
    {
        return function (string $ctx): void {
            $scope = self::SCOPES[mt_rand(0, \count(self::SCOPES) - 1)];
            $digest = StepUpOperationDigest::none($scope);
            $id = $this->nextDemandId();
            $demand = $this->mintDemand($id, $scope);
            $a = $this->arrayStore->createRootDemand($demand, self::RECORD_TTL);
            $r = $this->redisStore->createRootDemand($demand, self::RECORD_TTL);
            ($this->assert)($a === $r, $ctx.': the root mint answered different ids ('.$a.' vs '.$r.')');
            $tip = $this->families[$digest] ?? null;
            if ($tip !== null && $this->demands[$tip]['live']) {
                ($this->assert)($a === $tip, $ctx.': a standing tip must be answered as-is ('.$a.' vs tip '.$tip.')');
            } else {
                ($this->assert)($a === $id, $ctx.': a dead family must mint the fresh root ('.$a.' vs '.$id.')');
                $this->registerDemand($id, $demand);
                $this->families[$digest] = $id;
            }
        };
    }

    private function actionCreateDemand(): \Closure
    {
        return function (string $ctx): void {
            $id = $this->nextDemandId();
            $scope = self::SCOPES[mt_rand(0, \count(self::SCOPES) - 1)];
            $demand = $this->mintDemand($id, $scope);
            $a = $this->arrayStore->createDemand($demand, self::RECORD_TTL);
            $r = $this->redisStore->createDemand($demand, self::RECORD_TTL);
            ($this->assert)($a === $r && $a === $id, $ctx.': the create answers diverge ('.$a.' vs '.$r.')');
            $this->registerDemand($id, $demand);
        };
    }

    private function actionReadDemand(): \Closure
    {
        return function (string $ctx): void {
            $id = $this->demandOrder[array_rand($this->demandOrder)];
            $a = $this->arrayStore->readDemand($id);
            $r = $this->redisStore->readDemand($id);
            ($this->assert)($this->demandProjection($a) === $this->demandProjection($r), $ctx.'('.$id.'): the read projections diverge');
        };
    }

    /**
     * Consume the record from both stores. The $expiry flag marks the
     * modeled-expiry lane of the same external action (see the class
     * docblock for the equivalence argument).
     */
    private function actionConsumeDemand(bool $expiry): \Closure
    {
        return function (string $ctx) use ($expiry): void {
            $id = $this->liveDemandIds()[array_rand($this->liveDemandIds())];
            $a = $this->arrayStore->consumeDemand($id);
            $r = $this->redisStore->consumeDemand($id);
            ($this->assert)($this->demandProjection($a) === $this->demandProjection($r), $ctx.'('.$id.'): the consume answers diverge');
            ($this->assert)($a !== null && $r !== null, $ctx.'('.$id.'): a live demand must consume to a record on both stores');
            $this->demands[$id]['live'] = false;
            $this->demands[$id]['lease'] = null;
        };
    }

    private function actionCompleteDemand(): \Closure
    {
        return function (string $ctx): void {
            $open = array_values(array_filter($this->liveDemandIds(), fn (string $id): bool => $this->isOpenDemand($id)));
            $id = $open !== [] && mt_rand(0, 3) !== 0
                ? $open[array_rand($open)]
                : $this->liveDemandIds()[array_rand($this->liveDemandIds())];
            $legal = $this->isOpenDemand($id);
            $a = $this->arrayStore->completeDemand($id, $this->clock->now, self::RECORD_TTL);
            $r = $this->redisStore->completeDemand($id, $this->clock->now, self::RECORD_TTL);
            ($this->assert)($this->demandProjection($a) === $this->demandProjection($r), $ctx.'('.$id.'): the completion answers diverge');
            if ($legal) {
                ($this->assert)($a !== null, $ctx.'('.$id.'): the model judged the completion legal but the store refused');
                $this->demands[$id]['state'] = StepUpDemandState::Completed;
            } else {
                ($this->assert)($a === null && $r === null, $ctx.'('.$id.'): an illegal completion must refuse equivalently');
            }
        };
    }

    private function actionClaimFinalization(): \Closure
    {
        return function (string $ctx): void {
            $id = $this->claimableDemandIds()[array_rand($this->claimableDemandIds())];
            // The real lane never draws the 1 second window: the retake
            // boundary must never flip between the two calls of one
            // action on the wall clock. The dedicated companion test
            // walks that boundary with an explicit sleep.
            $claimSecs = $this->lane === self::LANE_REAL ? 60 : [1, 30, 60][mt_rand(0, 2)];
            $a = $this->arrayStore->claimDemandFinalization($id, $this->clock->now, $claimSecs);
            $r = $this->redisStore->claimDemandFinalization($id, $this->clock->now, $claimSecs);
            ($this->assert)($this->demandProjection($a) === $this->demandProjection($r), $ctx.'('.$id.','.$claimSecs.'): the claim answers diverge');
            if ($a !== null) {
                $this->demands[$id]['state'] = StepUpDemandState::Finalizing;
            }
        };
    }

    private function actionSettleFinalization(): \Closure
    {
        return function (string $ctx): void {
            $id = $this->finalizableDemandIds()[array_rand($this->finalizableDemandIds())];
            $terminal = [StepUpDemandState::Authorized, StepUpDemandState::Denied, StepUpDemandState::Superseded][mt_rand(0, 2)];
            $a = $this->arrayStore->settleDemandFinalization($id, $terminal, $this->clock->now);
            $r = $this->redisStore->settleDemandFinalization($id, $terminal, $this->clock->now);
            ($this->assert)($this->demandProjection($a) === $this->demandProjection($r), $ctx.'('.$id.','.$terminal->value.'): the settle answers diverge');
            if ($a !== null) {
                $this->demands[$id]['state'] = $terminal;
            }
        };
    }

    private function actionRecordEffect(): \Closure
    {
        return function (string $ctx): void {
            $id = $this->authorizedDemandIds()[array_rand($this->authorizedDemandIds())];
            $effect = mt_rand(0, 5) === 0 ? 'not_a_journal_effect' : self::EFFECTS[mt_rand(0, 3)];
            $a = $this->arrayStore->recordDemandEffect($id, $effect, $this->clock->now);
            $r = $this->redisStore->recordDemandEffect($id, $effect, $this->clock->now);
            ($this->assert)($this->demandProjection($a) === $this->demandProjection($r), $ctx.'('.$id.','.$effect.'): the journal answers diverge');
        };
    }

    private function actionSupersede(): \Closure
    {
        return function (string $ctx): void {
            $supersedeable = array_values(array_filter(
                $this->liveDemandIds(),
                fn (string $id): bool => $this->canSupersede($id),
            ));
            $id = $supersedeable !== [] && mt_rand(0, 3) !== 0
                ? $supersedeable[array_rand($supersedeable)]
                : $this->liveDemandIds()[array_rand($this->liveDemandIds())];
            $legal = $this->canSupersede($id);
            $parent = $this->arrayStore->readDemand($id);
            ($this->assert)($parent !== null, $ctx.'('.$id.'): the model tracks a demand the array store lost');
            // The child is always spawned from the live parent record,
            // so the parent link and the inherited expiry match by
            // construction. A forged parent link is the pinned
            // divergence lane of the differential test, never a
            // randomized emission.
            $child = $parent->spawnChild($this->nextChildId(), $this->clock->now, 'decision-'.$this->demandSeq);
            $a = $this->arrayStore->supersedeDemandWithChild($id, $child);
            $r = $this->redisStore->supersedeDemandWithChild($id, $child);
            ($this->assert)($this->demandProjection($a) === $this->demandProjection($r), $ctx.'('.$id.' -> '.$child->id.'): the supersede answers diverge');
            if ($legal) {
                ($this->assert)($a !== null, $ctx.'('.$id.'): the model judged the supersede legal but the store refused');
                $this->demands[$id]['state'] = StepUpDemandState::Superseded;
                $this->demands[$id]['supersededBy'] = $child->id;
                $this->registerDemand($child->id, $child);
                $this->families[$child->operationDigest] = $child->id;
            } else {
                ($this->assert)($a === null && $r === null, $ctx.'('.$id.'): an illegal supersede must refuse equivalently');
            }
        };
    }

    private function actionClaimSendLease(): \Closure
    {
        return function (string $ctx): void {
            $id = $this->liveDemandIds()[array_rand($this->liveDemandIds())];
            // The real lane pins the spacing at 60: the run takes far
            // less than a minute, so the spacing refusal cannot flip
            // between the two calls of one action on the wall clock.
            $resendAfter = $this->lane === self::LANE_REAL ? 60 : [10, 30, 60][mt_rand(0, 2)];
            $leaseSecs = [15, 300][mt_rand(0, 1)];
            $a = $this->arrayStore->claimDemandSendLease($id, $resendAfter, $leaseSecs);
            $r = $this->redisStore->claimDemandSendLease($id, $resendAfter, $leaseSecs);
            ($this->assert)(($a === null) === ($r === null), $ctx.'('.$id.'): one store claimed a lease the other refused');
            if ($a !== null && $r !== null) {
                ($this->assert)($a->recovered === $r->recovered, $ctx.'('.$id.'): the recovery flags diverge');
                ($this->assert)($a->priorSends === $r->priorSends, $ctx.'('.$id.'): the prior send counters diverge');
                ($this->assert)(($a->priorLastSentAt === null) === ($r->priorLastSentAt === null), $ctx.'('.$id.'): the prior delivery stamps diverge');
                ($this->assert)($this->demandProjection($a->demand) === $this->demandProjection($r->demand), $ctx.'('.$id.'): the claimed record projections diverge');
                $this->demands[$id]['lease'] = ['leaseA' => $a, 'leaseR' => $r];
            }
        };
    }

    private function actionSettleSendLease(): \Closure
    {
        return function (string $ctx): void {
            $id = $this->settleableLeases()[array_rand($this->settleableLeases())];
            $lease = $this->demands[$id]['lease'];
            $leaseA = $lease['leaseA'];
            $leaseR = $lease['leaseR'];
            $delivered = mt_rand(0, 1) === 1;
            $settlementA = new StepUpDemandSendSettlement($id, $leaseA->leaseUntilMs, $leaseA->claimAt, $leaseA->priorSends, $leaseA->priorLastSentAt, $delivered);
            $settlementR = new StepUpDemandSendSettlement($id, $leaseR->leaseUntilMs, $leaseR->claimAt, $leaseR->priorSends, $leaseR->priorLastSentAt, $delivered);
            $a = $this->arrayStore->settleDemandSendLease($settlementA);
            $r = $this->redisStore->settleDemandSendLease($settlementR);
            ($this->assert)($a === $r, $ctx.'('.$id.',delivered='.(int) $delivered.'): the settlement answers diverge (array='.(int) $a.' stampA='.$leaseA->leaseUntilMs.' storedA='.json_encode($this->arrayStore->readDemand($id)?->leaseUntilMs).' redis='.(int) $r.' stampR='.$leaseR->leaseUntilMs.' storedR='.json_encode($this->redisStore->readDemand($id)?->leaseUntilMs).')');
            $this->demands[$id]['lease'] = null;
        };
    }

    // ── challenge actions ───────────────────────────────────────────

    private function actionCreateChallenge(): \Closure
    {
        return function (string $ctx): void {
            $id = $this->nextChallengeId();
            $sessionBound = mt_rand(0, 1) === 1;
            $sessionId = $sessionBound ? 'diff-session-'.$this->challengeSeq : null;
            $boundDemand = null;
            if ($this->liveDemandIds() !== [] && mt_rand(0, 2) !== 0) {
                $boundDemand = $this->liveDemandIds()[array_rand($this->liveDemandIds())];
            }
            $challenge = StepUpChallenge::begin(
                $id,
                StepUpChallengeKind::EmailOtp,
                self::PRINCIPAL,
                null,
                'login',
                null,
                'post_solve_step_up_required',
                $this->clock->now,
                self::RECORD_TTL,
                5,
                str_repeat('a', 64),
                null,
                $sessionId,
                false,
                false,
                null,
                $boundDemand,
            );
            $a = $this->arrayStore->create($challenge, self::RECORD_TTL);
            $r = $this->redisStore->create($challenge, self::RECORD_TTL);
            ($this->assert)($a === $r && $a === $id, $ctx.': the challenge create answers diverge ('.$a.' vs '.$r.')');
            $this->challenges[$id] = [
                'record' => $challenge,
                'demandId' => $boundDemand,
                'live' => true,
                'binding' => $sessionBound ? (string) $challenge->sessionHash : (string) $challenge->clientSecretHash,
            ];
            $this->challengeOrder[] = $id;
        };
    }

    private function actionReadChallenge(): \Closure
    {
        return function (string $ctx): void {
            $id = $this->challengeOrder[array_rand($this->challengeOrder)];
            $a = $this->arrayStore->read($id);
            $r = $this->redisStore->read($id);
            ($this->assert)($this->challengeProjection($a) === $this->challengeProjection($r), $ctx.'('.$id.'): the challenge reads diverge');
        };
    }

    private function actionConsumeChallenge(bool $expiry): \Closure
    {
        return function (string $ctx) use ($expiry): void {
            $id = $this->liveChallengeIds()[array_rand($this->liveChallengeIds())];
            $a = $this->arrayStore->consume($id);
            $r = $this->redisStore->consume($id);
            ($this->assert)($this->challengeProjection($a) === $this->challengeProjection($r), $ctx.'('.$id.'): the challenge consumes diverge');
            ($this->assert)($a !== null && $r !== null, $ctx.'('.$id.'): a live challenge must consume to a record on both stores');
            $this->challenges[$id]['live'] = false;
        };
    }

    private function actionRecordFailure(): \Closure
    {
        return function (string $ctx): void {
            $id = $this->liveChallengeIds()[array_rand($this->liveChallengeIds())];
            $a = $this->arrayStore->recordFailure($id, 3);
            $r = $this->redisStore->recordFailure($id, 3);
            ($this->assert)($a === $r, $ctx.'('.$id.'): the attempt accounting diverged ('.$a.' vs '.$r.')');
            if ($a <= 0) {
                $this->challenges[$id]['live'] = false;
            }
        };
    }

    private function actionCompleteFactor(): \Closure
    {
        return function (string $ctx): void {
            $id = $this->liveChallengeIds()[array_rand($this->liveChallengeIds())];
            $challenge = $this->challenges[$id];
            $demandId = $challenge['demandId'];
            $pairOpen = $demandId !== null
                && isset($this->demands[$demandId])
                && $this->demands[$demandId]['live']
                && $this->isOpenDemand($demandId);
            $roll = mt_rand(0, 3);
            if ($pairOpen && $roll !== 3) {
                // The completion lane: the correct binding (the stored
                // session hash, or the minted client secret hash), a
                // wrong-binding probe, or a hint-less completion that
                // skips the escalation marker.
                $binding = $roll === 1 ? str_repeat('f', 64) : $challenge['binding'];
                $hint = $roll === 2 ? null : $this->hintFor($challenge);
                $a = $this->arrayStore->completeFactor($id, $demandId, $binding, $this->clock->now, $hint);
                $r = $this->redisStore->completeFactor($id, $demandId, $binding, $this->clock->now, $hint);
                ($this->assert)(($a === null) === ($r === null), $ctx.'('.$id.' -> '.$demandId.',roll='.$roll.'): one store completed a pair the other refused');
                if ($a !== null && $r !== null) {
                    ($this->assert)($a->challengeId === $r->challengeId && $a->demandId === $r->demandId, $ctx.': the completion identities diverge');
                    ($this->assert)($a->kind === $r->kind && $a->completedFactor === $r->completedFactor, $ctx.': the completed factors diverge');
                    ($this->assert)($a->verifiedSubjectPseudonym === $r->verifiedSubjectPseudonym, $ctx.': the verified subjects diverge');
                    $this->challenges[$id]['live'] = false;
                    $this->demands[$demandId]['state'] = StepUpDemandState::Completed;
                    $sessionHash = $challenge['record']->sessionHash;
                    if (\is_string($sessionHash) && $sessionHash !== '' && $hint !== null) {
                        $this->sessionMarks[] = [$sessionHash, $challenge['record']->scope];
                    }
                }

                return;
            }
            // A crossed probe: a live challenge against a different
            // open demand. Both stores must refuse with nothing spent.
            $others = array_values(array_filter(
                $this->liveDemandIds(),
                fn (string $candidate): bool => $candidate !== $demandId && $this->isOpenDemand($candidate),
            ));
            if ($others === []) {
                return;
            }
            $crossed = $others[array_rand($others)];
            $a = $this->arrayStore->completeFactor($id, $crossed, $challenge['binding'], $this->clock->now, null);
            $r = $this->redisStore->completeFactor($id, $crossed, $challenge['binding'], $this->clock->now, null);
            ($this->assert)($a === null && $r === null, $ctx.'('.$id.' -> '.$crossed.'): a crossed pair must refuse on both stores');
        };
    }

    /** The completion hint of a minted challenge: its session hash, or null. */
    private function hintFor(array $challenge): ?string
    {
        $sessionHash = $challenge['record']->sessionHash;

        return \is_string($sessionHash) && $sessionHash !== '' ? $sessionHash : null;
    }

    private function actionProbeCompletedFactor(): \Closure
    {
        return function (string $ctx): void {
            $mark = $this->sessionMarks[array_rand($this->sessionMarks)];
            $scope = mt_rand(0, 1) === 0 ? $mark[1] : 'login';
            $a = $this->arrayStore->completedFactorOf($mark[0], $scope, $this->clock->now);
            $r = $this->redisStore->completedFactorOf($mark[0], $scope, $this->clock->now);
            ($this->assert)($a === $r, $ctx.'('.$scope.'): the completion markers diverge ('.$a.' vs '.$r.')');
        };
    }

    private function actionProbeFamilyTip(): \Closure
    {
        return function (string $ctx): void {
            $digest = array_rand($this->families);
            $a = $this->arrayStore->demandIdForOperation($digest);
            $r = $this->redisStore->demandIdForOperation($digest);
            ($this->assert)($a === $r, $ctx.': the family tips diverge ('.$a.' vs '.$r.')');
        };
    }

    // ── quota actions ───────────────────────────────────────────────

    private function actionReserveQuota(): \Closure
    {
        return function (string $ctx): void {
            $reservationId = $this->nextReservationId();
            $keys = mt_rand(0, 1) === 0
                ? ['dom:'.str_pad(dechex(mt_rand(0, 255)), 4, '0', STR_PAD_LEFT)]
                : ['dom:'.str_pad(dechex(mt_rand(0, 255)), 4, '0', STR_PAD_LEFT), 'global:'];
            $limits = array_map(static fn (): int => mt_rand(1, 3), $keys);
            foreach ($keys as $key) {
                if (!\in_array($key, $this->budgetOrder, true)) {
                    $this->budgetOrder[] = $key;
                    $this->quotaCounts[$key] = 0;
                }
            }
            $a = $this->arrayStore->reserveMailQuota($reservationId, $keys, $limits, self::QUOTA_WINDOW, self::QUOTA_LEASE);
            $r = $this->redisStore->reserveMailQuota($reservationId, $keys, $limits, self::QUOTA_WINDOW, self::QUOTA_LEASE);
            ($this->assert)($a === $r, $ctx.'('.$reservationId.'): the quota answers diverge');
            if ($a) {
                foreach ($keys as $i => $key) {
                    $this->quotaCounts[$key] = ($this->quotaCounts[$key] ?? 0) + 1;
                    ($this->assert)($this->quotaCounts[$key] <= $limits[$i], $ctx.': the model booked past a limit it should have been refused at');
                }
                $this->reservations[$reservationId] = [
                    'keys' => array_values($keys),
                    'leaseUntil' => $this->clock->now + self::QUOTA_LEASE,
                    'releasable' => true,
                ];
            }
        };
    }

    private function actionReleaseQuota(): \Closure
    {
        return function (string $ctx): void {
            $id = $this->releasableReservations()[array_rand($this->releasableReservations())];
            $a = $this->arrayStore->releaseMailQuota($id);
            $r = $this->redisStore->releaseMailQuota($id);
            ($this->assert)($a === $r, $ctx.'('.$id.'): the release answers diverge');
            if ($a) {
                foreach ($this->reservations[$id]['keys'] as $key) {
                    $this->quotaCounts[$key] = max(0, ($this->quotaCounts[$key] ?? 0) - 1);
                }
            }
            $this->reservations[$id]['releasable'] = false;
        };
    }

    private function actionCommitQuota(): \Closure
    {
        return function (string $ctx): void {
            $id = $this->liveReservationIds()[array_rand($this->liveReservationIds())];
            $this->arrayStore->commitMailQuota($id);
            $this->redisStore->commitMailQuota($id);
            $this->reservations[$id]['releasable'] = false;
        };
    }

    // ── counter and marker actions ──────────────────────────────────

    private function actionCountBegin(): \Closure
    {
        return function (string $ctx): void {
            ++$this->beginCount;
            $a = $this->arrayStore->countBegin(self::PRINCIPAL, self::RECORD_TTL);
            $r = $this->redisStore->countBegin(self::PRINCIPAL, self::RECORD_TTL);
            ($this->assert)($a === $this->beginCount && $r === $this->beginCount, $ctx.': the begin window counts diverged ('.$a.' / '.$r.' vs '.$this->beginCount.')');
        };
    }

    private function actionMarkTotpStep(): \Closure
    {
        return function (string $ctx): void {
            $replay = $this->totpMarked !== 0 && mt_rand(0, 2) === 0;
            if ($replay) {
                // At or below the stored step: a replay on both stores.
                $step = $this->totpMarked - 1;
                $expected = false;
            } else {
                $this->totpMarked += 1 + mt_rand(0, 2);
                $step = $this->totpMarked;
                $expected = true;
            }
            $a = $this->arrayStore->markTotpStep(self::PRINCIPAL, $step, self::RECORD_TTL);
            $r = $this->redisStore->markTotpStep(self::PRINCIPAL, $step, self::RECORD_TTL);
            ($this->assert)($a === $expected && $r === $expected, $ctx.'('.$step.'): the replay guard answers diverged ('.$a.' / '.$r.')');
        };
    }

    private function actionTotpSecret(): \Closure
    {
        return function (string $ctx): void {
            $secret = 'secret-'.mt_rand(1000, 9999);
            $this->arrayStore->saveTotpSecret(self::PRINCIPAL, $secret);
            $this->redisStore->saveTotpSecret(self::PRINCIPAL, $secret);
            $a = $this->arrayStore->findTotpSecret(self::PRINCIPAL);
            $r = $this->redisStore->findTotpSecret(self::PRINCIPAL);
            ($this->assert)($a === $r && $a === $secret, $ctx.': the enrollment secrets diverge');
        };
    }

    private function actionStepUpMarker(): \Closure
    {
        return function (string $ctx): void {
            // The marker window doubles as its TTL: both stores flip
            // from recent to stale on the same boundary.
            $within = 900;
            $this->arrayStore->markStepUpSuccess(self::PRINCIPAL, $within, $this->clock->now);
            $this->redisStore->markStepUpSuccess(self::PRINCIPAL, $within, $this->clock->now);
            $a = $this->arrayStore->recentStepUpSuccess(self::PRINCIPAL, $within, $this->clock->now);
            $r = $this->redisStore->recentStepUpSuccess(self::PRINCIPAL, $within, $this->clock->now);
            ($this->assert)($a === $r && $a, $ctx.': the step-up markers diverge');
        };
    }

    private function actionSessionMarker(): \Closure
    {
        return function (string $ctx): void {
            $sessionId = 'diff-marker-session';
            $within = 900;
            $this->arrayStore->markSessionStepUpSuccess($sessionId, self::PRINCIPAL, 'email_otp', $within, $this->clock->now);
            $this->redisStore->markSessionStepUpSuccess($sessionId, self::PRINCIPAL, 'email_otp', $within, $this->clock->now);
            $a = $this->arrayStore->recentSessionStepUpSuccess($sessionId, self::PRINCIPAL, null, $within, $this->clock->now);
            $r = $this->redisStore->recentSessionStepUpSuccess($sessionId, self::PRINCIPAL, null, $within, $this->clock->now);
            ($this->assert)($a === $r && $a, $ctx.': the session markers diverge');
            // The factor floor: an email_otp marker never answers a
            // webauthn floor, on either store.
            $b = $this->arrayStore->recentSessionStepUpSuccess($sessionId, self::PRINCIPAL, 'webauthn', $within, $this->clock->now);
            $c = $this->redisStore->recentSessionStepUpSuccess($sessionId, self::PRINCIPAL, 'webauthn', $within, $this->clock->now);
            ($this->assert)($b === $c && !$b, $ctx.': the session factor floors diverge');
        };
    }

    private function actionLockout(): \Closure
    {
        return function (string $ctx): void {
            $roll = mt_rand(0, 3);
            if ($roll === 0) {
                $this->arrayStore->armLockout(self::LOCKOUT_DIMENSION, self::LOCKOUT_PSEUDONYM, $this->clock->now, 600);
                $this->redisStore->armLockout(self::LOCKOUT_DIMENSION, self::LOCKOUT_PSEUDONYM, $this->clock->now, 600);
            } elseif ($roll === 1) {
                $this->arrayStore->clearLockout(self::LOCKOUT_DIMENSION, self::LOCKOUT_PSEUDONYM);
                $this->redisStore->clearLockout(self::LOCKOUT_DIMENSION, self::LOCKOUT_PSEUDONYM);
                $this->lockFails = 0;
            } else {
                ++$this->lockFails;
                $a = $this->arrayStore->countLockoutFailure(self::LOCKOUT_DIMENSION, self::LOCKOUT_PSEUDONYM, self::RECORD_TTL);
                $r = $this->redisStore->countLockoutFailure(self::LOCKOUT_DIMENSION, self::LOCKOUT_PSEUDONYM, self::RECORD_TTL);
                ($this->assert)($a === $this->lockFails && $r === $this->lockFails, $ctx.': the failure counters diverged ('.$a.' / '.$r.' vs '.$this->lockFails.')');
            }
        };
    }

    private function actionTick(): \Closure
    {
        return function (string $ctx): void {
            $this->clock->now += mt_rand(1, 60);
            $this->syncClocks();
        };
    }

    // ── the model helpers ───────────────────────────────────────────

    private function mintDemand(string $id, string $scope): StepUpDemand
    {
        return StepUpDemand::mint(
            $id,
            $scope,
            null,
            null,
            'decision-root',
            $this->clock->now,
            self::RECORD_TTL,
            StepUpOperationBindingKind::None,
        );
    }

    private function registerDemand(string $id, StepUpDemand $demand): void
    {
        if (!isset($this->demands[$id])) {
            $this->demandOrder[] = $id;
        }
        $this->demands[$id] = [
            'state' => $demand->state,
            'supersededBy' => $demand->supersededByDemandId,
            'generation' => $demand->generation,
            'live' => true,
            'lease' => null,
        ];
    }

    /** @return list<string> */
    private function liveDemandIds(): array
    {
        return array_values(array_filter(
            $this->demandOrder,
            fn (string $id): bool => $this->demands[$id]['live'],
        ));
    }

    /** @return list<string> */
    private function claimableDemandIds(): array
    {
        return array_values(array_filter(
            $this->liveDemandIds(),
            fn (string $id): bool => \in_array($this->demands[$id]['state'], [StepUpDemandState::Completed, StepUpDemandState::Finalizing], true),
        ));
    }

    /** @return list<string> */
    private function finalizableDemandIds(): array
    {
        return array_values(array_filter(
            $this->liveDemandIds(),
            fn (string $id): bool => $this->demands[$id]['state'] === StepUpDemandState::Finalizing,
        ));
    }

    /** @return list<string> */
    private function authorizedDemandIds(): array
    {
        return array_values(array_filter(
            $this->liveDemandIds(),
            fn (string $id): bool => $this->demands[$id]['state'] === StepUpDemandState::Authorized,
        ));
    }

    private function isOpenDemand(string $id): bool
    {
        return $this->demands[$id]['state'] === StepUpDemandState::Open
            && $this->demands[$id]['supersededBy'] === null;
    }

    /**
     * The supersede legality the model tracks: live, never superseded,
     * open or finalizing (the escalator holding its own claim), and
     * below the family depth cap. The cap lives in spawnChild, so the
     * generator must respect it before minting the child.
     */
    private function canSupersede(string $id): bool
    {
        $state = $this->demands[$id]['state'];

        return $this->demands[$id]['supersededBy'] === null
            && $this->demands[$id]['generation'] < StepUpDemand::MAX_GENERATION
            && ($state === StepUpDemandState::Open || $state === StepUpDemandState::Finalizing);
    }

    /** @return list<string> */
    private function liveChallengeIds(): array
    {
        return array_values(array_filter(
            $this->challengeOrder,
            fn (string $id): bool => $this->challenges[$id]['live'],
        ));
    }

    /** @return list<string> */
    private function settleableLeases(): array
    {
        return array_values(array_filter(
            $this->demandOrder,
            fn (string $id): bool => $this->demands[$id]['lease'] !== null,
        ));
    }

    /** @return list<string> */
    private function releasableReservations(): array
    {
        return array_values(array_filter(
            array_keys($this->reservations),
            fn (string $id): bool => $this->reservations[$id]['releasable']
                && $this->clock->now <= $this->reservations[$id]['leaseUntil'],
        ));
    }

    /** @return list<string> */
    private function liveReservationIds(): array
    {
        return array_values(array_filter(
            array_keys($this->reservations),
            fn (string $id): bool => $this->reservations[$id]['releasable'],
        ));
    }

    private function nextDemandId(): string
    {
        return sprintf('dif%03d%04ddemand', $this->seedTag % 1000, ++$this->demandSeq);
    }

    private function nextChildId(): string
    {
        return sprintf('dif%03d%04dchildx', $this->seedTag % 1000, ++$this->demandSeq);
    }

    private function nextChallengeId(): string
    {
        return sprintf('dic%03d%04dchallg', $this->seedTag % 1000, ++$this->challengeSeq);
    }

    private function nextReservationId(): string
    {
        return sprintf('dif.res.%03d.%04d', $this->seedTag % 1000, ++$this->reservationSeq);
    }

    // ── the projection comparison ───────────────────────────────────

    /**
     * The full observable sweep, run after every action. Every demand
     * and challenge record ever minted, every family tip, every
     * completion marker, the enrollment secret and the raw quota
     * counters must answer identically on both stores. The counters
     * with no array-side accessor are compared through the model.
     */
    private function compareProjection(string $ctx): void
    {
        foreach ($this->demandOrder as $id) {
            $a = $this->demandProjection($this->arrayStore->readDemand($id));
            $r = $this->demandProjection($this->redisStore->readDemand($id));
            ($this->assert)($a === $r, $ctx.': demand '.$id.' projections diverge: '.json_encode($a).' vs '.json_encode($r));
        }
        foreach ($this->challengeOrder as $id) {
            $a = $this->challengeProjection($this->arrayStore->read($id));
            $r = $this->challengeProjection($this->redisStore->read($id));
            ($this->assert)($a === $r, $ctx.': challenge '.$id.' projections diverge: '.json_encode($a).' vs '.json_encode($r));
        }
        foreach ($this->families as $digest => $label) {
            $a = $this->arrayStore->demandIdForOperation($digest);
            $r = $this->redisStore->demandIdForOperation($digest);
            ($this->assert)($a === $r, $ctx.': family tip of '.$label.' diverges: '.$a.' vs '.$r);
        }
        foreach ($this->sessionMarks as $mark) {
            $a = $this->arrayStore->completedFactorOf($mark[0], $mark[1], $this->clock->now);
            $r = $this->redisStore->completedFactorOf($mark[0], $mark[1], $this->clock->now);
            ($this->assert)($a === $r, $ctx.': completion marker of '.$mark[1].' diverges: '.$a.' vs '.$r);
        }
        $a = $this->arrayStore->findTotpSecret(self::PRINCIPAL);
        $r = $this->redisStore->findTotpSecret(self::PRINCIPAL);
        ($this->assert)($a === $r, $ctx.': enrollment secrets diverge');
        // The quota counters: the model is the shared projection. The
        // Redis side is additionally read raw. The array store has no
        // counter accessor, so its counters are pinned through the
        // reserve and release answers that built the model.
        if ($this->rawRedis !== null) {
            foreach ($this->budgetOrder as $key) {
                $raw = $this->rawRedis->get($this->redisPrefix.'emb:'.$key);
                $count = (int) ($raw ?? '0');
                ($this->assert)($count === $this->quotaCounts[$key], $ctx.': raw quota counter '.$key.' reads '.$count.', the model says '.$this->quotaCounts[$key]);
            }
        }
    }

    /**
     * The normalized demand projection. Volatile store-clock fields
     * (stateAt, leaseUntilMs, lastSentAt values) are compared for
     * presence, never for value: the two stores stamp different clocks
     * by design. Everything else is compared exactly, including the
     * inherited authorization deadline both records carry.
     *
     * @return array<string, mixed>|null
     */
    private function demandProjection(?StepUpDemand $d): ?array
    {
        if ($d === null) {
            return null;
        }

        return [
            'id' => $d->id,
            'state' => $d->state->value,
            'supersededBy' => $d->supersededByDemandId,
            'parent' => $d->parentDemandId,
            'generation' => $d->generation,
            'sends' => $d->sends,
            'lastSentSet' => $d->lastSentAt !== null,
            'leaseSet' => $d->leaseUntilMs !== null,
            'createdAt' => $d->createdAt,
            'expiresAt' => $d->expiresAt,
            'scope' => $d->scope,
            'decisionId' => $d->decisionId,
            'raisedBy' => $d->raisedByDecisionId,
            'digest' => $d->operationDigest,
            'factor' => $d->factor,
            'authorizedAt' => $d->authorizedAt,
            'effects' => $d->effects?->toArray(),
            'required' => $d->requiredFactor === null
                ? null
                : [$d->requiredFactor->family, $d->requiredFactor->factorId, $d->requiredFactor->assuranceRank],
        ];
    }

    /**
     * The normalized challenge projection: everything the record
     * round-trips through both stores identically.
     *
     * @return array<string, mixed>|null
     */
    private function challengeProjection(?StepUpChallenge $c): ?array
    {
        if ($c === null) {
            return null;
        }

        return [
            'id' => $c->id,
            'kind' => $c->kind->value,
            'principal' => $c->principalPseudonym,
            'scope' => $c->scope,
            'reason' => $c->reason,
            'attempts' => $c->attempts,
            'maxAttempts' => $c->maxAttempts,
            'createdAt' => $c->createdAt,
            'expiresAt' => $c->expiresAt,
            'demandId' => $c->demandId,
            'sessionHash' => $c->sessionHash,
            'clientSecretHash' => $c->clientSecretHash,
            'codeHash' => $c->codeHash,
        ];
    }
}
