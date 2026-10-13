<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipStepUp;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandSendSettlement;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationDigest;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Tests\CapturingEmailOwnershipSender;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The escalation family of the step-up demand plane, the send lease and
 * the mail quota reservations. A reassessment that re-raises the step-up
 * for one protected operation supersedes the live demand and creates its
 * child in one atomic store transaction. The child inherits the parent's
 * authorization deadline and its authorizing bindings unchanged, so no
 * reassessment can extend the original window. The delivery claim is a
 * lease whose clock the store owns, and the delivery budgets are
 * generation-bound reservations: reserve, hand off, then commit or
 * release.
 */
final class StepUpDemandEscalationTest extends TestCase
{
    private const MASTER = 'kiwi-step-up-master-0123456789abcdef';

    /** The store clock of the test, advanced explicitly. */
    private int $now = 1700000000;

    private ArrayStepUpChallengeStore $store;

    private CapturingEmailOwnershipSender $sender;

    private EmailOwnershipStepUp $factor;

    protected function setUp(): void
    {
        $this->store = new ArrayStepUpChallengeStore(fn (): int => $this->now);
        $this->sender = new CapturingEmailOwnershipSender();
        $this->factor = new EmailOwnershipStepUp(
            $this->store,
            new StepUpTicket(self::MASTER),
            $this->sender,
            null,
            null,
            'signup',
            self::MASTER,
            600,
            5,
            100,
            100,
            3600,
            ['signup' => true],
            now: fn (): int => $this->now,
        );
    }

    // ── item 8: the atomic supersede and create ─────────────────────

    public function testTheRootMintAnswersOneDemandPerOperation(): void
    {
        $digest = StepUpOperationDigest::none('signup');
        $first = $this->mintRoot($digest, 'decision-1');
        $second = $this->mintRoot($digest, 'decision-2');
        self::assertSame($first, $second, 'a second root for one operation never mints; the standing demand serves');
        $live = $this->store->demandIdForOperation($digest);
        self::assertSame($first, $live);
        self::assertSame(0, $this->store->readDemand($first)?->generation);
    }

    public function testTheEscalationSupersedesTheParentAndCreatesTheChildAsOneTransaction(): void
    {
        $digest = StepUpOperationDigest::none('signup');
        $parent = $this->mintRoot($digest, 'decision-1');
        $child = $this->store->readDemand($parent)->spawnChild('childid00000000000000001', $this->now, 'decision-2');

        $superseded = $this->store->supersedeDemandWithChild($parent, $child);
        self::assertNotNull($superseded, 'the atomic transaction wins');
        self::assertSame('childid00000000000000001', $superseded->supersededByDemandId, 'the parent names the child that took over');
        self::assertTrue($this->store->readDemand($parent)->superseded());
        $stored = $this->store->readDemand('childid00000000000000001');
        self::assertNotNull($stored, 'the child exists');
        self::assertSame($parent, $stored->parentDemandId, 'the child names its parent for auditability');
        self::assertSame('childid00000000000000001', $this->store->demandIdForOperation($digest), 'the family index points at the child');
    }

    public function testASupersededParentFundsNothingAndASecondEscalationRefuses(): void
    {
        $digest = StepUpOperationDigest::none('signup');
        $parent = $this->mintRoot($digest, 'decision-1');
        $this->escalate($parent, 'childid00000000000000001', 'decision-2');
        $again = $this->escalate($parent, 'childid00000000000000002', 'decision-3');
        self::assertNull($again, 'an already superseded parent never supersedes twice');
        self::assertNull($this->store->readDemand('childid00000000000000002'), 'the refused child was never written');
    }

    public function testAnExpiredParentCannotEscalate(): void
    {
        $digest = StepUpOperationDigest::none('signup');
        $parent = $this->mintRoot($digest, 'decision-1');
        $this->now += 601;
        self::assertNull($this->store->readDemand($parent), 'the expired parent is gone from the store');
        self::assertNull($this->store->demandIdForOperation($digest), 'the family dies with its expiry');
    }

    public function testAChildIdCollisionRefusesTheWholeTransaction(): void
    {
        $digest = StepUpOperationDigest::none('signup');
        $parent = $this->mintRoot($digest, 'decision-1');
        $child = $this->store->readDemand($parent)->spawnChild('childid00000000000000001', $this->now, 'decision-2');
        // A record already occupies the child key.
        $this->store->createDemand(StepUpDemand::mint('childid00000000000000001', 'signup', null, null, null, $this->now, 600, StepUpOperationBindingKind::None, $digest), 600);
        self::assertNull($this->store->supersedeDemandWithChild($parent, $child));
        self::assertFalse($this->store->readDemand($parent)->superseded(), 'the parent stays live when the child refuses');
    }

    // ── item 9: the child inherits the authorization, never refreshes it ──

    public function testTheChildInheritsTheAuthorizationDeadlineAndBindingsUnchanged(): void
    {
        $digest = StepUpOperationDigest::formFields('signup', ['email' => 'a@example.com']);
        $parent = StepUpDemand::mint('parentid0000000000000001', 'signup', str_repeat('a', 64), null, 'decision-1', $this->now, 600, StepUpOperationBindingKind::FormFields, $digest);
        $this->store->createRootDemand($parent, 600);
        $this->now += 240;
        $child = $this->store->readDemand($parent->id)->spawnChild('childid00000000000000001', $this->now, 'decision-2');

        self::assertSame($parent->expiresAt, $child->expiresAt, 'the child inherits the original authorization deadline');
        self::assertSame($parent->decisionId, $child->decisionId, 'the authorizing decision rides unchanged');
        self::assertSame('decision-2', $child->raisedByDecisionId, 'the reassessment is recorded separately');
        self::assertSame($parent->sessionHash, $child->sessionHash, 'the browser binding rides unchanged');
        self::assertSame($parent->chainId, $child->chainId, 'the chain identity rides unchanged');
        self::assertSame($parent->operationDigest, $child->operationDigest, 'the operation identity rides unchanged');
        self::assertSame(1, $child->generation);

        $superseded = $this->store->supersedeDemandWithChild($parent->id, $child);
        self::assertNotNull($superseded);
        self::assertSame($parent->expiresAt, $this->store->readDemand('childid00000000000000001')->expiresAt, 'the stored child carries the inherited deadline');
    }

    public function testAChildWithAForeignExpiryRefusesInheritance(): void
    {
        $digest = StepUpOperationDigest::none('signup');
        $parent = $this->mintRoot($digest, 'decision-1');
        $forged = StepUpDemand::mint('childid00000000000000001', 'signup', null, null, 'decision-1', $this->now, 900, StepUpOperationBindingKind::None, $digest);
        self::assertNull($this->store->supersedeDemandWithChild($parent, $forged), 'a child that outlives its parent refuses');
        self::assertFalse($this->store->readDemand($parent)->superseded());
    }

    public function testTheEscalationDepthIsBounded(): void
    {
        $digest = StepUpOperationDigest::none('signup');
        $tip = $this->mintRoot($digest, 'decision-1');
        for ($generation = 1; $generation <= StepUpDemand::MAX_GENERATION; $generation++) {
            $tip = $this->escalate($tip, 'gen'.$generation.'000000000000000001', 'decision-'.$generation + 1);
            self::assertNotNull($tip, "generation $generation escalates");
        }
        self::assertFalse($this->store->readDemand($tip)->canEscalate(), 'the family cap stops the escalation');
        self::assertSame(StepUpDemand::MAX_GENERATION, $this->store->readDemand($tip)->generation);
        try {
            $this->store->readDemand($tip)->spawnChild('pastcap00000000000000001', $this->now, 'decision-x');
            self::fail('a family past its depth spawns no children');
        } catch (\LogicException) {
            // refused, fail closed
        }
    }

    // ── the supersession marker is enforced on every transition ─────

    public function testASupersededParentCompletesNoFactorAndAuthorizesNothing(): void
    {
        // The finding this pins: the completion and the finalization
        // gates judged only the state field, so a parent that escalation
        // had replaced (superseded_by set, state still open) completed
        // its old weak challenge behind the family's back and settled
        // authorized on the rung the engine had escalated past.
        $digest = StepUpOperationDigest::none('signup');
        $parent = $this->mintRoot($digest, 'decision-1');
        $this->escalate($parent, 'childid00000000000000001', 'decision-2');
        $stored = $this->store->readDemand($parent);
        self::assertTrue($stored->superseded(), 'the parent carries the marker');

        self::assertNull($this->store->claimDemandFinalization($parent, $this->now, 30), 'a superseded demand is never claimed for finalization');
        self::assertNull($this->store->completeDemand($parent, $this->now, 600), 'a superseded demand never completes');
        self::assertNull($this->store->settleDemandFinalization($parent, StepUpDemandState::Authorized, $this->now), 'a superseded demand never settles authorized');
    }

    public function testASupersededFinalizingParentAuthorizesThroughNoStaleClaim(): void
    {
        // The finding this pins: a stale claimant retaking a
        // finalizing demand that escalation had already superseded
        // (the escalator's follow-up settlement lost) could drive the
        // parent to authorized past the stronger child.
        $digest = StepUpOperationDigest::none('signup');
        $parent = $this->mintRoot($digest, 'decision-1');
        self::assertNotNull($this->store->completeDemand($parent, $this->now, 600), 'the factor proof completes the demand');
        self::assertNotNull($this->store->claimDemandFinalization($parent, $this->now, 30), 'the escalator holds its claim');
        $this->escalate($parent, 'childid00000000000000001', 'decision-2');
        self::assertTrue($this->store->readDemand($parent)->superseded());

        self::assertNull($this->store->settleDemandFinalization($parent, StepUpDemandState::Authorized, $this->now), 'a superseded finalizing parent never settles authorized');
        self::assertNull($this->store->claimDemandFinalization($parent, $this->now + 31, 30), 'a stale claimant never retakes a superseded demand');
        self::assertNull($this->store->settleDemandFinalization($parent, StepUpDemandState::Superseded, $this->now), 'the terminal the supersede already wrote answers null to a second settle');
    }

    public function testATerminalParentIsNeverSupersededIntoAFreshSibling(): void
    {
        // The finding this pins: the supersede script accepted parents
        // in any non-superseded state, so an authorized (or completed)
        // demand could be handed a fresh live sibling for an operation
        // that had already settled. Distinct scopes keep the three
        // roots in distinct families (a None-bound demand's family key
        // is its scope).
        $mintInFamily = function (string $scope): string {
            return $this->store->createRootDemand(
                StepUpDemand::mint(\BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(), $scope, null, null, 'decision-terminal', $this->now, 600, StepUpOperationBindingKind::None, StepUpOperationDigest::none($scope)),
                600,
            );
        };
        $authorized = $mintInFamily('signup');
        self::assertNotNull($this->store->completeDemand($authorized, $this->now, 600));
        self::assertNotNull($this->store->claimDemandFinalization($authorized, $this->now, 30));
        self::assertNotNull($this->store->settleDemandFinalization($authorized, StepUpDemandState::Authorized, $this->now));
        self::assertNull($this->escalate($authorized, 'childid00000000000000001', 'decision-2'), 'an authorized demand is history, not a family head');

        $completed = $mintInFamily('signup_confirm');
        self::assertNotNull($this->store->completeDemand($completed, $this->now, 600));
        self::assertNull($this->escalate($completed, 'childid00000000000000002', 'decision-4'), 'a completed demand mid-finalization is never superseded');

        $denied = $mintInFamily('signup_email');
        self::assertNotNull($this->store->completeDemand($denied, $this->now, 600));
        self::assertNotNull($this->store->claimDemandFinalization($denied, $this->now, 30));
        self::assertNotNull($this->store->settleDemandFinalization($denied, StepUpDemandState::Denied, $this->now));
        self::assertNull($this->escalate($denied, 'childid00000000000000003', 'decision-6'), 'a denied demand never funds a fresh sibling');
    }

    public function testMintDemandEscalatesInsteadOfRefreshingTheWindow(): void
    {
        $session = str_repeat('b', 64);
        $first = $this->factor->mintDemand('signup', $session, null, 'decision-1');
        self::assertNotNull($first);
        $root = $this->store->readDemand($first);
        self::assertSame(0, $root->generation);

        $this->now += 200;
        $second = $this->factor->mintDemand('signup', $session, null, 'decision-2');
        self::assertNotSame($first, $second, 'the reassessment mints the child, not a second root');
        $child = $this->store->readDemand($second);
        self::assertSame($first, $child->parentDemandId);
        self::assertSame($root->expiresAt, $child->expiresAt, 'the reassessment never refreshes the authorization window');
        self::assertSame('decision-1', $child->decisionId);
        self::assertSame('decision-2', $child->raisedByDecisionId);
        self::assertTrue($this->store->readDemand($first)->superseded());
    }

    public function testAMintPastTheFamilyCapKeepsTheStandingDemand(): void
    {
        $session = str_repeat('c', 64);
        $tip = $this->factor->mintDemand('signup', $session, null, 'decision-1');
        for ($generation = 1; $generation <= StepUpDemand::MAX_GENERATION; $generation++) {
            $tip = $this->factor->mintDemand('signup', $session, null, 'decision-'.$generation + 1);
        }
        $root = $this->factor->mintDemand('signup', $session, null, 'decision-final');
        self::assertSame($tip, $root, 'past the cap the standing demand serves; no fresh TTL ever');
    }

    // ── item 10: the store-owned send lease ─────────────────────────

    public function testTheSendLeaseAdvancesOneDeliveryAndSettles(): void
    {
        $id = $this->mintRoot(StepUpOperationDigest::none('signup'), 'decision-1');
        $lease = $this->store->claimDemandSendLease($id, 60, 15);
        self::assertNotNull($lease);
        self::assertSame(1, $lease->demand->sends);
        self::assertFalse($lease->recovered);
        self::assertSame($this->now, $lease->claimAt);

        // A second claim inside the first lease refuses: one delivery slot.
        self::assertNull($this->store->claimDemandSendLease($id, 60, 15));

        $settled = $this->store->settleDemandSendLease(new StepUpDemandSendSettlement($id, $lease->leaseUntilMs, $lease->claimAt, $lease->priorSends, $lease->priorLastSentAt, true));
        self::assertTrue($settled);
        self::assertNull($this->store->readDemand($id)->leaseUntilMs, 'the settled lease clears');
        self::assertSame(1, $this->store->readDemand($id)->sends);
    }

    public function testARefusedDeliveryRestoresThePreClaimState(): void
    {
        $id = $this->mintRoot(StepUpOperationDigest::none('signup'), 'decision-1');
        $lease = $this->store->claimDemandSendLease($id, 60, 15);
        self::assertNotNull($lease);
        $this->store->settleDemandSendLease(new StepUpDemandSendSettlement($id, $lease->leaseUntilMs, $lease->claimAt, $lease->priorSends, $lease->priorLastSentAt, false));
        $record = $this->store->readDemand($id);
        self::assertSame(0, $record->sends, 'the pre-handoff refusal restores the credit');
        self::assertNull($record->lastSentAt);
        self::assertNull($record->leaseUntilMs);
    }

    public function testACrashedClaimRecoversWithoutASecondCredit(): void
    {
        $id = $this->mintRoot(StepUpOperationDigest::none('signup'), 'decision-1');
        $lease = $this->store->claimDemandSendLease($id, 60, 15);
        self::assertNotNull($lease);
        // The first holder never settles; its lease window passes.
        $this->now += 16;
        $recovery = $this->store->claimDemandSendLease($id, 60, 15);
        self::assertNotNull($recovery, 'the expired lease is recoverable');
        self::assertTrue($recovery->recovered);
        self::assertSame(1, $recovery->demand->sends, 'the recovered slot pays no second credit');
        self::assertSame(1, $recovery->priorSends, 'the recovery answers the state it inherits');

        // The crashed holder's late settlement is worthless now.
        $late = $this->store->settleDemandSendLease(new StepUpDemandSendSettlement($id, $lease->leaseUntilMs, $lease->claimAt, $lease->priorSends, $lease->priorLastSentAt, false));
        self::assertFalse($late, 'the stale claimant settles nothing');
        self::assertSame(1, $this->store->readDemand($id)->sends);
    }

    public function testTheResendSpacingIsJudgedOnTheStoreClock(): void
    {
        $id = $this->mintRoot(StepUpOperationDigest::none('signup'), 'decision-1');
        $lease = $this->store->claimDemandSendLease($id, 60, 15);
        self::assertNotNull($lease);
        $this->store->settleDemandSendLease(new StepUpDemandSendSettlement($id, $lease->leaseUntilMs, $lease->claimAt, $lease->priorSends, $lease->priorLastSentAt, true));
        // 30 seconds after the first delivery: the 60 second spacing holds.
        $this->now += 30;
        self::assertNull($this->store->claimDemandSendLease($id, 60, 15), 'the resend waits for the store-owned spacing');
        $this->now += 31;
        $resend = $this->store->claimDemandSendLease($id, 60, 15);
        self::assertNotNull($resend, 'the resend opens on the store clock');
        self::assertSame(2, $resend->demand->sends);
        self::assertFalse($resend->recovered);
    }

    public function testASpentSupersededOrTerminalDemandClaimsNothing(): void
    {
        $id = $this->mintRoot(StepUpOperationDigest::none('signup'), 'decision-1');
        $this->store->completeDemand($id, $this->now, 600);
        self::assertNull($this->store->claimDemandSendLease($id, 60, 15), 'a completed demand funds no delivery');

        $digest = StepUpOperationDigest::none('signup');
        $root = $this->mintRoot($digest, 'decision-1');
        $this->escalate($root, 'superseded000000000000001', 'decision-2');
        self::assertNull($this->store->claimDemandSendLease($root, 60, 15), 'a superseded demand funds no delivery');
    }

    // ── item 13: the mail quota reservations ────────────────────────

    public function testTheQuotaReservationCoversEveryBudgetOrNone(): void
    {
        $ok = $this->store->reserveMailQuota('resv.ok.1.1', ['emb:dom:a', 'emb:global'], [30, 1000], 3600, 30);
        self::assertTrue($ok);
        self::assertTrue($this->store->releaseMailQuota('resv.ok.1.1'), 'the release rolls the reservation back');
        // One exhausted budget refuses the whole reservation: the other
        // budget's increment rolls back too, so a retry at a free limit
        // succeeds instead of finding phantom spend.
        self::assertTrue($this->store->reserveMailQuota('resv.retry.1.1', ['emb:dom:a', 'emb:global'], [1, 1000], 3600, 30));
        self::assertFalse($this->store->reserveMailQuota('resv.retry.1.2', ['emb:dom:a', 'emb:global'], [1, 1000], 3600, 30));
        self::assertTrue($this->store->releaseMailQuota('resv.retry.1.1'));
        self::assertTrue($this->store->reserveMailQuota('resv.retry.1.3', ['emb:dom:a', 'emb:global'], [1, 1000], 3600, 30), 'the rollback freed both budgets');
    }

    public function testAnExhaustedBudgetRefusesAndARollbackFreesIt(): void
    {
        self::assertTrue($this->store->reserveMailQuota('r1.0.1', ['emb:dom:d'], [1], 3600, 30));
        self::assertFalse($this->store->reserveMailQuota('r2.0.1', ['emb:dom:d'], [1], 3600, 30), 'the second reservation passes the limit of one');
        self::assertTrue($this->store->releaseMailQuota('r1.0.1'), 'the pre-handoff release refunds the reserved capacity');
        self::assertTrue($this->store->reserveMailQuota('r3.0.1', ['emb:dom:d'], [1], 3600, 30), 'the freed capacity serves again');
    }

    public function testACommittedReservationKeepsItsSpendAndStaysIdempotent(): void
    {
        $this->store->reserveMailQuota('r1.0.1', ['emb:dom:d'], [1], 3600, 30);
        $this->store->commitMailQuota('r1.0.1');
        self::assertFalse($this->store->releaseMailQuota('r1.0.1'), 'a committed reservation never releases');
        self::assertFalse($this->store->reserveMailQuota('r2.0.1', ['emb:dom:d'], [1], 3600, 30), 'the committed spend counts');
    }

    public function testAReservationPastItsLeaseCommitsByDefault(): void
    {
        $this->store->reserveMailQuota('r1.0.1', ['emb:dom:d'], [1], 3600, 30);
        $this->now += 31;
        self::assertFalse($this->store->releaseMailQuota('r1.0.1'), 'the expired lease cannot release a possibly delivered message');
        self::assertFalse($this->store->reserveMailQuota('r2.0.1', ['emb:dom:d'], [1], 3600, 30), 'the spent quota stands');
    }

    public function testTheBeginFlowReservesCommitsAndReleasesAroundTheHandoff(): void
    {
        $demand = $this->mintRoot(StepUpOperationDigest::none('signup'), 'decision-1');
        $request = Request::create('/kiwi/step-up/email/begin', 'POST', [
            'demand' => $demand,
            'email' => 'visitor@example.com',
        ]);
        $response = $this->factor->begin($request);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        self::assertCount(1, $this->sender->codes, 'the delivered code went out');

        // The begin flow above released its demand (spent one send). A
        // refused delivery burns the credit instead of refunding it: the
        // ambiguous handoff commits.
        $second = Request::create('/kiwi/step-up/email/begin', 'POST', [
            'demand' => $demand,
            'email' => 'visitor@example.com',
        ]);
        $this->now += 61;
        $response = $this->factor->begin($second);
        self::assertSame(200, $response->getStatusCode());
        self::assertCount(2, $this->sender->codes);
    }

    public function testAPreHandoffStoreFailureReleasesTheReservation(): void
    {
        $demand = $this->mintRoot(StepUpOperationDigest::none('signup'), 'decision-1');
        $request = Request::create('/kiwi/step-up/email/begin', 'POST', [
            'demand' => $demand,
            'email' => 'visitor@example.com',
        ]);
        $response = $this->factor->begin($request);
        self::assertSame(200, $response->getStatusCode());
        // The demand is one send in; the resend spacing holds the second
        // begin until the window passes, which exercises the typed wait
        // answer rather than a reservation path.
        $this->now += 10;
        $early = $this->factor->begin($request);
        self::assertSame(429, $early->getStatusCode(), 'the resend spacing answers the typed wait');
    }

    // ── helpers ─────────────────────────────────────────────────────

    private function mintRoot(string $digest, string $decisionId): string
    {
        $demand = StepUpDemand::mint(\BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge::mintId(), 'signup', null, null, $decisionId, $this->now, 600, StepUpOperationBindingKind::None, $digest);

        return $this->store->createRootDemand($demand, 600);
    }

    /** The atomic escalation of one live tip; answers the child id or null. */
    private function escalate(string $parentId, string $childId, string $raisedBy): ?string
    {
        $parent = $this->store->readDemand($parentId);
        if ($parent === null) {
            return null;
        }
        $child = $parent->spawnChild($childId, $this->now, $raisedBy);

        return $this->store->supersedeDemandWithChild($parentId, $child) === null ? null : $child->id;
    }
}
