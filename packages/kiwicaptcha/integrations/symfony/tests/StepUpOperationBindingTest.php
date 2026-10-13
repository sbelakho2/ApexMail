<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandFinalizer;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFactorAssurance;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFinalization;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationDigest;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationMaterial;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResult;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use PHPUnit\Framework\TestCase;

/**
 * The operation identity vs content split and the durable Authorized
 * terminal. Covered: two transfers with identical contents but
 * different server-owned logical operation ids never cross-authorize;
 * the same logical operation with the same contents reproduces its
 * authorization idempotently; a changed content or a different op is
 * rejected. The authorized terminal retains the digests, the decision,
 * the quarantine flag, the factor and the timestamp; FactorVerified
 * never books the enrollment marker (only Authorized does); and the
 * factor challenge rules (expiry <= parent demand, one active
 * generation per demand) hold.
 */
final class StepUpOperationBindingTest extends TestCase
{
    private const MASTER = '0123456789abcdef0123456789abcdef';

    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    private const SCOPE = 'financial_action';

    private int $now = 1700000000;

    private ArrayStepUpChallengeStore $store;

    private SpyOutcomeReporter $reporter;

    protected function setUp(): void
    {
        $this->store = new ArrayStepUpChallengeStore(fn (): int => $this->now);
        $this->reporter = new SpyOutcomeReporter();
    }

    private function finalizer(): StepUpDemandFinalizer
    {
        return new StepUpDemandFinalizer(
            $this->store,
            new StepUpCompletionCredit($this->reporter, self::MASTER),
            null,
            null,
            null,
            null,
            null,
            null,
            fn (): int => $this->now,
            self::MASTER,
        );
    }

    /**
     * The acceptance test of the identity/content split: tx-001 and
     * tx-002 move the same $100 to Alice. A step-up for tx-001 must
     * NOT authorize tx-002 — the content digests match, the identity
     * digests do not, and the split refuses the cross-authorization.
     */
    public function testTwoTransfersWithSameContentsAndDifferentOperationIdsNeverCrossAuthorize(): void
    {
        $finalizer = $this->finalizer();
        $content = ['amount' => '100.00', 'currency' => 'USD', 'recipient' => 'alice'];

        // The step-up for transfer A (tx-001).
        $demandA = $finalizer->mintFinancialDemand(self::SCOPE, 'tx-001', $content, ttlSecs: 600);
        self::assertNotNull($demandA);
        $this->completeFactor($demandA);
        $grantA = $finalizer->finalizeGrant(
            $demandA,
            new StepUpOperationMaterial(formFields: $content),
            null,
            'email_ownership',
            'tx-001',
            StepUpOperationDigest::canonicalOperationContent($content),
        );
        self::assertTrue($grantA->authorized, 'the step-up for tx-001 authorizes tx-001');

        // Transfer B (tx-002) with identical contents tries to ride
        // transfer A's authorization: refused.
        $replayB = $finalizer->reproduce(
            $demandA,
            'tx-002',
            StepUpOperationDigest::canonicalOperationContent($content),
        );
        self::assertNull($replayB, 'the authorization for tx-001 must not reproduce for tx-002');

        // And finalizing a demand minted for B with A's operation id is
        // refused too: the binding is mutual.
        $demandB = $finalizer->mintFinancialDemand(self::SCOPE, 'tx-002', $content, ttlSecs: 600);
        self::assertNotNull($demandB);
        self::assertNotSame($demandA, $demandB);
        $this->completeFactor($demandB);
        $cross = $finalizer->finalizeGrant(
            $demandB,
            new StepUpOperationMaterial(formFields: $content),
            null,
            'email_ownership',
            'tx-001',
            StepUpOperationDigest::canonicalOperationContent($content),
        );
        self::assertFalse($cross->authorized, 'the demand for tx-002 must not finalize under tx-001');
        self::assertSame(StepUpFinalization::REFUSED_DIGEST, $cross->reason);

        // The correct finalization of B under its own identity succeeds.
        $okB = $finalizer->finalizeGrant(
            $demandB,
            new StepUpOperationMaterial(formFields: $content),
            null,
            'email_ownership',
            'tx-002',
            StepUpOperationDigest::canonicalOperationContent($content),
        );
        self::assertTrue($okB->authorized);
    }

    /**
     * The same logical operation with the same contents reproduces the
     * durable authorization idempotently. Changed contents reject.
     */
    public function testSameLogicalOperationAndContentsReproduceTheAuthorizationIdempotently(): void
    {
        $finalizer = $this->finalizer();
        $content = ['amount' => '100.00', 'currency' => 'USD', 'recipient' => 'alice'];
        $demandId = $finalizer->mintFinancialDemand(self::SCOPE, 'tx-001', $content, ttlSecs: 600);
        self::assertNotNull($demandId);
        $this->completeFactor($demandId);
        $first = $finalizer->finalizeGrant(
            $demandId,
            new StepUpOperationMaterial(formFields: $content),
            null,
            'totp',
            'tx-001',
            StepUpOperationDigest::canonicalOperationContent($content),
        );
        self::assertTrue($first->authorized);

        // Idempotent reproduction: same op + same contents.
        $again = $finalizer->reproduce($demandId, 'tx-001', StepUpOperationDigest::canonicalOperationContent($content));
        self::assertNotNull($again, 'the same logical operation with the same contents reproduces the authorization');
        self::assertSame(StepUpDemandState::Authorized, $again->state);

        // Changed contents (a different amount) reject.
        $changed = $finalizer->reproduce($demandId, 'tx-001', StepUpOperationDigest::canonicalOperationContent([
            'amount' => '999.00',
            'currency' => 'USD',
            'recipient' => 'alice',
        ]));
        self::assertNull($changed, 'changed contents must reject the reproduction');
    }

    /**
     * The replay gate of the settled family (operationAuthorized) is
     * bound to both digests, the same invariant the finalization
     * binding check enforces. The exact regression matrix: the same
     * operation with the same contents is the authorized replay; the
     * same operation with a changed amount, recipient or currency is
     * refused; a different operation with identical contents is
     * refused. An authorized family tip alone answers nothing.
     */
    public function testOperationAuthorizedRequiresBothTheIdentityAndTheContentDigest(): void
    {
        $finalizer = $this->finalizer();
        $content = ['amount' => '100.00', 'currency' => 'USD', 'recipient' => 'alice'];
        $demandId = $finalizer->mintFinancialDemand(self::SCOPE, 'tx-001', $content, ttlSecs: 600);
        self::assertNotNull($demandId);
        $this->completeFactor($demandId);
        $settled = $finalizer->finalizeGrant(
            $demandId,
            new StepUpOperationMaterial(formFields: $content),
            null,
            'email_otp',
            'tx-001',
            StepUpOperationDigest::canonicalOperationContent($content),
        );
        self::assertTrue($settled->authorized, 'the preconditions: tx-001 sits authorized');

        // Same operation, same contents: the authorized replay.
        self::assertTrue(
            $finalizer->operationAuthorized(self::SCOPE, 'tx-001', $content),
            'the same logical operation with the same contents is the authorized replay',
        );

        // Same operation, changed amount: refused.
        self::assertFalse(
            $finalizer->operationAuthorized(self::SCOPE, 'tx-001', ['amount' => '50000.00', 'currency' => 'USD', 'recipient' => 'alice']),
            'a changed amount must not ride the settled authorization',
        );

        // Same operation, changed recipient: refused.
        self::assertFalse(
            $finalizer->operationAuthorized(self::SCOPE, 'tx-001', ['amount' => '100.00', 'currency' => 'USD', 'recipient' => 'bob']),
            'a changed recipient must not ride the settled authorization',
        );

        // Same operation, changed currency: refused.
        self::assertFalse(
            $finalizer->operationAuthorized(self::SCOPE, 'tx-001', ['amount' => '100.00', 'currency' => 'EUR', 'recipient' => 'alice']),
            'a changed currency must not ride the settled authorization',
        );

        // Different operation, identical contents: refused.
        self::assertFalse(
            $finalizer->operationAuthorized(self::SCOPE, 'tx-002', $content),
            'a different logical operation with identical contents must not ride the settled authorization',
        );
    }

    /**
     * The durable authorized terminal retains the operation digests,
     * the decision, the quarantine flag, the factor and the timestamp.
     */
    public function testTheAuthorizedTerminalRetainsTheBindingDecisionQuarantineFactorAndTimestamp(): void
    {
        $finalizer = $this->finalizer();
        $content = ['amount' => '100.00', 'currency' => 'USD', 'recipient' => 'alice'];
        $binding = StepUpOperationDigest::financialBinding(
            self::MASTER,
            self::SCOPE,
            'tx-001',
            StepUpOperationDigest::canonicalOperationContent($content),
        );
        $demand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            self::SCOPE,
            null,
            'chain-0000000000000000000000000000',
            'decision-1',
            $this->now,
            600,
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind::FormFields,
            $binding['identity'],
            $binding['identity'],
            $binding['content'],
            true,
        );
        $this->store->createDemand($demand, 600);
        $this->completeFactor($demand->id);
        $result = $finalizer->finalizeGrant(
            $demand->id,
            new StepUpOperationMaterial(formFields: $content),
            null,
            'webauthn',
            'tx-001',
            StepUpOperationDigest::canonicalOperationContent($content),
        );
        self::assertTrue($result->authorized);

        $settled = $this->store->readDemand($demand->id);
        self::assertNotNull($settled);
        self::assertSame(StepUpDemandState::Authorized, $settled->state);
        self::assertSame($binding['identity'], $settled->operationIdentityDigest);
        self::assertSame($binding['content'], $settled->operationContentDigest);
        self::assertSame('decision-1', $settled->decisionId);
        self::assertTrue($settled->quarantine);
        self::assertSame('webauthn', $settled->factor);
        self::assertSame($this->now, $settled->authorizedAt);
    }

    /**
     * FactorVerified != AuthorizedStepUp: a completed factor alone
     * never creates the generic enrollment bootstrap marker; only the
     * authorized settlement does.
     */
    public function testFactorVerifiedNeverBooksTheEnrollmentMarkerOnlyAuthorizedDoes(): void
    {
        $finalizer = $this->finalizer();
        $content = ['amount' => '100.00', 'currency' => 'USD', 'recipient' => 'alice'];
        $demandId = $finalizer->mintFinancialDemand(self::SCOPE, 'tx-001', $content, ttlSecs: 600);
        self::assertNotNull($demandId);
        // Factor verified only: the proof books nothing.
        $this->completeFactor($demandId);
        self::assertFalse(
            $this->store->recentStepUpSuccess(self::PRINCIPAL, 900, $this->now),
            'FactorVerified must not create the enrollment bootstrap marker',
        );

        $result = $finalizer->finalizeGrant(
            $demandId,
            new StepUpOperationMaterial(formFields: $content, principalPseudonym: self::PRINCIPAL),
            null,
            'email_otp',
            'tx-001',
            StepUpOperationDigest::canonicalOperationContent($content),
        );
        self::assertTrue($result->authorized);
        self::assertTrue(
            $this->store->recentStepUpSuccess(self::PRINCIPAL, 900, $this->now),
            'Authorized creates the generic enrollment bootstrap marker',
        );
    }

    /**
     * The factor challenge rules: a challenge may never outlive its
     * parent demand, and at most one active generation lives per demand.
     */
    public function testFactorChallengeExpiryNeverOutlivesTheParentDemandAndOneGenerationOnly(): void
    {
        $finalizer = $this->finalizer();
        $content = ['amount' => '100.00', 'currency' => 'USD', 'recipient' => 'alice'];
        $demandId = $finalizer->mintFinancialDemand(self::SCOPE, 'tx-001', $content, ttlSecs: 600);
        self::assertNotNull($demandId);
        $demand = $this->store->readDemand($demandId);
        self::assertNotNull($demand);

        // A challenge expiring after the parent demand refuses.
        $tooLong = $demand->admitFactorChallenge(StepUpChallenge::mintId(), $demand->expiresAt + 1, $this->now);
        self::assertNull($tooLong, 'a factor challenge may never outlive its parent demand');

        // A challenge within the demand is admitted (well before the
        // demand's own expiry).
        $challengeId = StepUpChallenge::mintId();
        $challengeExpiry = $this->now + 300;
        $admitted = $demand->admitFactorChallenge($challengeId, $challengeExpiry, $this->now);
        self::assertNotNull($admitted);
        self::assertSame($challengeId, $admitted->activeChallengeId);

        // A second generation while the first is live refuses.
        $second = $admitted->admitFactorChallenge(StepUpChallenge::mintId(), $challengeExpiry, $this->now);
        self::assertNull($second, 'at most one active factor challenge per demand');

        // After the first challenge expires, a new generation is admitted.
        $this->now = $challengeExpiry + 1;
        $third = $admitted->admitFactorChallenge(StepUpChallenge::mintId(), $demand->expiresAt, $this->now);
        self::assertNotNull($third);
    }

    /**
     * A denied terminal authorizes nothing ever again; a half bound
     * (identity without content) is refused at mint.
     */
    public function testDeniedIsDurableAndAHalfBoundMintRefuses(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        StepUpDemand::mint(
            StepUpChallenge::mintId(),
            self::SCOPE,
            null,
            null,
            null,
            $this->now,
            600,
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind::FormFields,
            str_repeat('a', 64),
            str_repeat('b', 64),
            null,
        );
    }

    /**
     * The wire form round-trips the split digests, the authorized
     * retention and the superseded link.
     */
    public function testTheWireFormRoundTripsTheSplitBindingAndTheDurableTerminals(): void
    {
        $content = ['amount' => '100.00', 'currency' => 'USD', 'recipient' => 'alice'];
        $binding = StepUpOperationDigest::financialBinding(
            self::MASTER,
            self::SCOPE,
            'tx-001',
            StepUpOperationDigest::canonicalOperationContent($content),
        );
        $demand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            self::SCOPE,
            null,
            null,
            'decision-9',
            $this->now,
            600,
            \BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationBindingKind::FormFields,
            $binding['identity'],
            $binding['identity'],
            $binding['content'],
            true,
        );
        $encoded = (string) json_encode($demand->toArray(), JSON_UNESCAPED_SLASHES);
        $decoded = StepUpDemand::fromJson($encoded);
        self::assertNotNull($decoded);
        self::assertSame($binding['identity'], $decoded->operationIdentityDigest);
        self::assertSame($binding['content'], $decoded->operationContentDigest);
        self::assertTrue($decoded->quarantine);
        self::assertSame('decision-9', $decoded->decisionId);

        $authorized = $decoded->withAuthorized('totp', $this->now + 10);
        $roundTrip = StepUpDemand::fromJson((string) json_encode($authorized->toArray(), JSON_UNESCAPED_SLASHES));
        self::assertNotNull($roundTrip);
        self::assertSame(StepUpDemandState::Authorized, $roundTrip->state);
        self::assertSame('totp', $roundTrip->factor);
        self::assertSame($this->now + 10, $roundTrip->authorizedAt);
        self::assertSame($binding['identity'], $roundTrip->operationIdentityDigest);
        self::assertSame($binding['content'], $roundTrip->operationContentDigest);
    }

    /**
     * Move the demand open -> completed (the factor+demand completion).
     */
    private function completeFactor(string $demandId): void
    {
        $completed = $this->store->completeDemand($demandId, $this->now, 600);
        self::assertNotNull($completed, 'the factor+demand completion must land');
        self::assertSame(StepUpDemandState::Completed, $completed->state);
    }
}
