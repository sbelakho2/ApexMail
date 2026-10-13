<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use BelConsulting\KiwiCaptchaBundle\Risk\AmbiguousForwardingException;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * The demand finalizer of the step-up plane: the one service the whole
 * plane authorizes a completed factor through. There is exactly one
 * implementation, and every completion lane calls it. The validator
 * calls it when a redeemed grant resubmits the protected form, and the
 * login completion path calls it before any session restore. Nothing
 * else books a step-up completion. FactorVerified is never
 * AuthorizedStepUp: only this finalizer's authorized terminal creates
 * the generic enrollment bootstrap marker, restores the login, trusts
 * the device/network, writes StepUpCompleted, or validates the
 * protected operation.
 *
 * The sequence, in order and shared by every lane:
 *
 *  1. the operation binding check: when the demand carries the split
 *     financial/action binding, both digests must reproduce:
 *     operationIdentityDigest (HMAC of the server-owned unique logical
 *     operation id) and operationContentDigest (HMAC of the canonical
 *     amount/currency/recipient contents). The same logical operation
 *     with the same contents is idempotent; a different operation
 *     (even with identical contents) or changed contents is rejected.
 *     A step-up for tx-001 never authorizes tx-002.
 *  2. the recipe rerun: the demand record carries the operation digest
 *     minted with one canonical recipe, named by its
 *     {@see StepUpOperationBindingKind}. The finalizer recomputes the
 *     digest with that same recipe over the caller's material and
 *     refuses on any mismatch.
 *  3. the acquisition: the demand lifecycle claim moves the completed
 *     demand to finalizing atomically, so exactly one owner runs the
 *     reassessment (a stale claim is retaken after its window).
 *  4. the reassessment: a fresh engine decision under the
 *     completed-step-up event, on the same inputs the demand was
 *     raised in. A Deny refuses the completion. A StepUp escalates the
 *     assurance: the demand is superseded by its strictly stronger
 *     child in one atomic store transaction. An absent engine
 *     (manual construction) or an absent or weaker decision authorizes
 *     the demand on the factor proof alone.
 *  5. the terminal compare-and-set: the demand settles authorized or
 *     denied, atomically, once. The authorized terminal is durable and
 *     retains the operation digests, the decision, the quarantine
 *     flag, the factor and the timestamp.
 *  6. the completion effects, authorized settlements only: the
 *     stepUpCompleted outcome credit ({@see StepUpCompletionCredit}),
 *     the pending-login restore ({@see SessionRestorer}) and the
 *     generic enrollment bootstrap marker. Every effect journals on
 *     the demand record ({@see StepUpEffectsJournal}) as it lands: a
 *     crash between the terminal and an effect is recovered by the
 *     demand-bound effects retry, {@see self::retryAuthorizedEffects()}.
 *     The retry runs on the session's own state, its pending token
 *     or, after a landed restore, the session's restore claim, never
 *     a second factor.
 *     An authorized replay re-runs exactly the unjournaled effects.
 *
 * The finalizer is also the mint of the login plane's demand: a pending
 * token's begin() obtains its demand record here, under the login
 * binding kind and the principal recipe. The custom handler a login
 * flow selects therefore binds to a demand through the same mechanism
 * as every built-in factor.
 */
final class StepUpDemandFinalizer
{
    /** The claim window of one finalization owner. */
    private const CLAIM_SECS = 30;

    /** The enrollment bootstrap marker lifetime (the same 900 s the handlers used). */
    public const ENROLLMENT_MARKER_TTL_SECS = 900;

    public function __construct(
        private readonly StepUpChallengeStore $store,
        private readonly StepUpCompletionCredit $credit,
        private readonly ?SessionRestorer $sessionRestorer = null,
        private readonly ?RiskGateway $risk = null,
        private readonly ?ClientIpResolver $clientIpResolver = null,
        private readonly ?ContinuityCookie $continuity = null,
        private readonly ?RequestStack $requestStack = null,
        private readonly ?LoggerInterface $logger = null,
        private readonly ?\Closure $now = null,
        /**
         * The HMAC master of the split operation digests (identity and
         * content). Purpose-separated HKDF derivations of this master
         * key the two digests; the master itself is never used as a key.
         * A deployment that mints financial bindings MUST pass the same
         * master here and at mint, or the reproduce check refuses.
         */
        private readonly string $operationBindingMaster = '',
        /**
         * The factor requirement source. Null keeps the login demand
         * un-snapshotted (a deployment that mints without the resolver);
         * wired, every minted demand records the factor it requires,
         * escalated strictly past the family's completed factor.
         */
        private readonly ?StepUpFactorResolver $factorResolver = null,
    ) {
    }

    /**
     * Mint the login plane's demand for one raised step-up demand: the
     * record a pending token's begin binds its factor challenge to. The
     * digest is minted under the login recipe over the principal
     * pseudonym, so only the session that resolves the same principal
     * can ever finalize it. Null when the store refused the record; the
     * begin then answers no demandId and its proof finalizes nothing,
     * fail closed.
     *
     * $demandId is the exact demand identity the pending token was
     * wrapped under. When given, the record takes it as its own id: the
     * completed proof names the demand of exactly this login, and the
     * finalization can hold the restoring session to it. A standing
     * open record of that identity is answered as-is (a re-begin inside
     * one pending login). Anything else is refused.
     */
    public function mintLoginDemand(string $scope, string $principalPseudonym, ?string $sessionHash, int $ttlSecs, ?string $demandId = null): ?string
    {
        if ($demandId !== null && preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $demandId) !== 1) {
            return null;
        }
        try {
            $required = $this->requiredFactorOf($scope, $sessionHash);
        } catch (StepUpAssuranceUnavailable $e) {
            // An unavailable assurance state is no basis for a demand:
            // the mint refuses (no demand id, nothing stored) instead of
            // minting a no-snapshot record, fail closed.
            $this->logger?->warning('kiwi step-up demand mint refused: {message}', ['message' => $e->getMessage()]);

            return null;
        }
        $demand = StepUpDemand::mint(
            $demandId ?? StepUpChallenge::mintId(),
            $scope,
            $sessionHash,
            null,
            null,
            $this->now(),
            $ttlSecs,
            StepUpOperationBindingKind::Login,
            StepUpOperationDigest::login($scope, $principalPseudonym),
            null,
            null,
            false,
            null,
            $required,
        );
        try {
            $this->store->createDemand($demand, $ttlSecs);
        } catch (\Throwable) {
            // The identity collides with a standing record: the same
            // pending login re-beginning is served by its live open
            // demand, anything else refuses, fail closed.
            if ($demandId === null) {
                return null;
            }
            try {
                $standing = $this->store->readDemand($demandId);
            } catch (\Throwable) {
                return null;
            }
            if ($standing === null || $standing->expired($this->now()) || !$standing->state->isOpen() || $standing->superseded()) {
                return null;
            }

            return $standing->id;
        }

        return $demand->id;
    }

    /**
     * The factor requirement the mint snapshots onto its demand: the
     * resolver's answer for the scope, escalated strictly past the
     * factor the family's live completion marker records. A demand
     * minted after a completed weaker factor can therefore never be
     * answered with that same weaker factor again. Null when no
     * resolver is wired (the demand then carries no snapshot), and null
     * when the resolver genuinely answers an empty history (no prior
     * factor stands). An unavailable completion history or a failing
     * resolver is the third state, and it is never folded into the
     * empty one: it answers
     * {@see StepUpAssuranceUnavailable}. The mint then refuses instead
     * of silently minting a demand with no assurance snapshot.
     *
     * @throws StepUpAssuranceUnavailable when the store or the resolver fails
     */
    private function requiredFactorOf(string $scope, ?string $sessionHash): ?FactorRequirement
    {
        if ($this->factorResolver === null) {
            return null;
        }
        $completed = null;
        if ($sessionHash !== null && $sessionHash !== '') {
            try {
                $completed = $this->store->completedFactorOf($sessionHash, $scope, $this->now());
            } catch (\Throwable $e) {
                // An unavailable completion history is not a session
                // without a prior factor: the mint cannot know what to
                // demand, so it refuses rather than degrade the failure
                // into "no requirement".
                throw new StepUpAssuranceUnavailable('the step-up completion history is unavailable', 0, $e);
            }
        }
        try {
            return $this->factorResolver->requiredFactor($scope, null, new StepUpFactorContext($completed));
        } catch (\Throwable $e) {
            throw new StepUpAssuranceUnavailable('the step-up factor resolver failed', 0, $e);
        }
    }

    /**
     * The demand id a begin of the login plane binds its factor to: the
     * named pending demand while it stands. Once an escalation
     * superseded it, the answer is the live open tip of its family: the
     * strictly stronger child the reassessment created, followed
     * through the supersede links, bounded by the family depth. This is
     * how the escalation child becomes beginnable: the pending token
     * still carries the superseded parent's id, and the begin follows
     * the family to the child instead of refusing. Everything is judged
     * against server-owned state, fail closed: the tip must be open,
     * carry the login binding kind and reproduce the resolved
     * principal's login recipe. Null when the named id carries no
     * demand (a fresh begin mints one), when the family died, or when
     * the tip refuses any of the checks.
     */
    public function loginDemandIdForBegin(string $scope, string $principalPseudonym, ?string $sessionHash, ?string $demandId): ?string
    {
        if ($demandId === null) {
            return null;
        }
        $computed = StepUpOperationDigest::login($scope, $principalPseudonym);
        $id = $demandId;
        for ($hop = 0; $hop <= StepUpDemand::MAX_GENERATION; $hop++) {
            $demand = $this->liveDemand($id);
            if ($demand === null) {
                return null;
            }
            if (!$demand->superseded()) {
                if ($demand->state !== StepUpDemandState::Open
                    || $demand->operationBindingKind !== StepUpOperationBindingKind::Login
                    || !hash_equals($demand->operationDigest, $computed)) {
                    return null;
                }

                return $demand->id;
            }
            $next = $demand->supersededByDemandId;
            if ($next === null || $next === $id) {
                return null;
            }
            $id = $next;
        }

        return null;
    }

    /**
     * Mint a financial/action-bound demand: the split operation binding
     * of the protected operation. The identity digest is the HMAC of
     * the server-owned unique logical operation id (never a raw client
     * value alone); the content digest is the HMAC of the canonical
     * amount/currency/recipient contents. The demand snapshots the
     * factor requirement the mint resolved for the session, so the
     * stored record, never the request, decides which factor answers
     * it. Null when the store refused the record.
     *
     * @param array<string, string> $canonicalContentFields the named
     *                                                      contents
     *                                                      (amount,
     *                                                      currency,
     *                                                      recipient,
     *                                                      ...)
     */
    public function mintFinancialDemand(
        string $scope,
        string $serverOwnedOperationId,
        array $canonicalContentFields,
        ?string $sessionHash = null,
        ?string $chainId = null,
        ?string $decisionId = null,
        int $ttlSecs = 600,
        bool $quarantine = false,
    ): ?string {
        return $this->mintBoundDemand(
            $scope,
            $serverOwnedOperationId,
            StepUpOperationDigest::canonicalOperationContent($canonicalContentFields),
            $sessionHash,
            $chainId,
            $decisionId,
            $ttlSecs,
            $quarantine,
        );
    }

    /**
     * The canonical-contents spelling of {@see self::mintFinancialDemand()}:
     * the operation resolver's protected contents, already canonicalized
     * by the one shared canonicalization, feed the content digest
     * directly. The actual business operation (the amount, the currency,
     * the beneficiary) rides the digest, not a shapeless stand-in.
     *
     * @param string $canonicalContent the canonical protected contents
     *                                 of the operation
     */
    public function mintBoundDemand(
        string $scope,
        string $serverOwnedOperationId,
        string $canonicalContent,
        ?string $sessionHash = null,
        ?string $chainId = null,
        ?string $decisionId = null,
        int $ttlSecs = 600,
        bool $quarantine = false,
    ): ?string {
        $binding = StepUpOperationDigest::financialBinding(
            $this->operationBindingMaster,
            $scope,
            $serverOwnedOperationId,
            $canonicalContent,
        );
        try {
            $required = $this->requiredFactorOf($scope, $sessionHash);
        } catch (StepUpAssuranceUnavailable $e) {
            // An unavailable assurance state is no basis for a demand:
            // the mint refuses (no demand id, nothing stored) instead of
            // minting a no-snapshot record, fail closed.
            $this->logger?->warning('kiwi step-up demand mint refused: {message}', ['message' => $e->getMessage()]);

            return null;
        }
        $demand = StepUpDemand::mint(
            StepUpChallenge::mintId(),
            $scope,
            $sessionHash,
            $chainId,
            $decisionId,
            $this->now(),
            $ttlSecs,
            StepUpOperationBindingKind::FormFields,
            $binding['identity'],
            $binding['identity'],
            $binding['content'],
            $quarantine,
            null,
            $required,
        );
        try {
            return $this->store->createRootDemand($demand, $ttlSecs);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Whether the logical operation already carries a durable authorized
     * step-up settlement: the operation identity digest is reproduced
     * exactly as the mint built it (the same master, the same
     * canonicalization) and the operation family tip is consulted. The
     * same invariant as the finalization binding check holds in full:
     * the tip is the answer only when it sits in the authorized terminal
     * and both digests reproduce. The identity digest runs over the
     * logical operation id, the content digest over the canonical
     * contents. A retry of the same operation with the same contents
     * then answers its settled demand. A different operation (even with
     * identical contents) derives a different identity digest and
     * answers false. The same operation with changed contents derives a
     * different content digest and answers false too. False for an
     * absent family, a non-authorized tip, a digest that does not
     * reproduce, an empty master, or a store failure: fail-closed
     * toward re-demand, never a silent pass.
     *
     * @param array<string, string> $canonicalContentFields the named
     *                                                      contents the
     *                                                      mint
     *                                                      canonicalized
     */
    public function operationAuthorized(
        string $scope,
        string $serverOwnedOperationId,
        array $canonicalContentFields,
    ): bool {
        return $this->operationAuthorizedContents(
            $scope,
            $serverOwnedOperationId,
            StepUpOperationDigest::canonicalOperationContent($canonicalContentFields),
        );
    }

    /**
     * The canonical-contents spelling of {@see self::operationAuthorized()}:
     * the protected contents already canonicalized by one shared
     * canonicalization, so the mint and this replay gate hash the same
     * bytes.
     *
     * @param string $canonicalContent the canonical operation contents
     *                                 the mint hashed
     */
    public function operationAuthorizedContents(
        string $scope,
        string $serverOwnedOperationId,
        string $canonicalContent,
    ): bool {
        if ($this->operationBindingMaster === '') {
            return false;
        }
        try {
            $binding = StepUpOperationDigest::financialBinding(
                $this->operationBindingMaster,
                $scope,
                $serverOwnedOperationId,
                $canonicalContent,
            );
            $tipId = $this->store->demandIdForOperation($binding['identity']);
            if (!\is_string($tipId) || $tipId === '') {
                return false;
            }
            $demand = $this->store->readDemand($tipId);
        } catch (\Throwable) {
            return false;
        }

        // The family tip alone is not the answer: the settled
        // authorization is bound to both digests, so the presented
        // operation reproduces it only when the identity AND the content
        // digest both match the stored terminal.
        return $demand !== null
            && $demand->state === StepUpDemandState::Authorized
            && $demand->matchesOperation($binding['identity'], $binding['content']);
    }

    /**
     * Finalize one completed factor for the login plane: the demand
     * named by the proof is completed by the caller (the atomic
     * factor+demand transition), reassessed, settled terminally and,
     * only when authorized, credited and restored.
     *
     * When the demand carries the split financial/action binding, the
     * caller supplies the operation the completion presents, resolved
     * through the wired resolver. The finalization reruns both digests
     * over it: a different logical operation, or the same operation
     * with changed contents, refuses the completion, so the principal
     * plane can never authorize a proof against operation material the
     * demand was never minted for.
     *
     * @param StepUpResult $proof the handler's verified factor proof
     */
    public function finalizeLogin(StepUpResult $proof, string $scope, ?Request $request = null, ?StepUpOperation $operation = null): StepUpFinalization
    {
        if ($proof->demandId === null || $proof->principalPseudonym === null) {
            return StepUpFinalization::refusedUnbound();
        }
        $demand = $this->liveDemand($proof->demandId);
        if ($demand === null) {
            return StepUpFinalization::refusedAbsent();
        }
        if ($demand->operationIdentityDigest !== null) {
            if (!$this->operationBindingMatches($demand, $operation?->logicalOperationId, $operation?->canonicalProtectedContents)) {
                $this->logger?->info('kiwi step-up demand finalization refused: the presented operation does not reproduce the bound authorization', [
                    'demand' => $demand->id,
                ]);

                return StepUpFinalization::refusedDigest();
            }
        }
        $material = StepUpOperationMaterial::login($proof->principalPseudonym);
        $reassessed = $this->finalize($demand, $material, $proof->factor ?? 'unknown', $request);

        return $this->bookEffects($reassessed, $proof, $request);
    }

    /**
     * Finalize the demand a redeemed grant answers, for the form
     * resubmission lane: the validator calls this after the factor
     * consumed the grant, with the canonical operation fields of the
     * resubmitted form and the transaction binding it resolved. The
     * demand must already sit in the completed state the factor's
     * atomic completion left it in; the authorized answer is the
     * validator's acceptance.
     *
     * When the demand carries the split financial/action binding, the
     * caller must supply the same logical operation id and contents the
     * demand was minted for: a different operation or changed contents
     * is refused, so a step-up for tx-001 never authorizes tx-002.
     */
    public function finalizeGrant(
        string $demandId,
        StepUpOperationMaterial $material,
        ?Request $request = null,
        string $factor = 'email_ownership',
        ?string $operationId = null,
        ?string $canonicalContent = null,
    ): StepUpFinalization {
        $demand = $this->liveDemand($demandId);
        if ($demand === null) {
            return StepUpFinalization::refusedAbsent();
        }
        if (!$this->operationBindingMatches($demand, $operationId, $canonicalContent)) {
            $this->logger?->info('kiwi step-up demand finalization refused: the presented operation does not reproduce the bound authorization', [
                'demand' => $demand->id,
            ]);

            return StepUpFinalization::refusedDigest();
        }
        $finalized = $this->finalize($demand, $material, $factor, $request);

        return $this->bookAuthorizedEffects($finalized, $demand, $factor, $material->principalPseudonym, $request);
    }

    /**
     * Reproduce a durable authorized settlement for the same logical
     * operation and the same contents. The same op + contents answers
     * the existing authorization idempotently; a different op or
     * changed contents is rejected. Null when the demand is not an
     * authorized terminal or the binding does not reproduce.
     */
    public function reproduce(
        string $demandId,
        ?string $operationId,
        ?string $canonicalContent,
    ): ?StepUpDemand {
        $demand = $this->liveDemand($demandId);
        if ($demand === null || $demand->state !== StepUpDemandState::Authorized) {
            return null;
        }
        if (!$this->operationBindingMatches($demand, $operationId, $canonicalContent)) {
            return null;
        }

        return $demand;
    }

    /**
     * The shared sequence over one completed demand: the recipe rerun,
     * the acquisition, the reassessment, the terminal settlement. The
     * completion effects are booked by the lane (it owns the proof
     * payload); every lane books them through
     * {@see self::bookEffects()} and nothing else.
     */
    private function finalize(StepUpDemand $demand, StepUpOperationMaterial $material, string $factor, ?Request $request): StepUpFinalization
    {
        if ($demand->state !== StepUpDemandState::Completed) {
            // An authorized terminal replays its disposition
            // idempotently; a denied or superseded demand stays closed.
            if ($demand->state === StepUpDemandState::Authorized) {
                return StepUpFinalization::authorizedReplay($demand);
            }
            if ($demand->state === StepUpDemandState::Denied) {
                return StepUpFinalization::refusedDenied();
            }

            return StepUpFinalization::refusedState($demand->state);
        }
        // The recipe rerun, before any state move: the digest the stored
        // binding kind prescribes, computed over the caller's material.
        // A mismatch (or a material that cannot feed the recipe) refuses
        // the finalization without spending the claim. The split
        // financial/action binding already ran its own dual-digest
        // check (identity AND content), so the recipe rerun applies to
        // the unsplit bindings only.
        if ($demand->operationIdentityDigest === null) {
            $computed = StepUpOperationDigest::rerun($demand->scope, $demand->operationBindingKind, $material);
            if ($computed === null || !hash_equals($demand->operationDigest, $computed)) {
                $this->logger?->info('kiwi step-up demand finalization refused: the operation digest does not match the stored recipe', [
                    'kind' => $demand->operationBindingKind->value,
                ]);

                return StepUpFinalization::refusedDigest();
            }
        }
        // The acquisition: exactly one owner reassesses. A demand that
        // is already authorized replays its disposition (the effects are
        // re-run idempotently by the caller); a denied demand stays
        // denied.
        $claimed = $this->store->claimDemandFinalization($demand->id, $this->now(), self::CLAIM_SECS);
        if ($claimed === null) {
            $fresh = $this->liveDemand($demand->id);
            if ($fresh !== null && $fresh->state === StepUpDemandState::Authorized) {
                return StepUpFinalization::authorizedReplay($fresh);
            }
            if ($fresh !== null && $fresh->state === StepUpDemandState::Denied) {
                return StepUpFinalization::refusedDenied();
            }

            return StepUpFinalization::refusedState($fresh?->state ?? StepUpDemandState::Denied);
        }
        // The reassessment: a fresh engine answer under the
        // completed-step-up event, on the context the demand carried.
        // Three answers: a Deny settles the demand denied, a StepUp
        // escalates the assurance (the demand is superseded by its
        // strictly stronger child, never authorized on the weaker
        // proof), and every weaker rung (Allow and the proof-of-work
        // actions, all below StepUp) settles the demand authorized. An
        // unwired engine (manual construction) authorizes on the factor
        // proof alone.
        $decision = $this->reassess($demand, $material, $request);
        if ($decision !== null && $decision->action === \KiwiCaptcha\Risk\RiskAction::Deny) {
            $this->settle($demand->id, StepUpDemandState::Denied);
            $this->logger?->info('kiwi step-up demand finalization refused: the fresh assessment denied the completed factor');

            return StepUpFinalization::refusedDenied();
        }
        if ($decision !== null && $decision->action === \KiwiCaptcha\Risk\RiskAction::StepUp) {
            return $this->escalate($demand, $factor, $decision->decisionId);
        }
        $this->settleAuthorized($demand->id, $factor);

        return StepUpFinalization::authorized($demand);
    }

    /**
     * The assurance escalation of one fresh StepUp reassessment: the
     * completed factor satisfied the proof but not the engine, so the
     * demand is superseded by a strictly stronger child in one atomic
     * store transaction. The child is answered as the demand the
     * caller still owes a proof for. The child inherits the parent's
     * remaining authorization lifetime and its operation binding, and
     * records the reassessment's decision id separately. The completed
     * factor is never carried over: the child demands the next rung of
     * the ladder. A family at its depth cap, or a completed factor no
     * rung outranks, fails closed: the demand settles denied, never
     * authorized on the weaker proof.
     */
    private function escalate(StepUpDemand $demand, string $completedFactor, ?string $raisedByDecisionId): StepUpFinalization
    {
        $requirement = $this->strongerRequirement($demand->scope, $completedFactor);
        // The parent sits in its completed (here: claimed) state, past
        // the factor proof: the family cap and the supersede link are
        // the escalation's own bounds, never the open-state rule of a
        // mint-time child.
        $capped = $demand->superseded() || $demand->generation >= StepUpDemand::MAX_GENERATION;
        if ($requirement === null || $capped) {
            $this->settle($demand->id, StepUpDemandState::Denied);
            $this->logger?->info('kiwi step-up demand finalization refused: the fresh assessment demands a stronger factor and the ladder offers none', [
                'demand' => $demand->id,
            ]);

            return StepUpFinalization::refusedDenied();
        }
        $child = $demand->spawnChild(StepUpChallenge::mintId(), $this->now(), $raisedByDecisionId, $requirement);
        $superseded = $this->store->supersedeDemandWithChild($demand->id, $child);
        if ($superseded === null) {
            // The family transaction refused. Two distinct shapes: a
            // concurrent escalation already won (the parent's superseded
            // terminal stands, written by the winner's own transaction)
            // or the parent expired inside the claim. The first settles
            // nothing — the absorbing terminal is already there and a
            // denied settlement would answer null and throw — it
            // returns the same refused answer. The second settles
            // denied, fail closed, never authorized.
            $current = $this->store->readDemand($demand->id);
            if ($current !== null && $current->superseded()) {
                $this->logger?->info('kiwi step-up demand escalation lost the supersede race; the standing terminal answers', [
                    'demand' => $demand->id,
                    'child' => $current->supersededByDemandId,
                ]);

                return StepUpFinalization::refusedDenied();
            }
            $this->settle($demand->id, StepUpDemandState::Denied);
            $this->logger?->info('kiwi step-up demand escalation refused; the demand settled denied', [
                'demand' => $demand->id,
            ]);

            return StepUpFinalization::refusedDenied();
        }
        // The superseded terminal landed atomically inside the store's
        // supersede transaction: state, stamp and child link together.
        // No follow-up settlement exists to lose.
        $this->logger?->info('kiwi step-up demand escalated to a strictly stronger factor', [
            'demand' => $child->id,
        ]);

        return StepUpFinalization::escalated($child);
    }

    /**
     * The requirement the escalation child demands: the resolver's
     * answer for the scope, judged past the factor family the
     * completion proved. Null when no strictly stronger rung exists
     * (the top of the ladder is already completed) or the resolver is
     * unwired: the escalation then has no factor to demand and fails
     * closed. The anonymous address-ownership grant proves the
     * email_otp rung of the ladder, spelled as the grant lane's own
     * factor identity.
     */
    private function strongerRequirement(string $scope, string $completedFactor): ?FactorRequirement
    {
        if ($this->factorResolver === null) {
            return null;
        }
        $family = FactorRequirement::isFamily($completedFactor)
            ? $completedFactor
            : ($completedFactor === StepUpFactorAssurance::EMAIL_OWNERSHIP ? FactorRequirement::EMAIL_OTP : $completedFactor);
        $completedRank = FactorRequirement::rankOf($family);
        try {
            $requirement = $this->factorResolver->requiredFactor($scope, null, new StepUpFactorContext($family));
        } catch (\Throwable) {
            return null;
        }
        if ($requirement->assuranceRank <= $completedRank) {
            return null;
        }

        return $requirement;
    }

    /**
     * The completion effects of an authorized settlement for the grant
     * lane: the outcome credit, the pending-login restore and the
     * generic enrollment bootstrap marker, each journaled on the demand
     * as it lands. Invoked only after {@see self::finalize()} answered
     * authorized, and re-invoked idempotently for an authorized replay:
     * journal effects skip, missing effects run once.
     */
    private function bookAuthorizedEffects(
        StepUpFinalization $finalization,
        StepUpDemand $demand,
        string $factor,
        ?string $principalPseudonym,
        ?Request $request,
    ): StepUpFinalization {
        if (!$finalization->authorized) {
            return $finalization;
        }
        if ($principalPseudonym === null || $principalPseudonym === '') {
            return $finalization;
        }

        return $finalization->withEffects(
            $this->runEffects($finalization->demand?->id ?? $demand->id, $demand->id, $principalPseudonym, null, false, $factor, $request),
        );
    }

    /**
     * The demand-bound effects retry of a durable authorized
     * settlement: the same completion endpoint, the same session, no
     * second factor. The crash boundary this closes: the challenge is
     * spent and the demand is terminal authorized, yet an effect (the
     * outcome credit, the session restore, the trust marker) never
     * landed. The ordinary completion can never re-run them, because
     * its proof is gone. The retry derives both identities from
     * server-owned state, the demand id and the principal, in one of
     * two shapes. Before a landed restore: the session's pending
     * token, with the resolver resolving behind it. After a landed
     * restore: the session's restore claim
     * ({@see SessionRestorer::RESTORE_CLAIM_ATTRIBUTE}), the demand id
     * the session itself wrote when it performed the restore, with the
     * resolver resolving against the restored token. The caller owns
     * which shape applies; this method judges the demand either way.
     * It re-verifies the demand's stored login recipe against the
     * resolved principal, and runs the journal: landed effects skip,
     * missing effects run once and journal on success. Null when the
     * demand is absent, expired, not authorized, not a login demand or
     * not this principal's: the caller keeps its original failure,
     * fail closed.
     */
    public function retryAuthorizedEffects(string $demandId, string $principalPseudonym, ?Request $request = null): ?StepUpFinalization
    {
        $demand = $this->liveDemand($demandId);
        if ($demand === null || $demand->state !== StepUpDemandState::Authorized) {
            return null;
        }
        if ($demand->operationBindingKind !== StepUpOperationBindingKind::Login) {
            return null;
        }
        $computed = StepUpOperationDigest::login($demand->scope, $principalPseudonym);
        if (!hash_equals($demand->operationDigest, $computed)) {
            $this->logger?->info('kiwi step-up effects retry refused: the pending identity does not reproduce the demand', [
                'demand' => $demand->id,
            ]);

            return null;
        }

        return (StepUpFinalization::authorizedReplay($demand))->withEffects(
            $this->runEffects($demandId, $demandId, $principalPseudonym, null, false, $demand->factor ?? 'unknown', $request),
        );
    }

    /**
     * Whether the presented operation binding reproduces the demand's
     * split financial/action binding. An unbound demand (no digests)
     * matches only an unbound presentation; a bound demand requires
     * both digests to match: the same logical operation and the same
     * contents.
     */
    private function operationBindingMatches(StepUpDemand $demand, ?string $operationId, ?string $canonicalContent): bool
    {
        if ($demand->operationIdentityDigest === null && $demand->operationContentDigest === null) {
            return $operationId === null && $canonicalContent === null;
        }
        if ($operationId === null || $canonicalContent === null) {
            return false;
        }
        $computed = StepUpOperationDigest::financialBinding(
            $this->operationBindingMaster,
            $demand->scope,
            $operationId,
            $canonicalContent,
        );

        return hash_equals((string) $demand->operationIdentityDigest, $computed['identity'])
            && hash_equals((string) $demand->operationContentDigest, $computed['content']);
    }

    /**
     * The completion effects of an authorized settlement: the outcome
     * credit, the pending-login restore and the generic enrollment
     * bootstrap marker, each journaled on the demand as it lands.
     * Invoked by the lane only after {@see self::finalize()} answered
     * authorized, and re-invoked idempotently for an authorized
     * replay: landed journal entries skip their effect, missing ones
     * run exactly once and journal on success.
     */
    public function bookEffects(StepUpFinalization $finalization, StepUpResult $proof, ?Request $request = null): StepUpFinalization
    {
        if (!$finalization->authorized) {
            return $finalization;
        }
        if ($proof->principalPseudonym === null || $proof->principalPseudonym === '') {
            return $finalization;
        }

        return $finalization->withEffects(
            $this->runEffects(
                $proof->demandId ?? $finalization->demand?->id ?? '',
                $proof->challengeId ?? '',
                $proof->principalPseudonym,
                $proof->targetPseudonym,
                $proof->targetOwned,
                $proof->factor ?? 'unknown',
                $request,
            ),
        );
    }

    /**
     * The journal-driven effects run of one authorized settlement, the
     * one sequence every lane shares. The journal lives on the demand
     * record itself; each landed effect journals after it ran, so a
     * crash between the two retries exactly the missing one. The order
     * is load-bearing: the credit runs before the restore. A crash
     * after the restore can then never leave an effect that only the
     * spent challenge's completion could have booked. The demand-bound
     * retry derives its authority from the session's own state: its
     * pending token before the restore, its restore claim once the
     * restore unwrapped the token. A credit failure and a
     * refused restore leave the journal incomplete on purpose: the
     * answer is the retryable failure, the retry re-runs exactly what
     * is missing.
     */
    private function runEffects(
        string $demandId,
        string $creditRef,
        string $principalPseudonym,
        ?string $targetPseudonym,
        bool $targetOwned,
        string $factor,
        ?Request $request,
    ): StepUpEffectsJournal {
        if ($demandId === '') {
            return StepUpEffectsJournal::none();
        }
        $demand = $this->liveDemand($demandId);
        if ($demand === null || $demand->state !== StepUpDemandState::Authorized) {
            // The terminal died (its TTL passed) with the effects
            // incomplete: nothing journalable remains, the caller
            // answers its authorized verdict without an effect claim.
            return StepUpEffectsJournal::none();
        }
        $journal = $demand->effects ?? StepUpEffectsJournal::none();
        $request ??= $this->requestStack?->getCurrentRequest();
        if (!$journal->settled()) {
            $journal = $this->journalEffect($demandId, StepUpEffectsJournal::SETTLED, $journal);
        }
        if (!$journal->outcomeCredited()) {
            try {
                $this->credit->report($creditRef, $principalPseudonym, $targetPseudonym, $targetOwned);
            } catch (\Throwable $e) {
                $this->logger?->warning('kiwi step-up completion credit failed: {message}', [
                    'message' => $e->getMessage(),
                ]);

                return $journal;
            }
            $journal = $this->journalEffect($demandId, StepUpEffectsJournal::OUTCOME_CREDITED, $journal);
        }
        if (!$journal->sessionRestored()) {
            $restore = $this->sessionRestorer?->restore($principalPseudonym, $request, $demandId);
            if ($restore === null) {
                // No restorer wired: there is no session surface to
                // restore, the effect is trivially complete.
                $journal = $this->journalEffect($demandId, StepUpEffectsJournal::SESSION_RESTORED, $journal);
            } elseif ($restore->landed()) {
                $journal = $this->journalEffect($demandId, StepUpEffectsJournal::SESSION_RESTORED, $journal);
                // The restore claim's work is done once its journal
                // entry stands: the normal request retires it in the
                // same session write, so only the crash window (the
                // mutation durable, the journal write lost) leaves a
                // claim behind for the recovery to answer.
                if ($restore->status === StepUpSessionRestore::RESTORED && $journal->sessionRestored()) {
                    SessionRestorer::clearRestoreClaim($request);
                }
            } else {
                // A refused restore journals nothing and stops the run:
                // the caller answers the retryable failure, never a
                // user-visible success for a session that stayed closed.
                $this->logger?->warning('kiwi step-up session restore refused: {status}', [
                    'status' => $restore->status,
                ]);

                return $journal;
            }
        }
        if (!$journal->trustWritten() && $this->writeEnrollmentMarker($principalPseudonym, $factor, $request)) {
            $journal = $this->journalEffect($demandId, StepUpEffectsJournal::TRUST_WRITTEN, $journal);
        }

        return $journal;
    }

    /**
     * Journal one effect on the demand record. A journal write failure
     * keeps the prior journal: the effect re-runs on the retry (each
     * effect is idempotent by design, the double-run is the safe side).
     */
    private function journalEffect(string $demandId, string $effect, StepUpEffectsJournal $prior): StepUpEffectsJournal
    {
        try {
            $record = $this->store->recordDemandEffect($demandId, $effect, $this->now());
        } catch (\Throwable) {
            return $prior;
        }

        return $record?->effects ?? $prior;
    }

    /**
     * The generic enrollment bootstrap marker: created only by the
     * authorized terminal, never by a FactorVerified proof. Answers
     * whether both markers landed, so the journal records a trust
     * write it can actually stand behind.
     */
    private function writeEnrollmentMarker(string $principalPseudonym, string $factor, ?Request $request): bool
    {
        $now = $this->now();
        $effectiveRequest = $request ?? $this->requestStack?->getCurrentRequest();
        try {
            $this->store->markStepUpSuccess($principalPseudonym, self::ENROLLMENT_MARKER_TTL_SECS, $now);
            $this->store->markSessionStepUpSuccess(
                $effectiveRequest !== null ? (string) StepUpSessionBinding::sessionId($effectiveRequest) : '',
                $principalPseudonym,
                $factor,
                self::ENROLLMENT_MARKER_TTL_SECS,
                $now,
            );
        } catch (\Throwable $e) {
            $this->logger?->warning('kiwi step-up enrollment marker failed: {message}', [
                'message' => $e->getMessage(),
            ]);

            return false;
        }

        return true;
    }

    /** The fresh engine decision of the completed factor, null when it cannot evaluate. */
    private function reassess(StepUpDemand $demand, StepUpOperationMaterial $material, ?Request $request): ?\KiwiCaptcha\Risk\RiskDecision
    {
        if ($this->risk === null) {
            return null;
        }
        $ip = '';
        if ($request !== null) {
            try {
                $ip = $this->clientIpResolver !== null
                    ? $this->clientIpResolver->resolve($request)
                    : (string) ($request->getClientIp() ?? '');
            } catch (AmbiguousForwardingException) {
                $ip = '';
            }
        }
        $session = $request !== null ? $this->continuity?->read($request) : null;
        try {
            return $this->risk->stepUpCompletedDecision(
                $demand->scope,
                $ip,
                $session,
                $material->principalPseudonym,
                'stepup-demand:'.$demand->id,
                $material->targetFields,
            );
        } catch (\InvalidArgumentException) {
            return $this->risk->degradedDecisionForScope($this->risk->scopeId($demand->scope));
        }
    }

    /** The terminal settlement; a store failure surfaces to the caller, fail closed. */
    private function settle(string $demandId, StepUpDemandState $state, ?string $factor = null): void
    {
        $settled = $this->store->settleDemandFinalization($demandId, $state, $this->now(), $factor);
        if ($settled === null) {
            throw new \RuntimeException('The step-up demand finalization could not settle its terminal state');
        }
    }

    /** The authorized terminal settlement, retaining the completed factor. */
    private function settleAuthorized(string $demandId, string $factor): void
    {
        $this->settle($demandId, StepUpDemandState::Authorized, $factor);
    }

    /** The live demand of an id: present and unexpired, else null. */
    private function liveDemand(string $demandId): ?StepUpDemand
    {
        try {
            $demand = $this->store->readDemand($demandId);
        } catch (\Throwable) {
            return null;
        }
        if ($demand === null || $demand->expired($this->now())) {
            return null;
        }

        return $demand;
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }
}
