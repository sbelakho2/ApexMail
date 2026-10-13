<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\KiwiStepUpHandlerRegistry;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\SessionRestorer;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpContext;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpFinalization;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpHandlerInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResult;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpResultStatus;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpSessionBinding;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The HTTP surface of the step-up plane: begin() presents the
 * challenge, complete() answers the verdict. The step-up endpoints
 * are application-facing: their chrome, paths and access control
 * belong to the application's own auth flow. This controller is
 * therefore exposed as a service and the application registers its
 * routes; the bundle's route loader keeps its own endpoint set
 * unchanged.
 *
 * Route registration (the application's routes.yaml):
 *
 *   kiwi_step_up_begin:
 *     path: /kiwi/step-up/begin
 *     controller: StepUpController::begin.
 *
 *   kiwi_step_up_complete:
 *     path: /kiwi/step-up/complete
 *     controller: StepUpController::complete.
 *
 * The anonymous email-ownership carrier (risk.step_up.email_ownership)
 * registers its own pair, reachable without any principal:
 *
 *   kiwi_step_up_email_begin:
 *     path: /kiwi/step-up/email/begin
 *     controller: StepUpController::emailBegin.
 *
 *   kiwi_step_up_email_complete:
 *     path: /kiwi/step-up/email/complete
 *     controller: StepUpController::emailComplete.
 *
 * The begin path is the one the step-up 403 body advertises, so the
 * anonymous visitor the body addresses can always reach the factor.
 *
 * The paths must equal risk.step_up.begin_path and complete_path, or
 * those knobs must be set to the application's own paths. The reason:
 * the forms the handlers render post to the configured complete path.
 * Both routes belong behind the application's authentication firewall,
 * because the principal is resolved server-side through the wired
 * resolver, never from a client-supplied field.
 *
 * The context inputs are server-owned: the principal pseudonym comes
 * from the resolver, the target pseudonym and the return path from
 * request attributes the application sets, and the presentation mode
 * from the request's own negotiation. The begin reason defaults to the
 * typed violation name the validator answers, so a step-up begun from
 * the post-solve flow carries its coherent reason. That name is
 * {@see \BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED}.
 *
 * Every begin under this controller mints the demand record of the
 * login plane and threads its id into the context, so the handler
 * binds its challenge to a demand through the same mechanism every
 * factor uses. There is no custom lane around it. A completion answers
 * a proof only. The controller runs the shared demand finalizer before
 * anything answers success, and only an authorized settlement lets the
 * completion redirect, restore the pending login or report the
 * completion credit. See
 * {@see StepUpDemandFinalizer::mintLoginDemand()} and
 * {@see StepUpDemandFinalizer::finalizeLogin()}.
 */
final class StepUpController
{
    private const DEFAULT_REASON = 'post_solve_step_up_required';

    /** The lifetime of the login plane's demand record. */
    private const DEMAND_TTL_SECS = 900;

    public function __construct(
        private readonly KiwiStepUpHandlerRegistry $registry,
        private readonly RiskIdentityFactory $identityFactory,
        private readonly string $scope,
        private readonly ?PrincipalResolverInterface $principalResolver = null,
        private readonly ?\Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface $tokenStorage = null,
        private readonly ?\BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOwnershipStepUp $emailOwnership = null,
        private readonly ?\BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandFinalizer $demandFinalizer = null,
        private readonly string $beginPath = '/kiwi/step-up/begin',
        private readonly ?\BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationResolverInterface $operationResolver = null,
    ) {
    }

    public function begin(Request $request): Response
    {
        $rawPrincipal = $this->unwrapPendingToken($request);
        if ($rawPrincipal === null || $rawPrincipal === '') {
            return self::plain('No principal is resolvable for this request; step-up is refused.', Response::HTTP_FORBIDDEN);
        }
        $returnPath = $request->query->get('return_to');
        if (\is_string($returnPath) && $returnPath !== '' && !StepUpContext::isSafeReturnPath($returnPath)) {
            return self::plain('The return path must be an absolute same-site path.', Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $reason = $request->query->get('reason');
        if (!\is_string($reason) || $reason === '') {
            $reason = self::DEFAULT_REASON;
        }

        try {
            $principal = $this->identityFactory->principalId($rawPrincipal);
            $context = new StepUpContext(
                $principal,
                $this->targetPseudonym($request),
                $this->scopeOf(),
                \is_string($returnPath) && $returnPath !== '' ? $returnPath : null,
                $reason,
                $this->mode($request),
            );
            $handler = $this->handler($request);
        } catch (\InvalidArgumentException $e) {
            return self::plain($e->getMessage(), Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // The demand of the login plane: every begin under this
        // controller mints the demand record its challenge binds to,
        // under the login binding kind and the principal recipe, so the
        // proof can only ever finalize the demand of this very browser
        // session. The minted demand takes the exact identity the
        // current pending token was wrapped under, so the completed
        // proof names the demand of exactly this login and the restore
        // can hold the session to it. A failed mint refuses the begin
        // outright: a challenge without its demand could only end in
        // the unbound refusal at the completion.
        $sessionHash = StepUpChallenge::sessionHash(StepUpSessionBinding::sessionId($request));
        // The escalation resume: when an earlier completion escalated,
        // the pending token still names the superseded parent, and the
        // begin follows the family to its live open child instead of
        // refusing. The browser that begins the child binds its factor
        // to exactly the demand the wire answer named.
        $demandId = $this->demandFinalizer?->loginDemandIdForBegin($context->scope, $principal, $sessionHash, $this->pendingDemandId())
            ?? $this->demandFinalizer?->mintLoginDemand($context->scope, $principal, $sessionHash, self::DEMAND_TTL_SECS, $this->pendingDemandId());
        if ($demandId === null) {
            return self::plain('The step-up demand could not be recorded; try again.', Response::HTTP_SERVICE_UNAVAILABLE);
        }
        $context = new StepUpContext(
            $principal,
            $context->targetPseudonym,
            $context->scope,
            $context->returnPath,
            $context->reason,
            $context->mode,
            $context->targetOwned,
            $demandId,
        );

        return $handler->begin($request, $context);
    }

    /**
     * The exact demand identity the current pending token carries: the
     * mint the first-attempt gate stamped at wrap time. Null when the
     * current token is not pending or carries no usable identity, in
     * which case the login demand mints its own unguessable id.
     */
    private function pendingDemandId(): ?string
    {
        $token = $this->tokenStorage?->getToken();

        return $token instanceof StepUpPendingToken ? $token->demandId() : null;
    }

    public function complete(Request $request): Response
    {
        try {
            $handler = $this->handler($request);
        } catch (\InvalidArgumentException $e) {
            return self::plain($e->getMessage(), Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        // The completion is bound to the session that began the
        // challenge: the principal is re-resolved here, exactly like
        // at begin(), and the handler refuses a challenge that belongs
        // to anyone else. A request with no resolvable principal can
        // complete nothing.
        $rawPrincipal = $this->unwrapPendingToken($request);
        if ($rawPrincipal === null || $rawPrincipal === '') {
            return self::plain('No principal is resolvable for this request; step-up completion is refused.', Response::HTTP_FORBIDDEN);
        }
        try {
            $boundPrincipal = $this->identityFactory->principalId($rawPrincipal);
        } catch (\Throwable) {
            return self::plain('No principal is resolvable for this request; step-up completion is refused.', Response::HTTP_FORBIDDEN);
        }
        StepUpSessionBinding::bind($request, $boundPrincipal);
        $result = $handler->complete($request);

        // The proof is the factor's verdict only. The authorization is
        // the demand finalization's: the demand is completed atomically
        // with the proof, reassessed, settled terminally and, only when
        // authorized, credited and the pending login restored (the
        // restore runs inside the finalizer, after the authorization).
        if ($result->status === StepUpResultStatus::Succeeded) {
            $result = $this->authorize($result, $request);
        }
        // The demand-bound effects retry: when the proof is spent (the
        // challenge already consumed) but the demand this session pends
        // under settled authorized with incomplete completion effects,
        // the same endpoint completes them without a second factor.
        if ($result->status !== StepUpResultStatus::Succeeded) {
            $retried = $this->retryAuthorizedEffects($request);
            if ($retried !== null) {
                $result = $retried;
            }
        }

        if ($this->mode($request) === StepUpContext::MODE_JSON) {
            return new Response(
                (string) json_encode($result->toArray(), JSON_UNESCAPED_SLASHES),
                self::statusOf($result),
                ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store'],
            );
        }
        if ($result->status === StepUpResultStatus::Succeeded) {
            $returnPath = $request->query->get('return_to');
            if (\is_string($returnPath) && $returnPath !== '' && StepUpContext::isSafeReturnPath($returnPath)) {
                return new RedirectResponse($returnPath, Response::HTTP_SEE_OTHER);
            }
        }

        return self::plain(match ($result->status) {
            StepUpResultStatus::Succeeded => 'Verification complete.',
            StepUpResultStatus::Pending => 'That code was not accepted; try again with the current code.',
            default => 'This verification can no longer be completed; begin a fresh challenge.',
        }, self::statusOf($result));
    }

    /**
     * The authorization of one verified factor proof through the shared
     * demand finalizer. An unbound proof (a challenge that named no
     * demand, a finalizer the deployment never wired) refuses, fail
     * closed: the demand architecture has no bypass lane. A refused
     * finalization answers the typed failure the flow answers; a store
     * failure surfaces as the retryable outcome-unavailable verdict.
     */
    private function authorize(StepUpResult $proof, Request $request): StepUpResult
    {
        $finalizer = $this->demandFinalizer;
        if ($finalizer === null) {
            return StepUpResult::failed(StepUpResult::FAIL_DEMAND_UNBOUND, $proof->challengeId);
        }
        try {
            // The booking scope is the same one the begin booked under:
            // the pending token's stamped scope with the configured
            // fallback, so the demand's operation identity is rerun in
            // exactly the scope it was minted in. A demand carrying the
            // split financial/action binding reruns both digests over
            // the operation the completion presents, resolved through
            // the wired resolver; an unwired resolver (or a thrown
            // resolution) refuses that demand, fail closed.
            $finalization = $finalizer->finalizeLogin($proof, $this->scopeOf(), $request, $this->presentedOperation($request));
        } catch (\Throwable) {
            return StepUpResult::failed(StepUpResult::FAIL_OUTCOME_UNAVAILABLE, $proof->challengeId);
        }
        if ($finalization->authorized) {
            // An authorized settlement whose completion effects never
            // landed answers the retryable failure, never success: the
            // demand-bound retry below completes them on the same
            // endpoint, without another factor.
            if (!$finalization->effectsComplete()) {
                return StepUpResult::failed(StepUpResult::FAIL_OUTCOME_UNAVAILABLE, $proof->challengeId);
            }

            return StepUpResult::succeeded(true, $proof->targetOwned && $proof->targetPseudonym !== null);
        }
        if ($finalization->reason === StepUpFinalization::REFUSED_UNBOUND) {
            return StepUpResult::failed(StepUpResult::FAIL_DEMAND_UNBOUND, $proof->challengeId);
        }
        if ($finalization->reason === StepUpFinalization::REFUSED_DENIED) {
            return StepUpResult::failed(StepUpResult::FAIL_DEMAND_REFUSED, $proof->challengeId);
        }
        if ($finalization->reason === StepUpFinalization::ESCALATED) {
            // The fresh assessment re-raised the step-up: the completed
            // factor was verified, the engine demanded more, and a
            // strictly stronger child demand took the family over. The
            // answer is a structured step_up_required document naming
            // the child demand, the factor it requires, its assurance
            // rank and the begin path: the application can begin the
            // child's factor instead of treating this proof as an
            // authorization, and the child demand survives the wire
            // boundary it used to be dropped at.
            $child = $finalization->demand;
            if ($child !== null) {
                return StepUpResult::escalated(
                    $proof->challengeId,
                    $child->id,
                    $child->requiredFactor?->family,
                    $child->requiredFactor?->assuranceRank,
                    $this->beginPath,
                );
            }

            return StepUpResult::failed(StepUpResult::FAIL_DEMAND_ESCALATED, $proof->challengeId);
        }

        return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $proof->challengeId);
    }

    /**
     * The protected operation the completion presents, resolved through
     * the wired resolver. Null when no resolver is wired (no scope
     * names a content recipe, the binding rerun is then the form-field
     * lane's business) or the resolution threw (a bound demand then
     * refuses the completion at the digest compare, fail closed).
     */
    private function presentedOperation(Request $request): ?\BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperation
    {
        if ($this->operationResolver === null) {
            return null;
        }
        try {
            return $this->operationResolver->resolve($request, $this->scopeOf());
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * The demand-bound effects retry of the completion endpoint. Both
     * identities arrive from server-owned state, never client input.
     * Two authority shapes apply, in order.
     *
     * The pending-token lane: the demand id from the session's own
     * pending token, the principal from the wired resolver (temporarily
     * unwrapping the pending token exactly like begin() and complete()
     * do). This is the crash before the restore: the session still
     * pends, so the retry completes the missing effects and restores.
     *
     * The restore-claim lane: the demand id from the session's restore
     * claim ({@see SessionRestorer::RESTORE_CLAIM_ATTRIBUTE}), the
     * principal from the resolver against the restored token. This is
     * the crash after the restore landed but before its journal entry:
     * the pending token is gone, and the session holds the claim the
     * restore itself wrote. The claim proves this session performed
     * exactly that demand's restore, so completing its journal is no
     * second factor. The claim is retired once the
     * journal completes; a claim whose demand refuses (absent, expired,
     * another principal's, an incomplete run) stays for the next
     * attempt and the caller keeps its original failure, fail closed.
     * Null when neither shape applies or the demand refuses: the caller
     * keeps its original failure. A retried settlement with an
     * incomplete journal answers the retryable failure; a complete one
     * answers success.
     */
    private function retryAuthorizedEffects(Request $request): ?StepUpResult
    {
        $finalizer = $this->demandFinalizer;
        if ($finalizer === null) {
            return null;
        }
        $token = $this->tokenStorage?->getToken();
        if ($token instanceof StepUpPendingToken && $token->demandId() !== null) {
            return $this->retryWithDemand($request, $token->demandId());
        }
        $claim = SessionRestorer::restoreClaimOf($request);
        if ($claim === null) {
            return null;
        }
        $answer = $this->retryWithDemand($request, $claim);
        if ($answer !== null && $answer->status === StepUpResultStatus::Succeeded) {
            // The journal of the claimed restore is complete: the
            // session holds no recovery authority anymore.
            SessionRestorer::clearRestoreClaim($request);
        }

        return $answer;
    }

    /**
     * The retry of one named demand: the principal from the wired
     * resolver, the demand's stored login recipe re-verified, the
     * journal run. Null when nothing is resolvable or the demand
     * refuses the retry.
     */
    private function retryWithDemand(Request $request, string $demandId): ?StepUpResult
    {
        $rawPrincipal = $this->unwrapPendingToken($request);
        if ($rawPrincipal === null || $rawPrincipal === '') {
            return null;
        }
        try {
            $principal = $this->identityFactory->principalId($rawPrincipal);
        } catch (\Throwable) {
            return null;
        }
        if ($principal === '') {
            return null;
        }
        try {
            $finalization = $this->demandFinalizer?->retryAuthorizedEffects($demandId, $principal, $request);
        } catch (\Throwable) {
            return null;
        }
        if ($finalization === null || !$finalization->authorized) {
            return null;
        }
        if (!$finalization->effectsComplete()) {
            return StepUpResult::failed(StepUpResult::FAIL_OUTCOME_UNAVAILABLE, null);
        }

        return StepUpResult::succeeded(true, false);
    }

    /**
     * The anonymous email-ownership begin: no principal is resolved or
     * required, the factor IS the identity proof. The action refuses
     * with 404 when the carrier is not wired, so the route can exist
     * unconditionally.
     */
    public function emailBegin(Request $request): Response
    {
        if ($this->emailOwnership === null) {
            return self::plain('The email-ownership factor is not available on this deployment.', Response::HTTP_NOT_FOUND);
        }

        return $this->emailOwnership->begin($request);
    }

    /** The anonymous email-ownership complete: answers the grant. */
    public function emailComplete(Request $request): Response
    {
        if ($this->emailOwnership === null) {
            return self::plain('The email-ownership factor is not available on this deployment.', Response::HTTP_NOT_FOUND);
        }

        return $this->emailOwnership->complete($request);
    }

    /**
     * The booking scope of a begin: the scope the first-attempt gate
     * stamped onto the pending token when it raised the demand (the
     * risk.login_scopes target of the login's firewall), or the
     * configured fallback scope when no pending scope applies. The
     * principal plane therefore books under the same per-event scope
     * the guard assessed the login in.
     */
    private function scopeOf(): string
    {
        $token = $this->tokenStorage?->getToken();
        if ($token instanceof StepUpPendingToken) {
            return $token->scope() ?? $this->scope;
        }

        return $this->scope;
    }

    /**
     * The raw principal of the request, resolved through the wired
     * resolver with a pending token temporarily unwrapped.
     *
     * A {@see StepUpPendingToken} deliberately answers null from
     * getUser() (a pending session must never pass IS_AUTHENTICATED_*
     * checks), so the typical application resolver — $security->getUser()
     * — resolves nothing and step-up would be refused to exactly the
     * users who need it. The wrapped token is therefore exposed to the
     * resolver for the duration of this resolution only, then the
     * pending token is put back: a begin, or a failed complete, never
     * upgrades the session. Only a completed factor does, through
     * {@see StepUpSessionBinding} and the session restorer.
     *
     * The scope the resolver books under is the same scope the
     * challenge books under: {@see self::scopeOf()}, the pending
     * token's stamped scope with the configured fallback. Resolving
     * the principal under a different scope than the challenge would
     * split the step-up's identity context across two scopes.
     */
    private function unwrapPendingToken(Request $request): ?string
    {
        $scope = $this->scopeOf();
        $token = $this->tokenStorage?->getToken();
        $pending = $token instanceof StepUpPendingToken ? $token : null;
        if ($pending !== null) {
            $this->tokenStorage?->setToken($pending->getWrapped());
        }
        try {
            return $this->principalResolver?->resolve($request, $scope);
        } finally {
            if ($pending !== null) {
                $this->tokenStorage?->setToken($pending);
            }
        }
    }

    /**
     * The handler of the request: the explicit handler query name, or
     * the configured default. A malformed or unknown name is refused
     * (fail-closed), never defaulted.
     */
    private function handler(Request $request): StepUpHandlerInterface
    {
        $name = $request->query->get('handler');
        if (\is_string($name) && $name !== '' && preg_match('/^[a-z0-9_]{1,64}$/D', $name) !== 1) {
            throw new \InvalidArgumentException('The handler name must be 1-64 chars of [a-z0-9_]');
        }

        return $this->registry->get(\is_string($name) && $name !== '' ? $name : null);
    }

    /**
     * The presentation mode: the explicit mode query parameter, or the
     * request's own json negotiation, html otherwise.
     */
    private function mode(Request $request): string
    {
        $mode = $request->query->get('mode');
        if (\is_string($mode) && $mode !== '') {
            return $mode === StepUpContext::MODE_JSON ? StepUpContext::MODE_JSON : StepUpContext::MODE_HTML;
        }

        return str_contains((string) $request->headers->get('Accept', ''), 'application/json')
            ? StepUpContext::MODE_JSON
            : StepUpContext::MODE_HTML;
    }

    /**
     * The server-owned target pseudonym: the application sets the
     * request attribute when the flow addresses a target identity (for
     * example the claimed username of a login step-up). Only the exact
     * pseudonym shape is accepted — the canonical 64-char lowercase
     * hex digest the engine derives
     * {@see \KiwiCaptcha\Risk\RiskIdentityFactory::targetId()}. A
     * truncated or raw value is refused.
     */
    private function targetPseudonym(Request $request): ?string
    {
        $target = $request->attributes->get('_kiwi_step_up_target');
        if ($target === null) {
            return null;
        }
        if (!\is_string($target) || preg_match('/^[0-9a-f]{64}$/D', $target) !== 1) {
            throw new \InvalidArgumentException('The _kiwi_step_up_target attribute must be the 64 lowercase hex target pseudonym, never a raw identifier');
        }

        return $target;
    }

    private static function statusOf(StepUpResult $result): int
    {
        return match ($result->status) {
            StepUpResultStatus::Succeeded => Response::HTTP_OK,
            StepUpResultStatus::Pending => Response::HTTP_UNAUTHORIZED,
            default => Response::HTTP_UNPROCESSABLE_ENTITY,
        };
    }

    private static function plain(string $body, int $status): Response
    {
        return new Response($body, $status, ['Content-Type' => 'text/plain; charset=utf-8', 'Cache-Control' => 'no-store']);
    }
}
