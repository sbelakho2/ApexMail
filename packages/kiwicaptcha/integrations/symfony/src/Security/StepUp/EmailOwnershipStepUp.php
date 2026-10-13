<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use BelConsulting\KiwiCaptchaBundle\Risk\ChainId;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The anonymous-completable step-up factor behind the step_up_email
 * carrier. A visitor whose issuance or submission was answered with the
 * step-up 403 proves control of an email address and receives a grant
 * the validator honors in place of a solved token.
 *
 * A code is only ever sent for a demand the engine raised. The 403
 * that names this carrier mints a {@see StepUpDemand} record, and both
 * begin() and complete() require its id. The scope, the session
 * binding and the chain id come from the stored record, never from the
 * request. A begin without a live, session-matched demand answers the
 * typed `STEP_UP_NOT_DEMANDED` refusal, so the factor cannot be driven
 * blind.
 *
 * begin(): a 6-digit code from random_int, valid for 10 minutes. The
 * stored records carry only pseudonyms: the address exists solely as
 * an HMAC-derived pseudonym and the code solely as a keyed hash, so a
 * store snapshot leaks neither the address nor the factor. Delivery
 * rides the application-bound {@see EmailOwnershipCodeSenderInterface}.
 * Each begin claims the demand's send lease on the store's own clock:
 * one initial delivery plus one resend after the resend delay, then
 * the demand is spent. Mail volume is bounded twice over. The cheap
 * per-address attempt limiter counts every begin attempt before
 * anything else (independent of the reservation flow, refused attempts
 * included). The delivery budgets (address domain, source,
 * deployment-wide) are generation-bound quota reservations: reserve,
 * hand off, then commit. A pre-handoff refusal releases the
 * reservation and the send credit together; an ambiguous or
 * post-handoff failure commits both; a reservation past its lease
 * commits by default. Every counter key is confined to this factor's
 * own key family.
 *
 * A reassessment that re-raises the step-up for a protected operation
 * never extends its authorization window. The fresh demand is minted
 * as the escalation child of the live one in one atomic store
 * transaction (supersede parent, create child). The child inherits the
 * original authorization deadline and bindings, so repeated refusals
 * cannot outlive the first demand.
 *
 * complete(): the answered code is consumed single-use together with
 * its demand and a grant is issued. The grant is a signed, expiring,
 * single-use token bound to its demand: the scope, the address
 * pseudonym, the session hash and the chain id. The scope must equal
 * the constraint scope at validation, the submitted address must
 * resolve to the grant's pseudonym, the session hash must match the
 * browser that began the challenge, and a bound chain id must be
 * re-presented with the submission. Single use is the store's atomic
 * get-and-delete consumption of a server-held record named by the
 * signature, so a captured grant answers exactly once across workers.
 * The authorization rule of the demand plane is explicit here: the
 * code assessment alone authorizes nothing. A passing assessment
 * becomes a grant only when the demand completion compare-and-set is
 * won, and a demand another worker completed first leaves this
 * completer with nothing.
 *
 * The signing and hashing keys are purpose-separated derivations of
 * the step-up master through the bundle's shared HKDF shape, never the
 * master itself.
 */
final class EmailOwnershipStepUp
{
    /** The kind string the 403 step-up body and the grant share. */
    public const KIND = 'email_ownership';

    /** The begin path the 403 step-up body advertises. */
    public const BEGIN_PATH = '/kiwi/step-up/email/begin';

    /** The complete path the begin document advertises. */
    public const COMPLETE_PATH = '/kiwi/step-up/email/complete';

    /** The grant prefix: a validator value starting with it is a grant. */
    public const GRANT_PREFIX = 'kiwiemg1';

    /** The request field carrying the grant at form submission. */
    public const GRANT_FIELD = 'kiwi_step_up_grant';

    /** The begin request field carrying the address. */
    public const EMAIL_FIELD = 'email';

    /** The begin request field carrying the protected scope. */
    public const SCOPE_FIELD = 'scope';

    /** The begin and complete request field carrying the demand id. */
    public const DEMAND_FIELD = 'demand';

    /** The optional begin, complete and submit field carrying the chain id. */
    public const CHAIN_FIELD = 'kiwi_step_up_chain';

    private const CODE_HKDF_INFO = 'kiwi/v1/email-ownership-code';

    private const EMAIL_HKDF_INFO = 'kiwi/v1/email-ownership-email';

    private const GRANT_HKDF_INFO = 'kiwi/v1/email-ownership-grant';

    private const HKDF_SALT = 'kiwicaptcha/deploy-salt/v1';

    private const GRANT_VERSION = 2;

    /**
     * The send lease window: how long one claimed delivery attempt
     * exclusively owns the demand's send slot. Every liveness decision
     * about the lease (another worker's claim, a crashed claim's
     * recovery) is taken on the store's clock inside the lease scripts;
     * a claimant whose window expired is recoverable and settles
     * nothing.
     */
    private const SEND_LEASE_SECS = 15;

    /**
     * The quota reservation lease: how long a reserved delivery may
     * take from reservation to commit or release. Past it (a crashed
     * worker) the reservation commits by default: spent quota is the
     * fail-closed side, never free mail.
     */
    private const QUOTA_LEASE_SECS = 30;

    private readonly string $codeKey;

    private readonly string $emailKey;

    private readonly string $grantKey;

    /** The once-per-process guard of the deployment budget warning. */
    private bool $budgetWarned = false;

    public function __construct(
        private readonly StepUpChallengeStore $store,
        private readonly StepUpTicket $ticket,
        private readonly EmailOwnershipCodeSenderInterface $sender,
        private readonly ?ContinuityCookie $continuity,
        private readonly ?ClientIpResolver $clientIpResolver,
        private readonly string $defaultScope,
        string $masterSecret,
        private readonly int $ttlSecs = 600,
        private readonly int $maxAttempts = 5,
        private readonly int $maxBeginsPerEmail = 3,
        private readonly int $maxBeginsPerSource = 10,
        private readonly int $beginWindowSecs = 3600,
        /**
         * The scopes whose step-up demands this factor carries (built
         * from risk.scopes.*.carrier === 'step_up_email'). A demand for
         * any other scope is refused: the factor answers exactly the
         * scopes that name it.
         *
         * @var array<string, true>
         */
        private readonly array $emailCarrierScopes = [],
        /** The hourly per-domain begin bound (email_ownership.max_per_domain). */
        private readonly int $maxBeginsPerDomain = 30,
        /** The hourly deployment-wide begin budget. */
        private readonly int $maxBeginsGlobal = 1000,
        /** The minimum spacing between the two deliveries one demand funds. */
        private readonly int $resendAfterSecs = 60,
        private readonly ?LoggerInterface $logger = null,
        private readonly ?\Closure $now = null,
        /**
         * The factor requirement source. Null keeps minted demands
         * un-snapshotted; wired, every demand records the factor it
         * requires, escalated strictly past the factor the family's
         * completion history holds.
         */
        private readonly ?StepUpFactorResolver $factorResolver = null,
    ) {
        if (\strlen($masterSecret) < 32) {
            throw new \InvalidArgumentException('The step-up secret master must be at least 32 bytes (the same floor as secret_key)');
        }
        $this->codeKey = hash_hkdf('sha256', $masterSecret, 32, self::CODE_HKDF_INFO, self::HKDF_SALT);
        $this->emailKey = hash_hkdf('sha256', $masterSecret, 32, self::EMAIL_HKDF_INFO, self::HKDF_SALT);
        $this->grantKey = hash_hkdf('sha256', $masterSecret, 32, self::GRANT_HKDF_INFO, self::HKDF_SALT);
    }

    /**
     * Mint the demand record for one raised step-up demand: the id the
     * 403 body hands to the visitor, the record the factor requires
     * before it sends anything. The record binds the continuity session
     * hash, the open chain id (the stage-2 obligation when one is open)
     * and the disposition's decision id, plus the operation identity
     * the caller minted. That identity is the binding kind naming the
     * canonical recipe, and the digest that recipe produced; the demand
     * finalization reruns it at redemption. Null when the scope does
     * not name this carrier, or the store refused the record (the 403
     * then carries no demand, and begin() refuses every code request,
     * fail-closed).
     *
     * A live demand already standing for the same operation identity is
     * never silently replaced by a fresh root. The reassessment's
     * demand is minted as its escalation child: one atomic store
     * transaction supersedes the parent and creates the child. The
     * child inherits the parent's authorization deadline, its decision
     * id, its operation identity, its browser binding and its chain
     * identity unchanged, and records the reassessment's decision id
     * separately as `raisedByDecisionId`. Past the family depth cap
     * (or on a lost escalation race) the standing demand keeps serving:
     * the authorization window of an operation is the first demand's,
     * and no reassessment extends it.
     */
    public function mintDemand(
        string $scope,
        ?string $sessionHash,
        ?string $chainId,
        ?string $decisionId,
        StepUpOperationBindingKind $operationBindingKind = StepUpOperationBindingKind::None,
        string $operationDigest = '',
    ): ?string {
        if (!isset($this->emailCarrierScopes[$scope])) {
            return null;
        }
        $now = $this->now();
        try {
            $requirement = $this->requiredFactorOf($scope, $sessionHash);
        } catch (StepUpAssuranceUnavailable $e) {
            // An unavailable assurance state is no basis for a demand:
            // the 403 then carries no demand, and begin() refuses every
            // code request, fail closed.
            $this->logger?->warning('kiwi step-up demand mint refused: {message}', ['message' => $e->getMessage()]);

            return null;
        }
        $demand = StepUpDemand::mint(StepUpChallenge::mintId(), $scope, $sessionHash, $chainId, $decisionId, $now, $this->ttlSecs, $operationBindingKind, $operationDigest, null, null, false, null, $requirement);
        try {
            $tipId = $this->store->demandIdForOperation($demand->operationDigest);
            if (\is_string($tipId)) {
                $parent = $this->store->readDemand($tipId);
                if ($parent !== null && !$parent->expired($now) && !$parent->superseded() && !$parent->state->isTerminal()) {
                    if ($parent->canEscalate()) {
                        // The re-raised demand of one operation demands
                        // strictly more than its parent: the child's
                        // requirement escalates past the family's
                        // standing requirement, resolved by the same
                        // ladder the mint used for the root.
                        $childRequirement = $parent->requiredFactor === null
                            ? $requirement
                            : ($this->factorResolver?->requiredFactor($scope, null, new StepUpFactorContext($parent->requiredFactor->family)) ?? $requirement);
                        $child = $parent->spawnChild(StepUpChallenge::mintId(), $now, $decisionId, $childRequirement);
                        $superseded = $this->store->supersedeDemandWithChild($parent->id, $child);
                        if ($superseded !== null) {
                            return $child->id;
                        }
                    }

                    // The family cap is reached, or a concurrent
                    // escalation won the transaction: the standing tip
                    // serves. Never a fresh TTL.
                    return $tipId;
                }
            }

            return $this->store->createRootDemand($demand, $this->ttlSecs);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * The factor requirement the mint snapshots onto its demand: the
     * resolver's answer for the scope, escalated strictly past the
     * factor the live completion marker records for this browser
     * session and scope. Null when no resolver is wired, and null when
     * the resolver genuinely answers an empty history (no prior factor
     * stands). An unavailable completion history or a failing resolver
     * is the third state, and it is never folded into the empty one: it
     * answers {@see StepUpAssuranceUnavailable}. The mint then refuses
     * instead of silently minting a demand with no assurance snapshot.
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
     * The live demand of the request: present, unexpired, still open
     * (never spent by its completion) and bound to the presenting
     * browser when the demand carries a session hash. Null means no
     * code may be sent or redeemed against it.
     */
    private function demandOf(Request $request, int $now): ?StepUpDemand
    {
        $id = $request->request->get(self::DEMAND_FIELD);
        if (!\is_string($id) || preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $id) !== 1) {
            return null;
        }
        try {
            $demand = $this->store->readDemand($id);
        } catch (\Throwable) {
            return null;
        }
        // A superseded demand funds nothing: its escalation child is
        // the only live member of the family.
        if ($demand === null || $demand->expired($now) || !$demand->state->isOpen() || $demand->superseded()) {
            return null;
        }
        if ($demand->sessionHash !== null) {
            $presented = $this->presentedSessionHash($request);
            if ($presented === null || !hash_equals($demand->sessionHash, $presented)) {
                return null;
            }
        }

        return $demand;
    }

    /**
     * Begin one email-ownership challenge: demand gate, the cheap
     * attempt limiter, the quota reservation, the send-lease claim, mint
     * the record, deliver the code, answer the begin document. The
     * scope, the session binding and the chain id come from the demand
     * record. The answer is always a json document; the anonymous
     * callers are programmatic.
     */
    public function begin(Request $request): Response
    {
        $now = $this->now();
        $email = $this->emailOf($request);
        if ($email === null) {
            return self::json(['error' => 'invalid_email', 'message' => 'A deliverable email address is required.'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $demand = $this->demandOf($request, $now);
        if ($demand === null || !isset($this->emailCarrierScopes[$demand->scope])) {
            return self::json(['error' => 'step_up_not_demanded', 'message' => 'No step-up demand stands for this browser; solve the challenge that was refused.'], Response::HTTP_FORBIDDEN);
        }
        $scope = $demand->scope;
        $emailPseudonym = $this->emailPseudonym($email);

        // The demand's send budget, checked on the read record for the
        // typed refusals: one initial delivery plus one resend after
        // the resend delay, then the demand is spent. The authoritative
        // re-check runs inside the store's lease script, on the store's
        // clock.
        if (!$demand->canSend()) {
            return self::json(['error' => 'step_up_rate_limited', 'message' => 'This demand was fully used; request a fresh challenge.'], Response::HTTP_TOO_MANY_REQUESTS, ['Retry-After' => (string) max(1, $demand->expiresAt - $now)]);
        }
        $resendWaiting = $demand->nextSendIsResend() && $demand->lastSentAt !== null && ($now - $demand->lastSentAt) < $this->resendAfterSecs;
        if ($resendWaiting) {
            $wait = max(1, $this->resendAfterSecs - ($now - $demand->lastSentAt));

            return self::json(['error' => 'step_up_resend_wait', 'message' => 'The resend opens shortly; wait for the stated interval.'], Response::HTTP_TOO_MANY_REQUESTS, ['Retry-After' => (string) $wait]);
        }

        // The cheap attempt limiter: per address, scope-free, counted
        // on every begin attempt before anything is reserved or
        // claimed. It stays independent of the reservation flow —
        // refused attempts count, so an outage cannot be retried for
        // free.
        $emailAdmissions = $this->store->countBegin('emg:email:'.$emailPseudonym, $this->beginWindowSecs);
        if ($emailAdmissions > $this->maxBeginsPerEmail) {
            return self::json(['error' => 'step_up_rate_limited', 'message' => 'Too many codes were requested for this address; retry after the window.'], Response::HTTP_TOO_MANY_REQUESTS, ['Retry-After' => (string) $this->beginWindowSecs]);
        }

        // The delivery budgets as one generation-bound quota
        // reservation (address domain, source, deployment-wide): all
        // budgets reserve or none does. The reservation id rides the
        // demand's identity — the base64url demand id, the escalation
        // generation and the delivery index — so the reservation, the
        // message that spends it and the Message-ID are auditable as
        // one unit.
        $delivery = new EmailOwnershipDeliveryMetadata($demand->id, $demand->generation, $demand->sends + 1);
        // The semantic budget names; the store carries them inside its
        // own namespaced key family.
        $budgetKeys = [
            'dom:'.$this->domainPseudonym(substr($email, (int) strrpos($email, '@') + 1)),
            'global:',
        ];
        $budgetLimits = [$this->maxBeginsPerDomain, $this->maxBeginsGlobal];
        $source = $this->sourcePseudonym($request);
        if ($source !== null) {
            $budgetKeys[] = 'src:'.$source;
            $budgetLimits[] = $this->maxBeginsPerSource;
        }
        $globalAdmissions = $this->store->countBegin('emg:global-attempts', $this->beginWindowSecs);
        $this->warnNearBudget($globalAdmissions);
        try {
            $reserved = $this->store->reserveMailQuota($delivery->reservationId(), $budgetKeys, $budgetLimits, $this->beginWindowSecs, self::QUOTA_LEASE_SECS);
        } catch (\Throwable) {
            $reserved = false;
        }
        if (!$reserved) {
            return self::json(['error' => 'step_up_rate_limited', 'message' => 'Too many codes were requested; retry after the window.'], Response::HTTP_TOO_MANY_REQUESTS, ['Retry-After' => (string) $this->beginWindowSecs]);
        }

        // The send lease: the store's clock owns the send cap, the
        // resend spacing and the lease liveness. Null means a concurrent
        // begin holds the slot (or the demand died): a pre-handoff
        // refusal, so both the reservation and the credit return.
        $lease = null;
        try {
            $lease = $this->store->claimDemandSendLease($demand->id, $this->resendAfterSecs, self::SEND_LEASE_SECS);
        } catch (\Throwable) {
            $lease = null;
        }
        if ($lease === null) {
            $this->releaseQuota($delivery->reservationId());
            if ($resendWaiting) {
                return self::json(['error' => 'step_up_resend_wait', 'message' => 'The resend opens shortly; wait for the stated interval.'], Response::HTTP_TOO_MANY_REQUESTS, ['Retry-After' => (string) max(1, $this->resendAfterSecs)]);
            }

            return self::json(['error' => 'step_up_not_demanded', 'message' => 'No step-up demand stands for this browser; solve the challenge that was refused.'], Response::HTTP_FORBIDDEN);
        }
        $claimed = $lease->demand;

        $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $sessionValue = $this->sessionValueOf($request);
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOwnership,
            $emailPseudonym,
            null,
            $scope,
            null,
            self::KIND,
            $now,
            $this->ttlSecs,
            $this->maxAttempts,
            $this->codeHash($code),
            null,
            $sessionValue,
            false,
            false,
            null,
            $claimed->id,
        );
        try {
            $this->store->create($challenge, $this->ttlSecs);
        } catch (\Throwable) {
            // Pre-handoff refusal: the reservation and the send credit
            // both return, fail closed on the record.
            $this->releaseQuota($delivery->reservationId());
            $this->settleLease(new StepUpDemandSendSettlement($claimed->id, $lease->leaseUntilMs, $lease->claimAt, $lease->priorSends, $lease->priorLastSentAt, false));

            return self::json(['error' => 'step_up_delivery_failed', 'message' => 'The code could not be delivered; try again.'], Response::HTTP_SERVICE_UNAVAILABLE);
        }
        try {
            // The handoff. Past this call the outcome can be ambiguous:
            // the transport may have accepted the message before its
            // error surfaced.
            $this->sender->send($email, $code, $this->ttlSecs, $delivery);
        } catch (\Throwable) {
            // Ambiguous failure at or after the handoff: both the send
            // credit and the quota reservation commit (spent quota is
            // the fail-closed side, never a free extra send), and no
            // challenge record survives a code the factor cannot vouch
            // for.
            $this->settleLease(new StepUpDemandSendSettlement($claimed->id, $lease->leaseUntilMs, $lease->claimAt, $lease->priorSends, $lease->priorLastSentAt, true));
            $this->commitQuota($delivery->reservationId());
            try {
                $this->store->consume($challenge->id);
            } catch (\Throwable) {
            }

            return self::json(['error' => 'step_up_delivery_failed', 'message' => 'The code could not be delivered; try again.'], Response::HTTP_SERVICE_UNAVAILABLE);
        }

        // Delivered: the lease settles to its advanced state and the
        // reservation commits.
        $this->settleLease(new StepUpDemandSendSettlement($claimed->id, $lease->leaseUntilMs, $lease->claimAt, $lease->priorSends, $lease->priorLastSentAt, true));
        $this->commitQuota($delivery->reservationId());

        return self::json(array_filter([
            'kind' => self::KIND,
            'challenge' => $this->ticket->issue($challenge->id, $challenge->expiresAt),
            'expires_in' => max(0, $challenge->expiresAt - $now),
            'complete_path' => self::COMPLETE_PATH,
            'scope' => $scope,
            'demand' => $claimed->id,
            'client_secret' => $challenge->issuedClientSecret(),
        ], static fn ($v): bool => $v !== null), Response::HTTP_OK);
    }

    /**
     * Complete one challenge: verify the code, consume the record and
     * its demand single-use, and answer the signed grant bound to
     * (scope, address pseudonym, session, chain id) exactly as the
     * demand carried it. A rejected code counts against the attempt
     * cap and removes the record at the cap.
     */
    public function complete(Request $request): Response
    {
        $now = $this->now();
        $demand = $this->demandOf($request, $now);
        if ($demand === null || !isset($this->emailCarrierScopes[$demand->scope])) {
            return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_UNKNOWN_CHALLENGE], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $ticket = (string) $request->request->get(EmailOtpStepUpHandler::TICKET_FIELD, '');
        $payload = $ticket === '' ? null : $this->ticket->verify($ticket, $now);
        $challenge = $payload === null ? null : $this->store->read($payload['challengeId']);
        if ($challenge === null || $challenge->kind !== StepUpChallengeKind::EmailOwnership) {
            return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_UNKNOWN_CHALLENGE], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        if (!hash_equals($challenge->scope, $demand->scope)) {
            // The challenge and its demand must name the same scope: a
            // ticket crossed between scopes completes nothing.
            return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_UNKNOWN_CHALLENGE], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        if ($challenge->demandId !== $demand->id) {
            // The challenge must be the demand's own: a proof is bound
            // to the demand it was begun against, and a crossed ticket
            // (another demand of the same scope, a stale sibling of an
            // escalation family) finalizes nothing.
            return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_UNKNOWN_CHALLENGE], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        if ($challenge->expired($now)) {
            $this->store->consume($challenge->id);

            return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_EXPIRED], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        if (!$this->sessionMatches($request, $challenge)) {
            return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_SESSION_MISMATCH], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $code = (string) $request->request->get(EmailOtpStepUpHandler::CODE_FIELD, '');
        if (!preg_match('/^[0-9]{6}$/D', $code) || !hash_equals((string) $challenge->codeHash, $this->codeHash($code))) {
            $answer = $this->store->recordFailure($challenge->id, $challenge->maxAttempts);
            if ($answer === 0) {
                return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_TOO_MANY_ATTEMPTS], Response::HTTP_UNPROCESSABLE_ENTITY);
            }
            if ($answer < 0) {
                return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_UNKNOWN_CHALLENGE], Response::HTTP_UNPROCESSABLE_ENTITY);
            }

            return self::json(['status' => 'pending', 'challenge_id' => $challenge->id], Response::HTTP_UNAUTHORIZED);
        }

        // The single-use boundary of the factor is one atomic
        // transition: the challenge consumption and the demand
        // completion are the same script, so the two-record state can
        // never land half-moved. The binding hash rides the script (the
        // stored session binding or the stateless client secret, both
        // as keyed hashes), so the winner of the race is always a
        // browser that holds the binding, and a completer that loses
        // any race leaves with nothing consumed. The demand record is
        // kept in the completed state, so the redemption's finalization
        // can rerun the operation recipe the demand carried.
        $binding = $this->presentedBindingHash($request, $challenge);
        $completion = $binding === null ? null : $this->store->completeFactor(
            $challenge->id,
            $demand->id,
            $binding,
            $now,
            $challenge->sessionHash,
        );
        if ($completion === null) {
            return self::json(['status' => 'failed', 'failure_code' => StepUpResult::FAIL_UNKNOWN_CHALLENGE], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // The bound chain id rides the demand record: the value the
        // challenged transaction carried, re-presented at submission.
        return $this->grantResponse($challenge, (string) ($demand->chainId ?? ''), $demand->id, $now);
    }

    /**
     * The grant answer: the consumption record is minted here (the
     * client never picks its id), signed over, and answered once. The
     * record carries the completed demand id as its own demand binding
     * (the wire shape requires it on this family), and the grant names
     * the completed demand, so the redemption's finalization reads
     * exactly the demand this factor completed.
     */
    private function grantResponse(StepUpChallenge $challenge, string $chainId, string $demandId, int $now): Response
    {
        $grantRecord = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::EmailOwnership,
            $challenge->principalPseudonym,
            null,
            $challenge->scope,
            null,
            self::KIND,
            $now,
            $this->ttlSecs,
            1,
            null,
            null,
            null,
            false,
            false,
            null,
            $demandId,
        );
        // The consumption record IS the single-use budget: the grant
        // names it, the validator's atomic consume spends it.
        $this->store->create($grantRecord, $this->ttlSecs);

        return self::json([
            'status' => 'succeeded',
            'grant' => $this->issueGrant($grantRecord, $challenge->scope, $challenge->sessionHash ?? '', $chainId, $demandId),
            'expires_in' => $this->ttlSecs,
            'scope' => $challenge->scope,
        ], Response::HTTP_OK);
    }

    /**
     * Verify a presented grant: signature, structure, expiry. The
     * answer carries the scope, the address pseudonym, the session
     * hash (empty when the stateless binding applies), the chain id
     * (empty when unbound), the completed demand id and the
     * consumption record id. Null on anything suspicious.
     *
     * @return array{grantId: string, scope: string, emailPseudonym: string, sessionHash: string, chainId: string, demandId: string, expiresAt: int}|null
     */
    public function verifyGrant(string $grant, ?int $now = null): ?array
    {
        $prefix = self::GRANT_PREFIX.'.';
        if (!str_starts_with($grant, $prefix)) {
            return null;
        }
        $parts = explode('.', substr($grant, \strlen($prefix)), 2);
        if (\count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            return null;
        }
        if (!hash_equals($this->sign($parts[0]), $parts[1])) {
            return null;
        }
        $raw = base64_decode(strtr($parts[0], '-_', '+/'), true);
        if ($raw === false) {
            return null;
        }
        try {
            $payload = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!\is_array($payload) || \count($payload) !== 8) {
            return null;
        }
        [$version, $grantId, $scope, $emailPseudonym, $sessionHash, $chainId, $demandId, $expiresAt] = array_values($payload);
        if ($version !== self::GRANT_VERSION
            || !\is_string($grantId) || preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $grantId) !== 1
            || !\is_string($scope) || preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $scope) !== 1
            || !\is_string($emailPseudonym) || preg_match('/^[0-9a-f]{32}$/D', $emailPseudonym) !== 1
            || !\is_string($sessionHash) || ($sessionHash !== '' && preg_match('/^[0-9a-f]{64}$/D', $sessionHash) !== 1)
            || !\is_string($chainId) || ($chainId !== '' && !ChainId::isValid($chainId))
            || !\is_string($demandId) || preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $demandId) !== 1
            || !\is_int($expiresAt)
        ) {
            return null;
        }
        if (($now ?? $this->now()) >= $expiresAt) {
            return null;
        }

        return ['grantId' => $grantId, 'scope' => $scope, 'emailPseudonym' => $emailPseudonym, 'sessionHash' => $sessionHash, 'chainId' => $chainId, 'demandId' => $demandId, 'expiresAt' => $expiresAt];
    }

    /**
     * Consume the grant exactly once: the atomic store consume of the
     * signed record. True for exactly one caller of a concurrent pair.
     *
     * @param array{grantId: string, scope: string, emailPseudonym: string, sessionHash: string, chainId: string, demandId: string, expiresAt: int} $grant
     */
    public function consumeGrant(array $grant): bool
    {
        return $this->store->consume($grant['grantId']) !== null;
    }

    /**
     * The grant for a submission: verify, bind, consume. The answer is
     * the verified grant payload or null; null means the demand stands.
     * A session-bound grant requires the same browser session, a bound
     * chain id requires the same value re-presented at submission, and
     * the submitted address must resolve to the grant's pseudonym. The
     * factor proves one address, and only the form that uses it may
     * spend the proof.
     *
     * @return array{grantId: string, scope: string, emailPseudonym: string, sessionHash: string, chainId: string, demandId: string, expiresAt: int}|null
     */
    public function redeem(string $grant, string $scope, Request $request, ?string $presentedChainId = null, ?string $submittedEmail = null): ?array
    {
        $payload = $this->verifyGrant($grant);
        if ($payload === null || !hash_equals($payload['scope'], $scope)) {
            return null;
        }
        $submitted = $submittedEmail === null ? '' : strtolower(trim($submittedEmail));
        if ($submitted === '' || !hash_equals($payload['emailPseudonym'], $this->emailPseudonym($submitted))) {
            return null;
        }
        if ($payload['sessionHash'] !== '') {
            $presented = $this->presentedSessionHash($request);
            if ($presented === null || !hash_equals($payload['sessionHash'], $presented)) {
                return null;
            }
        }
        if ($payload['chainId'] !== ''
            && ($presentedChainId === null || !hash_equals($payload['chainId'], $presentedChainId))
        ) {
            return null;
        }
        if (!$this->consumeGrant($payload)) {
            return null;
        }

        return $payload;
    }

    /**
     * Issue the signed grant over the consumption record: the payload
     * is the base64url json [v, grantId, scope, emailPseudonym,
     * sessionHash, chainId, demandId, expiresAt], then the base64url
     * HMAC.
     */
    private function issueGrant(StepUpChallenge $grantRecord, string $scope, string $sessionHash, string $chainId, string $demandId): string
    {
        $body = (string) json_encode([
            self::GRANT_VERSION,
            $grantRecord->id,
            $scope,
            $grantRecord->principalPseudonym,
            $sessionHash,
            $chainId,
            $demandId,
            $grantRecord->expiresAt,
        ], JSON_UNESCAPED_SLASHES);
        $encoded = rtrim(strtr(base64_encode($body), '+/', '-_'), '=');

        return self::GRANT_PREFIX.'.'.$encoded.'.'.$this->sign($encoded);
    }

    private function sign(string $body): string
    {
        return rtrim(strtr(base64_encode(hash_hmac('sha256', $body, $this->grantKey, true)), '+/', '-_'), '=');
    }

    /**
     * The stored pseudonym of the address: the truncated HMAC, never
     * the address itself, in the 32-hex shape the challenge records
     * carry.
     */
    private function emailPseudonym(string $email): string
    {
        return substr(hash_hmac('sha256', $email, $this->emailKey), 0, 32);
    }

    private function codeHash(string $code): string
    {
        return hash_hmac('sha256', $code, $this->codeKey);
    }

    /**
     * The presented address: a bounded, syntactically deliverable
     * address of at most 254 bytes. The check is shape-only; ownership
     * is what the code proves.
     */
    private function emailOf(Request $request): ?string
    {
        $email = $request->request->get(self::EMAIL_FIELD);
        if (!\is_string($email) || \strlen($email) > 254) {
            return null;
        }
        $trimmed = trim($email);
        if (filter_var($trimmed, FILTER_VALIDATE_EMAIL) === false) {
            return null;
        }

        return strtolower($trimmed);
    }

    /** The keyed pseudonym of an address domain, never the domain itself. */
    private function domainPseudonym(string $domain): string
    {
        return substr(hash_hmac('sha256', $domain, $this->emailKey), 0, 32);
    }

    /**
     * The one-shot deployment budget warning at the 80 percent mark:
     * the once-per-process guard keeps a sustained campaign from
     * flooding the log, and a raising logger must never break begin().
     */
    private function warnNearBudget(int $globalAdmissions): void
    {
        if ($this->budgetWarned || $this->logger === null || $this->maxBeginsGlobal < 1) {
            return;
        }
        if ($globalAdmissions < (int) ceil($this->maxBeginsGlobal * 0.8)) {
            return;
        }
        $this->budgetWarned = true;
        try {
            $this->logger->warning('KiwiCaptcha: the email step-up begin budget passed 80 percent of its hourly deployment bound', [
                'admissions' => $globalAdmissions,
                'budget' => $this->maxBeginsGlobal,
            ]);
        } catch (\Throwable) {
        }
    }

    /**
     * Settle a claimed send lease. Best effort by design: a settlement
     * that cannot land (a store failure, or a lease another worker
     * already recovered) leaves the credit spent — the fail-closed
     * side, never a free extra send.
     */
    private function settleLease(StepUpDemandSendSettlement $settlement): void
    {
        try {
            $this->store->settleDemandSendLease($settlement);
        } catch (\Throwable) {
        }
    }

    /** Release a quota reservation (pre-handoff refusal). Best effort: a failed release commits the spend. */
    private function releaseQuota(string $reservationId): void
    {
        try {
            $this->store->releaseMailQuota($reservationId);
        } catch (\Throwable) {
        }
    }

    /** Commit a quota reservation (delivered or ambiguous). Best effort: the lease commits by default anyway. */
    private function commitQuota(string $reservationId): void
    {
        try {
            $this->store->commitMailQuota($reservationId);
        } catch (\Throwable) {
        }
    }

    /**
     * The continuity identity of the request: the continuity cookie
     * value when presented, else the started session's id, else null
     * (a stateless begin, which mints the one-time client secret).
     */
    private function sessionValueOf(Request $request): ?string
    {
        $continuity = $this->continuity?->read($request);
        if (\is_string($continuity) && $continuity !== '') {
            return $continuity;
        }
        $session = $request->hasSession() ? $request->getSession() : null;
        if ($session !== null && $session->isStarted() && (string) $session->getId() !== '') {
            return (string) $session->getId();
        }

        return null;
    }

    /**
     * The session hash the current request must present for a
     * session-bound grant or challenge: the same derivation the begin
     * stored. Null when the request carries no continuity session.
     */
    public function presentedSessionHash(Request $request): ?string
    {
        $sessionValue = $this->sessionValueOf($request);

        return $sessionValue === null ? null : hash('sha256', $sessionValue);
    }

    /**
     * Whether the operation already carries an authorized step-up
     * settlement: the family tip of the operation digest exists and its
     * demand reached the durable authorized terminal. A retry of the
     * same logical operation then reproduces the authorization
     * idempotently (see {@see StepUpDemandState::Authorized}) and must
     * never re-demand. False for every other state, absent operation or
     * store failure (fail-closed toward re-demand, never a silent pass).
     */
    public function isOperationAuthorized(string $operationDigest): bool
    {
        if ($operationDigest === '') {
            return false;
        }
        try {
            $tipId = $this->store->demandIdForOperation($operationDigest);
            if (!\is_string($tipId) || $tipId === '') {
                return false;
            }
            $demand = $this->store->readDemand($tipId);

            return $demand !== null && $demand->state === StepUpDemandState::Authorized;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * The completion binding: a session-bound challenge answers only
     * the browser that began it, a stateless challenge only a request
     * presenting the per-challenge client secret. Fail closed.
     */
    private function sessionMatches(Request $request, StepUpChallenge $challenge): bool
    {
        return $this->presentedBindingHash($request, $challenge) !== null;
    }

    /**
     * The presented binding hash of this factor's completion: the SHA-256
     * of the presented continuity session for a session-bound challenge,
     * of the presented client secret for a stateless one. The derivation
     * mirrors the stored hashes exactly, so the store's atomic completion
     * can compare it inside the script. Null presents nothing the
     * challenge could be bound to, fail closed.
     */
    private function presentedBindingHash(Request $request, StepUpChallenge $challenge): ?string
    {
        if ($challenge->sessionHash !== null && $challenge->sessionHash !== '') {
            $presented = $this->presentedSessionHash($request);

            return $presented;
        }
        if ($challenge->clientSecretHash !== null && $challenge->clientSecretHash !== '') {
            $presented = (string) $request->request->get(StepUpSessionBinding::CLIENT_SECRET_FIELD, '');

            return $presented === '' ? null : StepUpChallenge::clientSecretHash($presented);
        }

        return null;
    }

    /**
     * The keyed pseudonym of the source: HMAC over the resolved client
     * IP, never a raw address, stable inside the begin window.
     */
    private function sourcePseudonym(Request $request): ?string
    {
        try {
            $ip = $this->clientIpResolver !== null
                ? $this->clientIpResolver->resolve($request)
                : (string) ($request->getClientIp() ?? '');
        } catch (\Throwable) {
            return null;
        }
        if ($ip === '') {
            return null;
        }

        return substr(hash_hmac('sha256', $ip, $this->emailKey), 0, 32);
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }

    /**
     * @param array<string, mixed> $body
     * @param array<string, string> $headers
     */
    private static function json(array $body, int $status, array $headers = []): Response
    {
        return new Response((string) json_encode($body, JSON_UNESCAPED_SLASHES), $status, $headers + ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store']);
    }
}
