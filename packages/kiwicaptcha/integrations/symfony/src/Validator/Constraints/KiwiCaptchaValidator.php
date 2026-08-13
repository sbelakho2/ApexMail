<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Validator\Constraints;

use BelConsulting\KiwiCaptchaBundle\Risk\AmbiguousForwardingException;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\DecodeError;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;

final class KiwiCaptchaValidator extends ConstraintValidator
{
    /**
     * Request attribute holding the canonical jti of the LAST successfully
     * verified challenge of this request (the core's VerifyOutcome::nonce()).
     * Request-scoped: set on the RequestStack main request only on a valid
     * verification, so the application can key its business operation
     * idempotency on (jti, action) after the form validates.
     */
    public const VERIFIED_JTI_ATTRIBUTE = '_kiwi_captcha_verified_jti';

    /**
     * Request attribute holding the transaction binding (audit #41) the
     * application controller copied from the POSTed `kiwi_request_binding`
     * field BEFORE form validation. When the attribute is absent the
     * validator falls back to the raw POST field of the same name. The
     * binding is enforced against the challenge record's SIGNED
     * request_binding: a bound challenge whose binding does not match is
     * rejected with the same invalid_or_expired outcome.
     */
    public const REQUEST_BINDING_ATTRIBUTE = '_kiwi_captcha_request_binding';

    /** @var string|null the canonical jti of the last valid verification */
    private ?string $lastVerifiedJti = null;

    /** @var string|null the record's transaction binding of the last valid verification */
    private ?string $lastVerifiedRequestBinding = null;

    /**
     * @param Verifier $verifier KiwiCaptcha\Verifier with the bundle's
     *                           configured Argon2id admission gate wired in
     *                           (when applicable) — capacity exhaustion is
     *                           reported as a VerifyOutcome, never a 500
     * @param bool     $enforceTelemetry when true, bot-signal telemetry is
     *                                   rejected (defense-in-depth; only
     *                                   meaningful when the widget collects
     *                                   telemetry)
     * @param LoggerInterface|null $logger internal verification detail on
     *                                     failures (audit #57): the public
     *                                     violation code is collapsed, the
     *                                     precise core reason stays in the
     *                                     logs
     * @param StorageInterface|null $storage the challenge storage — required
     *                                       for the ambiguous-consume
     *                                       deterministic-retry resolution
     *                                       (audit #74): on
     *                                       ConsumeIndeterminate the stored
     *                                       consumed record (state +
     *                                       consumed_result) decides the
     *                                       outcome instead of a second
     *                                       derivation
     * @param ClientIpResolver|null $clientIpResolver trusted client-IP policy
     *                                               (audit #64) — the SAME
     *                                               canonical IP the challenge
     *                                               controller bound the
     *                                               record to (a resolver
     *                                               mismatch would fail every
     *                                               bound challenge)
     */
    public function __construct(
        private readonly Verifier $verifier,
        private readonly RequestStack $requestStack,
        private readonly string $secretKey,
        private readonly bool $enforceTelemetry = false,
        private readonly ?RiskGateway $risk = null,
        private readonly ?ContinuityCookie $continuityCookie = null,
        private readonly ?OutstandingChallenges $outstanding = null,
        private readonly ?LoggerInterface $logger = null,
        private readonly ?StorageInterface $storage = null,
        private readonly ?ClientIpResolver $clientIpResolver = null,
    ) {
    }

    /**
     * The canonical jti (VerifyOutcome::nonce()) of the last successfully
     * verified token, or null when no verification succeeded yet. Read from
     * a WEB request via the request attribute instead:
     * {@see self::VERIFIED_JTI_ATTRIBUTE} (request-scoped and race-free).
     */
    public function verifiedJti(): ?string
    {
        return $this->lastVerifiedJti;
    }

    /**
     * The transaction binding of the last successfully verified challenge
     * (VerifyOutcome::requestBinding() — the SIGNED record binding, null
     * when the record is unbound), or null when no verification succeeded
     * yet. Audit #41 passthrough.
     */
    public function verifiedRequestBinding(): ?string
    {
        return $this->lastVerifiedRequestBinding;
    }

    public function validate(mixed $value, Constraint $constraint): void
    {
        if (!$constraint instanceof KiwiCaptcha) {
            throw new UnexpectedTypeException($constraint, KiwiCaptcha::class);
        }
        if ($value === null || $value === '') {
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR)
                ->addViolation();

            return;
        }
        if (!\is_string($value)) {
            throw new UnexpectedTypeException($value, 'string');
        }

        $request = $this->requestStack->getMainRequest();
        // The issued record is authoritative: a non-empty binding tag means
        // the challenge IS bound, so always pass the request IP (a bound
        // record with a missing IP fails closed with MissingClientIp inside
        // the verifier). Records issued with BindingMode::None carry an
        // empty tag and verify regardless.
        //
        // Audit #64: the client IP comes through the bundle's trusted
        // client-IP policy (ClientIpResolver) — the SAME canonical IP the
        // challenge controller used when it minted (and bound) the record.
        // A request with ambiguous double-forwarding from a trusted peer is
        // rejected outright (fail closed — the binding cannot be evaluated
        // reliably) when risk.reject_ambiguous_forwarding is true.
        $clientIp = null;
        if ($request !== null) {
            try {
                $clientIp = $this->clientIpResolver !== null
                    ? $this->clientIpResolver->resolve($request)
                    : $request->getClientIp();
            } catch (AmbiguousForwardingException $e) {
                $this->logger?->info('KiwiCaptcha: verification refused — ambiguous forwarding headers (audit #64)', [
                    'scope' => $constraint->scope,
                ]);
                $this->context->buildViolation($constraint->message)
                    ->setCode(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR)
                    ->addViolation();

                return;
            }
        }

        // Audit #47: pass the scope into the Argon2id admission gate. The
        // core Verifier calls acquire() without arguments, so the scope
        // travels through the request: stamp it here and let the bundle's
        // RequestScopeAdmissionGate forward it into the semaphore's
        // PER-SCOPE budget (argon2_max_per_tenant, checked in addition to
        // the global cap).
        $request?->attributes->set(\BelConsulting\KiwiCaptchaBundle\Security\RequestScopeAdmissionGate::SCOPE_ATTRIBUTE, $constraint->scope);

        // CapacityExceeded (Argon2id admission saturated) surfaces as a
        // regular failed verification — fail closed as a captcha violation.
        $outcome = $this->verifier->verify($value, $this->secretKey, $constraint->scope, $clientIp, null, $this->enforceTelemetry);

        // ── AMBIGUOUS-CONSUME DETERMINISTIC RETRY (audit #74) ──────────────
        // ConsumeIndeterminate means the consume transition MAY have happened
        // but its response was lost: the challenge may already be consumed —
        // with (or without) a committed result. The validator resolves the
        // outcome from the STORED record instead of re-deriving:
        //   - consumed record + stored VALID result + request binding == the
        //     STORED consumed binding -> the SAME success (jti + binding
        //     exposed, NO second derivation, no repeated side effects);
        //   - stored valid result + a DIFFERENT binding -> invalid_or_expired
        //     (a challenge minted for one transaction is never redeemable
        //     for another — the round-9 rule applied to the retry);
        //   - stored INVALID result -> invalid_or_expired (the original
        //     derive failed);
        //   - record still pending / consumed without a committed result /
        //     storage unavailable -> the outcome stays indeterminate
        //     (temporary_unavailable — retryable, never silently valid).
        // The stored-result VALID outcome (a re-verify of a consumed record
        // with a committed result — the core returns the SAME outcome
        // without re-deriving) takes the identical retry path: the round-9
        // binding check below applies to it, and the stored-result flag
        // suppresses the repeated side effects (risk feedback, post-solve,
        // outstanding decrement — they already ran exactly once on the
        // ORIGINAL verification).
        $fromStoredResult = \method_exists($outcome, 'fromStoredResult') && $outcome->fromStoredResult();
        if ($outcome->error === VerifyError::ConsumeIndeterminate) {
            $resolved = $this->resolveAmbiguousConsume($value, $request);
            if ($resolved === 'success') {
                return;
            }
            if ($resolved === 'invalid') {
                $this->logger?->info('KiwiCaptcha: ambiguous consume resolved to a refused outcome (audit #74)', [
                    'scope' => $constraint->scope,
                ]);
                $this->context->buildViolation($constraint->message)
                    ->setCode(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR)
                    ->addViolation();

                return;
            }
            // Unresolvable: fall through — publicCode() maps the remaining
            // indeterminate outcome to temporary_unavailable.
        }

        // TRANSACTION BINDING (audit #41): after a VALID verification, the
        // consumed record's SIGNED request_binding must equal the binding
        // the request carried (the request attribute the application
        // controller copied from the POSTed kiwi_request_binding field — or
        // the raw POST field). A bound record with a missing/mismatched
        // binding is rejected with the SAME invalid_or_expired outcome
        // (audit #57's collapsed code): a challenge minted for one
        // transaction is never redeemable for another. Unbound records
        // (binding null) skip the check entirely. For a stored-result
        // retry the outcome's requestBinding() IS the stored consumed
        // binding, so the SAME rule gives the audit #74 contract: same
        // binding -> same success, different binding -> invalid_or_expired.
        if ($outcome->isOk() && !$this->requestBindingMatches($outcome, $request)) {
            $this->logger?->info('KiwiCaptcha: valid proof rejected — request binding mismatch (audit #41)', [
                'scope' => $constraint->scope,
            ]);
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR)
                ->addViolation();

            return;
        }

        // POST-SOLVE feedback: feed the outcome into the adaptive risk
        // engine (SolveSuccess / InvalidProof / MalformedToken / Expired /
        // Replay), keyed on the continuity session when the client carries
        // one. The scope string is never validated against the policy map
        // here — unknown scopes are handled by the gateway (minimum mode
        // observes under the synthetic scope id; baseline/reject modes skip
        // the signal with a debug log, never an exception). An unavailable
        // client IP is not a risk signal and must never break the form
        // submit (RiskGateway skips it internally).
        //
        // NONCE -> DECISION CONSUMPTION: after a VALID verification the
        // bounded solution token is decoded to its nonce and the short-lived
        // nonce -> decision handle is CONSUMED (GETDEL, at most one winner).
        // On scopes WITHOUT post_solve_check the ORIGINAL pre-issue decision
        // id becomes the request's current decision id
        // ({@see RiskGateway::setCurrentDecisionId()}), so the application
        // can confirm this challenge's original decision. On post_solve_check
        // scopes the old mapping is still consumed (cleanup — it can never be
        // confirmed against a stale decision), and the fresh POST-SOLVE
        // decision becomes the current confirmation target instead.
        //
        // POST-SOLVE CHECK: when the scope opts in (post_solve_check), a
        // VALID solve additionally runs a fresh SolveSuccess assessment with
        // the same context. A Deny there fails the validation with the
        // distinct POST_SOLVE_REJECTED_ERROR (the security context changed
        // while the client was solving); a StepUp fails it with
        // POST_SOLVE_STEP_UP_REQUIRED (PoW alone is insufficient — the
        // application routes the user to MFA/passkey/email confirmation).
        // The gateway does NOT confirm its own post-solve decision:
        // ConfirmedLegitimate / ConfirmedAbuse are application-only signals
        // (they require a decision id), so a valid solve that passes the
        // re-assessment is recorded as plain SolveSuccess feedback.
        //
        // A STORED-RESULT outcome (audit #74 retry) skips this block
        // entirely: the post-solve assessment, the nonce->decision
        // consumption and the outstanding decrement all ran EXACTLY ONCE on
        // the original verification — a retry must return the same outcome
        // deterministically, not re-score the same token.
        if ($this->risk !== null && !$fromStoredResult) {
            $session = $request !== null ? $this->continuityCookie?->read($request) : null;
            $ip = (string) ($clientIp ?? '');
            $postSolveScope = $outcome->isOk() && $this->risk->postSolveCheck($constraint->scope);

            if ($outcome->isOk()) {
                $originalDecisionId = $this->consumeDecisionForToken($value);
                if (!$postSolveScope && $originalDecisionId !== null) {
                    $this->risk->setCurrentDecisionId($originalDecisionId);
                }
            }

            if ($postSolveScope) {
                try {
                    $postSolve = $this->risk->postSolveDecision($constraint->scope, $ip, $session);
                } catch (\InvalidArgumentException) {
                    // No live risk signal for this context (e.g. an
                    // unparseable or missing client IP): enforce the scope's
                    // DEGRADED friction instead of silently skipping the
                    // adaptive re-check — in BindingMode::None deployments a
                    // valid PoW must not pass with zero adaptive friction.
                    // This mirrors the fail-safe degraded rule on the
                    // pre-issue path (degradedDecisionForScope applies the
                    // policy's degraded action without touching the state
                    // store).
                    $postSolve = $this->risk->degradedDecisionForScope($this->risk->scopeId($constraint->scope));
                }
                if ($postSolve !== null && $postSolve->action === RiskAction::Deny) {
                    $this->context->buildViolation($constraint->message)
                        ->setCode(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR)
                        ->addViolation();

                    return;
                }
                if ($postSolve !== null && $postSolve->action === RiskAction::StepUp) {
                    $this->context->buildViolation($constraint->message)
                        ->setCode(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED)
                        ->addViolation();

                    return;
                }
            } else {
                $this->risk->solveOutcome($constraint->scope, $ip, $session, $outcome->error);
            }
        }

        // JTI + BINDING passthrough (audit #37/#41): a VALID verification
        // exposes the canonical jti — the core's VerifyOutcome::nonce(), the
        // challenge nonce of the CONSUMED record — and the record's signed
        // transaction binding (VerifyOutcome::requestBinding()) to the
        // application, both via {@see verifiedJti()} /
        // {@see verifiedRequestBinding()} and the request attribute
        // (VERIFIED_JTI_ATTRIBUTE; request-scoped and race-free for web
        // flows). The application keys its business operation idempotency on
        // (jti, action): a retry carrying the same jti must never create a
        // second operation (see README).
        if ($outcome->isOk()) {
            $jti = null;
            if (\method_exists($outcome, 'nonce')) {
                $jti = $outcome->nonce();
            }
            if (!\is_string($jti) || $jti === '') {
                // Compat fallback (cores predating VerifyOutcome::nonce()):
                // the canonical jti is the consumed record's nonce, which
                // equals the solution token's nonce (verification just
                // succeeded against that record).
                try {
                    $jti = SolutionToken::decode($value)->nonce;
                } catch (DecodeError) {
                    $jti = null;
                }
            }
            if (\is_string($jti) && $jti !== '') {
                $this->lastVerifiedJti = $jti;
                $request?->attributes->set(self::VERIFIED_JTI_ATTRIBUTE, $jti);
            }
            if (\method_exists($outcome, 'requestBinding')) {
                $this->lastVerifiedRequestBinding = $outcome->requestBinding();
            }

            // Anti-stockpiling (audit #26): the source's outstanding
            // challenge counter is decremented (best-effort, floored at 0)
            // when a challenge verifies successfully — a solved challenge is
            // no longer outstanding. Never breaks the solve. Skipped for a
            // stored-result retry (audit #74): the ORIGINAL verification
            // already decremented it.
            if (!$fromStoredResult) {
                $this->outstanding?->solved((string) ($clientIp ?? ''));
            }
        }

        if (!$outcome->isOk()) {
            $code = $this->publicCode($outcome->error);
            // Audit #57: the collapsed public code; the PRECISE core reason
            // (WrongScope, Expired, BadSignature, ...) stays in the logs —
            // never exposed to the client (no oracle for which check
            // failed).
            if ($outcome->error !== null && $code !== KiwiCaptcha::INVALID_OR_EXPIRED_ERROR) {
                $this->logger?->info('KiwiCaptcha: verification refused', [
                    'reason' => $outcome->error->value,
                    'detail' => $outcome->detail,
                    'scope' => $constraint->scope,
                ]);
            }
            $this->context->buildViolation($constraint->message)
                ->setCode($code)
                ->addViolation();
        }
    }

    /**
     * The record's signed request_binding (VerifyOutcome::requestBinding())
     * must equal the binding the request carried — when the record is
     * bound. An unbound record (null binding) skips the check.
     */
    private function requestBindingMatches(\KiwiCaptcha\VerifyOutcome $outcome, ?Request $request): bool
    {
        $recordBinding = \method_exists($outcome, 'requestBinding') ? $outcome->requestBinding() : null;
        if ($recordBinding === null) {
            return true;
        }

        $requestBinding = $this->requestBindingFromRequest($request);

        return $requestBinding !== null && hash_equals($recordBinding, $requestBinding);
    }

    /**
     * Audit #57's public violation-code collapse: every token-level failure
     * collapses to invalid_or_expired; the capacity refusals stay distinct
     * (rate_limited / temporary_unavailable). Internal detail is logged, the
     * client only ever sees the collapsed code.
     *
     * ConsumeIndeterminate is NOT a token-level failure: it is a storage
     * I/O ambiguity (the consume may or may not have happened) — the audit
     * #74 resolution tries the stored record first, and an UNRESOLVABLE
     * indeterminate outcome maps to temporary_unavailable (retryable, like
     * StorageUnavailable), never to invalid_or_expired — the client must
     * not be told its token is burned when it may still redeem.
     */
    private function publicCode(?VerifyError $error): string
    {
        return match ($error) {
            VerifyError::CapacityExceeded => KiwiCaptcha::RATE_LIMITED_ERROR,
            VerifyError::AdmissionUnavailable,
            VerifyError::StorageUnavailable,
            VerifyError::ConsumeIndeterminate => KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR,
            default => KiwiCaptcha::INVALID_OR_EXPIRED_ERROR,
        };
    }

    /**
     * Audit #74's ambiguous-consume resolution: decide the outcome of a
     * ConsumeIndeterminate verification from the STORED consumed record
     * instead of re-deriving.
     *
     * @return 'success'|'invalid'|'unresolved' — 'success' also exposes the
     *         canonical jti + signed binding of the consumed record (the
     *         SAME outcome the original verification produced)
     */
    private function resolveAmbiguousConsume(string $token, ?Request $request): string
    {
        $record = $this->findConsumedRecord($token);
        if ($record === null) {
            // No storage wired, undecodable token, storage failure, record
            // absent, or record still PENDING (the first attempt never
            // consumed it — a retry will consume normally): the outcome
            // stays indeterminate.
            return 'unresolved';
        }

        $result = $this->consumedResultOf($record);
        if ($result === false) {
            // The original derivation FAILED — the stored result is the
            // authoritative outcome.
            return 'invalid';
        }
        if ($result !== true) {
            // Consumed but the result was never committed (the original
            // attempt died mid-proof): genuinely indeterminate.
            return 'unresolved';
        }

        // Stored VALID result: deterministic retry. The request binding must
        // equal the STORED consumed binding — a challenge bound to one
        // transaction is never redeemable for another, retries included.
        $storedBinding = $this->consumedBindingOf($record);
        if ($storedBinding !== null) {
            $requestBinding = $this->requestBindingFromRequest($request);
            if ($requestBinding === null || !hash_equals($storedBinding, $requestBinding)) {
                return 'invalid';
            }
        }

        // The SAME success: expose the canonical jti + signed binding (the
        // application's (jti, action) idempotency key stays stable across
        // the retry) — no re-derive, no repeated side effects.
        $this->lastVerifiedJti = $record->nonce;
        $request?->attributes->set(self::VERIFIED_JTI_ATTRIBUTE, $record->nonce);
        $binding = $this->consumedBindingOf($record);
        if ($binding !== null) {
            $this->lastVerifiedRequestBinding = $binding;
        }

        return 'success';
    }

    /**
     * The consumed record behind a token: decoded nonce -> storage find,
     * restricted to records in the CONSUMED state (the audit #74 state
     * transition). null when the state cannot be resolved.
     */
    private function findConsumedRecord(string $token): ?ChallengeRecord
    {
        if ($this->storage === null) {
            return null;
        }
        try {
            $nonce = SolutionToken::decode($token)->nonce;
        } catch (DecodeError) {
            return null;
        }
        try {
            $record = $this->storage->find($nonce);
        } catch (\Throwable) {
            return null;
        }
        if ($record === null || !$this->recordIsConsumed($record)) {
            return null;
        }

        return $record;
    }

    /**
     * Whether the record is in the consumed state (the consumed-state
     * TRANSITION of the audit #74 storage contract). Probing
     * `ChallengeRecord::consumed` defensively: cores predating the
     * transition never set it (false) — on those cores consumed records
     * are DELETED by consume(), so a ConsumeIndeterminate followed by a
     * find() yields no record and stays unresolved (legacy behavior).
     */
    private function recordIsConsumed(ChallengeRecord $record): bool
    {
        return (bool) ($record->consumed ?? false);
    }

    /**
     * The stored consumed result of a consumed record: true = the original
     * derivation was VALID, false = it FAILED, null = consumed but no
     * result committed (indeterminate). The parallel core exposes it as
     * `ChallengeRecord::$consumedResult` (audit #74).
     */
    private function consumedResultOf(ChallengeRecord $record): ?bool
    {
        $result = $record->consumedResult ?? null;

        return $result === null ? null : (bool) $result;
    }

    /**
     * The STORED binding of the consumed state (the binding the original
     * verification committed — `ChallengeRecord::$consumedBinding`,
     * falling back to the record's signed request_binding on cores that
     * store it there), or null for an unbound record.
     */
    private function consumedBindingOf(ChallengeRecord $record): ?string
    {
        $binding = $record->consumedBinding ?? $record->requestBinding;
        if (!\is_string($binding) || $binding === '') {
            return null;
        }

        return $binding;
    }

    /**
     * The request's transaction binding: the documented attribute first,
     * then the raw POSTed kiwi_request_binding field (the widget fallback).
     * Shared by the round-9 check and the audit #74 retry resolution.
     */
    private function requestBindingFromRequest(?Request $request): ?string
    {
        $binding = $request?->attributes->get(self::REQUEST_BINDING_ATTRIBUTE);
        if (!\is_string($binding) || $binding === '') {
            $binding = $request?->request->get('kiwi_request_binding');
        }

        return \is_string($binding) && $binding !== '' ? $binding : null;
    }

    /**
     * Decode the bounded solution token to its nonce and CONSUME the
     * nonce -> decision handle (GETDEL — at most one consumer wins).
     * Returns the paired ORIGINAL pre-issue decision id, or null when the
     * token cannot be decoded or no handle exists. Never throws: a valid
     * verification implies a decodable token (defense in depth).
     */
    private function consumeDecisionForToken(string $token): ?string
    {
        try {
            $nonce = SolutionToken::decode($token)->nonce;
        } catch (DecodeError) {
            return null;
        }

        return $this->risk?->resolveDecisionForNonce($nonce);
    }
}
