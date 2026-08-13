<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Validator\Constraints;

use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use KiwiCaptcha\DecodeError;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use Psr\Log\LoggerInterface;
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
        $clientIp = $request?->getClientIp();

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

        // TRANSACTION BINDING (audit #41): after a VALID verification, the
        // consumed record's SIGNED request_binding must equal the binding
        // the request carried (the request attribute the application
        // controller copied from the POSTed kiwi_request_binding field — or
        // the raw POST field). A bound record with a missing/mismatched
        // binding is rejected with the SAME invalid_or_expired outcome
        // (audit #57's collapsed code): a challenge minted for one
        // transaction is never redeemable for another. Unbound records
        // (binding null) skip the check entirely.
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
        if ($this->risk !== null) {
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
            // no longer outstanding. Never breaks the solve.
            $this->outstanding?->solved((string) ($clientIp ?? ''));
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
    private function requestBindingMatches(\KiwiCaptcha\VerifyOutcome $outcome, ?\Symfony\Component\HttpFoundation\Request $request): bool
    {
        $recordBinding = \method_exists($outcome, 'requestBinding') ? $outcome->requestBinding() : null;
        if ($recordBinding === null) {
            return true;
        }

        $requestBinding = $request?->attributes->get(self::REQUEST_BINDING_ATTRIBUTE);
        if (!\is_string($requestBinding) || $requestBinding === '') {
            // Fallback: the raw POSTed field (the widget's hidden
            // kiwi_request_binding input). The attribute contract is
            // preferred (the application controller copies the field before
            // validation) — this fallback makes the plain widget flow work
            // without an application shim.
            $requestBinding = $request?->request->get('kiwi_request_binding');
        }

        return \is_string($requestBinding) && $requestBinding !== '' && hash_equals($recordBinding, $requestBinding);
    }

    /**
     * Audit #57's public violation-code collapse: every token-level failure
     * collapses to invalid_or_expired; the capacity refusals stay distinct
     * (rate_limited / temporary_unavailable). Internal detail is logged, the
     * client only ever sees the collapsed code.
     */
    private function publicCode(?VerifyError $error): string
    {
        return match ($error) {
            VerifyError::CapacityExceeded => KiwiCaptcha::RATE_LIMITED_ERROR,
            VerifyError::AdmissionUnavailable,
            VerifyError::StorageUnavailable => KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR,
            default => KiwiCaptcha::INVALID_OR_EXPIRED_ERROR,
        };
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
