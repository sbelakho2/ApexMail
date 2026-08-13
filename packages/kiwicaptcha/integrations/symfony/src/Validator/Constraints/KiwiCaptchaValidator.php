<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Validator\Constraints;

use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use KiwiCaptcha\DecodeError;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Verifier;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;

final class KiwiCaptchaValidator extends ConstraintValidator
{
    /**
     * @param Verifier $verifier KiwiCaptcha\Verifier with the bundle's
     *                           configured Argon2id admission gate wired in
     *                           (when applicable) — capacity exhaustion is
     *                           reported as a VerifyOutcome, never a 500
     * @param bool     $enforceTelemetry when true, bot-signal telemetry is
     *                                   rejected (defense-in-depth; only
     *                                   meaningful when the widget collects
     *                                   telemetry)
     */
    public function __construct(
        private readonly Verifier $verifier,
        private readonly RequestStack $requestStack,
        private readonly string $secretKey,
        private readonly bool $enforceTelemetry = false,
        private readonly ?RiskGateway $risk = null,
        private readonly ?ContinuityCookie $continuityCookie = null,
    ) {
    }

    public function validate(mixed $value, Constraint $constraint): void
    {
        if (!$constraint instanceof KiwiCaptcha) {
            throw new UnexpectedTypeException($constraint, KiwiCaptcha::class);
        }
        if ($value === null || $value === '') {
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::NOT_SOLVED_ERROR)
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

        // CapacityExceeded (Argon2id admission saturated) surfaces as a
        // regular failed verification — fail closed as a captcha violation.
        $outcome = $this->verifier->verify($value, $this->secretKey, $constraint->scope, $clientIp, null, $this->enforceTelemetry);

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

        if (!$outcome->isOk()) {
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::NOT_SOLVED_ERROR)
                ->addViolation();
        }
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
