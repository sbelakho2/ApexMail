<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Validator\Constraints;

use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
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
        // one. The scope string is never validated against the policy map —
        // unknown scopes are still observed (crc32 fallback id). An
        // unavailable client IP is not a risk signal and must never break
        // the form submit (RiskGateway skips it internally).
        if ($this->risk !== null) {
            $session = $request !== null ? $this->continuityCookie?->read($request) : null;
            $this->risk->solveOutcome($constraint->scope, (string) ($clientIp ?? ''), $session, $outcome->error);
        }

        if (!$outcome->isOk()) {
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::NOT_SOLVED_ERROR)
                ->addViolation();
        }
    }
}
