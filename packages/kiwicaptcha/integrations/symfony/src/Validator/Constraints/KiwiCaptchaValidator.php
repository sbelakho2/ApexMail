<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Validator\Constraints;

use BelConsulting\KiwiCaptchaBundle\Security\ThrottledVerifier;
use BelConsulting\KiwiCaptchaBundle\Security\VerificationCapacityExceededException;
use KiwiCaptcha\Verifier;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;

final class KiwiCaptchaValidator extends ConstraintValidator
{
    /**
     * @param Verifier|ThrottledVerifier $verifier KiwiCaptcha\Verifier is
     *                                             final; the bundle's
     *                                             ThrottledVerifier composes
     *                                             it to enforce the Argon2id
     *                                             concurrency cap and exposes
     *                                             the same verify() signature.
     */
    public function __construct(
        private readonly Verifier|ThrottledVerifier $verifier,
        private readonly RequestStack $requestStack,
        private readonly string $secretKey,
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

        $clientIp = null;
        if ($constraint->bindIp && $this->requestStack->getMainRequest() !== null) {
            $clientIp = $this->requestStack->getMainRequest()->getClientIp();
        }

        try {
            $outcome = $this->verifier->verify($value, $this->secretKey, $constraint->scope, $clientIp);
        } catch (VerificationCapacityExceededException) {
            // Aggregate Argon2id verification capacity exhausted: fail closed
            // as a regular captcha failure (never a 500).
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::NOT_SOLVED_ERROR)
                ->addViolation();

            return;
        }

        if (!$outcome->isOk()) {
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::NOT_SOLVED_ERROR)
                ->addViolation();
        }
    }
}
