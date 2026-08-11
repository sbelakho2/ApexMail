<?php

declare(strict_types=1);

namespace KiwiCaptcha\Symfony\Validator;

use KiwiCaptcha\Verifier;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;

final class KiwiCaptchaValidator extends ConstraintValidator
{
    public function __construct(
        private readonly Verifier $verifier,
        private readonly RequestStack $requestStack,
        private readonly ?string $configuredSecretKey = null,
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

        $secretKey = $constraint->secretKey ?? $this->configuredSecretKey;
        if ($secretKey === null) {
            throw new \LogicException('KiwiCaptcha secret key is not configured (set kiwicaptcha.secret or pass secretKey to the constraint)');
        }

        $outcome = $this->verifier->verify(
            $value,
            $secretKey,
            $constraint->scope,
            $constraint->bindIp ? $this->clientIp() : null,
        );

        if (!$outcome->isOk()) {
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::NOT_SOLVED_ERROR)
                ->addViolation();
        }
    }

    /**
     * The client IP must come from the same source that bound the challenge
     * when it was issued (ChallengeController uses Request::getClientIp()),
     * so both sides agree on TrustedProxies handling. Never fall back to
     * $_SERVER['REMOTE_ADDR'], which bypasses Request::getClientIp().
     */
    private function clientIp(): ?string
    {
        return $this->requestStack->getMainRequest()?->getClientIp();
    }
}
