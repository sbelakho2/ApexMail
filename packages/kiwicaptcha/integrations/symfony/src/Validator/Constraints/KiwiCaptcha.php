<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Validator\Constraints;

use Symfony\Component\Validator\Constraint;

/**
 * Validates a KiwiCaptcha solution token (the value of the kiwi__token field).
 *
 * Verification is performed locally using the verified kiwicaptcha-php core —
 * no external service, no secret key ever leaves the application.
 *
 * Usage:
 *   #[KiwiCaptcha(scope: 'login')]
 *   private ?string $kiwiToken = null;
 *
 * @Annotation
 * @Target({"PROPERTY", "METHOD", "ANNOTATION"})
 */
#[\Attribute(\Attribute::TARGET_PROPERTY | \Attribute::TARGET_METHOD | \Attribute::IS_REPEATABLE)]
class KiwiCaptcha extends Constraint
{
    public const NOT_SOLVED_ERROR = 'kiwicaptcha_not_solved';

    protected const ERROR_NAMES = [
        self::NOT_SOLVED_ERROR => 'NOT_SOLVED_ERROR',
    ];

    public string $message = 'The security check failed. Please try again.';

    /** Expected challenge scope (null = accept any scope). */
    public ?string $scope = null;

    /** Bind the challenge to the client IP (recommended). */
    public bool $bindIp = true;

    public function __construct(
        mixed $options = null,
        ?string $scope = null,
        ?bool $bindIp = null,
        ?string $message = null,
        ?array $groups = null,
        mixed $payload = null,
    ) {
        parent::__construct($options, $groups, $payload);
        $this->scope = $scope ?? $this->scope;
        $this->bindIp = $bindIp ?? $this->bindIp;
        $this->message = $message ?? $this->message;
    }

    public function validatedBy(): string
    {
        return KiwiCaptchaValidator::class;
    }
}
