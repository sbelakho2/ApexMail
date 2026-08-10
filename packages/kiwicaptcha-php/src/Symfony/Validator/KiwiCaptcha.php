<?php

declare(strict_types=1);

namespace KiwiCaptcha\Symfony\Validator;

use Symfony\Component\Validator\Constraint;

/**
 * Validates a KiwiCaptcha solution token (the value of the kiwi__token field).
 *
 * Usage:
 *   #[Assert\KiwiCaptcha(scope: 'login', secretKey: '%env(KIWI_SECRET_KEY)%')]
 *   private ?string $kiwiToken = null;
 */
#[\Attribute(\Attribute::TARGET_PROPERTY | \Attribute::TARGET_METHOD)]
final class KiwiCaptcha extends Constraint
{
    public const NOT_SOLVED_ERROR = 'kiwicaptcha_not_solved';

    protected const ERROR_NAMES = [
        self::NOT_SOLVED_ERROR => 'NOT_SOLVED_ERROR',
    ];

    public string $message = 'The security check failed. Please retry.';

    public ?string $scope = null;

    /** HMAC secret key. When null, the configured service secret is used. */
    public ?string $secretKey = null;

    /** Bind the challenge to the client IP (recommended). */
    public bool $bindIp = true;

    public function __construct(
        mixed $options = null,
        ?string $scope = null,
        ?string $secretKey = null,
        ?bool $bindIp = null,
        ?string $message = null,
        ?array $groups = null,
        mixed $payload = null,
    ) {
        parent::__construct($options, $groups, $payload);
        $this->scope = $scope ?? $this->scope;
        $this->secretKey = $secretKey ?? $this->secretKey;
        $this->bindIp = $bindIp ?? $this->bindIp;
        $this->message = $message ?? $this->message;
    }
}
