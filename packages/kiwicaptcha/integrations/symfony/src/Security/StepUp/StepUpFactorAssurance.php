<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The server-owned assurance of a step-up factor: the factor identity
 * and its rank. Both live on the handler, never on the wire, so a
 * client can neither name nor negotiate the assurance a completion
 * claims. The rank orders the factors by their resistance to a
 * phished or stuffed completion; the identity names the factor the
 * way the rest of the plane spells it (the registry keys, the session
 * success markers, the enrollment factor floors).
 *
 * A custom handler carries its own identity and rank under the same
 * contract. The registry refuses a handler whose identity disagrees
 * with the name it is registered under. The assurance a demand books
 * is therefore always the one the deployment configured.
 */
final class StepUpFactorAssurance
{
    public const EMAIL_OWNERSHIP = 'email_ownership';
    public const EMAIL_OTP = 'email_otp';
    public const TOTP = 'totp';
    public const WEBAUTHN = 'webauthn';

    public function __construct(
        public readonly string $identity,
        public readonly int $rank,
    ) {
        if (preg_match('/^[a-z0-9_]{1,64}$/D', $identity) !== 1) {
            throw new \InvalidArgumentException('The factor identity must be 1-64 chars of [a-z0-9_]');
        }
        if ($rank < 1) {
            throw new \InvalidArgumentException('The factor assurance rank must be a positive integer');
        }
    }

    public static function emailOwnership(): self
    {
        return new self(self::EMAIL_OWNERSHIP, 1);
    }

    public static function emailOtp(): self
    {
        return new self(self::EMAIL_OTP, 2);
    }

    public static function totp(): self
    {
        return new self(self::TOTP, 3);
    }

    public static function webauthn(): self
    {
        return new self(self::WEBAUTHN, 4);
    }

    /** A custom factor: the application owns the identity and the rank. */
    public static function custom(string $identity, int $rank): self
    {
        return new self($identity, $rank);
    }
}
