<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The factor one step-up demand requires: the assurance family, the
 * handler id that serves it and the fixed assurance rank of the pair.
 *
 * The ladder is closed and ordered: email_otp ranks 1, totp ranks 2,
 * webauthn ranks 3. A custom handler name can serve a family as its
 * factorId, but it can never add a rung: the resolver serves exactly
 * these three families, so "strictly stronger" always has one meaning
 * across every deployment.
 */
final class FactorRequirement
{
    public const EMAIL_OTP = 'email_otp';

    public const TOTP = 'totp';

    public const WEBAUTHN = 'webauthn';

    /**
     * The fixed assurance ladder: email_otp = 1, totp = 2,
     * webauthn = 3. Strictly monotonic, like the risk action ladder.
     *
     * @var array<string, int>
     */
    public const LADDER = [
        self::EMAIL_OTP => 1,
        self::TOTP => 2,
        self::WEBAUTHN => 3,
    ];

    public function __construct(
        public readonly string $family,
        public readonly string $factorId,
        public readonly int $assuranceRank,
    ) {
        if (!isset(self::LADDER[$family])) {
            throw new \InvalidArgumentException(sprintf(
                'The factor family of a step-up requirement must be one of %s',
                implode(', ', array_keys(self::LADDER)),
            ));
        }
        if (preg_match('/^[a-z0-9_]{1,64}$/D', $factorId) !== 1) {
            throw new \InvalidArgumentException('The factor id of a step-up requirement must be 1-64 chars of [a-z0-9_]');
        }
        if ($assuranceRank !== self::LADDER[$family]) {
            throw new \InvalidArgumentException('The assurance rank of a step-up requirement must be the ladder rank of its family');
        }
    }

    /** Whether the string names a family of the ladder. */
    public static function isFamily(string $family): bool
    {
        return isset(self::LADDER[$family]);
    }

    /** The ladder rank of a family, 0 for anything outside the ladder. */
    public static function rankOf(string $family): int
    {
        return self::LADDER[$family] ?? 0;
    }
}
