<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The one chain-id grammar: every component that validates, stamps or
 * decodes a chain id consults this validator, so no surface can accept
 * (or mint) a shape another surface refuses. The chain protocol mints
 * 22-char base64url ids; the grammar is deliberately the same family
 * the minter can produce.
 */
final class ChainId
{
    public const PATTERN = '/^[A-Za-z0-9_-]{1,64}$/D';

    public static function isValid(string $value): bool
    {
        return preg_match(self::PATTERN, $value) === 1;
    }
}
