<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Failure reasons for token decoding.
 */
final class DecodeError extends \RuntimeException
{
    public const INVALID_BASE64 = 'invalid_base64';
    public const INVALID_UTF8 = 'invalid_utf8';
    public const MALFORMED = 'malformed';
    public const INVALID_COUNTER = 'invalid_counter';
    public const COUNTER_EXCEEDS_SOLVER_MAXIMUM = 'counter exceeds solver maximum';
    public const INVALID_DURATION = 'invalid_duration';

    private function __construct(string $code)
    {
        parent::__construct($code);
    }

    public static function invalidBase64(): self
    {
        return new self(self::INVALID_BASE64);
    }

    public static function invalidUtf8(): self
    {
        return new self(self::INVALID_UTF8);
    }

    public static function malformed(): self
    {
        return new self(self::MALFORMED);
    }

    public static function invalidCounter(): self
    {
        return new self(self::INVALID_COUNTER);
    }

    public static function counterExceedsSolverMaximum(): self
    {
        return new self(self::COUNTER_EXCEEDS_SOLVER_MAXIMUM);
    }

    public static function invalidDuration(): self
    {
        return new self(self::INVALID_DURATION);
    }
}
