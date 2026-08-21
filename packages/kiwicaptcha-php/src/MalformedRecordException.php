<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * A stored challenge record failed the strict serde-mirror parser, see
 * {@see ChallengeRecord::fromArray()}.
 *
 * Thrown on any structural violation the Rust `ChallengeRecord` serde
 * schema rejects: unknown keys (deny_unknown_fields), wrong types,
 * out-of-range or negative integers, oversized strings, algorithm
 * aliases, unexpected nulls, duplicate `binding_tag`/`ip_hash` aliases,
 * missing required fields, and JSON arrays in place of objects.
 * Identifier-alphabet violations for the deployment-bound identifiers
 * also throw. Storage backends catch it and treat the record as absent;
 * callers of `fromArray()` can catch it explicitly.
 */
final class MalformedRecordException extends \RuntimeException
{
    private function __construct(string $reason)
    {
        parent::__construct($reason);
    }

    public static function for(string $reason): self
    {
        return new self($reason);
    }

    public static function unknownKey(string $key): self
    {
        return new self(sprintf('unknown record key "%s"', $key));
    }

    public static function missingField(string $field): self
    {
        return new self(sprintf('missing required record field "%s"', $field));
    }

    public static function duplicateAlias(string $field, string $alias): self
    {
        return new self(sprintf('record carries both "%s" and its legacy alias "%s"', $field, $alias));
    }

    public static function wrongType(string $field, string $expected, mixed $actual): self
    {
        return new self(sprintf(
            'record field "%s" must be %s, %s given',
            $field,
            $expected,
            get_debug_type($actual),
        ));
    }

    public static function outOfRange(string $field, int $min, int $max, mixed $actual): self
    {
        return new self(sprintf(
            'record field "%s" must be within %d..%d, %s given',
            $field,
            $min,
            $max,
            get_debug_type($actual) === 'int' ? (string) $actual : get_debug_type($actual),
        ));
    }

    public static function oversized(string $field, int $length, int $max = 4096): self
    {
        return new self(sprintf('record field "%s" exceeds the %d-byte ceiling (%d bytes)', $field, $max, $length));
    }

    public static function invalidAlgorithm(mixed $value): self
    {
        $shown = \is_string($value) ? $value : get_debug_type($value);

        return new self(sprintf('record algorithm must be exactly "sha256" or "argon2id", got "%s"', $shown));
    }

    /**
     * A deployment-bound identifier (region, request_binding,
     * issuer) violated the narrow identifier alphabet `[A-Za-z0-9._:-]+`
     * or its length cap, e.g. Unicode, whitespace, invisible characters,
     * empty strings, or the canonical `|` separator.
     */
    public static function invalidIdentifier(string $field): self
    {
        return new self(sprintf(
            'record field "%s" must be 1-%d characters of [A-Za-z0-9._:-]',
            $field,
            $field === 'region' ? 64 : 128,
        ));
    }

    public static function unexpectedNull(string $field): self
    {
        return new self(sprintf('record field "%s" must not be null', $field));
    }
}
