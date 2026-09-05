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

    /**
     * The optional decoy (honeypot) field name violated its alphabet
     * `[A-Za-z0-9_-]{1,64}` — e.g. the canonical `|` separator, an
     * identifier-shaped `.`, Unicode/whitespace, an empty string or an
     * over-long name (the Rust validate_record mirror; none can alter the
     * canonical segment structure).
     */
    public static function invalidDecoyField(): self
    {
        return new self('record field "decoy_field" must be 1-64 characters of [A-Za-z0-9_-]');
    }

    /**
     * A protocol-v2 record that carries `decoy_field`: the decoy segment
     * is a protocol v3 canonical extension and the v2 canonical never
     * includes it. A conforming armed issuance writes protocol v3, so
     * the combination is a corrupt or foreign record, rejected
     * explicitly (the capability becomes inferable from
     * protocol_version, which is the point).
     */
    public static function decoyOnV2Record(): self
    {
        return new self('record protocol_version 2 must not carry a "decoy_field" (the decoy segment is a protocol v3 canonical extension)');
    }

    /**
     * A protocol-v3 record without `decoy_field`: the decoy is mandatory
     * on v3, since the v3 canonical is the 18-field base plus the
     * `|decoy_field` segment. A v3 record without one cannot have come
     * from a conforming issuer, because an armed issuance always writes
     * the segment. The rejection closes the stored-version-flip window:
     * a signed v2 record with its stored protocol_version flipped to 3
     * keeps the plain 18-field canonical bytes and is refused here.
     * The protocol capability is therefore fully inferable from the
     * authenticated canonical shape, the v2-plus-decoy mirror.
     */
    public static function decoylessV3Record(): self
    {
        return new self('record protocol_version 3 must carry a "decoy_field" (the decoy segment is mandatory on the protocol v3 canonical)');
    }

    public static function unexpectedNull(string $field): self
    {
        return new self(sprintf('record field "%s" must not be null', $field));
    }

    /**
     * The optional ExecutionChallengeV1 program is not a well-formed
     * program blob: non-canonical base64, an unknown format version, an
     * out-of-bound scope/action/op count, an unknown opcode, or a
     * truncated operand section.
     * Trailing bytes after the op list, an op version other than 1, or
     * a scope/action outside the identifier alphabet are also rejected.
     * A record carrying it cannot be verified against its execution
     * dimension, so it is a corrupt or foreign record.
     */
    public static function invalidExecutionProgram(): self
    {
        return new self('record field "execution_program" must be a well-formed ExecutionChallengeV1 program blob (canonical base64 of a parseable program)');
    }

    /**
     * A partial protocol-v4 execution field set: the three execution
     * keys (`execution_program`, `execution_version`,
     * `execution_commitment`) are present together or all absent. A
     * partial set cannot come from a conforming issuer and is a corrupt
     * or foreign record — the signed commitment is the exact mirror of
     * the stored program, never a separate field that can be stripped
     * or injected independently.
     */
    public static function incompleteExecutionFields(): self
    {
        return new self('record execution fields must be present together or all absent: "execution_program", "execution_version" and "execution_commitment" are one triplet');
    }

    /**
     * The protocol-v4 `execution_version` is not a canonical numeric
     * byte of the execution-dimension register: the accepted set is
     * 1..MAX_EXECUTION_VERSION (the generator's live maximum). Anything
     * else is a corrupt or foreign record.
     */
    public static function invalidExecutionVersion(int $version): self
    {
        return new self(sprintf('record field "execution_version" must be one of the canonical execution-dimension versions 1..%d, got %d', ExecutionChallengeGenerator::MAX_EXECUTION_VERSION, $version));
    }

    /**
     * The protocol-v4 `execution_commitment` is not 64 lowercase hex
     * characters — the canonical shape of SHA-256. A malformed
     * commitment is a corrupt or foreign record.
     */
    public static function invalidExecutionCommitment(): self
    {
        return new self('record field "execution_commitment" must be exactly 64 lowercase hex characters (the SHA-256 of the execution program)');
    }

    /**
     * The stored execution program's SHA-256 does not equal the signed
     * `execution_commitment`: the authenticated mirror was stripped,
     * substituted or desynchronized. The record is corrupt or foreign.
     */
    public static function executionCommitmentMismatch(): self
    {
        return new self('record "execution_program" does not match the signed "execution_commitment" (SHA-256 of the stored program must equal the commitment)');
    }

    /**
     * A protocol-v2 or protocol-v3 record carrying the protocol-v4
     * execution triplet: the execution segments are a protocol v4
     * canonical extension and neither the v2 nor the v3 canonical ever
     * includes them. A conforming execution-armed issuance writes
     * protocol v4, so the combination is a corrupt or foreign record.
     */
    public static function executionOnLegacyProtocol(int $protocolVersion): self
    {
        return new self(sprintf('record protocol_version %d must not carry execution_program/execution_version/execution_commitment (the execution segments are a protocol v4 canonical extension)', $protocolVersion));
    }

    /**
     * A protocol-v4 record without the execution triplet: the
     * execution_version + execution_commitment segments are mandatory on
     * the v4 canonical, so a v4 record without them cannot have come
     * from a conforming issuer (an execution-armed issuance always
     * writes the segments). The rejection closes the stored-version-flip
     * window: a signed v2/v3 record with its stored protocol_version
     * flipped to 4 keeps the plain canonical bytes and is refused here.
     */
    public static function executionlessV4Record(): self
    {
        return new self('record protocol_version 4 must carry "execution_program" with "execution_version" and "execution_commitment" (the execution commitment is mandatory on the protocol v4 canonical)');
    }
}
