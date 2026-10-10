<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * The one canonical SiteVerify idempotency record schema: the PHP half
 * of the versioned predicate whose Lua mirror is
 * {@see SiteVerifyIdempotencyLuaPredicate}. Every read, transition and
 * cached-success acceptance validates through this class (the two stores
 * delegate here) and the differential corpus test requires identical
 * accept/reject outcomes from both halves.
 *
 * Schema v2 (every current writer): exactly the eight members
 * `v`, `response_hash`, `remoteip_fingerprint`, `binding`, `state`,
 * `owner`, `lease_expires_at`, `result`. The response hash is exactly
 * 64 lowercase hex. The remoteip fingerprint is the `no-ip` sentinel or
 * a 64-lowercase-hex keyed digest. The binding is the empty string
 * (unbound) or a 64-lowercase-hex keyed digest. The owner is exactly
 * 32 lowercase hex. The lease is a positive integer, and a completed
 * result passes the canonical {@see SiteVerifyResult} validator.
 *
 * The legacy shape (no `v` member) is recognized with one narrowly
 * constrained transition.
 *
 *   - An identity-complete pending legacy record may be taken over
 *     once its owner lease expired. Identity-complete means
 *     response_hash, remoteip_fingerprint and binding are all present
 *     and equal to the caller's operation. The takeover atomically
 *     rewrites the record as the canonical v2 schema with a fresh
 *     owner, a new lease and the identity fields preserved.
 *   - Every other legacy record is read-only. A completed record may
 *     replay through the operation-bound read. An underspecified
 *     record, with any identity component missing or differing, is
 *     never mutated and never taken over.
 *
 * No claim or renewal ever touches a legacy record, and none is ever
 * finalized in place.
 */
final class SiteVerifyIdempotencyRecordSchema
{
    public const VERSION_V2 = 2;

    public const SCHEMA_LEGACY = 1;

    private const RESPONSE_HASH_PATTERN = '/^[0-9a-f]{64}$/D';

    private const OWNER_PATTERN = '/^[0-9a-f]{32}$/D';

    private const V2_KEYS = ['v', 'state', 'response_hash', 'remoteip_fingerprint', 'binding', 'owner', 'lease_expires_at', 'result'];

    private const LEGACY_KEYS = ['state', 'response_hash', 'remoteip_fingerprint', 'binding', 'owner', 'lease_expires_at', 'result'];

    /**
     * The canonical writer-input shapes: the store validates the claim
     * identity before it writes, so a non-canonical input can never mint
     * a record every later boundary must treat as corrupt.
     *
     * @throws \InvalidArgumentException on a non-canonical input
     */
    public static function assertCanonicalClaimIdentity(string $responseHash, string $remoteipFingerprint, ?string $binding): void
    {
        if (preg_match(self::RESPONSE_HASH_PATTERN, $responseHash) !== 1) {
            throw new \InvalidArgumentException('the siteverify idempotency response hash must be 64 lowercase hex characters');
        }
        if (!self::isFingerprint($remoteipFingerprint)) {
            throw new \InvalidArgumentException('the siteverify remoteip fingerprint must be the no-ip sentinel or 64 lowercase hex characters');
        }
        if ($binding !== null && $binding !== '' && preg_match(self::RESPONSE_HASH_PATTERN, $binding) !== 1) {
            throw new \InvalidArgumentException('the siteverify idempotency binding must be empty or 64 lowercase hex characters');
        }
    }

    /**
     * The classification: the schema version, or null when the record is
     * corrupt under both shapes. Never throws.
     *
     * @param array<string, mixed> $rec
     *
     * @return self::VERSION_V2|self::SCHEMA_LEGACY|null
     */
    public static function tryClassify(array $rec): ?int
    {
        if (self::v2Ok($rec)) {
            return self::VERSION_V2;
        }
        if (self::legacyOk($rec)) {
            return self::SCHEMA_LEGACY;
        }

        return null;
    }

    /**
     * The strict validation used by every read and transition: a record
     * that satisfies neither the v2 nor the legacy shape is corrupt.
     *
     * @param array<string, mixed> $rec
     *
     * @return self::VERSION_V2|self::SCHEMA_LEGACY the recognized schema version
     *
     * @throws SiteVerifyIdempotencyCorruptException
     */
    public static function validate(array $rec): int
    {
        $version = self::tryClassify($rec);
        if ($version === null) {
            throw new SiteVerifyIdempotencyCorruptException('the idempotency record violates the v2 schema and the legacy shape');
        }

        return $version;
    }

    /**
     * @param array<string, mixed> $rec
     */
    private static function v2Ok(array $rec): bool
    {
        if (\count($rec) !== 8 || array_diff(array_keys($rec), self::V2_KEYS) !== []) {
            return false;
        }
        if (($rec['v'] ?? null) !== self::VERSION_V2) {
            return false;
        }
        if (!\is_string($rec['response_hash'] ?? null) || preg_match(self::RESPONSE_HASH_PATTERN, $rec['response_hash']) !== 1) {
            return false;
        }
        if (!\is_string($rec['remoteip_fingerprint'] ?? null) || !self::isFingerprint($rec['remoteip_fingerprint'])) {
            return false;
        }
        $binding = $rec['binding'] ?? null;
        if (!\is_string($binding) || ($binding !== '' && preg_match(self::RESPONSE_HASH_PATTERN, $binding) !== 1)) {
            return false;
        }
        $state = $rec['state'] ?? null;
        if ($state === 'pending') {
            $owner = $rec['owner'] ?? null;
            if (!\is_string($owner) || preg_match(self::OWNER_PATTERN, $owner) !== 1) {
                return false;
            }
            $lease = $rec['lease_expires_at'] ?? null;
            if (!\is_int($lease) || $lease <= 0) {
                return false;
            }
            if (($rec['result'] ?? null) !== null) {
                return false;
            }

            return true;
        }
        if ($state === 'complete') {
            if (($rec['owner'] ?? null) !== null || ($rec['lease_expires_at'] ?? null) !== null) {
                return false;
            }

            return self::resultOk($rec['result'] ?? null);
        }

        return false;
    }

    /**
     * @param array<string, mixed> $rec
     */
    private static function legacyOk(array $rec): bool
    {
        if (\array_key_exists('v', $rec)) {
            return false;
        }
        if (array_diff(array_keys($rec), self::LEGACY_KEYS) !== []) {
            return false;
        }
        if (!\is_string($rec['response_hash'] ?? null)) {
            return false;
        }
        $state = $rec['state'] ?? null;
        if ($state === 'pending') {
            $owner = $rec['owner'] ?? null;
            if (!\is_string($owner) || $owner === '') {
                return false;
            }
            if (!\is_int($rec['lease_expires_at'] ?? null)) {
                return false;
            }
            if (($rec['result'] ?? null) !== null) {
                return false;
            }

            return true;
        }
        if ($state === 'complete') {
            if (($rec['owner'] ?? null) !== null || ($rec['lease_expires_at'] ?? null) !== null) {
                return false;
            }

            return self::resultOk($rec['result'] ?? null);
        }

        return false;
    }

    private static function resultOk(mixed $result): bool
    {
        if (!\is_array($result)) {
            return false;
        }
        try {
            SiteVerifyResult::validate($result);
        } catch (SiteVerifyIdempotencyCorruptException) {
            return false;
        }

        return true;
    }

    private static function isFingerprint(string $value): bool
    {
        return $value === 'no-ip' || preg_match(self::RESPONSE_HASH_PATTERN, $value) === 1;
    }
}
