<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The one canonical rsw modulus identity used across the whole
 * repository: the lowercase-hex SHA-256 of the decoded 256-byte
 * modulus.
 *
 * The shipped generator (tools/rsw-keygen) prints `rsw_modulus_n_sha256`
 * as exactly this value: SHA-256 over the canonical 256-byte big-endian
 * modulus. The keygen fingerprint, the identity riding an issued record,
 * and the verifier's resolution therefore all agree on one semantic
 * rule. The decoded value must be exactly {@see Rsw::MODULUS_BYTES}
 * bytes, and the base64 must be the canonical padded round-trip before
 * it is hashed. A non-canonical spelling of the same bytes must never
 * mint a second identity for one modulus.
 *
 * The pre-definition PHP releases hashed the base64 text instead:
 * `hash('sha256', $modulusB64)`, which disagrees with the generator.
 * That historical value stays supported as a clearly named legacy
 * alias for one bounded migration window. Identity-bearing records
 * issued before the protocol v5 grammar carry it, so their outstanding
 * challenges keep resolving. `legacyBase64TextFingerprint()` is never
 * used for new issuance.
 */
final class RswModulusIdentity
{
    /** The fingerprint is 64 lowercase hex characters. */
    public const FINGERPRINT_PATTERN = '/^[0-9a-f]{64}$/D';

    /**
     * The canonical fingerprint: lowercase-hex SHA-256 of the decoded
     * canonical 256-byte modulus.
     *
     * @throws \InvalidArgumentException when the modulus is not canonical
     *                                   standard base64 of exactly 256 bytes
     */
    public static function fingerprint(string $modulusNBase64): string
    {
        return hash('sha256', self::decodeCanonicalModulus($modulusNBase64));
    }

    /**
     * The legacy (pre-migration) identity: SHA-256 of the base64 string
     * itself. It disagrees with the keygen's `rsw_modulus_n_sha256` and
     * exists only to keep identity-bearing records issued before the
     * canonical-byte rule resolvable during their bounded lifetime. Never
     * mint new identities with this value.
     */
    public static function legacyBase64TextFingerprint(string $modulusNBase64): string
    {
        return hash('sha256', $modulusNBase64);
    }

    /**
     * Every identity form a modulus may be addressed by: the canonical
     * fingerprint and the legacy alias (when it differs). The keyring
     * registers all of them, so a rotated/mixed-node record resolves
     * under the form it was issued with.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException when the modulus is not canonical
     *                                   standard base64 of exactly 256 bytes
     */
    public static function allFingerprints(string $modulusNBase64): array
    {
        $canonical = self::fingerprint($modulusNBase64);
        $legacy = self::legacyBase64TextFingerprint($modulusNBase64);

        return $legacy === $canonical ? [$canonical] : [$canonical, $legacy];
    }

    /**
     * Whether `$identity` is an accepted identity form of `$modulusNBase64`.
     * The canonical fingerprint always matches; the legacy base64-text
     * alias matches only when `$allowLegacyAlias` is set — true for
     * identity-bearing records issued before the v5 grammar (protocol
     * <= 4), false for v5 records and new issuance.
     *
     * @throws \InvalidArgumentException when the modulus is not canonical
     *                                   standard base64 of exactly 256 bytes
     */
    public static function matches(string $identity, string $modulusNBase64, bool $allowLegacyAlias): bool
    {
        if (hash_equals(self::fingerprint($modulusNBase64), $identity)) {
            return true;
        }

        return $allowLegacyAlias
            && hash_equals(self::legacyBase64TextFingerprint($modulusNBase64), $identity);
    }

    /**
     * The decoded canonical 256-byte modulus: standard base64 that
     * decodes to exactly 256 bytes and re-encodes byte-identically (a
     * non-canonical spelling is refused, so one modulus has exactly one
     * canonical identity).
     *
     * @throws \InvalidArgumentException on a malformed modulus
     */
    public static function decodeCanonicalModulus(string $modulusNBase64): string
    {
        $decoded = base64_decode($modulusNBase64, true);
        if ($decoded === false
            || \strlen($decoded) !== Rsw::MODULUS_BYTES
            || !hash_equals($modulusNBase64, base64_encode($decoded))
        ) {
            throw new \InvalidArgumentException(sprintf(
                'rsw_modulus_n must be canonical standard base64 of exactly %d bytes',
                Rsw::MODULUS_BYTES,
            ));
        }

        return $decoded;
    }
}
