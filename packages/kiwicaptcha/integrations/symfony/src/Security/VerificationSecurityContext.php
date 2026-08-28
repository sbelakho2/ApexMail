<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

/**
 * Single source of truth for the deployment's verification security
 * context: the current signing key (kid + secret), the historical
 * secrets_by_kid map, the revoked_kids set, and the optional issuer and
 * region. The extension wires the core verifier and the Siteverify
 * idempotency identity from this one object, so the keyring the verifier
 * resolves and the keyring the digest covers can never diverge.
 *
 * acceptedKeys() builds the effective verification keyring: the
 * historical secrets_by_kid map merged with the current signing key
 * (kid => secret_key), numerically sorted. The core verifier resolves
 * every record's kid against this ring. An outstanding challenge signed
 * under a superseded kid still verifies (rotation grace), a freshly
 * issued challenge resolves the current secret, and the core's
 * rollback/forward guard still rejects future keys, because a record
 * kid above the newest ring key is unknown. With an empty historical
 * map the ring stays empty: the core's legacy single-secret path stays,
 * verify() with the current secret keeps the pre-rotation behavior
 * byte-for-byte.
 *
 * contextDigest() hashes a versioned canonical serialization of the
 * whole signing context. It covers a version marker, the issuer and
 * region, the current kid, a sha256 of the current secret (never the
 * raw secret), and canonical json of the accepted keyring and the
 * revoked set. The digest changes when any of those changes, so a
 * cached Siteverify provider result can never outlive the signing
 * security context that produced it.
 */
final class VerificationSecurityContext
{
    /**
     * Version marker of the canonical serialization. Bump it when the
     * serialization shape changes so digests from before and after the
     * shape change can never collide by accident.
     */
    private const DIGEST_VERSION = 'kiwi-siteverify-security-context-v2';

    public function __construct(
        private readonly int $currentKid,
        private readonly string $currentSecret,
        /** @var array<int|string, string> historical kid => secret map */
        private readonly array $historicalSecrets,
        /** @var list<int> revoked kid ids */
        private readonly array $revokedKids,
        private readonly ?string $issuer = null,
        private readonly ?string $region = null,
    ) {
    }

    /**
     * The effective verification keyring: the historical secrets_by_kid
     * map merged with the current signing key, numerically sorted by
     * kid. Empty when there are no historical secrets, which keeps the
     * core's legacy single-secret verification path untouched.
     *
     * @return array<int, string>
     */
    public function acceptedKeys(): array
    {
        if ($this->historicalSecrets === []) {
            return [];
        }

        $keys = [];
        foreach ($this->historicalSecrets as $kid => $secret) {
            $keys[(int) $kid] = $secret;
        }
        $keys[$this->currentKid] = $this->currentSecret;
        ksort($keys, SORT_NUMERIC);

        return $keys;
    }

    /**
     * sha256 over the versioned canonical serialization of the whole
     * signing security context. The serialization includes the current
     * kid and a hash of the current secret, so a kid/secret rotation
     * invalidates the digest even when the accepted keyring is empty
     * (no historical secrets configured yet).
     */
    public function contextDigest(): string
    {
        return hash('sha256', implode("\0", [
            self::DIGEST_VERSION,
            $this->issuer ?? '',
            $this->region ?? '',
            (string) $this->currentKid,
            hash('sha256', $this->currentSecret),
            self::canonicalJson($this->acceptedKeys()),
            self::canonicalJson($this->revokedKids),
        ]));
    }

    /**
     * Deterministic json: a kid => secret map is sorted by numeric key
     * (the accepted keyring order), a plain list is sorted by value (the
     * revoked set), so equal inputs always serialize byte-identically.
     */
    private static function canonicalJson(array $values): string
    {
        ksort($values, SORT_NUMERIC);
        if (array_is_list($values)) {
            sort($values, SORT_NUMERIC);
        }

        return json_encode($values, JSON_THROW_ON_ERROR);
    }
}
