<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * Signs and verifies the client-carrying half of a step-up challenge:
 * the base64url of [version, challengeId, expiresAt, kid], a dot, and
 * the base64url of the raw hmac_sha256(body, key, true) digest. The
 * same signed-record shape the chain tickets use. Everything the
 * ticket names is server-held in the challenge record, so a client can
 * never alter its principal, extend its validity, or skip the
 * single-use consumption by presenting a forged id.
 *
 * The signing key is purpose-separated from the deployment master
 * through the bundle's shared HKDF derivation (hash_hkdf over the
 * master with this service's own info string), so the step-up ticket
 * HMAC never shares key material with any other purpose.
 *
 * Key rotation ({@see StepUpKeyRing}): the signed payload carries the
 * `stepUpKid` that minted it, so a verifier selects the matching
 * historical or current master. A kid that is revoked, unknown or
 * ahead of the newest configured kid fails fail-closed. Version-1
 * payloads (no kid segment) verify as kid 1 — the legacy single-master
 * shape — so already-issued tickets survive the introduction of the
 * ring. Node A mints under the old kid; node B, already rotated,
 * finalizes under that historical key as long as the ring still
 * carries it unrevoked for the maximum demand lifetime.
 */
final class StepUpTicket
{
    private const TICKET_VERSION = 2;

    /** The legacy wire version whose payload has no kid segment (kid 1). */
    private const LEGACY_TICKET_VERSION = 1;

    private const HKDF_INFO = 'kiwi/v1/stepup-ticket';

    private const HKDF_SALT = 'kiwicaptcha/deploy-salt/v1';

    private readonly StepUpKeyRing $ring;

    /** kid => derived HMAC key, resolved once per process. */
    private readonly array $keys;

    public function __construct(string|StepUpKeyRing $masterOrRing)
    {
        $ring = \is_string($masterOrRing) ? StepUpKeyRing::single($masterOrRing) : $masterOrRing;
        if (\strlen($ring->resolve($ring->currentKid()) ?? '') < 32) {
            throw new \InvalidArgumentException('The step-up ticket secret must be at least 32 bytes (the same floor as secret_key)');
        }
        $this->ring = $ring;
        $keys = [];
        foreach ($ring->historicalKids() as $kid) {
            $secret = $ring->resolve($kid);
            if ($secret !== null) {
                $keys[$kid] = hash_hkdf('sha256', $secret, 32, self::HKDF_INFO, self::HKDF_SALT);
            }
        }
        $currentSecret = $ring->resolve($ring->currentKid());
        if ($currentSecret === null) {
            throw new \InvalidArgumentException('The step-up key ring must resolve its current kid');
        }
        $keys[$ring->currentKid()] = hash_hkdf('sha256', $currentSecret, 32, self::HKDF_INFO, self::HKDF_SALT);
        $this->keys = $keys;
    }

    /**
     * The deterministic signed ticket of one challenge: byte-identical
     * for the same (challengeId, expiresAt). Stamps the ring's current
     * `stepUpKid` into the signed payload so a later verifier picks the
     * right master after a rotation.
     */
    public function issue(string $challengeId, int $expiresAt): string
    {
        $kid = $this->ring->currentKid();
        $body = self::encode([self::TICKET_VERSION, $challengeId, $expiresAt, $kid]);

        return $body.'.'.$this->sign($body, $kid);
    }

    /** The kid the next {@see issue()} will stamp (the ring's current kid). */
    public function currentKid(): int
    {
        return $this->ring->currentKid();
    }

    /**
     * Verify a ticket's signature and expiry and answer its signed
     * payload, or null when the ticket is malformed, forged, expired
     * or structurally invalid. The signature comparison is
     * constant-time.
     *
     * @return array{challengeId: string, expiresAt: int, stepUpKid: int}|null
     */
    public function verify(string $ticket, int $now): ?array
    {
        $payload = $this->look($ticket);
        if ($payload === null) {
            return null;
        }
        // A ticket expiring exactly now is already expired (<= now).
        if ($payload['expiresAt'] <= $now) {
            return null;
        }

        return $payload;
    }

    /**
     * The signature-only inspection: the signed payload of a
     * well-signed, structurally valid ticket, whatever its expiry. The
     * expired-vs-unknown discrimination of a completion uses this after
     * verify() refused the ticket, so an honestly expired challenge
     * answers the expired failure code, never a bare unknown.
     *
     * @return array{challengeId: string, expiresAt: int, stepUpKid: int}|null
     */
    public function look(string $ticket): ?array
    {
        $parts = explode('.', $ticket, 2);
        if (\count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            return null;
        }
        $payload = self::decode($parts[0]);
        if ($payload === null) {
            return null;
        }
        if (\count($payload) === 4) {
            [$version, $challengeId, $expiresAt, $kid] = $payload;
            if ($version !== self::TICKET_VERSION || !\is_int($kid)) {
                return null;
            }
        } else {
            // Legacy version-1 payload: no kid segment, kid 1 implicit.
            [$version, $challengeId, $expiresAt] = $payload;
            if ($version !== self::LEGACY_TICKET_VERSION) {
                return null;
            }
            $kid = 1;
        }
        if (!\is_string($challengeId) || !\is_int($expiresAt)) {
            return null;
        }
        if (preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $challengeId) !== 1) {
            return null;
        }
        // The kid gate, then the signature under that kid's master. A
        // revoked / unknown / future kid fails here — never a silent
        // fallback to the current key.
        $key = $this->keys[$kid] ?? null;
        if ($key === null) {
            return null;
        }
        if (!hash_equals($this->sign($parts[0], $kid), $parts[1])) {
            return null;
        }

        return ['challengeId' => $challengeId, 'expiresAt' => $expiresAt, 'stepUpKid' => $kid];
    }

    /**
     * The raw 32-byte digest, base64url (43 chars), compared
     * constant-time on the verify side (hash_equals). Derived under the
     * kid-selected master so one kid's compromise never forges another.
     */
    private function sign(string $body, int $kid): string
    {
        $key = $this->keys[$kid] ?? null;
        if ($key === null) {
            throw new \InvalidArgumentException('The step-up ticket kid is not resolvable');
        }

        return rtrim(strtr(base64_encode(hash_hmac('sha256', $body, $key, true)), '+/', '-_'), '=');
    }

    /** @param list<mixed> $payload */
    private static function encode(array $payload): string
    {
        $body = (string) json_encode($payload, JSON_THROW_ON_ERROR);

        return rtrim(strtr(base64_encode($body), '+/', '-_'), '=');
    }

    /** @return list<mixed>|null */
    private static function decode(string $body): ?array
    {
        $raw = base64_decode(strtr($body, '-_', '+/'), true);
        if ($raw === false || $raw === '') {
            return null;
        }
        try {
            $decoded = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!\is_array($decoded) || (\count($decoded) !== 3 && \count($decoded) !== 4)) {
            return null;
        }

        return array_values($decoded);
    }
}
