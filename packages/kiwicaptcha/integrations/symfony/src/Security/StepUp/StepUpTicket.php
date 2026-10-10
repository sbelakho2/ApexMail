<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * Signs and verifies the client-carrying half of a step-up challenge:
 * the base64url of [1, challengeId, expiresAt], a dot, and the
 * base64url of the raw hmac_sha256(body, key, true) digest. The same
 * signed-record shape the chain tickets use. Everything the ticket
 * names is server-held in the challenge record, so a client can never
 * alter its principal, extend its validity, or skip the single-use
 * consumption by presenting a forged id.
 *
 * The signing key is purpose-separated from the deployment master
 * through the bundle's shared HKDF derivation (hash_hkdf over the
 * master with this service's own info string), so the step-up ticket
 * HMAC never shares key material with any other purpose.
 */
final class StepUpTicket
{
    private const TICKET_VERSION = 1;

    private const HKDF_INFO = 'kiwi/v1/stepup-ticket';

    private const HKDF_SALT = 'kiwicaptcha/deploy-salt/v1';

    private readonly string $key;

    public function __construct(string $master)
    {
        if (\strlen($master) < 32) {
            throw new \InvalidArgumentException('The step-up ticket secret must be at least 32 bytes (the same floor as secret_key)');
        }
        $this->key = hash_hkdf('sha256', $master, 32, self::HKDF_INFO, self::HKDF_SALT);
    }

    /**
     * The deterministic signed ticket of one challenge: byte-identical
     * for the same (challengeId, expiresAt).
     */
    public function issue(string $challengeId, int $expiresAt): string
    {
        $body = self::encode([self::TICKET_VERSION, $challengeId, $expiresAt]);

        return $body.'.'.$this->sign($body);
    }

    /**
     * Verify a ticket's signature and expiry and answer its signed
     * payload, or null when the ticket is malformed, forged, expired
     * or structurally invalid. The signature comparison is
     * constant-time.
     *
     * @return array{challengeId: string, expiresAt: int}|null
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
     * @return array{challengeId: string, expiresAt: int}|null
     */
    public function look(string $ticket): ?array
    {
        $parts = explode('.', $ticket, 2);
        if (\count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            return null;
        }
        if (!hash_equals($this->sign($parts[0]), $parts[1])) {
            return null;
        }
        $payload = self::decode($parts[0]);
        if ($payload === null) {
            return null;
        }
        [$version, $challengeId, $expiresAt] = $payload;
        if ($version !== self::TICKET_VERSION || !\is_string($challengeId) || !\is_int($expiresAt)) {
            return null;
        }
        if (preg_match('/^[A-Za-z0-9_-]{16,43}$/D', $challengeId) !== 1) {
            return null;
        }

        return ['challengeId' => $challengeId, 'expiresAt' => $expiresAt];
    }

    /**
     * The raw 32-byte digest, base64url (43 chars), compared
     * constant-time on the verify side (hash_equals).
     */
    private function sign(string $body): string
    {
        return rtrim(strtr(base64_encode(hash_hmac('sha256', $body, $this->key, true)), '+/', '-_'), '=');
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
        if (!\is_array($decoded) || \count($decoded) !== 3) {
            return null;
        }

        return array_values($decoded);
    }
}
