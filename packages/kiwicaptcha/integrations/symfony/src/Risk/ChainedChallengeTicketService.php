<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * Signs and verifies one-shot CHAIN TICKETS for selective chained
 * challenges.
 *
 * A chain ticket is the client-carrying half of a chain: the server-held
 * half is the {@see ChainedChallengeStateStore} record, created in the
 * SAME {@see issue()} call. The ticket signs the full chain identity —
 *
 *   {chainId, stage1Nonce, scope, policyVersion, issuedAt, expiresAt}
 *
 * — with HMAC-SHA256 over a base64url JSON-array body, so a client can
 * never skip a stage (the ticket proves the stage-1 nonce was verified and
 * the reassessment demanded more), never re-run the same stage (the
 * stage-1 nonce must differ from any new challenge nonce), and never
 * extend its own validity (expiry is signed). The state consume is ATOMIC
 * one-shot: a consumed chain id can never gate a second issuance.
 *
 * TICKET FORMAT (stable, documented — the server's accepted pattern
 * [A-Za-z0-9._:-]{1,256}):
 *
 *   base64url([chainId, stage1Nonce, scope, policyVersion, issuedAt,
 *              expiresAt]) "." base64url(hmac_sha256(body))
 *
 * chainId is base64url(16 random bytes); stage1Nonce is the verified
 * stage-1 challenge nonce (the core's base64 nonce string, carried
 * verbatim inside the JSON body).
 */
final class ChainedChallengeTicketService
{
    /** The chain id alphabet (base64url of 16 random bytes). */
    private const CHAIN_ID_PATTERN = '/^[A-Za-z0-9_-]{1,64}$/D';

    /** Scope names satisfy the bundle identifier charset. */
    private const SCOPE_PATTERN = '/^[A-Za-z0-9._:-]{1,128}$/D';

    /** The wire bound shared with the controller's accepted pattern. */
    private const MAX_TICKET_BYTES = 256;

    /**
     * @param int            $ttlSecs  the chain lifetime (risk.chaining.ttl_secs,
     *                                 bounded 30..3600 by the config tree)
     * @param \Closure|null  $now      test seam: returns the current Unix
     *                                 seconds (defaults to time())
     */
    public function __construct(
        private readonly ChainedChallengeStateStore $store,
        private readonly string $hmacSecret,
        private readonly int $ttlSecs = 300,
        private readonly ?\Closure $now = null,
    ) {
    }

    /**
     * Issue a chain ticket for a successfully verified stage-1 proof:
     * persist the server-held chain state (atomic with the ticket — no
     * ticket exists without its state) and return the signed ticket.
     *
     * Returns null when the chain state could not be persisted (backend
     * failure — the caller fails closed: a stronger stage was demanded
     * but cannot be chained) or when the signed ticket would exceed the
     * accepted 256-byte shape bound (an over-long scope — the chain is
     * then not offered for that scope).
     */
    public function issue(string $stage1Nonce, string $scope, int $policyVersion): ?string
    {
        $now = $this->now();
        $chainId = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
        $payload = [
            'chainId' => $chainId,
            'stage1Nonce' => $stage1Nonce,
            'scope' => $scope,
            'policyVersion' => $policyVersion,
            'issuedAt' => $now,
            'expiresAt' => $now + $this->ttlSecs,
        ];
        try {
            $this->store->create($chainId, $stage1Nonce, $scope, $this->ttlSecs);
        } catch (\Throwable $e) {
            error_log(sprintf('kiwicaptcha: chained-challenge state creation failed: %s', $e->getMessage()));

            return null;
        }
        $body = self::encode($payload);
        $ticket = $body.'.'.self::sign($body);
        if (\strlen($ticket) > self::MAX_TICKET_BYTES) {
            return null;
        }

        return $ticket;
    }

    /**
     * Verify a ticket's signature + expiry and return its signed payload,
     * or null when the ticket is malformed, forged, expired or carries a
     * structurally invalid payload. The signature comparison is
     * constant-time (hash_equals).
     *
     * @return array{chainId: string, stage1Nonce: string, scope: string,
     *               policyVersion: int, issuedAt: int, expiresAt: int}|null
     */
    public function verify(string $ticket): ?array
    {
        $parts = explode('.', $ticket, 2);
        if (\count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            return null;
        }
        if (!hash_equals(self::sign($parts[0]), $parts[1])) {
            return null;
        }
        $payload = self::decode($parts[0]);
        if ($payload === null) {
            return null;
        }
        foreach (['chainId', 'stage1Nonce', 'scope', 'policyVersion', 'issuedAt', 'expiresAt'] as $key) {
            if (!\array_key_exists($key, $payload)) {
                return null;
            }
        }
        if (!\is_string($payload['chainId']) || preg_match(self::CHAIN_ID_PATTERN, $payload['chainId']) !== 1) {
            return null;
        }
        if (!\is_string($payload['stage1Nonce']) || $payload['stage1Nonce'] === '') {
            return null;
        }
        if (!\is_string($payload['scope']) || preg_match(self::SCOPE_PATTERN, $payload['scope']) !== 1) {
            return null;
        }
        if (!\is_int($payload['policyVersion']) || $payload['policyVersion'] < 1) {
            return null;
        }
        if (!\is_int($payload['issuedAt']) || !\is_int($payload['expiresAt'])) {
            return null;
        }
        if ($payload['expiresAt'] < $this->now() || $payload['issuedAt'] > $this->now()) {
            return null;
        }

        return $payload;
    }

    /**
     * VERIFY + ATOMIC CONSUME: validates the ticket (signature, expiry,
     * structural shape) and then consumes the server-held chain state
     * one-shot. Returns the verified payload, or null when the ticket is
     * invalid/expired OR the chain state is absent/expired/already
     * consumed (a replayed ticket lands here).
     *
     * @return array{chainId: string, stage1Nonce: string, scope: string,
     *               policyVersion: int, issuedAt: int, expiresAt: int}|null
     */
    public function consume(string $ticket): ?array
    {
        $payload = $this->verify($ticket);
        if ($payload === null) {
            return null;
        }
        $state = $this->store->consume((string) $payload['chainId']);
        if ($state === null) {
            return null;
        }
        // The server-held state must match the signed ticket (both were
        // created together in issue(); this is defense-in-depth).
        if (!hash_equals((string) $state['stage1Nonce'], (string) $payload['stage1Nonce'])) {
            return null;
        }

        return $payload;
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }

    private function sign(string $body): string
    {
        return rtrim(strtr(base64_encode(hash_hmac('sha256', $body, $this->hmacSecret)), '+/', '-_'), '=');
    }

    private static function encode(array $payload): string
    {
        // The compact JSON-array body keeps the signed ticket inside the
        // accepted 256-byte wire bound for every realistic scope length
        // (up to ~59 chars of scope): the six signed fields in order
        // [chainId, stage1Nonce, scope, policyVersion, issuedAt, expiresAt].
        $body = (string) json_encode([
            $payload['chainId'],
            $payload['stage1Nonce'],
            $payload['scope'],
            $payload['policyVersion'],
            $payload['issuedAt'],
            $payload['expiresAt'],
        ], JSON_THROW_ON_ERROR);

        return rtrim(strtr(base64_encode($body), '+/', '-_'), '=');
    }

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
        if (!\is_array($decoded) || \count($decoded) !== 6) {
            return null;
        }

        return [
            'chainId' => $decoded[0],
            'stage1Nonce' => $decoded[1],
            'scope' => $decoded[2],
            'policyVersion' => $decoded[3],
            'issuedAt' => $decoded[4],
            'expiresAt' => $decoded[5],
        ];
    }
}
