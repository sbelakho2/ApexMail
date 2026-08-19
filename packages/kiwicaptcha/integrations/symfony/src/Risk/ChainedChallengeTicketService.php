<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * Signs and verifies one-shot CHAIN TICKETS for selective chained
 * challenges.
 *
 * A chain ticket is the client-carrying half of a chain: the server-held
 * half is the {@see ChainedChallengeStateStore} record, created in the
 * SAME {@see issue()} call. The ticket is MINIMAL by design — it proves
 * only the chain's identity and validity:
 *
 *   base64url([1, chainId, expiresAt]) "." base64url(hmac_sha256(body,
 *   secret, true))
 *
 * (version 1, the random chain id, the signed expiry, the raw 32-byte
 * MAC). EVERYTHING else — stage1Nonce, scope, requestBinding,
 * requiredAction, chainDepth, policyVersion, state — is SERVER-HELD in
 * the state record, written by the validator at issue() time, so a client
 * can never alter it and the ticket stays ~60 bytes no matter how long
 * the legitimate request_binding is (a 128-char binding fits easily
 * inside the accepted 256-byte wire bound). A client can never skip a
 * stage (the server-held state records the verified stage-1 nonce, which
 * must differ from any new challenge nonce), never extend its own
 * validity (expiry is signed), never downgrade the promised stage (the
 * required action is server-held and enforced at stage-2 issuance), and
 * never detach the chain from its transaction (the stage-1 request
 * binding is server-held and must match at stage-2).
 *
 * The chain is a SELECTIVE EXTENSION of depth 2 (chainDepth is always 2 —
 * one selective extension): the state machine (reserve/release/complete)
 * lets a FAILED stage-2 issuance release the reservation so the SAME
 * ticket retries, while a COMPLETED issuance is a terminal state that
 * recovers the already-issued challenge on retry — a chain id can never
 * gate a second mint.
 *
 * TICKET FORMAT (stable, documented — the server's accepted pattern
 * [A-Za-z0-9._:-]{1,256}):
 *
 *   base64url([version, chainId, expiresAt])
 *   "." base64url(hmac_sha256(body, secret, raw))
 *
 * chainId is base64url(16 random bytes); the raw 32-byte HMAC-SHA256
 * digest is base64url-encoded (43 chars); expiresAt is the signed
 * absolute expiry (issuedAt + risk.chaining.ttl_secs).
 */
final class ChainedChallengeTicketService
{
    /** The ONLY ticket format version this service issues/accepts. */
    private const TICKET_VERSION = 1;

    /** The chain id alphabet (base64url of 16 random bytes). */
    private const CHAIN_ID_PATTERN = '/^[A-Za-z0-9_-]{1,64}$/D';

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
     * Issue a chain ticket for a successfully verified stage-1 proof whose
     * reassessment demanded a stronger action: build the minimal signed
     * ticket and persist the FULL server-held chain state (atomic with the
     * ticket — no ticket exists without its state) and return the signed
     * ticket.
     *
     * Returns null when the signed ticket would exceed the accepted
     * 256-byte shape bound or when the chain state could not be persisted
     * (backend failure — the caller fails closed: a stronger stage was
     * demanded but cannot be chained).
     *
     * @param string      $requiredAction the reassessed RiskAction's value
     *                                    (never StepUp/Deny — those are
     *                                    terminal application-level actions
     *                                    and never chainable)
     * @param string|null $requestBinding the stage-1 challenge's signed
     *                                    request binding (null when the
     *                                    challenge had none)
     */
    public function issue(string $stage1Nonce, string $scope, int $policyVersion, string $requiredAction, ?string $requestBinding = null): ?string
    {
        $now = $this->now();
        $chainId = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
        $body = self::encode([self::TICKET_VERSION, $chainId, $now + $this->ttlSecs]);
        $ticket = $body.'.'.self::sign($body);
        if (\strlen($ticket) > self::MAX_TICKET_BYTES) {
            return null;
        }
        try {
            $this->store->create($chainId, $stage1Nonce, $scope, $this->ttlSecs, $requestBinding, $requiredAction, $policyVersion);
        } catch (\Throwable $e) {
            error_log(sprintf('kiwicaptcha: chained-challenge state creation failed: %s', $e->getMessage()));

            return null;
        }

        return $ticket;
    }

    /**
     * Verify a ticket's signature + expiry and return its signed payload,
     * or null when the ticket is malformed, forged, expired or carries a
     * structurally invalid payload. The signature comparison is
     * constant-time (hash_equals over the raw-digest base64url encoding).
     *
     * @return array{version: int, chainId: string, expiresAt: int}|null
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
        $version = $payload[0] ?? null;
        $chainId = $payload[1] ?? null;
        $expiresAt = $payload[2] ?? null;
        if (!\is_int($version) || $version !== self::TICKET_VERSION) {
            return null;
        }
        if (!\is_string($chainId) || preg_match(self::CHAIN_ID_PATTERN, $chainId) !== 1) {
            return null;
        }
        if (!\is_int($expiresAt)) {
            return null;
        }
        // A ticket expiring exactly now is already expired (<= now).
        if ($expiresAt <= $this->now()) {
            return null;
        }

        return ['version' => $version, 'chainId' => $chainId, 'expiresAt' => $expiresAt];
    }

    /**
     * PLAIN read of the server-held chain state behind a verified ticket:
     * verifies the ticket (signature, expiry, structural shape) and reads
     * the state record without any transition. Returns the full record, or
     * null when the ticket is invalid/expired OR the chain state is
     * absent/expired. The controller uses this for the policy checks
     * (scope, policy epoch, chain depth, request binding) BEFORE the
     * reservation claim.
     *
     * @throws \Throwable on backend failure — the caller fails closed
     */
    public function read(string $ticket): ?array
    {
        $payload = $this->verify($ticket);
        if ($payload === null) {
            return null;
        }

        return $this->store->read((string) $payload['chainId']);
    }

    /**
     * RESERVE the chain behind a verified ticket for ONE owner: validates
     * the ticket (signature, expiry, structural shape) and atomically
     * transitions the server-held chain state via the owner-scoped lease
     * machine (available -> reserved(me); 'retry' when already reserved
     * by ME; 'busy' when reserved by another owner with a live lease;
     * expired-lease takeover; 'completed' when the chain already
     * completed; 'missing' when the state is absent/expired). The caller
     * proceeds ONLY on 'available'/'retry'.
     *
     * @throws \Throwable on backend failure — the caller fails closed (the
     *                    one-shot state cannot be confirmed)
     */
    public function reserve(string $ticket, string $ownerToken): string
    {
        $payload = $this->verify($ticket);
        if ($payload === null) {
            return 'missing';
        }

        return $this->store->reserve((string) $payload['chainId'], $ownerToken, $this->ttlSecs);
    }

    /**
     * Release a reservation (the reservation owner's retry path): the
     * chain returns to the available state so a refused or failed issuance
     * never burns the ticket. A release by a NON-owner is an atomic no-op
     * — a failing request can never free another owner's live
     * reservation. Best-effort — the reservation also expires with the
     * chain TTL.
     */
    public function release(string $chainId, string $ownerToken): void
    {
        $this->store->release($chainId, $ownerToken);
    }

    /**
     * TERMINAL COMPLETION of a durably issued stage-2 challenge: the
     * owner-scoped transition reserved(me) -> completed(stage2Nonce) — a
     * state TRANSITION, never a delete (the completed record keeps its TTL
     * so a retry recovers the issued challenge). Returns the completed
     * state, or null when the transition was refused (absent, not
     * reserved, not the owner — atomic no-op — or already completed). A
     * completed chain NEVER allows a second mint.
     *
     * @return array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, policyVersion: int, chainDepth: int, state: 'completed', owner: ?string, leaseUntil: ?int, stage2Nonce: ?string}|null
     */
    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array
    {
        return $this->store->complete($chainId, $ownerToken, $stage2Nonce);
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }

    /**
     * The RAW 32-byte HMAC-SHA256 digest, base64url-encoded (43 chars —
     * vs 64 for the hex digest): the compact signature keeps the signed
     * ticket inside the accepted 256-byte wire bound. The verify side
     * compares the same encoding constant-time (hash_equals).
     */
    private function sign(string $body): string
    {
        return rtrim(strtr(base64_encode(hash_hmac('sha256', $body, $this->hmacSecret, true)), '+/', '-_'), '=');
    }

    private static function encode(array $payload): string
    {
        // The compact JSON-array body keeps the signed ticket at ~60
        // bytes: the three signed fields in order [version, chainId,
        // expiresAt]. No scope/binding/action in the ticket payload — the
        // server-held state owns them.
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
