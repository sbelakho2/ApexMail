<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Risk\RiskAction;

/**
 * Signs and verifies one-shot CHAIN TICKETS for selective chained
 * challenges.
 *
 * A chain ticket is the client-carrying half of a chain: the server-held
 * half is the {@see ChainedChallengeStateStore} record, created in the
 * SAME {@see issue()} call. The ticket signs the full chain identity —
 *
 *   {chainId, stage1Nonce, scope, policyVersion, issuedAt, expiresAt,
 *    requestBinding, requiredAction, chainDepth}
 *
 * — with HMAC-SHA256 over a base64url JSON-array body, so a client can
 * never skip a stage (the ticket proves the stage-1 nonce was verified and
 * the reassessment demanded more), never re-run the same stage (the
 * stage-1 nonce must differ from any new challenge nonce), never extend
 * its own validity (expiry is signed), never downgrade the promised stage
 * (the required action is signed and enforced at stage-2 issuance), and
 * never detach the chain from its transaction (the stage-1 request
 * binding is signed and must match at stage-2). The state consume is
 * ATOMIC one-shot: a consumed chain id can never gate a second issuance.
 *
 * The chain is a SELECTIVE EXTENSION of depth 2 (chainDepth is always 2 —
 * one selective extension): the state machine (reserve/consume/release)
 * lets a FAILED stage-2 issuance release the reservation so the SAME
 * ticket retries, while a COMPLETED issuance consumes the chain exactly
 * once.
 *
 * TICKET FORMAT (stable, documented — the server's accepted pattern
 * [A-Za-z0-9._:-]{1,256}):
 *
 *   base64url([chainId, stage1Nonce, scope, policyVersion, issuedAt,
 *              expiresAt, requestBinding, requiredAction, chainDepth])
 *   "." base64url(hmac_sha256(body))
 *
 * chainId is base64url(16 random bytes); stage1Nonce is the verified
 * stage-1 challenge nonce (the core's base64 nonce string, carried
 * verbatim inside the JSON body); requestBinding is the stage-1
 * challenge's signed request binding (null when the challenge had none);
 * requiredAction is the reassessed RiskAction's string value (the chain
 * must issue at least that stage; StepUp/Deny are never chainable —
 * terminal application-level actions); chainDepth is 2.
 */
final class ChainedChallengeTicketService
{
    /** The chain id alphabet (base64url of 16 random bytes). */
    private const CHAIN_ID_PATTERN = '/^[A-Za-z0-9_-]{1,64}$/D';

    /** Scope names and request bindings satisfy the bundle identifier charset. */
    private const SCOPE_PATTERN = '/^[A-Za-z0-9._:-]{1,128}$/D';

    /** The wire bound shared with the controller's accepted pattern. */
    private const MAX_TICKET_BYTES = 256;

    /** The ONLY chain depth the format carries: one selective extension. */
    private const CHAIN_DEPTH = 2;

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
     * reassessment demanded a stronger action: build the signed ticket and
     * persist the server-held chain state (atomic with the ticket — no
     * ticket exists without its state) and return the signed ticket.
     *
     * The SIZE check runs BEFORE any state is created: an over-length
     * ticket (an over-long scope/binding combination beyond the accepted
     * 256-byte shape bound) leaves NO chain state behind — the chain is
     * simply not offered for that scope.
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
        $payload = [
            'chainId' => $chainId,
            'stage1Nonce' => $stage1Nonce,
            'scope' => $scope,
            'policyVersion' => $policyVersion,
            'issuedAt' => $now,
            'expiresAt' => $now + $this->ttlSecs,
            'requestBinding' => $requestBinding,
            'requiredAction' => $requiredAction,
            'chainDepth' => self::CHAIN_DEPTH,
        ];
        $body = self::encode($payload);
        $ticket = $body.'.'.self::sign($body);
        if (\strlen($ticket) > self::MAX_TICKET_BYTES) {
            // SIZE BEFORE STATE: an over-length ticket creates nothing —
            // no unreachable chain state until expiry.
            return null;
        }
        try {
            $this->store->create($chainId, $stage1Nonce, $scope, $this->ttlSecs, $requestBinding, $requiredAction);
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
     * @return array{chainId: string, stage1Nonce: string, scope: string,
     *               policyVersion: int, issuedAt: int, expiresAt: int,
     *               requestBinding: ?string, requiredAction: string,
     *               chainDepth: int}|null
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
        foreach (['chainId', 'stage1Nonce', 'scope', 'policyVersion', 'issuedAt', 'expiresAt', 'requestBinding', 'requiredAction', 'chainDepth'] as $key) {
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
        // A ticket expiring exactly now is already expired (<= now).
        if ($payload['expiresAt'] <= $this->now() || $payload['issuedAt'] > $this->now() || $payload['expiresAt'] < $payload['issuedAt']) {
            return null;
        }
        if ($payload['requestBinding'] !== null
            && (!\is_string($payload['requestBinding']) || preg_match(self::SCOPE_PATTERN, $payload['requestBinding']) !== 1)
        ) {
            return null;
        }
        if (!\is_string($payload['requiredAction'])) {
            return null;
        }
        // The required action must be a real RiskAction and NEVER
        // StepUp/Deny — those are terminal application-level actions and
        // the ticket format never carries them (a ticket demanding one is
        // structurally invalid).
        $requiredAction = RiskAction::tryFrom($payload['requiredAction']);
        if ($requiredAction === null || $requiredAction === RiskAction::StepUp || $requiredAction === RiskAction::Deny) {
            return null;
        }
        if (!\is_int($payload['chainDepth']) || $payload['chainDepth'] < 1) {
            return null;
        }

        return $payload;
    }

    /**
     * RESERVE the chain behind a verified ticket: validates the ticket
     * (signature, expiry, structural shape) and atomically transitions the
     * server-held chain state available -> reserved (idempotent for the
     * same chain id — a retry of the same ticket re-enters the reserved
     * state and re-attempts issuance). Returns the verified payload, or
     * null when the ticket is invalid/expired OR the chain state is
     * absent/expired/already consumed (a replayed ticket lands here).
     *
     * The reservation is the stage-2 issuance's claim on the chain: the
     * one-shot consume runs only after the issuance is durably complete,
     * and a refused/failed issuance releases the reservation so the SAME
     * ticket stays reusable.
     *
     * @throws \Throwable on backend failure — the caller fails closed (the
     *                    one-shot state cannot be confirmed)
     */
    public function reserve(string $ticket): ?array
    {
        $payload = $this->verify($ticket);
        if ($payload === null) {
            return null;
        }
        $status = $this->store->reserve((string) $payload['chainId'], $this->ttlSecs);
        if ($status === 'consumed' || $status === 'missing') {
            return null;
        }

        return $payload;
    }

    /**
     * Release a reservation (the reservation holder's retry path): the
     * chain returns to the available state so a refused or failed issuance
     * never burns the ticket. Best-effort — the reservation also expires
     * with the chain TTL.
     */
    public function release(string $chainId): void
    {
        $this->store->release($chainId);
    }

    /**
     * ONE-SHOT COMPLETION of a durably issued stage-2 challenge: consume
     * the server-held chain state (GET + DEL — at most one consumer ever
     * wins) and re-check it against the signed ticket (defense-in-depth:
     * the state was created together with the ticket in {@see issue()} and
     * must carry the same stage-1 nonce, scope, request binding and
     * required action). Returns the consumed state, or null when the chain
     * state is absent/already consumed or does not match the ticket.
     *
     * @param array $payload the verified ticket payload (reserve() output)
     *
     * @return array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: ?string}|null
     */
    public function consume(string $chainId, array $payload): ?array
    {
        $state = $this->store->consume($chainId);
        if ($state === null) {
            return null;
        }
        // The server-held state must match the signed ticket (both were
        // created together in issue(); this is defense-in-depth).
        if (!hash_equals((string) $state['stage1Nonce'], (string) $payload['stage1Nonce'])) {
            return null;
        }
        if (!hash_equals((string) $state['scope'], (string) $payload['scope'])) {
            return null;
        }
        if ((string) ($state['requestBinding'] ?? '') !== (string) ($payload['requestBinding'] ?? '')) {
            return null;
        }
        if ((string) ($state['requiredAction'] ?? '') !== (string) ($payload['requiredAction'] ?? '')) {
            return null;
        }

        return $state;
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }

    /**
     * The RAW 32-byte HMAC-SHA256 digest, base64url-encoded (43 chars —
     * vs 64 for the hex digest): the compact signature keeps the signed
     * ticket inside the accepted 256-byte wire bound for the longest
     * realistic scope/binding lengths. The verify side compares the same
     * encoding constant-time (hash_equals).
     */
    private function sign(string $body): string
    {
        return rtrim(strtr(base64_encode(hash_hmac('sha256', $body, $this->hmacSecret, true)), '+/', '-_'), '=');
    }

    private static function encode(array $payload): string
    {
        // The compact JSON-array body keeps the signed ticket inside the
        // accepted 256-byte wire bound: the nine signed fields in order
        // [chainId, stage1Nonce, scope, policyVersion, issuedAt,
        //  expiresAt, requestBinding, requiredAction, chainDepth].
        $body = (string) json_encode([
            $payload['chainId'],
            $payload['stage1Nonce'],
            $payload['scope'],
            $payload['policyVersion'],
            $payload['issuedAt'],
            $payload['expiresAt'],
            $payload['requestBinding'],
            $payload['requiredAction'],
            $payload['chainDepth'],
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
        if (!\is_array($decoded) || \count($decoded) !== 9) {
            return null;
        }

        return [
            'chainId' => $decoded[0],
            'stage1Nonce' => $decoded[1],
            'scope' => $decoded[2],
            'policyVersion' => $decoded[3],
            'issuedAt' => $decoded[4],
            'expiresAt' => $decoded[5],
            'requestBinding' => $decoded[6],
            'requiredAction' => $decoded[7],
            'chainDepth' => $decoded[8],
        ];
    }
}
