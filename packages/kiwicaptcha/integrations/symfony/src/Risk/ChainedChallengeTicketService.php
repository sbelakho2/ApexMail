<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Risk\RiskAction;

/**
 * Signs and verifies one-shot CHAIN TICKETS and drives the transactional
 * chained-challenge machine (risk.chaining).
 *
 * A chain ticket is the client-carrying half of a chain: the server-held
 * half is the {@see TransactionalChainedChallengeStateStore} record +
 * its OBLIGATION mapping, created in the SAME atomic operation
 * ({@see requireStage2()} -> createOrGetObligation). The ticket is
 * MINIMAL by design — it proves only the chain's identity and validity:
 *
 *   base64url([1, chainId, expiresAt]) "." base64url(hmac_sha256(body,
 *   secret, true))
 *
 * (version 1, the random chain id, the signed expiry, the raw 32-byte
 * MAC). EVERYTHING else — stage1Nonce, scope, requestBinding,
 * requiredAction, requiredRank, policyVersion, chainDepth, state — is
 * SERVER-HELD in the state record, so a client can never alter it and the
 * ticket stays ~60 bytes no matter how long the legitimate
 * request_binding is. A client can never skip a stage (the server-held
 * state records the verified stage-1 nonce), never extend its own
 * validity (expiry is signed), never downgrade the promised stage (the
 * required action is server-held and enforced at stage-2 issuance), and
 * never detach the chain from its transaction (the chain is ANCHORED on
 * the pseudonymous obligation id of the (policy-epoch, scope,
 * AUTHORITATIVE request-binding) triple — the raw binding is never a
 * Redis key — and a ticket whose obligation cannot match the current
 * transaction is refused).
 *
 * THE TRANSACTION OBLIGATION: a chain opened by a CHAIN_REQUIRED stage-1
 * verification leaves a server-side obligation
 * ({kiwi:<ns>}:chain-obligation:<obligationId> -> chainId, same TTL), so
 * a client CANNOT restart the transaction at stage 1 by discarding the
 * ticket: a later challenge request for the same transaction AUTO-RESUMES
 * the open chain, and a repeated stage-1 verification of the same
 * transaction returns the SAME chain (the required rank only ever
 * RAISES). The obligation id participates in the policy version, so an
 * old-policy chain never blocks a new-policy flow.
 *
 * The chain is a SELECTIVE EXTENSION of depth 2 (chainDepth is always 2):
 * the state machine (reserveStage2 / markIssued / markVerified /
 * rearmIssued) lets a FAILED stage-2 issuance release the reservation so
 * the SAME ticket retries, an ISSUED issuance is recovered on retry (the
 * exact same challenge — no re-mint), a consumed-valid stage-2 VERIFIES
 * the chain (the TERMINAL state — the obligation is cleared atomically),
 * and an expired/invalid stage-2 REARMS the chain for a FRESH stage-2
 * mint at the same-or-stronger floor — NEVER a stage-1. Every result is
 * TYPED ({@see ChainReservationResult} / {@see ChainIssuedResult} /
 * {@see ChainVerifiedResult} / bool) — never magic strings at this
 * surface.
 *
 * The reservation lease is the SHORT risk.chaining.reservation_lease_secs
 * (bounded by the chain record's own remaining TTL — a crashed owner
 * blocks retries for seconds, not minutes).
 *
 * TICKET FORMAT (stable, documented — the server's accepted pattern
 * [A-Za-z0-9._:-]{1,256}):
 *
 *   base64url([version, chainId, expiresAt])
 *   "." base64url(hmac_sha256(body, secret, raw))
 *
 * chainId is base64url(16 random bytes); the raw 32-byte HMAC-SHA256
 * digest is base64url-encoded (43 chars); expiresAt is the signed
 * absolute expiry. {@see ticketFor()} reconstructs the EXACT
 * deterministic ticket for a (chainId, expiresAt) pair — the body is
 * deterministic from version/chainId/expiresAt.
 */
final class ChainedChallengeTicketService
{
    /** The ONLY ticket format version this service issues/accepts. */
    private const TICKET_VERSION = 1;

    /** The chain id alphabet (base64url of 16 random bytes). */
    private const CHAIN_ID_PATTERN = '/^[A-Za-z0-9_-]{1,64}$/D';

    /** The wire bound shared with the controller's accepted pattern. */
    private const MAX_TICKET_BYTES = 256;

    /** The chainable PoW actions (Sha16..Argon64 — never StepUp/Deny). */
    private const CHAINABLE_ACTIONS = [RiskAction::Sha16, RiskAction::Sha18, RiskAction::Sha20, RiskAction::Argon16, RiskAction::Argon32, RiskAction::Argon64];

    /**
     * @param TransactionalChainedChallengeStateStore $store               the
     *                                                                     obligation-anchored
     *                                                                     chain
     *                                                                     state
     *                                                                     store
     * @param int $ttlSecs                the chain lifetime
     *                                    (risk.chaining.ttl_secs, bounded
     *                                    30..3600 by the config tree)
     * @param int $reservationLeaseSecs   the SHORT owner-scoped
     *                                    reservation lease
     *                                    (risk.chaining.reservation_lease_secs,
     *                                    bounded 5..60 and < ttl_secs by
     *                                    the config tree — a crashed
     *                                    owner blocks retries for seconds)
     * @param RequestBindingAuthorityInterface|null $bindingAuthority the
     *                                    deployment's authoritative
     *                                    transaction-binding resolver
     *                                    (risk.request_binding_authority;
     *                                    null = the legacy static/
     *                                    attribute binding applies)
     * @param \Closure|null $now          test seam: returns the current
     *                                    Unix seconds (defaults to
     *                                    time())
     */
    public function __construct(
        private readonly TransactionalChainedChallengeStateStore $store,
        private readonly string $hmacSecret,
        private readonly int $ttlSecs = 300,
        private readonly int $reservationLeaseSecs = 15,
        private readonly ?RequestBindingAuthorityInterface $bindingAuthority = null,
        private readonly ?\Closure $now = null,
    ) {
    }

    /**
     * The bounded pseudonymous transaction-obligation id:
     * hmac_sha256("chain-obligation\0{policyVersion}\0{scope}\0{binding}",
     * chainSecret) — the transaction anchor of a chain. NEVER a raw
     * binding in a Redis key; the policy version participates so an
     * old-policy chain never blocks a new-policy flow. The same id is
     * computed at stage-1 issuance (the verified record's authoritative
     * binding) and at stage-2 resumption (the re-resolved authoritative
     * binding), so the obligation index matches exactly when — and only
     * when — the transaction is the same.
     */
    public function obligationIdFor(string $scope, string $requestBinding, int $policyVersion): string
    {
        return hash_hmac('sha256', "chain-obligation\0".$policyVersion."\0".$scope."\0".($requestBinding ?? ''), $this->hmacSecret);
    }

    /**
     * The OPEN-CHAIN REQUIREMENT of the current transaction: compute the
     * obligation id of (scope, authoritative binding, policy version),
     * read the obligation -> the chain record and return the typed
     * requirement, or null when no open obligation exists (the ordinary
     * stage-1 flow). A VERIFIED chain never returns here — its obligation
     * was cleared atomically at verification.
     *
     * @throws MalformedChainedChallengeStateException when the chain
     *                                                 record violates the
     *                                                 strict v2 schema
     *                                                 (fail closed — the
     *                                                 caller answers
     *                                                 temporary-unavailable)
     * @throws \Throwable on backend failure — the caller fails closed
     */
    public function findOpenRequirement(string $scope, string $requestBinding, int $policyVersion): ?ChainRequirement
    {
        $chainId = $this->store->obligationChainId($this->obligationIdFor($scope, $requestBinding, $policyVersion));
        if ($chainId === null) {
            return null;
        }

        return $this->requirementFor($chainId);
    }

    /**
     * Stage-1 issuance entry: ATOMICALLY create-or-get the transaction's
     * chain + obligation mapping (ONE script over the two keys) and
     * return the typed requirement.
     *
     *  - no obligation -> the chain is created (state available, v2
     *    schema) with the obligation (same TTL) — NEVER a silent stage-1
     *    issuance when an obligation exists;
     *  - the obligation exists -> the EXISTING chain is returned (a
     *    repeated stage-1 token of the same transaction gets the SAME
     *    chain); a stronger reassessment RAISES the required rank/action
     *    (never lowers);
     *  - the obligation points at a missing/corrupt chain -> the stale
     *    mapping is compare-deleted and the chain created fresh (the
     *    atomic retry).
     *
     * @param RiskAction $requiredAction the reassessed action — a
     *                                   chainable PoW action (Sha16..
     *                                   Argon64); StepUp/Deny are
     *                                   terminal application-level
     *                                   actions and NEVER chainable
     *                                   (\InvalidArgumentException)
     * @param int        $expiresAt      the absolute chain expiry (unix
     *                                   seconds) — the SAME value the
     *                                   ticket will carry; the chain
     *                                   record + obligation TTL match it
     *
     * @throws \InvalidArgumentException on a non-chainable action or a
     *                                   non-future expiry
     * @throws \Throwable                on backend failure — the caller
     *                                   fails closed (no ticket without a
     *                                   server-held chain state)
     */
    public function requireStage2(string $stage1Nonce, string $scope, string $requestBinding, int $policyVersion, RiskAction $requiredAction, int $expiresAt): ChainRequirement
    {
        if (!\in_array($requiredAction, self::CHAINABLE_ACTIONS, true)) {
            throw new \InvalidArgumentException(sprintf('requiredAction %s is not chainable (only the PoW actions Sha16..Argon64 open a chain)', $requiredAction->value));
        }
        if ($expiresAt <= $this->now()) {
            throw new \InvalidArgumentException('the chain expiry must be in the future');
        }
        $obligationId = $this->obligationIdFor($scope, $requestBinding, $policyVersion);
        $chainId = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
        $chainId = $this->store->createOrGetObligation(
            $obligationId,
            $chainId,
            $stage1Nonce,
            $scope,
            $requestBinding ?? '',
            $requiredAction->value,
            $requiredAction->rank(),
            $policyVersion,
            $expiresAt,
            max(1, $expiresAt - $this->now()),
        );
        $requirement = $this->requirementFor($chainId);
        if ($requirement === null) {
            // The chain vanished between the create and the read (an
            // expired clock boundary) — fail closed, never a silent
            // stage-1 issuance.
            throw new \RuntimeException('the chain state could not be confirmed after creation');
        }

        return $requirement;
    }

    /**
     * Reconstruct the EXACT deterministic ticket of a chain: the body
     * [version, chainId, expiresAt] is deterministic, so the signed
     * ticket is byte-identical for the same (chainId, expiresAt).
     */
    public function ticketFor(string $chainId, int $expiresAt): string
    {
        $body = self::encode([self::TICKET_VERSION, $chainId, $expiresAt]);

        return $body.'.'.self::sign($body);
    }

    /**
     * The stage-1 issuance convenience: requireStage2() + ticketFor().
     * Returns the signed ticket, or null when the signed ticket would
     * exceed the accepted 256-byte wire bound.
     *
     * @throws \InvalidArgumentException on a non-chainable action
     * @throws \Throwable                on backend failure — the caller
     *                                   fails closed
     */
    public function ticket(string $stage1Nonce, string $scope, string $requestBinding, int $policyVersion, RiskAction $requiredAction, ?int $expiresAt = null): ?string
    {
        $expiresAt ??= $this->now() + $this->ttlSecs;
        $requirement = $this->requireStage2($stage1Nonce, $scope, $requestBinding, $policyVersion, $requiredAction, $expiresAt);
        $ticket = $this->ticketFor($requirement->chainId, $expiresAt);
        if (\strlen($ticket) > self::MAX_TICKET_BYTES) {
            return null;
        }

        return $ticket;
    }

    /**
     * PLAIN read of the chain state behind a chain id: the typed
     * requirement, or null when the chain is absent/expired. Used for the
     * direct verification of a ticket whose obligation is already cleared
     * (a TERMINAL verified chain) and for the lost-reply confirmation of
     * the issuance/verification transitions.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema
     * @throws \Throwable on backend failure — the caller fails closed
     */
    public function requirementFor(string $chainId): ?ChainRequirement
    {
        $record = $this->store->read($chainId);
        if ($record === null) {
            return null;
        }

        return self::requirementFromRecord($chainId, $record);
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
     * RESERVE the chain for ONE owner with the SHORT configured lease
     * (risk.chaining.reservation_lease_secs, bounded by the record's own
     * remaining TTL): available -> reserved(me) ('available'); 'retry'
     * when already reserved by ME; 'busy' when reserved by another owner
     * with a live lease (the retryable in-progress 503 — the caller must
     * NOT enter the issuance pipeline); 'taken_over' when the other
     * owner's lease expired; 'issued'/'verified' when the chain already
     * issued (recover, never re-mint); 'missing' when the state is
     * absent/expired.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema
     * @throws \Throwable on backend failure — the caller fails closed (the
     *                    one-shot state cannot be confirmed)
     */
    public function reserveStage2(string $chainId, string $ownerToken): ChainReservationResult
    {
        $status = $this->store->reserve($chainId, $ownerToken, $this->reservationLeaseSecs);

        return match ($status) {
            'available' => ChainReservationResult::Available,
            'retry' => ChainReservationResult::Retry,
            'busy' => ChainReservationResult::Busy,
            'taken_over' => ChainReservationResult::TakenOver,
            'issued', 'completed' => ChainReservationResult::Issued,
            'verified' => ChainReservationResult::Verified,
            default => ChainReservationResult::Missing,
        };
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
     * IDEMPOTENT issuance of a durably stored stage-2 challenge: the
     * owner-scoped transition reserved(me) -> issued(stage2Nonce) — a
     * state TRANSITION, never a delete (the issued record keeps its TTL
     * so a retry recovers the issued challenge). 'issued_new' on the
     * first transition, 'issued_same' on a same-nonce retry,
     * 'verified_same' when the chain is already verified with the same
     * nonce, 'conflict' when issued/verified with a DIFFERENT nonce,
     * 'not_owner' when not reserved by this owner, 'missing' when the
     * state is absent.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema
     * @throws \Throwable on backend failure — the caller must apply the
     *                    lost-reply recovery (read the state; never
     *                    delete state that may be authoritative)
     */
    public function markIssued(string $chainId, string $ownerToken, string $stage2Nonce): ChainIssuedResult
    {
        $result = $this->store->markIssued($chainId, $ownerToken, $stage2Nonce);

        return match ($result) {
            'issued_new' => ChainIssuedResult::IssuedNew,
            'issued_same' => ChainIssuedResult::IssuedSame,
            'verified_same' => ChainIssuedResult::VerifiedSame,
            'conflict' => ChainIssuedResult::Conflict,
            'not_owner' => ChainIssuedResult::NotOwner,
            default => ChainIssuedResult::Missing,
        };
    }

    /**
     * TERMINAL verification of a solved stage-2 challenge: issued(
     * stage2Nonce) -> verified(stage2Nonce), ATOMICALLY deleting the
     * obligation mapping ONLY if it still points at this chainId (the
     * terminal verified chain record is kept until its TTL). Idempotent:
     * 'verified_same' on a same-nonce retry, 'conflict' on a different
     * nonce, 'missing' when the chain is absent.
     *
     * A lost reply is recoverable by READING the state and confirming the
     * exact nonce — the obligation deletion is atomic with the
     * transition, so a verified state with the nonce means the
     * transaction's obligation is cleared; the caller must NOT return a
     * final pass while the obligation may be uncleared.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema
     * @throws \Throwable on backend failure
     */
    public function markVerified(string $chainId, string $stage2Nonce): ChainVerifiedResult
    {
        $result = $this->store->markVerified($chainId, $stage2Nonce);

        return match ($result) {
            'verified_new' => ChainVerifiedResult::VerifiedNew,
            'verified_same' => ChainVerifiedResult::VerifiedSame,
            'conflict' => ChainVerifiedResult::Conflict,
            default => ChainVerifiedResult::Missing,
        };
    }

    /**
     * REARM an issued chain for a FRESH stage-2 mint: issued(
     * expectedStage2Nonce) -> available, ATOMICALLY (a different nonce or
     * any other state is an atomic no-op — false). The controller then
     * reserves + mints a NEW stage-2 challenge at the SAME OR STRONGER
     * floor — NEVER a stage-1.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema
     * @throws \Throwable on backend failure
     */
    public function rearmIssued(string $chainId, string $expectedStage2Nonce): bool
    {
        return $this->store->rearmIssued($chainId, $expectedStage2Nonce);
    }

    /**
     * @deprecated use requireStage2() + ticketFor() (or ticket()) — the
     *             obligation-anchored stage-1 issuance entry. Retained
     *             for source compatibility; the transaction semantics are
     *             identical (a repeated stage-1 verification of the same
     *             transaction returns the SAME chain).
     *
     * Returns null when the signed ticket would exceed the accepted
     * 256-byte shape bound or when the chain state could not be persisted
     * (backend failure — the caller fails closed).
     *
     * @param string      $requiredAction the reassessed RiskAction's value
     *                                    (a chainable PoW action Sha16..
     *                                    Argon64; StepUp/Deny are terminal
     *                                    application-level actions and
     *                                    never chainable)
     * @param string|null $requestBinding the authoritative request binding
     *                                    (null when the transaction is
     *                                    unbound)
     */
    public function issue(string $stage1Nonce, string $scope, int $policyVersion, string $requiredAction, ?string $requestBinding = null): ?string
    {
        try {
            return $this->ticket($stage1Nonce, $scope, $requestBinding ?? '', $policyVersion, RiskAction::from($requiredAction));
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * @deprecated use findOpenRequirement()/requirementFor() — the plain
     *             read of the server-held chain state behind a verified
     *             ticket.
     *
     * @return array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, requiredRank: int, policyVersion: int, chainDepth: int, state: string, owner: ?string, leaseUntil: ?int, stage2Nonce: ?string, obligationId: string, expiresAt: int}|null
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema
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
     * @deprecated use reserveStage2() — the owner-scoped reservation
     *             behind a verified ticket.
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

        return $this->store->reserve((string) $payload['chainId'], $ownerToken, $this->reservationLeaseSecs);
    }

    /**
     * @deprecated use markIssued() — the TERMINAL legacy completion
     *             (reserved(me) -> completed(stage2Nonce), the historical
     *             name of the issued state). Returns the completed
     *             record, or null when the transition was refused.
     *
     * @return array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, requiredRank: int, policyVersion: int, chainDepth: int, state: 'completed', owner: ?string, leaseUntil: ?int, stage2Nonce: string, obligationId: string, expiresAt: int}|null
     */
    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array
    {
        return $this->store->complete($chainId, $ownerToken, $stage2Nonce);
    }

    /**
     * Map a strictly-decoded chain record to the typed requirement. A
     * legacy 'completed' record is the historical name of the
     * terminal-with-nonce state — reported as 'issued' (semantically
     * identical).
     *
     * @param array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, requiredRank: int, policyVersion: int, chainDepth: int, state: 'available'|'reserved'|'issued'|'verified'|'completed', owner: ?string, leaseUntil: ?int, stage2Nonce: ?string, obligationId: string, expiresAt: int} $record
     */
    private static function requirementFromRecord(string $chainId, array $record): ChainRequirement
    {
        return new ChainRequirement(
            chainId: $chainId,
            stage1Nonce: $record['stage1Nonce'],
            scope: $record['scope'],
            requestBinding: $record['requestBinding'] ?? '',
            policyVersion: $record['policyVersion'],
            requiredAction: RiskAction::from($record['requiredAction']),
            requiredRank: $record['requiredRank'],
            chainDepth: $record['chainDepth'],
            state: $record['state'] === 'completed' ? 'issued' : $record['state'],
            stage2Nonce: $record['stage2Nonce'],
            owner: $record['owner'],
            leaseUntil: $record['leaseUntil'],
            expiresAt: $record['expiresAt'],
        );
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
