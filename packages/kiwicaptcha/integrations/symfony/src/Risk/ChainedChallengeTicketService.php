<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Risk\RiskAction;

/**
 * Signs and verifies one-shot chain tickets and drives the transactional
 * chained-challenge machine (risk.chaining). A chain ticket is the
 * client-carrying half of a chain: the base64url of [1, chainId,
 * expiresAt], a dot, and the base64url of the raw
 * hmac_sha256(body, secret, true) digest. Everything else is
 * server-held in the obligation-anchored state record, so a client can
 * never alter it, skip a stage, or extend its own validity. The ticket
 * format and the full state machine are documented in
 * docs/chained-challenges.md.
 */
final class ChainedChallengeTicketService
{
    /** The ticket format version this service issues and accepts. */
    private const TICKET_VERSION = 1;

    /** The chain id alphabet (base64url of 16 random bytes). */
    private const CHAIN_ID_PATTERN = '/^[A-Za-z0-9_-]{1,64}$/D';

    /** The wire bound shared with the controller's accepted pattern. */
    private const MAX_TICKET_BYTES = 256;

    /** The chainable PoW actions (Sha16..Argon64, never StepUp/Deny). */
    private const CHAINABLE_ACTIONS = [RiskAction::Sha16, RiskAction::Sha18, RiskAction::Sha20, RiskAction::Argon16, RiskAction::Argon32, RiskAction::Argon64];

    /**
     * @param TransactionalChainedChallengeStateStore $store               the
     *                                                                     obligation-anchored
     *                                                                     chain
     *                                                                     state
     *                                                                     store.
     * @param int $ttlSecs                the chain lifetime
     *                                    (risk.chaining.ttl_secs, bounded
     *                                    30..3600 by the config tree)
     * @param int $reservationLeaseSecs   the short owner-scoped
     *                                    reservation lease
     *                                    (risk.chaining.reservation_lease_secs,
     *                                    bounded 5..60 and < ttl_secs by
     *                                    the config tree; a crashed owner
     *                                    blocks retries for seconds).
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
     * chainSecret), the transaction anchor of a chain. Never a raw
     * binding in a Redis key; the policy version participates so an
     * old-policy chain never blocks a new-policy flow. The same id is
     * computed at stage-1 issuance (the verified record's authoritative
     * binding) and at stage-2 resumption (the re-resolved authoritative
     * binding), so the obligation index matches exactly when the
     * transaction is the same.
     */
    public function obligationIdFor(string $scope, string $requestBinding, int $policyVersion): string
    {
        return hash_hmac('sha256', "chain-obligation\0".$policyVersion."\0".$scope."\0".($requestBinding ?? ''), $this->hmacSecret);
    }

    /**
     * The open-chain requirement of the current transaction: compute the
     * obligation id of (scope, authoritative binding, policy version),
     * read the obligation -> the chain record and return the typed
     * requirement, or null when no open obligation exists (the ordinary
     * stage-1 flow). A verified chain never returns here, since its
     * obligation was cleared atomically at verification. A chain in the
     * terminal step_up_required/denied state does: its obligation mapping
     * is kept, so the controller answers the terminal response instead of
     * issuing (never a new stage-1).
     *
     * @throws MalformedChainedChallengeStateException when the chain
     *                                                 record violates the
     *                                                 strict v2 schema
     *                                                 (fail closed; the
     *                                                 caller answers
     *                                                 temporary-unavailable).
     * @throws \Throwable on backend failure: the caller fails closed.
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
     * Stage-1 issuance entry: atomically create-or-get the transaction's
     * chain and obligation mapping (one script over the two keys) and
     * return the typed requirement. With no obligation the chain is
     * created (state available, v2 schema) with the obligation (same
     * TTL). With an existing obligation the existing chain is returned: a
     * repeated stage-1 token of the same transaction gets the same chain,
     * and a stronger reassessment only ever raises the required
     * rank/action, never lowers. When the obligation points at a missing
     * or corrupt chain, the stale mapping is compare-deleted and the
     * chain created fresh (the atomic retry).
     *
     * @param RiskAction $requiredAction the reassessed action, a
     *                                   chainable PoW action (Sha16..
     *                                   Argon64). StepUp/Deny are
     *                                   terminal application-level
     *                                   actions and never chainable
     *                                   (\InvalidArgumentException).
     * @param int        $expiresAt      the absolute chain expiry (unix
     *                                   seconds), the same value the
     *                                   ticket will carry; the chain
     *                                   record and obligation TTL match
     *                                   it.
     *
     * @throws \InvalidArgumentException on a non-chainable action or a
     *                                   non-future expiry.
     * @throws \Throwable                on backend failure: the caller
     *                                   fails closed (no ticket without a
     *                                   server-held chain state).
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
            // expired clock boundary): fail closed, never a silent
            // stage-1 issuance.
            throw new \RuntimeException('the chain state could not be confirmed after creation');
        }

        return $requirement;
    }

    /**
     * Reconstruct the exact deterministic ticket of a chain. The body
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
     * The signed-expiry invariant: the ticket is always signed from the
     * server-held requirement's actual expiry ($requirement->expiresAt),
     * never the caller-requested $expiresAt. On the fresh path the
     * requested expiry seeds the chain creation (requireStage2), so a new
     * chain's requirement expiry equals the requested expiry. On the
     * existing path (an open chain of the same transaction) the
     * requirement keeps its original expiry, so the signed ticket can
     * never outlive the chain state. Repeated calls against the same
     * obligation produce byte-identical tickets regardless of the
     * requested expiry.
     *
     * @param int|null $expiresAt the requested absolute chain expiry (unix
     *                            seconds; defaults to now + ttl_secs).
     *                            Seeds the chain creation on the fresh
     *                            path; the signed expiry is always the
     *                            requirement's actual server-held expiry.
     *
     * @throws \InvalidArgumentException on a non-chainable action.
     * @throws \Throwable                on backend failure: the caller
     *                                   fails closed.
     */
    public function ticket(string $stage1Nonce, string $scope, string $requestBinding, int $policyVersion, RiskAction $requiredAction, ?int $expiresAt = null): ?string
    {
        $expiresAt ??= $this->now() + $this->ttlSecs;
        $requirement = $this->requireStage2($stage1Nonce, $scope, $requestBinding, $policyVersion, $requiredAction, $expiresAt);
        $ticket = $this->ticketFor($requirement->chainId, $requirement->expiresAt);
        if (\strlen($ticket) > self::MAX_TICKET_BYTES) {
            return null;
        }

        return $ticket;
    }

    /**
     * Plain read of the chain state behind a chain id: the typed
     * requirement, or null when the chain is absent/expired. Used for
     * the direct verification of a ticket whose obligation is already
     * cleared (a terminal verified chain) and for the lost-reply
     * confirmation of the issuance/verification transitions. Also the
     * validator's by-chain-id liveness check when it re-signs a
     * `CHAIN_REQUIRED` ticket, whose signing expiry comes from the
     * disposition-carried bound, never the obligation lookup.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema.
     * @throws \Throwable on backend failure: the caller fails closed.
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
    public function establishReplicationFence(string $what): void
    {
        if ($this->store instanceof \KiwiCaptcha\ReplicationBarrierInterface) {
            $this->store->establishReplicationFence($what);
        }
    }

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
     * Reserve the chain for one owner with the short configured lease
     * (risk.chaining.reservation_lease_secs, bounded by the record's own
     * remaining TTL). Results: 'available' when available ->
     * reserved(me). 'retry' when already reserved by me. 'busy' when
     * another owner holds a live lease; the retryable in-progress 503
     * applies and the caller must not enter the issuance pipeline.
     * 'taken_over' when the other owner's lease expired. 'issued' and
     * 'verified' when already issued (recover, never re-mint). The
     * terminal 'step_up_required'/'denied' when already ended in its
     * final disposition (never issue). 'missing' when absent or
     * expired.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema.
     * @throws \Throwable on backend failure: the caller fails closed (the
     *                    one-shot state cannot be confirmed).
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
            'step_up_required' => ChainReservationResult::StepUpRequired,
            'denied' => ChainReservationResult::Denied,
            default => ChainReservationResult::Missing,
        };
    }

    /**
     * Release a reservation (the reservation owner's retry path): the
     * chain returns to the available state so a refused or failed
     * issuance never burns the ticket. A release by a non-owner is an
     * atomic no-op, so a failing request can never free another owner's
     * live reservation. Best-effort: the reservation also expires with
     * the chain TTL.
     */
    public function release(string $chainId, string $ownerToken): void
    {
        $this->store->release($chainId, $ownerToken);
    }

    /**
     * Idempotent issuance of a durably stored stage-2 challenge: the
     * owner-scoped transition reserved(me) -> issued(stage2Nonce). A
     * state transition, never a delete: the issued record keeps its TTL
     * so a retry recovers the issued challenge. Results: 'issued_new'
     * (first transition), 'issued_same' (same-nonce retry),
     * 'verified_same' (already verified with the same nonce), 'conflict'
     * (issued/verified with a different nonce), 'not_owner' (not
     * reserved by this owner), 'missing' (absent).
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema.
     * @throws \Throwable on backend failure: the caller must apply the
     *                    lost-reply recovery (read the state; never
     *                    delete state that may be authoritative).
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
     * Terminal verification of a solved stage-2 challenge: issued(
     * stage2Nonce) -> verified(stage2Nonce), atomically deleting the
     * obligation mapping only if it still points at this chainId (the
     * terminal verified chain record is kept until its TTL). Idempotent:
     * 'verified_same' on a same-nonce retry, 'conflict' on a different
     * nonce, 'missing' when the chain is absent. A lost reply is
     * recoverable by reading the state and confirming the exact nonce.
     * The obligation deletion is atomic with the transition, so a
     * verified state with the nonce means the transaction's obligation is
     * cleared; the caller must not return a final pass while the
     * obligation may be uncleared.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema.
     * @throws \Throwable on backend failure.
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
     * Terminal step-up transition of a solved stage-2 challenge whose
     * final disposition is StepUp: issued(stage2Nonce) ->
     * step_up_required(stage2Nonce), KEEPTTL. The obligation mapping is
     * kept, so the transaction stays bound to the step-up requirement and
     * a later challenge request re-encounters the terminal state (never
     * a new stage-1). Idempotent: 'step_up_required_same' on a same-nonce
     * retry, 'conflict' on a different nonce, 'missing' when the chain
     * is absent. A lost reply is recoverable by reading the state and
     * confirming the exact nonce; the caller must not answer a final
     * step-up while the chain may still be issued.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema.
     * @throws \Throwable on backend failure.
     */
    public function markStepUpRequired(string $chainId, string $stage2Nonce): ChainVerifiedResult
    {
        $result = $this->store->markStepUpRequired($chainId, $stage2Nonce);

        return match ($result) {
            'step_up_required_new' => ChainVerifiedResult::StepUpRequiredNew,
            'step_up_required_same' => ChainVerifiedResult::StepUpRequiredSame,
            'conflict' => ChainVerifiedResult::Conflict,
            default => ChainVerifiedResult::Missing,
        };
    }

    /**
     * Terminal denial transition of a solved stage-2 challenge whose
     * final disposition is Deny: issued(stage2Nonce) -> denied(
     * stage2Nonce), KEEPTTL. The obligation mapping is kept, so the
     * transaction stays bound to its final denial and a later challenge
     * request re-encounters the terminal state (never a new stage-1).
     * Idempotent: 'denied_same' on a same-nonce retry, 'conflict' on a
     * different nonce, 'missing' when the chain is absent. A lost reply
     * is recoverable by reading the state and confirming the exact
     * nonce; the caller must not answer a final denial while the chain
     * may still be issued.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema.
     * @throws \Throwable on backend failure.
     */
    public function markDenied(string $chainId, string $stage2Nonce): ChainVerifiedResult
    {
        $result = $this->store->markDenied($chainId, $stage2Nonce);

        return match ($result) {
            'denied_new' => ChainVerifiedResult::DeniedNew,
            'denied_same' => ChainVerifiedResult::DeniedSame,
            'conflict' => ChainVerifiedResult::Conflict,
            default => ChainVerifiedResult::Missing,
        };
    }

    /**
     * Obligation-bound, nonce-agnostic terminalization of an open
     * obligation, the transaction-level denial: available|reserved|
     * issued -> denied, KEEPTTL (the record keeps its own remaining
     * TTL). The transition is atomic over the chain record plus the
     * obligation mapping (one hash tag). The mapping must still point at
     * this chain and the record must still agree on the obligation id,
     * or the transition is refused (Conflict; the caller re-reads the
     * requirement and terminalizes the current chain). The obligation
     * mapping is kept, so the transaction stays bound to its final denial
     * for the rest of its lifetime (never a new stage-1, never a chain
     * the stage-2 path could clear). The exact stage-2 nonce is not
     * required: a fresh Deny of any verified nonce of the obligated
     * transaction makes the denial durable, keyed by the
     * chain/obligation identity. Idempotent: 'denied_same'; 'conflict'
     * on the other terminal disposition (a terminal state can never be
     * flipped); 'already_verified'/'already_completed' (the transaction
     * already ended via Pass, so the obligation is gone); 'missing'
     * (absent).
     *
     * @param string $obligationId the transaction's obligation id (the
     *                             exact 64-lowercase-hex id the chain was
     *                             created under; the obligation key the
     *                             transition verifies).
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema.
     * @throws \Throwable on backend failure.
     */
    public function markTransactionDenied(string $chainId, string $obligationId): ChainVerifiedResult
    {
        $result = $this->store->markTransactionDenied($chainId, $obligationId);

        return match ($result) {
            'denied_new' => ChainVerifiedResult::DeniedNew,
            'denied_same' => ChainVerifiedResult::DeniedSame,
            'already_verified', 'already_completed' => ChainVerifiedResult::AlreadyVerified,
            'obligation_moved', 'conflict' => ChainVerifiedResult::Conflict,
            default => ChainVerifiedResult::Missing,
        };
    }

    /**
     * Obligation-bound, nonce-agnostic terminalization of an open
     * obligation, the transaction-level step-up: available|reserved|
     * issued -> step_up_required, KEEPTTL (the record keeps its own
     * remaining TTL). The transition is atomic over the chain record plus
     * the obligation mapping (one hash tag). The mapping must still
     * point at this chain and the record must still agree on the
     * obligation id, or the transition is refused (Conflict; the caller
     * re-reads the requirement and terminalizes the current chain). The
     * obligation mapping is kept, so the transaction stays bound to the
     * step-up requirement for the rest of its lifetime (never a new
     * stage-1, never a chain the stage-2 path could clear). The exact
     * stage-2 nonce is not required: a fresh StepUp of any verified
     * nonce of the obligated transaction makes the step-up durable,
     * keyed by the chain/obligation identity. Idempotent:
     * 'step_up_required_same'; 'conflict' on the other terminal
     * disposition (a terminal state can never be flipped);
     * 'already_verified'/'already_completed' (the transaction already
     * ended via Pass, so the obligation is gone); 'missing' (absent).
     *
     * @param string $obligationId the transaction's obligation id (the
     *                             exact 64-lowercase-hex id the chain was
     *                             created under; the obligation key the
     *                             transition verifies).
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema.
     * @throws \Throwable on backend failure.
     */
    public function markTransactionStepUpRequired(string $chainId, string $obligationId): ChainVerifiedResult
    {
        $result = $this->store->markTransactionStepUpRequired($chainId, $obligationId);

        return match ($result) {
            'step_up_required_new' => ChainVerifiedResult::StepUpRequiredNew,
            'step_up_required_same' => ChainVerifiedResult::StepUpRequiredSame,
            'already_verified', 'already_completed' => ChainVerifiedResult::AlreadyVerified,
            'obligation_moved', 'conflict' => ChainVerifiedResult::Conflict,
            default => ChainVerifiedResult::Missing,
        };
    }

    /**
     * Rearm an issued chain for a fresh stage-2 mint: issued(
     * expectedStage2Nonce) -> available, atomically (a different nonce or
     * any other state is an atomic no-op, false). The controller then
     * reserves and mints a new stage-2 challenge at the same or stronger
     * floor, never a stage-1.
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema.
     * @throws \Throwable on backend failure.
     */
    public function rearmIssued(string $chainId, string $expectedStage2Nonce): bool
    {
        return $this->store->rearmIssued($chainId, $expectedStage2Nonce);
    }

    /**
     * @deprecated use requireStage2() + ticketFor(), or ticket(), the
     *             obligation-anchored stage-1 issuance entry. Retained
     *             for source compatibility; the transaction semantics are
     *             identical (a repeated stage-1 verification of the same
     *             transaction returns the same chain).
     *
     * Returns null when the signed ticket would exceed the accepted
     * 256-byte shape bound or when the chain state could not be persisted
     * (backend failure; the caller fails closed).
     *
     * @param string      $requiredAction the reassessed RiskAction's value
     *                                    (a chainable PoW action Sha16..
     *                                    Argon64; StepUp/Deny are terminal
     *                                    application-level actions and
     *                                    never chainable).
     * @param string|null $requestBinding the authoritative request binding
     *                                    (null when the transaction is
     *                                    unbound).
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
     * @deprecated use findOpenRequirement()/requirementFor(), the plain
     *             read of the server-held chain state behind a verified
     *             ticket.
     *
     * @return array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, requiredRank: int, policyVersion: int, chainDepth: int, state: string, owner: ?string, leaseUntil: ?int, stage2Nonce: ?string, obligationId: string, expiresAt: int}|null
     *
     * @throws MalformedChainedChallengeStateException when the record
     *                                                 violates the strict
     *                                                 v2 schema.
     * @throws \Throwable on backend failure: the caller fails closed.
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
     * @deprecated use reserveStage2(), the owner-scoped reservation
     *             behind a verified ticket.
     *
     * @throws \Throwable on backend failure: the caller fails closed (the
     *                    one-shot state cannot be confirmed).
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
     * @deprecated use markIssued(), the terminal legacy completion,
     *             reserved(me) -> completed(stage2Nonce), the historical
     *             name of the issued state. Returns the completed
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
     * terminal-with-nonce state, reported as 'issued' (semantically
     * identical).
     *
     * @param array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, requiredRank: int, policyVersion: int, chainDepth: int, state: 'available'|'reserved'|'issued'|'verified'|'step_up_required'|'denied'|'completed', owner: ?string, leaseUntil: ?int, stage2Nonce: ?string, obligationId: string, expiresAt: int} $record
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
     * The raw 32-byte HMAC-SHA256 digest, base64url-encoded (43 chars,
     * vs 64 for the hex digest). The compact signature keeps the signed
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
        // expiresAt]. No scope, binding or action in the ticket payload:
        // the server-held state owns them.
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
