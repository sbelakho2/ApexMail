<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Risk\RiskAction;

/**
 * In-memory chained-challenge state store for tests/dev (single-process
 * semantics), mirroring the Redis store's transactional v2 machine exactly:
 * the same obligation-anchored transitions and the same all-or-nothing
 * strict v2 decode, see {@see MalformedChainedChallengeStateException}: a
 * corrupt record never becomes a defaulted one. It runs on a
 * caller-provided clock so TTL and lease expiry are enforceable (mirroring
 * redis TIME). The full state machine is documented in
 * docs/chained-challenges.md.
 */
final class ArrayChainedChallengeStateStore implements TransactionalChainedChallengeStateStore
{
    /** The Kiwi challenge nonce shape: base64 of 32 random bytes. */
    private const NONCE_PATTERN = '/^[A-Za-z0-9+\/]{43}=$/D';

    /** The canonical scope/identifier shape (the controller's charset). */
    private const IDENTIFIER_PATTERN = '/^[A-Za-z0-9._:-]{1,128}$/D';

    /** The obligation id: HMAC-SHA256 of the transaction triple, hex. */
    private const OBLIGATION_PATTERN = '/^[0-9a-f]{64}$/D';

    /** The chainable PoW actions (Sha16..Argon64 — never StepUp/Deny). */
    private const CHAINABLE_ACTIONS = ['sha16', 'sha18', 'sha20', 'argon16', 'argon32', 'argon64'];

    private const STATES = ['available', 'reserved', 'issued', 'verified', 'completed', 'step_up_required', 'denied'];

    /**
     * @var array<string, array{v: int, stage1Nonce: string, scope: string, obligationId: string, requiredAction: string, requiredRank: int, policyVersion: int, chainDepth: int, state: string, owner: ?string, leaseUntil: ?int, stage2Nonce: ?string, requestBinding: ?string, expiresAt: float}>
     */
    private array $records = [];

    /** @var array<string, string> obligationId => chainId */
    private array $obligations = [];

    /**
     * @param \Closure|null $now test seam: returns the current unix
     *                           seconds (defaults to microtime(true)).
     */
    public function __construct(private readonly ?\Closure $now = null)
    {
    }

    private function clock(): float
    {
        return ($this->now) ? (float) ($this->now)() : microtime(true);
    }

    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs, ?string $requestBinding = null, ?string $requiredAction = null, int $policyVersion = 1): void
    {
        // The deprecated legacy path is not transaction-anchored, it
        // carries no obligation id: the record carries a derived
        // placeholder obligation id (never a real transaction mapping —
        // hash of the random chain id, no obligation entry is written), so
        // the strict v2 decode stays satisfied.
        if ($requiredAction === null || !\in_array($requiredAction, self::CHAINABLE_ACTIONS, true)) {
            throw new \InvalidArgumentException('a chainable requiredAction (Sha16..Argon64) is required to create a chain record');
        }
        $requestBinding = $requestBinding !== '' ? $requestBinding : null;
        $this->records[$chainId] = [
            'v' => 2,
            'stage1Nonce' => $stage1Nonce,
            'scope' => $scope,
            'obligationId' => hash('sha256', $chainId),
            'requiredAction' => $requiredAction,
            'requiredRank' => RiskAction::from($requiredAction)->rank(),
            'policyVersion' => $policyVersion,
            'chainDepth' => 2,
            'state' => 'available',
            'owner' => null,
            'leaseUntil' => null,
            'stage2Nonce' => null,
            'requestBinding' => $requestBinding,
            'expiresAt' => (int) ($this->clock() + max(1, $ttlSecs)),
        ];
    }

    public function createWithObligation(string $chainId, string $obligationId, string $stage1Nonce, string $scope, ?string $requestBinding, string $requiredAction, int $policyVersion, int $ttlSecs): void
    {
        if (preg_match(self::OBLIGATION_PATTERN, $obligationId) !== 1) {
            throw new \InvalidArgumentException('obligationId must be 64 lowercase hex characters');
        }
        if (!\in_array($requiredAction, self::CHAINABLE_ACTIONS, true)) {
            throw new \InvalidArgumentException('a chainable requiredAction (Sha16..Argon64) is required to create a chain record');
        }
        $requestBinding = $requestBinding !== '' ? $requestBinding : null;
        $this->records[$chainId] = [
            'v' => 2,
            'stage1Nonce' => $stage1Nonce,
            'scope' => $scope,
            'obligationId' => $obligationId,
            'requiredAction' => $requiredAction,
            'requiredRank' => RiskAction::from($requiredAction)->rank(),
            'policyVersion' => $policyVersion,
            'chainDepth' => 2,
            'state' => 'available',
            'owner' => null,
            'leaseUntil' => null,
            'stage2Nonce' => null,
            'requestBinding' => $requestBinding,
            'expiresAt' => (int) ($this->clock() + max(1, $ttlSecs)),
        ];
        $this->obligations[$obligationId] = $chainId;
    }

    public function createOrGetObligation(string $obligationId, string $chainId, string $stage1Nonce, string $scope, string $requestBinding, string $requiredAction, int $requiredRank, int $policyVersion, int $expiresAt, int $ttlSecs): string
    {
        if (preg_match(self::OBLIGATION_PATTERN, $obligationId) !== 1) {
            throw new \InvalidArgumentException('obligationId must be 64 lowercase hex characters');
        }
        $existing = $this->obligations[$obligationId] ?? null;
        if ($existing !== null) {
            $record = $this->records[$existing] ?? null;
            if ($record !== null && $record['expiresAt'] > $this->clock()) {
                // The obligation exists: return the existing chain id,
                // raising the required rank/action when the new
                // reassessment is stronger (never lower).
                if ($requiredRank > $record['requiredRank']) {
                    $this->records[$existing]['requiredRank'] = $requiredRank;
                    $this->records[$existing]['requiredAction'] = $requiredAction;
                }

                return $existing;
            }
            // The obligation points at a missing/expired/corrupt chain:
            // compare-delete the stale mapping and create fresh (the
            // atomic retry of the Redis script).
            if (($this->obligations[$obligationId] ?? null) === $existing) {
                unset($this->obligations[$obligationId]);
            }
        }
        $this->records[$chainId] = [
            'v' => 2,
            'stage1Nonce' => $stage1Nonce,
            'scope' => $scope,
            'obligationId' => $obligationId,
            'requiredAction' => $requiredAction,
            'requiredRank' => $requiredRank,
            'policyVersion' => $policyVersion,
            'chainDepth' => 2,
            'state' => 'available',
            'owner' => null,
            'leaseUntil' => null,
            'stage2Nonce' => null,
            'requestBinding' => $requestBinding !== '' ? $requestBinding : null,
            'expiresAt' => (int) $expiresAt,
        ];
        $this->obligations[$obligationId] = $chainId;

        return $chainId;
    }

    public function obligationChainId(string $obligationId): ?string
    {
        $chainId = $this->obligations[$obligationId] ?? null;
        if ($chainId === null) {
            return null;
        }
        $record = $this->records[$chainId] ?? null;
        if ($record === null || $record['expiresAt'] <= $this->clock()) {
            unset($this->obligations[$obligationId]);

            return null;
        }

        return $chainId;
    }

    public function read(string $chainId): ?array
    {
        $record = $this->liveRecord($chainId);
        if ($record === null) {
            return null;
        }

        return self::wire($record);
    }

    public function reserve(string $chainId, string $ownerToken, int $leaseSecs): string
    {
        $record = $this->liveRecord($chainId);
        if ($record === null) {
            return 'missing';
        }
        if ($record['state'] === 'issued') {
            return 'issued';
        }
        if ($record['state'] === 'verified') {
            return 'verified';
        }
        if ($record['state'] === 'completed') {
            return 'completed';
        }
        if ($record['state'] === 'step_up_required') {
            return 'step_up_required';
        }
        if ($record['state'] === 'denied') {
            return 'denied';
        }
        if ($record['state'] === 'reserved') {
            if ($record['owner'] === $ownerToken) {
                return 'retry';
            }
            if ($record['leaseUntil'] > $this->clock()) {
                return 'busy';
            }
            // Expired lease: takeover (the whole record expires with the
            // signed ticket anyway — the lease can never outlive it).
            $this->records[$chainId]['owner'] = $ownerToken;
            $this->records[$chainId]['leaseUntil'] = $this->leaseDeadline($record, $leaseSecs);

            return 'taken_over';
        }
        $this->records[$chainId]['state'] = 'reserved';
        $this->records[$chainId]['owner'] = $ownerToken;
        $this->records[$chainId]['leaseUntil'] = $this->leaseDeadline($record, $leaseSecs);

        return 'available';
    }

    public function release(string $chainId, string $ownerToken): void
    {
        $record = $this->liveRecord($chainId);
        if ($record === null) {
            return;
        }
        if ($record['state'] !== 'reserved' || $record['owner'] !== $ownerToken) {
            return;
        }
        $this->records[$chainId]['state'] = 'available';
        $this->records[$chainId]['owner'] = null;
        $this->records[$chainId]['leaseUntil'] = null;
    }

    public function markIssued(string $chainId, string $ownerToken, string $stage2Nonce): string
    {
        $record = $this->liveRecord($chainId);
        if ($record === null) {
            return 'missing';
        }
        if ($record['state'] === 'reserved') {
            if ($record['owner'] !== $ownerToken) {
                return 'not_owner';
            }
            $this->records[$chainId]['state'] = 'issued';
            $this->records[$chainId]['stage2Nonce'] = $stage2Nonce;
            $this->records[$chainId]['owner'] = null;
            $this->records[$chainId]['leaseUntil'] = null;

            return 'issued_new';
        }
        if ($record['state'] === 'issued' || $record['state'] === 'completed') {
            return $record['stage2Nonce'] === $stage2Nonce ? 'issued_same' : 'conflict';
        }
        if ($record['state'] === 'verified') {
            return $record['stage2Nonce'] === $stage2Nonce ? 'verified_same' : 'conflict';
        }
        if ($record['state'] === 'step_up_required' || $record['state'] === 'denied') {
            return 'conflict';
        }

        return 'not_owner';
    }

    public function markVerified(string $chainId, string $stage2Nonce): string
    {
        $record = $this->liveRecord($chainId);
        if ($record === null) {
            return 'missing';
        }
        if ($record['state'] === 'verified') {
            return $record['stage2Nonce'] === $stage2Nonce ? 'verified_same' : 'conflict';
        }
        if (($record['state'] !== 'issued' && $record['state'] !== 'completed') || $record['stage2Nonce'] !== $stage2Nonce) {
            return 'conflict';
        }
        $this->records[$chainId]['state'] = 'verified';
        // The verified transition clears the obligation mapping only
        // while it still points at this chain (a re-created chain of the
        // same transaction must never be unlinked by a stale delete).
        if (($this->obligations[(string) $record['obligationId']] ?? null) === $chainId) {
            unset($this->obligations[(string) $record['obligationId']]);
        }

        return 'verified_new';
    }

    public function markStepUpRequired(string $chainId, string $stage2Nonce): string
    {
        $record = $this->liveRecord($chainId);
        if ($record === null) {
            return 'missing';
        }
        if ($record['state'] === 'step_up_required') {
            return $record['stage2Nonce'] === $stage2Nonce ? 'step_up_required_same' : 'conflict';
        }
        if (($record['state'] !== 'issued' && $record['state'] !== 'completed') || $record['stage2Nonce'] !== $stage2Nonce) {
            return 'conflict';
        }
        $this->records[$chainId]['state'] = 'step_up_required';
        // The step-up transition keeps the obligation mapping: the
        // transaction stays bound to the step-up requirement, so a later
        // challenge request for the same transaction re-encounters the
        // terminal state (never a new stage-1).

        return 'step_up_required_new';
    }

    public function markDenied(string $chainId, string $stage2Nonce): string
    {
        $record = $this->liveRecord($chainId);
        if ($record === null) {
            return 'missing';
        }
        if ($record['state'] === 'denied') {
            return $record['stage2Nonce'] === $stage2Nonce ? 'denied_same' : 'conflict';
        }
        if (($record['state'] !== 'issued' && $record['state'] !== 'completed') || $record['stage2Nonce'] !== $stage2Nonce) {
            return 'conflict';
        }
        $this->records[$chainId]['state'] = 'denied';
        // The denied transition keeps the obligation mapping: the
        // transaction stays bound to its final denial, so a later
        // challenge request for the same transaction re-encounters the
        // terminal state (never a new stage-1).

        return 'denied_new';
    }

    public function markTransactionDenied(string $chainId, string $obligationId): string
    {
        if (preg_match(self::OBLIGATION_PATTERN, $obligationId) !== 1) {
            throw new \InvalidArgumentException('obligationId must be 64 lowercase hex characters');
        }
        $record = $this->liveRecord($chainId);
        if ($record === null) {
            return 'missing';
        }
        // Obligation-bound (the mirror of the Redis Lua, atomic over
        // both keys): the chain record must still agree on the
        // obligation id and the obligation mapping must still point at
        // this chain; otherwise the transaction's chain moved and
        // nothing is transitioned (fail closed).
        if ($record['obligationId'] !== $obligationId) {
            return 'obligation_moved';
        }
        $mapped = $this->obligations[$obligationId] ?? null;
        if ($mapped === null) {
            // The obligation mapping is gone while the chain survives:
            // the transaction already ended (the mapping is deleted
            // atomically at verification), so there is no chain left to
            // terminalize.
            return 'already_completed';
        }
        if ($mapped !== $chainId) {
            return 'obligation_moved';
        }
        if ($record['state'] === 'denied') {
            return 'denied_same';
        }
        if ($record['state'] === 'step_up_required') {
            return 'conflict';
        }
        if ($record['state'] === 'verified') {
            return 'already_verified';
        }
        if (!\in_array($record['state'], ['available', 'reserved', 'issued', 'completed'], true)) {
            return 'conflict';
        }
        $this->records[$chainId]['state'] = 'denied';
        // The reservation fields are cleared (the terminal state requires
        // owner/leaseUntil null).
        $this->records[$chainId]['owner'] = null;
        $this->records[$chainId]['leaseUntil'] = null;
        // The stage2Nonce field is preserved: the exact stage-2 nonce
        // when one exists (issued/completed), null otherwise
        // (available/reserved); the terminal state carries an optional
        // stage-2 nonce.
        // The denied transition keeps the obligation mapping: the
        // transaction stays bound to its final denial, so a later
        // challenge request for the same transaction re-encounters the
        // terminal state (never a new stage-1).

        return 'denied_new';
    }

    public function markTransactionStepUpRequired(string $chainId, string $obligationId): string
    {
        if (preg_match(self::OBLIGATION_PATTERN, $obligationId) !== 1) {
            throw new \InvalidArgumentException('obligationId must be 64 lowercase hex characters');
        }
        $record = $this->liveRecord($chainId);
        if ($record === null) {
            return 'missing';
        }
        // OBLIGATION-BOUND (the mirror of the Redis Lua — atomic over
        // BOTH keys): the chain record must STILL agree on the
        // obligation id AND the obligation mapping must STILL point at
        // this chain — otherwise the transaction's chain moved and
        // NOTHING is transitioned (fail closed).
        if ($record['obligationId'] !== $obligationId) {
            return 'obligation_moved';
        }
        $mapped = $this->obligations[$obligationId] ?? null;
        if ($mapped === null) {
            // The obligation mapping is GONE while the chain survives —
            // the transaction already ended (the mapping is deleted
            // atomically at verification): there is no chain left to
            // terminalize.
            return 'already_completed';
        }
        if ($mapped !== $chainId) {
            return 'obligation_moved';
        }
        if ($record['state'] === 'step_up_required') {
            return 'step_up_required_same';
        }
        if ($record['state'] === 'denied') {
            return 'conflict';
        }
        if ($record['state'] === 'verified') {
            return 'already_verified';
        }
        if (!\in_array($record['state'], ['available', 'reserved', 'issued', 'completed'], true)) {
            return 'conflict';
        }
        $this->records[$chainId]['state'] = 'step_up_required';
        // The reservation fields are cleared (the terminal state requires
        // owner/leaseUntil null).
        $this->records[$chainId]['owner'] = null;
        $this->records[$chainId]['leaseUntil'] = null;
        // The stage2Nonce field is preserved: the exact stage-2 nonce
        // when one exists (issued/completed), null otherwise
        // (available/reserved); the terminal state carries an optional
        // stage-2 nonce.
        // The step-up transition keeps the obligation mapping: the
        // transaction stays bound to the step-up requirement, so a later
        // challenge request for the same transaction re-encounters the
        // terminal state (never a new stage-1).

        return 'step_up_required_new';
    }

    public function rearmIssued(string $chainId, string $expectedStage2Nonce): bool
    {
        $record = $this->liveRecord($chainId);
        if ($record === null) {
            return false;
        }
        if (($record['state'] !== 'issued' && $record['state'] !== 'completed') || $record['stage2Nonce'] !== $expectedStage2Nonce) {
            return false;
        }
        $this->records[$chainId]['state'] = 'available';
        $this->records[$chainId]['owner'] = null;
        $this->records[$chainId]['leaseUntil'] = null;
        $this->records[$chainId]['stage2Nonce'] = null;

        return true;
    }

    public function deleteObligation(string $chainId, string $obligationId): void
    {
        if (($this->obligations[$obligationId] ?? null) === $chainId) {
            unset($this->obligations[$obligationId]);
        }
    }

    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array
    {
        $record = $this->liveRecord($chainId);
        if ($record === null) {
            return null;
        }
        if ($record['state'] !== 'reserved' || $record['owner'] !== $ownerToken) {
            return null;
        }
        $this->records[$chainId]['state'] = 'completed';
        $this->records[$chainId]['stage2Nonce'] = $stage2Nonce;
        $this->records[$chainId]['owner'] = null;
        $this->records[$chainId]['leaseUntil'] = null;

        return self::wire($this->records[$chainId]);
    }

    /**
     * The live record of a chain: absent -> null, corrupt -> the strict
     * v2 decode throws (fail closed — a corrupt server record can never
     * be transitioned into valid state), expired -> null (the record is
     * cleaned up).
     *
     * @return array<string, mixed>|null
     */
    private function liveRecord(string $chainId): ?array
    {
        $record = $this->records[$chainId] ?? null;
        if ($record === null) {
            return null;
        }
        self::validateState($record);
        if ($record['expiresAt'] <= $this->clock()) {
            unset($this->records[$chainId]);

            return null;
        }

        return $record;
    }

    /**
     * The short reservation lease deadline: the smaller of the
     * reservation lease and the record's own remaining TTL. The whole
     * record expires with the signed ticket, so the lease can never
     * outlive the chain.
     *
     * @param array<string, mixed> $record
     */
    private function leaseDeadline(array $record, int $leaseSecs): int
    {
        $remaining = (int) max(1, $record['expiresAt'] - $this->clock());
        $lease = max(1, $leaseSecs);
        if ($remaining < $lease) {
            $lease = $remaining;
        }

        return (int) $this->clock() + $lease;
    }

    /**
     * The strict v2 decode, all-or-nothing, identical to the Redis
     * store's decode: a missing/malformed field or a state-invariant
     * violation throws {@see MalformedChainedChallengeStateException},
     * never defaults: a corrupt requiredAction must never become '',
     * policyVersion never 1, chainDepth never 2, state never available.
     *
     * @param array<string, mixed> $rec
     *
     * @return array<string, mixed> the validated record
     *
     * @throws MalformedChainedChallengeStateException
     */
    private static function validateState(array $rec): array
    {
        if (($rec['v'] ?? null) !== 2) {
            throw new MalformedChainedChallengeStateException('chain record schema version must be 2');
        }
        $stage1Nonce = $rec['stage1Nonce'] ?? null;
        if (!\is_string($stage1Nonce) || preg_match(self::NONCE_PATTERN, $stage1Nonce) !== 1) {
            throw new MalformedChainedChallengeStateException('chain record stage1Nonce must be a Kiwi base64 nonce');
        }
        $scope = $rec['scope'] ?? null;
        if (!\is_string($scope) || preg_match(self::IDENTIFIER_PATTERN, $scope) !== 1) {
            throw new MalformedChainedChallengeStateException('chain record scope must match the canonical identifier shape');
        }
        $obligationId = $rec['obligationId'] ?? null;
        if (!\is_string($obligationId) || preg_match(self::OBLIGATION_PATTERN, $obligationId) !== 1) {
            throw new MalformedChainedChallengeStateException('chain record obligationId must be 64 lowercase hex characters');
        }
        $requiredAction = $rec['requiredAction'] ?? null;
        if (!\is_string($requiredAction) || !\in_array($requiredAction, self::CHAINABLE_ACTIONS, true)) {
            throw new MalformedChainedChallengeStateException('chain record requiredAction must be a chainable PoW action (Sha16..Argon64)');
        }
        $requiredRank = $rec['requiredRank'] ?? null;
        if (!\is_int($requiredRank) || $requiredRank !== RiskAction::from($requiredAction)->rank()) {
            throw new MalformedChainedChallengeStateException('chain record requiredRank must be the rank of the required action');
        }
        $policyVersion = $rec['policyVersion'] ?? null;
        if (!\is_int($policyVersion) || $policyVersion < 1) {
            throw new MalformedChainedChallengeStateException('chain record policyVersion must be a positive integer');
        }
        if (($rec['chainDepth'] ?? null) !== 2) {
            throw new MalformedChainedChallengeStateException('chain record chainDepth must be exactly 2');
        }
        $state = $rec['state'] ?? null;
        if (!\is_string($state) || !\in_array($state, self::STATES, true)) {
            throw new MalformedChainedChallengeStateException('chain record state must be one of available|reserved|issued|verified|step_up_required|denied');
        }
        $owner = $rec['owner'] ?? null;
        $leaseUntil = $rec['leaseUntil'] ?? null;
        if ($state === 'reserved') {
            if (!\is_string($owner) || $owner === '' || !\is_int($leaseUntil)) {
                throw new MalformedChainedChallengeStateException('chain record owner/leaseUntil are required in the reserved state');
            }
        } elseif ($owner !== null || $leaseUntil !== null) {
            throw new MalformedChainedChallengeStateException('chain record owner/leaseUntil must be null outside the reserved state');
        }
        $stage2Nonce = $rec['stage2Nonce'] ?? null;
        if ($state === 'issued' || $state === 'verified' || $state === 'completed') {
            if (!\is_string($stage2Nonce) || preg_match(self::NONCE_PATTERN, $stage2Nonce) !== 1) {
                throw new MalformedChainedChallengeStateException('chain record stage2Nonce must be a Kiwi base64 nonce in the issued/verified states');
            }
        } elseif ($state === 'step_up_required' || $state === 'denied') {
            // The terminal states carry an optional stage-2 nonce: the
            // exact stage-2 nonce when the chain was issued before the
            // terminal transition, null when the transaction was
            // terminalized without the exact stage-2 nonce (the
            // nonce-agnostic markTransactionDenied() /
            // markTransactionStepUpRequired() terminalizations of an
            // open obligation). A non-null value must still be a valid
            // Kiwi nonce.
            if ($stage2Nonce !== null && (!\is_string($stage2Nonce) || preg_match(self::NONCE_PATTERN, $stage2Nonce) !== 1)) {
                throw new MalformedChainedChallengeStateException('chain record stage2Nonce must be a Kiwi base64 nonce or null in the terminal step_up_required/denied states');
            }
        } elseif ($stage2Nonce !== null) {
            throw new MalformedChainedChallengeStateException('chain record stage2Nonce must be null in the available/reserved states');
        }
        $requestBinding = $rec['requestBinding'] ?? null;
        if ($requestBinding !== null && (!\is_string($requestBinding) || preg_match(self::IDENTIFIER_PATTERN, $requestBinding) !== 1)) {
            throw new MalformedChainedChallengeStateException('chain record requestBinding must match the canonical identifier shape or be null');
        }
        if (!\is_int($rec['expiresAt'] ?? null)) {
            throw new MalformedChainedChallengeStateException('chain record expiresAt must be an integer');
        }

        return $rec;
    }

    /**
     * The wire shape of a strictly-decoded record: the server-held fields
     * without the internal expiry bookkeeping.
     *
     * @param array<string, mixed> $record
     *
     * @return array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, requiredRank: int, policyVersion: int, chainDepth: int, state: 'available'|'reserved'|'issued'|'verified'|'step_up_required'|'denied'|'completed', owner: ?string, leaseUntil: ?int, stage2Nonce: ?string, obligationId: string, expiresAt: int}
     */
    private static function wire(array $record): array
    {
        return [
            'stage1Nonce' => $record['stage1Nonce'],
            'scope' => $record['scope'],
            'requestBinding' => $record['requestBinding'],
            'requiredAction' => $record['requiredAction'],
            'requiredRank' => $record['requiredRank'],
            'policyVersion' => $record['policyVersion'],
            'chainDepth' => $record['chainDepth'],
            'state' => $record['state'],
            'owner' => $record['owner'],
            'leaseUntil' => $record['leaseUntil'],
            'stage2Nonce' => $record['stage2Nonce'],
            'obligationId' => $record['obligationId'],
            'expiresAt' => (int) $record['expiresAt'],
        ];
    }
}
