<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * In-memory chained-challenge state store for tests/dev (single-process
 * semantics), mirroring the Redis store's owner-scoped three-state machine
 * exactly: available -> reserved(owner, leaseUntil) -> completed(
 * stage2Nonce), with an owner-gated release undoing a reservation and an
 * owner-gated complete transitioning to the TERMINAL completed state (a
 * completed record is kept — never deleted — so a retry recovers the
 * issued challenge). A non-owner release/complete is an atomic no-op, and
 * an expired lease is taken over by the next reserving owner.
 *
 * EXPLICIT CLOCK: the store runs on a caller-provided clock (unix
 * seconds, defaulting to microtime(true)) so the record TTL and the
 * reservation lease expiry are enforceable — tests advance the clock to
 * exercise the expired-lease takeover, mirroring redis TIME on the
 * production store.
 */
final class ArrayChainedChallengeStateStore implements ChainedChallengeStateStore
{
    /**
     * @var array<string, array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, policyVersion: int, chainDepth: int, state: 'available'|'reserved'|'completed', owner: ?string, leaseUntil: ?int, stage2Nonce: ?string, expiresAt: float}>
     */
    private array $records = [];

    /**
     * @param \Closure|null $now test seam: returns the current unix
     *                           seconds (defaults to microtime(true))
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
        $this->records[$chainId] = [
            'stage1Nonce' => $stage1Nonce,
            'scope' => $scope,
            'requestBinding' => $requestBinding,
            'requiredAction' => $requiredAction,
            'policyVersion' => $policyVersion,
            'chainDepth' => 2,
            'state' => 'available',
            'owner' => null,
            'leaseUntil' => null,
            'stage2Nonce' => null,
            'expiresAt' => $this->clock() + max(1, $ttlSecs),
        ];
    }

    public function read(string $chainId): ?array
    {
        $record = $this->records[$chainId] ?? null;
        if ($record === null || $record['expiresAt'] <= $this->clock()) {
            unset($this->records[$chainId]);

            return null;
        }

        return self::wire($record);
    }

    public function reserve(string $chainId, string $ownerToken, int $ttlSecs): string
    {
        $record = $this->records[$chainId] ?? null;
        if ($record === null || $record['expiresAt'] <= $this->clock()) {
            unset($this->records[$chainId]);

            return 'missing';
        }
        if ($record['state'] === 'completed') {
            return 'completed';
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
        }
        $this->records[$chainId]['state'] = 'reserved';
        $this->records[$chainId]['owner'] = $ownerToken;
        $this->records[$chainId]['leaseUntil'] = (int) ($this->clock() + max(1, $record['expiresAt'] - $this->clock()));

        return 'available';
    }

    public function release(string $chainId, string $ownerToken): void
    {
        $record = $this->records[$chainId] ?? null;
        if ($record === null || $record['expiresAt'] <= $this->clock()) {
            unset($this->records[$chainId]);

            return;
        }
        if ($record['state'] !== 'reserved' || $record['owner'] !== $ownerToken) {
            return;
        }
        $this->records[$chainId]['state'] = 'available';
        $this->records[$chainId]['owner'] = null;
        $this->records[$chainId]['leaseUntil'] = null;
    }

    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array
    {
        $record = $this->records[$chainId] ?? null;
        if ($record === null || $record['expiresAt'] <= $this->clock()) {
            unset($this->records[$chainId]);

            return null;
        }
        if ($record['state'] !== 'reserved' || $record['owner'] !== $ownerToken) {
            return null;
        }
        $this->records[$chainId]['state'] = 'completed';
        $this->records[$chainId]['stage2Nonce'] = $stage2Nonce;

        return self::wire($this->records[$chainId]);
    }

    /**
     * The wire shape of a record: the server-held fields without the
     * internal expiry bookkeeping.
     *
     * @param array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, policyVersion: int, chainDepth: int, state: 'available'|'reserved'|'completed', owner: ?string, leaseUntil: ?int, stage2Nonce: ?string, expiresAt: float} $record
     *
     * @return array{stage1Nonce: string, scope: string, requestBinding: ?string, requiredAction: string, policyVersion: int, chainDepth: int, state: 'available'|'reserved'|'completed', owner: ?string, leaseUntil: ?int, stage2Nonce: ?string}
     */
    private static function wire(array $record): array
    {
        return [
            'stage1Nonce' => $record['stage1Nonce'],
            'scope' => $record['scope'],
            'requestBinding' => $record['requestBinding'],
            'requiredAction' => $record['requiredAction'],
            'policyVersion' => $record['policyVersion'],
            'chainDepth' => $record['chainDepth'],
            'state' => $record['state'],
            'owner' => $record['owner'],
            'leaseUntil' => $record['leaseUntil'],
            'stage2Nonce' => $record['stage2Nonce'],
        ];
    }
}
