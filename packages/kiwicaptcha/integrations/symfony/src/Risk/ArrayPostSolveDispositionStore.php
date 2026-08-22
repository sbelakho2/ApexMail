<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * In-memory post-solve disposition store for test/dev semantics. The
 * extension uses the Redis variant whenever a Redis client is available.
 *
 * Mirrors the Redis state machine exactly, with an explicit clock: the
 * optional `$now` constructor argument defaults to time(). Claim is the
 * single-writer machine: missing -> pending(me, lease) -> 'claimed';
 * pending+me -> 'pending'; pending+other+live -> 'pending' (busy);
 * pending+other+expired -> takeover -> 'taken_over'; complete ->
 * 'complete'. The claim response carries the claim outcome and the
 * record the caller needs: the pending record on claimed/taken_over
 * (the consumed decision handle), and the complete record on complete.
 * The caller runs claim -> compute -> finalize with no separate read,
 * the exact mirror of the Redis claim Lua's response. Finalize is the
 * atomic pending(me) -> complete transition and never overwrites another
 * owner's work. Every record expires with its TTL; the short fixed lease
 * is a contention bound, never the record TTL. The machine reads the
 * existing state before touching anything else: a complete claim, a busy
 * claim and a takeover never consume the nonce -> decision mapping. Only
 * the missing path consumes it, with getdel semantics and at most one
 * winner, and persists the paired decision id in the pending record in
 * the same transition, the exact mirror of the Redis claim Lua's keys[2]
 * transfer. The pending record carries the original decision handle the
 * first owner's claim consumed; a takeover keeps it, so a completed
 * disposition survives the crash of its first owner with the original
 * decision id.
 *
 * Every record is decoded all-or-nothing against the strict schema, the
 * identical decode as the Redis store: a missing/malformed field or a
 * state-invariant violation throws
 * {@see MalformedPostSolveDispositionException}, never a defaulted
 * record. An unknown state never becomes pending, a corrupt kind never
 * Pass, a missing disposition never a silent pass, and a ChainRequired
 * record without its chain expiry bound never a ticket. The decoder
 * accepts both schema versions 1 and 2: new writes are v1, where
 * chain_required carries chain_expires_at, a shape an earlier release
 * already reads. A v1 chain_required record with a null carried expiry
 * is a legacy record: the signing falls back to the exact chain
 * record's server-held bound, never corrupt. Any other v1 violation
 * stays corrupt, and a v2 chain_required record requires a positive
 * chain expiry, the forward-looking v2 acceptance. The strict decode
 * runs on the read path and before every claim transition: a corrupt
 * server record throws (fail closed) and is never healed into valid
 * state by a takeover.
 */
final class ArrayPostSolveDispositionStore implements PostSolveDispositionStore
{
    /** The short fixed computation lease — a contention bound, never the record TTL. */
    private const LEASE_SECS = 15;

    /** The chain id shape (base64url of 16 random bytes — the ticket service's alphabet). */
    private const CHAIN_ID_PATTERN = '/^[A-Za-z0-9_-]{1,64}$/D';

    /**
     * @var array<string, array{v: int, ttl: int, created: int, state: 'pending'|'complete', owner: ?string, leaseUntil: ?int, disposition: ?PostSolveDisposition, decisionId: ?string}>
     */
    private array $records = [];

    /**
     * @param \Closure|null $now         test seam: returns the current Unix
     *                                   seconds, defaulting to time().
     * @param int           $ttlSecs     the record TTL (the extension wires
     *                                   Config::MAX_TTL_secs + ttl margin);
     *                                   0 = use the per-call claim TTL.
     * @param \ArrayAccess|null $decisionMap the shared nonce -> decision
     *                                   mapping, keyed by the full decision
     *                                   key ({kiwi:<ns>}:decision:<nonce>),
     *                                   the test/dev mirror of the gateway's
     *                                   decision Redis: the claim consumes
     *                                   the mapping (getdel semantics) inside
     *                                   the same operation as the claim.
     *                                   null = no decision transfer (the
     *                                   records carry null).
     */
    public function __construct(
        private readonly ?\Closure $now = null,
        private readonly int $ttlSecs = 0,
        private readonly ?\ArrayAccess $decisionMap = null,
    ) {
    }

    public function claim(string $nonce, string $owner, int $ttlSeconds, ?string $decisionKey = null): array
    {
        $now = $this->now();
        if ($this->expired($nonce, $now)) {
            unset($this->records[$nonce]);
        }
        $existing = $this->records[$nonce] ?? null;
        if ($existing !== null) {
            // strict validation: a corrupt record throws (fail closed) — it
            // is never healed into valid state by a takeover.
            self::validateRecord($existing);
            if ($existing['state'] === 'complete') {
                // A completed disposition is terminal: the replay claim
                // answers 'complete' with the complete record and never
                // touches the decision key.
                return ['complete', self::recordFromExisting($existing)];
            }
            if ($existing['owner'] === $owner) {
                return ['pending', null];
            }
            if ($existing['leaseUntil'] !== null && $existing['leaseUntil'] > $now) {
                // Another owner's claim is live: busy — the decision key
                // is never touched (the mapping stays resolvable for the
                // caller who will win the next claim).
                return ['pending', null];
            }
            // Expired lease: takeover. The original decision handle is
            // preserved — a takeover never consumes the decision mapping
            // (the fresh mapping belongs to the caller who will win the
            // next claim): a completed disposition survives the crash of
            // its first owner with the original decision id.
            $this->records[$nonce]['owner'] = $owner;
            $this->records[$nonce]['leaseUntil'] = $now + self::LEASE_SECS;
            $this->records[$nonce]['disposition'] = null;

            return ['taken_over', self::recordFromExisting($this->records[$nonce])];
        }
        // missing: the only path that consumes the decision mapping
        // (getdel semantics, at most one winner) — the paired decision id
        // is persisted in the pending record in the same operation (the
        // mirror of the Redis claim Lua's keys[2] transfer).
        $decisionId = $this->consumeDecision($decisionKey);
        $this->records[$nonce] = [
            'v' => 1,
            'ttl' => max(1, $this->ttlSecs > 0 ? $this->ttlSecs : $ttlSeconds),
            'created' => $now,
            'state' => 'pending',
            'owner' => $owner,
            'leaseUntil' => $now + self::LEASE_SECS,
            'disposition' => null,
            'decisionId' => $decisionId,
        ];

        return ['claimed', self::recordFromExisting($this->records[$nonce])];
    }

    /**
     * getdel the nonce -> decision mapping (mirror of the Redis claim
     * Lua): returns the paired decision id, or null when no mapping is
     * wired/keyed/decodable. The mapping is removed on consumption — at
     * most one claim wins, exactly like the gateway's getdel.
     */
    private function consumeDecision(?string $decisionKey): ?string
    {
        if ($decisionKey === null || $this->decisionMap === null || !$this->decisionMap->offsetExists($decisionKey)) {
            return null;
        }
        $raw = $this->decisionMap[$decisionKey];
        $this->decisionMap->offsetUnset($decisionKey);
        if (!\is_string($raw) || $raw === '') {
            return null;
        }
        $data = json_decode($raw, true);

        return \is_array($data) && \is_string($data['decision_id'] ?? null) ? $data['decision_id'] : null;
    }

    public function read(string $nonce): ?PostSolveDispositionRecord
    {
        $now = $this->now();
        if ($this->expired($nonce, $now)) {
            unset($this->records[$nonce]);

            return null;
        }
        $existing = $this->records[$nonce] ?? null;
        if ($existing === null) {
            return null;
        }
        self::validateRecord($existing);

        return self::recordFromExisting($existing);
    }

    /**
     * Build the typed record from a validated in-memory record (the
     * pending claim state + owner + lease deadline + decision handle, or
     * the complete state + persisted disposition + decision handle).
     *
     * @param array<string, mixed> $existing the validated record
     */
    private static function recordFromExisting(array $existing): PostSolveDispositionRecord
    {
        return new PostSolveDispositionRecord(
            $existing['state'],
            $existing['owner'],
            $existing['leaseUntil'],
            $existing['disposition'],
            $existing['decisionId'] ?? null,
        );
    }

    public function finalize(string $nonce, string $owner, PostSolveDisposition $disposition): bool
    {
        $now = $this->now();
        if ($this->expired($nonce, $now)) {
            unset($this->records[$nonce]);

            return false;
        }
        $existing = $this->records[$nonce] ?? null;
        if ($existing === null || $existing['state'] !== 'pending' || $existing['owner'] !== $owner) {
            return false;
        }
        $this->records[$nonce]['state'] = 'complete';
        $this->records[$nonce]['owner'] = null;
        $this->records[$nonce]['leaseUntil'] = null;
        $this->records[$nonce]['disposition'] = $disposition;
        // The decision handle survives in the complete record.
        $this->records[$nonce]['decisionId'] = $existing['decisionId'] ?? null;

        return true;
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }

    private function expired(string $nonce, int $now): bool
    {
        $existing = $this->records[$nonce] ?? null;
        if ($existing === null || !isset($existing['created'], $existing['ttl'])) {
            return false;
        }

        return $now > $existing['created'] + $existing['ttl'];
    }

    /**
     * The strict decode, all-or-nothing, identical to the Redis store's
     * decode: a missing/malformed field or a state-invariant violation
     * throws {@see MalformedPostSolveDispositionException}, never
     * defaults. It validates schema version 1 or 2 within the
     * compatibility window: v2 carries the strict chain-expiry
     * requirement, and v1 additionally accepts a legacy chain_required
     * record with a null carried expiry; every other rule is identical
     * for both versions. The state must be exactly pending|complete. A
     * non-empty string owner and an integer lease deadline are required
     * in pending and null in complete. The disposition is required in
     * complete and null in pending: a valid typed disposition with a
     * well-shaped decision id or chain id, plus the chain expiry integer
     * required on the ChainRequired kind, v1 legacy excepted, and null
     * outside it. The decision handle must be a non-empty string or null
     * in both states.
     *
     * @param array<string, mixed> $record
     *
     * @return array<string, mixed> the validated record
     *
     * @throws MalformedPostSolveDispositionException
     */
    private static function validateRecord(array $record): array
    {
        $version = $record['v'] ?? null;
        if ($version !== 1 && $version !== 2) {
            throw new MalformedPostSolveDispositionException('post-solve disposition record schema version must be 1 or 2');
        }
        $state = $record['state'] ?? null;
        if (!\is_string($state) || !\in_array($state, ['pending', 'complete'], true)) {
            throw new MalformedPostSolveDispositionException('post-solve disposition record state must be pending|complete');
        }
        $owner = $record['owner'] ?? null;
        $leaseUntil = $record['leaseUntil'] ?? null;
        $disposition = $record['disposition'] ?? null;
        if ($state === 'pending') {
            if (!\is_string($owner) || $owner === '') {
                throw new MalformedPostSolveDispositionException('post-solve disposition record owner is required in the pending state');
            }
            if (!\is_int($leaseUntil)) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record lease_until must be an integer in the pending state');
            }
            if ($disposition !== null) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record disposition must be null in the pending state');
            }
        } else {
            if ($owner !== null || $leaseUntil !== null) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record owner/lease_until must be null in the complete state');
            }
            if (!$disposition instanceof PostSolveDisposition) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record disposition is required in the complete state');
            }
            if ($disposition->decisionId !== null && $disposition->decisionId === '') {
                throw new MalformedPostSolveDispositionException('post-solve disposition record decision_id must be a non-empty string or null');
            }
            if ($disposition->chainId !== null && preg_match(self::CHAIN_ID_PATTERN, $disposition->chainId) !== 1) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record chain_id must match the chain id shape or be null');
            }
            if ($disposition->kind === PostSolveDispositionKind::ChainRequired && ($disposition->chainId === null || $disposition->chainId === '')) {
                throw new MalformedPostSolveDispositionException('a ChainRequired disposition must carry a chain id');
            }
            if ($disposition->kind !== PostSolveDispositionKind::ChainRequired && $disposition->chainId !== null) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record chain_id must be null outside the ChainRequired kind');
            }
            // The ChainRequired record carries its chain's original expiry
            // bound (the signing never re-consults the obligation): under
            // v2 the bound is required on the kind and null outside it —
            // a ChainRequired v2 record without it is malformed state,
            // never a ticket. A v1 chain_required record with a null
            // carried expiry is a legacy record (the shape of the earlier
            // store generation): the signing falls back to the exact
            // chain record's server-held bound — never corrupt.
            if ($disposition->kind === PostSolveDispositionKind::ChainRequired) {
                if (!($version === 1 && $disposition->chainExpiresAt === null) && (!\is_int($disposition->chainExpiresAt) || $disposition->chainExpiresAt <= 0)) {
                    throw new MalformedPostSolveDispositionException('a ChainRequired disposition record must carry a positive integer chain expiry');
                }
            } elseif ($disposition->chainExpiresAt !== null) {
                throw new MalformedPostSolveDispositionException('post-solve disposition record chain expiry must be null outside the ChainRequired kind');
            }
        }
        $decisionId = $record['decisionId'] ?? null;
        if ($decisionId !== null && (!\is_string($decisionId) || $decisionId === '')) {
            throw new MalformedPostSolveDispositionException('post-solve disposition record decision_id must be a non-empty string or null');
        }

        return $record;
    }
}
