<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * In-memory post-solve disposition store (test/dev semantics — the
 * extension uses the Redis variant whenever a Redis client is available).
 *
 * Mirrors the Redis state machine exactly, with an EXPLICIT clock (the
 * optional `$now` constructor argument, defaulting to time()): claim is
 * the single-writer machine (missing -> pending(me, lease) -> 'claimed';
 * pending+me -> 'pending'; pending+other+live -> 'pending' (busy);
 * pending+other+expired -> takeover -> 'taken_over'; complete ->
 * 'complete'), finalize is the atomic pending(me) -> complete transition
 * (never overwrites another owner's work), and every record expires with
 * its TTL (the SHORT FIXED lease is a contention bound, never the record
 * TTL). The pending record carries the ORIGINAL decision handle the
 * first owner consumed (claim's decision_id); a TAKEOVER keeps it — a
 * completed disposition survives the crash of its first owner with the
 * original decision id.
 *
 * EVERY record is decoded ALL-OR-NOTHING against the strict v1 schema
 * (the identical decode as the Redis store): a missing/malformed field
 * or a state-invariant violation throws
 * {@see MalformedPostSolveDispositionException} — NEVER a defaulted
 * record (an unknown state never becomes pending, a corrupt kind never
 * Pass, a missing disposition never a silent pass). The strict decode
 * runs on the READ path AND before every claim transition: a corrupt
 * server record throws (fail closed), it is NEVER healed into valid
 * state by a takeover.
 */
final class ArrayPostSolveDispositionStore implements PostSolveDispositionStore
{
    /** The SHORT FIXED computation lease — a contention bound, never the record TTL. */
    private const LEASE_SECS = 15;

    /** The chain id shape (base64url of 16 random bytes — the ticket service's alphabet). */
    private const CHAIN_ID_PATTERN = '/^[A-Za-z0-9_-]{1,64}$/D';

    /**
     * @var array<string, array{v: int, ttl: int, created: int, state: 'pending'|'complete', owner: ?string, leaseUntil: ?int, disposition: ?PostSolveDisposition, decisionId: ?string}>
     */
    private array $records = [];

    /**
     * @param \Closure|null $now     test seam: returns the current Unix
     *                               seconds (defaults to time())
     * @param int           $ttlSecs the RECORD TTL (the extension wires
     *                               Config::MAX_TTL_SECS + ttl margin);
     *                               0 = use the per-call claim TTL
     */
    public function __construct(
        private readonly ?\Closure $now = null,
        private readonly int $ttlSecs = 0,
    ) {
    }

    public function claim(string $nonce, string $owner, int $ttlSeconds, ?string $decisionId = null): string
    {
        $now = $this->now();
        if ($this->expired($nonce, $now)) {
            unset($this->records[$nonce]);
        }
        $existing = $this->records[$nonce] ?? null;
        if ($existing !== null) {
            // STRICT PRE-READ: a corrupt record throws (fail closed) — it
            // is NEVER healed into valid state by a takeover.
            self::validateRecord($existing);
        }
        if ($existing === null) {
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

            return 'claimed';
        }
        if ($existing['state'] === 'complete') {
            return 'complete';
        }
        if ($existing['owner'] === $owner) {
            return 'pending';
        }
        if ($existing['leaseUntil'] !== null && $existing['leaseUntil'] > $now) {
            return 'pending';
        }
        // Expired lease: takeover. The ORIGINAL decision handle is
        // PRESERVED (the new owner's GETDEL is empty after the first
        // owner consumed the mapping) — a completed disposition survives
        // the crash of its first owner with the original decision id.
        $this->records[$nonce]['owner'] = $owner;
        $this->records[$nonce]['leaseUntil'] = $now + self::LEASE_SECS;
        $this->records[$nonce]['disposition'] = null;

        return 'taken_over';
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
     * The strict v1 decode — ALL-OR-NOTHING, IDENTICAL to the Redis
     * store's decode: a missing/malformed field or a state-invariant
     * violation throws {@see MalformedPostSolveDispositionException}
     * (NEVER defaults). Validates: schema version 1; the exact state enum
     * (pending|complete — nothing else); a non-empty string owner and an
     * integer lease deadline REQUIRED in pending and NULL in complete;
     * the disposition REQUIRED (a valid typed disposition with a
     * well-shaped decision id / chain id) in complete and NULL in
     * pending; a non-empty string-or-null decision handle in both states.
     *
     * @param array<string, mixed> $record
     *
     * @return array<string, mixed> the validated record
     *
     * @throws MalformedPostSolveDispositionException
     */
    private static function validateRecord(array $record): array
    {
        if (($record['v'] ?? null) !== 1) {
            throw new MalformedPostSolveDispositionException('post-solve disposition record schema version must be 1');
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
        }
        $decisionId = $record['decisionId'] ?? null;
        if ($decisionId !== null && (!\is_string($decisionId) || $decisionId === '')) {
            throw new MalformedPostSolveDispositionException('post-solve disposition record decision_id must be a non-empty string or null');
        }

        return $record;
    }
}
