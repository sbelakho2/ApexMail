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
 * TTL).
 */
final class ArrayPostSolveDispositionStore implements PostSolveDispositionStore
{
    /** The SHORT FIXED computation lease — a contention bound, never the record TTL. */
    private const LEASE_SECS = 15;

    /**
     * @var array<string, array{ttl: int, created: int, state: 'pending'|'complete', owner: ?string, leaseUntil: ?int, disposition: ?PostSolveDisposition}>
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

    public function claim(string $nonce, string $owner, int $ttlSeconds): string
    {
        $now = $this->now();
        if ($this->expired($nonce, $now)) {
            unset($this->records[$nonce]);
        }
        $existing = $this->records[$nonce] ?? null;
        if ($existing === null) {
            $this->records[$nonce] = [
                'ttl' => max(1, $this->ttlSecs > 0 ? $this->ttlSecs : $ttlSeconds),
                'created' => $now,
                'state' => 'pending',
                'owner' => $owner,
                'leaseUntil' => $now + self::LEASE_SECS,
                'disposition' => null,
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

        return new PostSolveDispositionRecord(
            $existing['state'],
            $existing['owner'],
            $existing['leaseUntil'],
            $existing['disposition'],
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

        return true;
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }

    private function expired(string $nonce, int $now): bool
    {
        $existing = $this->records[$nonce] ?? null;

        return $existing !== null && $now > $existing['created'] + $existing['ttl'];
    }
}
