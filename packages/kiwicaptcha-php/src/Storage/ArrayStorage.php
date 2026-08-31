<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\ConsumedResult;
use KiwiCaptcha\OperationIdentity;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\ResumeDerivationClaimInterface;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\ChallengeRuntimeStateReadableInterface;
use KiwiCaptcha\ChallengeRuntimeStateKind;
use KiwiCaptcha\ChallengeRuntimeState;

/**
 * In-memory storage (single-process, non-persistent). Intended for tests,
 * CLI tools, and single-worker apps where Redis or a database is not
 * available.
 *
 * consume() is the one-shot transition: the record is marked consumed
 * and kept until deletion; replay protection is the consumed marker, not
 * absence. The transition is read-then-write, and the state is a plain
 * in-process array that no other process or thread can observe (PHP
 * copies on fork, so forked children never share it). Because the state
 * is unshareable, the read-modify-write transition is de-facto atomic,
 * and the class therefore implements {@see AtomicStorageInterface}.
 * Shared backends with genuine concurrent access (PSR-6 pools, Redis
 * clients without transactions) must implement the compare-and-set
 * contract themselves; see {@see Psr6Storage} for the documented
 * counter-example.
 *
 * The runtime envelope mirrors the Redis backend: every entry carries the
 * `operation_identity` marker (null | a bounded <= 128-byte
 * logical-operation identity written in the same transition as the state
 * flip via
 * {@see OperationIdentityAwareStorageInterface::consumeWithOperationIdentity()}),
 * exposed on the consumed read. The envelope also carries the terminal
 * `cancelled` marker of
 * {@see \KiwiCaptcha\CancellableStorageInterface::cancel()}; a cancelled
 * record is unverifiable and retained until deletion.
 *
 * Implements {@see \KiwiCaptcha\ResumeDerivationClaimInterface}: the
 * resultless consumed-operation resume can claim the re-derivation
 * ownership in-process, tracked in the same envelope. Exactly one
 * concurrent same-operation recovery derives and commits (the
 * read-modify-write sequence is de-facto atomic here, like every other
 * transition of this backend). The claim carries the same bounded-lease
 * contract as the Redis backend: `resume_until`, the server clock at
 * claim time plus the TTL, bounds the lease; an expired claim is
 * re-claimable, and a stale owner whose claim expired can never commit.
 * The clock comes from the optional `$now` constructor closure, which
 * defaults to `time()`, the same test seam the {@see Verifier} uses.
 * Shared claim contract (both languages agree): a valid owner is
 * exactly 32 lowercase hex characters (rejected with
 * InvalidArgumentException at the storage boundary otherwise) and the
 * claim lease TTL is >= 1 second.
 *
 * Expiry semantics (Redis TTL parity): a record whose expires_at has
 * passed on the storage clock is absent. `find()` returns null, consume
 * and the consume-with-identity transition report missing, and the
 * retained consumed state is null. The runtime state is Missing, the
 * fused cleanup answers missing, cancel is idempotently null and the
 * result commit refuses, exactly what the Redis backend's key TTLs
 * give. The expiry boundary matches the verifier's own
 * (`now >= expires_at`). A verifier fail-closed on a record the storage
 * still holds is an availability property, never a security one.
 *
 * Retention margin, {@see self::$retentionMarginSecs} with default 0: the
 * storage keeps a record readable for `retentionMarginSecs` seconds
 * beyond its signed expires_at, the exact mirror of the Redis
 * backend's `ttlMarginSecs`. The bundle forces that margin on
 * siteverify deployments so the retained consumed-state evidence
 * outlives the maximum takeover and retry horizon. With the default 0
 * the boundary is exactly `expires_at`, the Redis-margin-0 shape. With
 * a margin the record stays physically present inside the window
 * `[expires_at, expires_at + margin)`. There the verifier's own TTL
 * check still rejects it as Expired, or resolves a retained outcome
 * through the replay-exempt consumed branch. This is never a security
 * weakening, only the retention window the production margin gives.
 *
 * Bounded retention: `store()` first prunes expired entries. When the
 * map is at the hard cap, {@see self::DEFAULT_MAX_ENTRIES} or the
 * constructor's $maxEntries, it evicts the earliest-expiring entries
 * first, so a long-lived CLI process sharing one storage instance can
 * never accumulate unbounded state.
 */
final class ArrayStorage implements AtomicStorageInterface, \KiwiCaptcha\ConsumedStateReadableInterface, OperationIdentityAwareStorageInterface, \KiwiCaptcha\AtomicDeleteIfPendingInterface, \KiwiCaptcha\CancellableStorageInterface, \KiwiCaptcha\ChallengeRuntimeStateReadableInterface, ResumeDerivationClaimInterface
{
    /**
     * The default hard cap on retained entries. `store()` prunes
     * expired records first and then, only when the map is at the cap,
     * evicts the earliest-expiring entries. A long-lived CLI process
     * sharing one storage instance stays memory-bounded, matching what
     * the Redis backend gets for free from key TTLs.
     */
    public const DEFAULT_MAX_ENTRIES = 10_000;

    /** @var array<string, array{record: ChallengeRecord, consumed: bool, cancelled: bool, result: ConsumedResult|null, operationIdentity: string|null, claim: string|null, claimUntil: int|null}> */
    private array $records = [];

    /**
     * @param \Closure|null $now                  the clock override (epoch
     *                                            seconds) used for the
     *                                            resume-claim lease and the
     *                                            expiry semantics; defaults
     *                                            to `time()`. Test seam,
     *                                            same style as
     *                                            {@see Verifier}'s `$now`.
     * @param int           $maxEntries           the hard cap on retained
     *                                            entries (>= 1). `store()`
     *                                            prunes expired records
     *                                            first and evicts the
     *                                            oldest-expiring entries
     *                                            only when the cap would be
     *                                            exceeded.
     * @param int           $retentionMarginSecs  extra retention beyond the
     *                                            signed expires_at (>= 0),
     *                                            mirroring the Redis
     *                                            backend's `ttlMarginSecs`.
     *                                            The storage keeps the
     *                                            record readable inside
     *                                            `[expires_at, expires_at +
     *                                            margin)` so retained
     *                                            consumed-state evidence
     *                                            outlives the signed
     *                                            lifetime; the default 0 is
     *                                            the strict Redis-TTL-parity
     *                                            boundary.
     *
     * @throws \InvalidArgumentException when $maxEntries is below 1, or
     *                                   $retentionMarginSecs below 0
     */
    public function __construct(
        private readonly ?\Closure $now = null,
        private readonly int $maxEntries = self::DEFAULT_MAX_ENTRIES,
        private readonly int $retentionMarginSecs = 0,
    ) {
        if ($this->maxEntries < 1) {
            throw new \InvalidArgumentException('maxEntries must be at least 1');
        }
        if ($this->retentionMarginSecs < 0) {
            throw new \InvalidArgumentException('retentionMarginSecs must be at least 0');
        }
    }

    public function store(ChallengeRecord $record): void
    {
        // Bounded retention: expired entries never accumulate (they are
        // absent to every read anyway, see {@see self::entry()}), and a
        // long-lived process never exceeds the hard cap — the evictions
        // drop the entries that expire soonest first, mirroring what
        // Redis key TTLs do for the other backend.
        $this->pruneExpired();
        $needed = (isset($this->records[$record->nonce]) ? 0 : 1) + \count($this->records) - $this->maxEntries;
        if ($needed > 0) {
            $byExpiry = [];
            foreach ($this->records as $nonce => $entry) {
                $byExpiry[$nonce] = $entry['record']->expiresAt;
            }
            asort($byExpiry);
            $evictables = array_keys($byExpiry);
            for ($i = 0; $i < $needed; $i++) {
                unset($this->records[$evictables[$i]]);
            }
        }
        $this->records[$record->nonce] = ['record' => $record, 'consumed' => false, 'cancelled' => false, 'result' => null, 'operationIdentity' => null, 'claim' => null, 'claimUntil' => null];
    }

    public function find(string $nonce): ?ChallengeRecord
    {
        return $this->entry($nonce)['record'] ?? null;
    }

    public function consume(string $nonce): ?ConsumedRecord
    {
        $entry = $this->entry($nonce);
        if ($entry === null) {
            return null;
        }
        if (($entry['cancelled'] ?? false)) {
            // A cancelled record is never consumable: the one-shot
            // transition reports it as missing, mirroring the Redis
            // backend's raw-splice gsub failure (the verifier then fails
            // the token closed instead of ever redeeming it).
            return null;
        }
        if ($entry['consumed']) {
            return new ConsumedRecord($entry['record'], false, true, $entry['result'], $entry['operationIdentity']);
        }
        // The pending-envelope guard (the in-process mirror of the Redis
        // consume script's raw-marker check): a pending record must not
        // carry any terminal or claim field — a result, an operation
        // identity, or a resume-claim lease. Only the consume transition
        // itself may introduce them; a pending record that already
        // carries one is refused with the missing semantics (null).
        if ($entry['result'] !== null || $entry['operationIdentity'] !== null || $entry['claim'] !== null) {
            return null;
        }
        $this->records[$nonce]['consumed'] = true;

        return new ConsumedRecord($entry['record'], true, false, null, null);
    }

    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
    {
        // The identity, validated against the narrow shared alphabet via
        // {@see OperationIdentity::validate()} (1..128 bytes of
        // [A-Za-z0-9_-]), lands in the same write as the state flip. A
        // malformed identity is rejected with InvalidArgumentException,
        // never silently dropped.
        $validated = OperationIdentity::validate($operationIdentity);
        $entry = $this->entry($nonce);
        if ($entry === null) {
            return null;
        }
        if (($entry['cancelled'] ?? false)) {
            return null;
        }
        if ($entry['consumed']) {
            return new ConsumedRecord($entry['record'], false, true, $entry['result'], $entry['operationIdentity']);
        }
        // The pending-envelope guard, mirroring the Redis consume
        // script's raw-marker check: a pending record that already
        // carries a result, an operation identity or a resume-claim
        // lease is refused with the missing semantics.
        if ($entry['result'] !== null || $entry['operationIdentity'] !== null || $entry['claim'] !== null) {
            return null;
        }
        $this->records[$nonce]['consumed'] = true;
        if ($validated !== null) {
            $this->records[$nonce]['operationIdentity'] = $validated;
        }

        return new ConsumedRecord($entry['record'], true, false, null, $this->records[$nonce]['operationIdentity']);
    }

    public function consumedState(string $nonce): ?ConsumedRecord
    {
        $entry = $this->entry($nonce);
        if ($entry === null || !$entry['consumed']) {
            return null;
        }

        return new ConsumedRecord($entry['record'], false, true, $entry['result'], $entry['operationIdentity']);
    }

    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        $entry = $this->entry($nonce);
        if ($entry === null || !$entry['consumed'] || $entry['result'] !== null) {
            return false;
        }
        $this->records[$nonce]['result'] = new ConsumedResult($valid, $binding);

        return true;
    }

    public function delete(string $nonce): void
    {
        unset($this->records[$nonce]);
    }

    /**
     * The resume-claim transition (in-process de-facto atomic, like the
     * other transitions here) claims the re-derivation ownership of a
     * consumed, resultless record and returns a fresh random owner
     * token. It returns null when the record is missing, not consumed,
     * already committed, cancelled, or already claimed by a live lease.
     * The lease is bounded like the Redis backend: `claimUntil` is the
     * current clock plus the TTL, a claim whose `claimUntil` has passed
     * is dead and re-claimable, and the clock comes from the optional
     * `$now` closure, which defaults to `time()`.
     *
     * @param int $ttlSecs the claim lease length in seconds (>= 1).
     *                     Shared claim contract: a TTL below 1 second
     *                     is rejected at the storage boundary with an
     *                     InvalidArgumentException.
     *
     * @throws \InvalidArgumentException when $ttlSecs is below 1
     */
    public function claimResumeDerivation(string $nonce, int $ttlSecs = 60): ?string
    {
        if ($ttlSecs < 1) {
            throw new \InvalidArgumentException('the resume claim TTL must be at least 1 second');
        }
        $entry = $this->entry($nonce);
        if ($entry === null || !$entry['consumed'] || ($entry['cancelled'] ?? false) || $entry['result'] !== null) {
            return null;
        }
        $now = $this->nowInSeconds();
        if (($entry['claim'] ?? null) !== null && ($entry['claimUntil'] ?? null) !== null && ($entry['claimUntil'] ?? 0) > $now) {
            return null;
        }
        $owner = bin2hex(random_bytes(16));
        $this->records[$nonce]['claim'] = $owner;
        $this->records[$nonce]['claimUntil'] = $now + $ttlSecs;

        return $owner;
    }

    /**
     * Compare-and-delete release of the resume claim: clears the claim
     * only when it still holds exactly this owner token; a stale owner
     * can never delete a newer recovery's claim.
     *
     * Shared claim contract (mirrors the Redis backend and the Rust
     * verifier): a valid owner is exactly 32 lowercase hex characters,
     * and any other shape is rejected at the storage boundary with an
     * InvalidArgumentException.
     *
     * @throws \InvalidArgumentException when the owner is not 32 lowercase hex chars
     */
    public function releaseResumeDerivation(string $nonce, string $owner): bool
    {
        $this->assertValidResumeOwner($owner);
        $entry = $this->entry($nonce);
        if ($entry === null || ($entry['claim'] ?? null) !== $owner) {
            return false;
        }
        $this->records[$nonce]['claim'] = null;
        $this->records[$nonce]['claimUntil'] = null;

        return true;
    }

    /**
     * The resume-path commit that clears the re-derivation claim with
     * the result write (in-process de-facto atomic): the same one-shot
     * semantics as commitResult() with the claim as a fencing
     * precondition. The caller must still hold a live claim; a stale
     * owner — a different token, or a token whose lease expired — can
     * never commit, and the successful write clears the claim.
     *
     * Shared claim contract (mirrors the Redis backend and the Rust
     * verifier): a valid owner is exactly 32 lowercase hex characters,
     * and any other shape is rejected at the storage boundary with an
     * InvalidArgumentException.
     *
     * @throws \InvalidArgumentException when the owner is not 32 lowercase hex chars
     */
    public function commitResultResume(string $nonce, bool $valid, ?string $binding, string $owner): bool
    {
        $this->assertValidResumeOwner($owner);
        $entry = $this->entry($nonce);
        if ($entry === null || !$entry['consumed'] || ($entry['cancelled'] ?? false) || $entry['result'] !== null) {
            return false;
        }
        $now = $this->nowInSeconds();
        if (($entry['claim'] ?? null) !== $owner || ($entry['claimUntil'] ?? null) === null || ($entry['claimUntil'] ?? 0) <= $now) {
            return false;
        }
        $this->records[$nonce]['result'] = new ConsumedResult($valid, $binding);
        $this->records[$nonce]['claim'] = null;
        $this->records[$nonce]['claimUntil'] = null;

        return true;
    }

    /**
     * The shared resume-claim owner contract: exactly 32 lowercase hex
     * characters (the bin2hex of 16 random bytes the claim API mints),
     * identical to the Redis backend and the Rust verifier.
     *
     * @throws \InvalidArgumentException
     */
    private function assertValidResumeOwner(string $owner): void
    {
        if (preg_match('/^[0-9a-f]{32}$/D', $owner) !== 1) {
            throw new \InvalidArgumentException('the resume claim owner must be exactly 32 lowercase hex characters');
        }
    }

    /**
     * The storage clock: the constructor's $now closure (epoch seconds)
     * or the wall clock. Shared by the expiry semantics, the resume
     * claim lease and the pruning pass.
     */
    private function nowInSeconds(): int
    {
        return $this->now !== null ? (int) ($this->now)() : time();
    }

    /**
     * The live entry, or null when the nonce is absent or its record
     * has expired, the Redis TTL semantics: an expired key is
     * indistinguishable from a missing one on every read and transition.
     * `find()` returns null, consume reports missing, the runtime state
     * is Missing, the cleanup is missing, and cancel is idempotently
     * null. The expiry boundary is
     * `now >= expires_at + retentionMarginSecs`. With the default margin
     * 0 that is exactly the verifier's own `now >= expires_at`, so a
     * record this backend reports present is exactly one the verifier
     * would not immediately fail as Expired. Inside a configured margin
     * window the record stays readable while the verifier's TTL check
     * still rejects it, the retained-evidence window the Redis
     * ttlMarginSecs gives. The lazy unset also evicts the expired entry
     * from the map on first observation.
     *
     * @return array{record: ChallengeRecord, consumed: bool, cancelled: bool, result: ConsumedResult|null, operationIdentity: string|null, claim: string|null, claimUntil: int|null}|null
     */
    private function entry(string $nonce): ?array
    {
        $entry = $this->records[$nonce] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($this->nowInSeconds() >= $entry['record']->expiresAt + $this->retentionMarginSecs) {
            unset($this->records[$nonce]);

            return null;
        }

        return $entry;
    }

    /**
     * Drop every expired entry from the map (the bounded-retention half
     * of {@see self::store()}): an entry no read can observe never
     * accumulates in a long-lived process.
     */
    private function pruneExpired(): void
    {
        $now = $this->nowInSeconds();
        foreach ($this->records as $nonce => $entry) {
            if ($now >= $entry['record']->expiresAt + $this->retentionMarginSecs) {
                unset($this->records[$nonce]);
            }
        }
    }

    /**
     * The fused cleanup transition. The state is a plain in-process
     * array no other process can observe, so the read-decide-delete
     * sequence is de-facto atomic here. A missing record reports
     * missing, a pending record is deleted, and a consumed record is
     * kept untouched with its retained state riding back on the answer —
     * the same tri-state contract as the Redis backend's Lua script. A
     * cancelled record is kept too: dead but retained until its TTL.
     *
     * No replica barrier: this backend has no replicas, so the verified
     * WAIT durability contract of the Redis backend's delete-if-pending
     * transition does not apply — there is nothing to replicate, and a
     * delete cannot be resurrected by a promoted stale replica.
     */
    public function deleteIfPending(string $nonce): \KiwiCaptcha\DeleteIfPendingResult
    {
        $entry = $this->entry($nonce);
        if ($entry === null) {
            return new \KiwiCaptcha\DeleteIfPendingResult('missing');
        }
        if ($entry['consumed']) {
            return new \KiwiCaptcha\DeleteIfPendingResult(
                'consumed',
                new ConsumedRecord($entry['record'], false, true, $entry['result'], $entry['operationIdentity']),
            );
        }
        if (($entry['cancelled'] ?? false)) {
            // A cancelled record is dead but retained until its TTL — the
            // cleanup never deletes it, so a cancellation can never be
            // resurrected as pending (mirrors the Redis backend's
            // delete-if-pending script).
            return new \KiwiCaptcha\DeleteIfPendingResult('cancelled');
        }
        unset($this->records[$nonce]);

        return new \KiwiCaptcha\DeleteIfPendingResult('deleted-pending');
    }

    /**
     * The atomic cancellation transition (in-process de-facto atomic, like
     * the other transitions here): a pending record is marked cancelled
     * and kept; a consumed record is finalized and never cancellable; an
     * already-cancelled record is idempotent; a missing record is null.
     */
    public function runtimeState(string $nonce): ChallengeRuntimeState
    {
        $entry = $this->entry($nonce);
        if ($entry === null) {
            return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Missing);
        }
        if ($entry['cancelled'] ?? false) {
            return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Cancelled, $entry['record']);
        }
        if ($entry['consumed']) {
            return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Consumed, $entry['record'], new ConsumedRecord($entry['record'], false, true, $entry['result'], $entry['operationIdentity']));
        }

        return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Pending, $entry['record']);
    }

    public function cancel(string $nonce): ?\KiwiCaptcha\CancellationResult
    {
        $entry = $this->entry($nonce);
        if ($entry === null) {
            return null;
        }
        if ($entry['consumed']) {
            return new \KiwiCaptcha\CancellationResult('consumed');
        }
        if (($entry['cancelled'] ?? false)) {
            return new \KiwiCaptcha\CancellationResult('cancelled');
        }
        $this->records[$nonce]['cancelled'] = true;

        return new \KiwiCaptcha\CancellationResult('cancelled-now');
    }
}
