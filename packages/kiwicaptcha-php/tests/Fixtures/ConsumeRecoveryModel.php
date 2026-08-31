<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

use PHPUnit\Framework\Assert;

/**
 * The clean-room abstract model of the consume / commit / recovery state
 * machine of the one-shot challenge storages (RedisStorage and
 * ArrayStorage), written independently from the stores so the concrete
 * implementations can be checked against it.
 *
 * Per-record state:
 *
 *  - pending: the issued, not-yet-consumed record.
 *  - consumed_resultless: the consume transition won, the deterministic
 *    derivation result not yet committed (a crash window).
 *  - committed_valid / committed_invalid: the deterministic result was
 *    committed. The record also records the logical-operation identity
 *    when the consume transition was identity-bearing.
 *  - cancelled: the terminal marker of the cancel endpoint; the record
 *    is dead but retained until its TTL.
 *  - missing: the record vanished (TTL sweep or the record-vanish
 *    transition).
 *
 * The recovery claim is carried inside the state: a resultless consumed
 * record may hold a bounded lease (owner token plus expiry). A live
 * lease fences the re-derivation, an expired lease is re-claimable,
 * and the claim-bearing commit clears the lease in the same
 * transition.
 *
 * Every transition returns the documented outcome of the stores and
 * the verifier resolution. The consume transition answers
 * 'win'/'lose'/null, the derivation and commit transitions answer
 * 'committed'/'refused', the claim answers the owner token or null,
 * and the lease transitions answer true/false. The cancel statuses
 * are 'cancelled-now', 'consumed', 'cancelled' or null. The replay
 * codes are 'granted', 'already_consumed', 'insufficient',
 * 'indeterminate' and 'not_consumed'.
 *
 * The model carries the per-record counters the invariants are stated
 * over: winCount (the consume-transition winners, bounded by 1),
 * derivations (fresh derivations, bounded by 1) and freshSuccesses
 * (fresh valid grants, bounded by 1). grantedReplays counts the
 * identity-gated stored-success replays, unbounded but every one
 * requires the exact identity gate.
 */
final class ConsumeRecoveryModel
{
    public const PENDING = 'pending';
    public const CONSUMED_RESULTLESS = 'consumed_resultless';
    public const COMMITTED_VALID = 'committed_valid';
    public const COMMITTED_INVALID = 'committed_invalid';
    public const CANCELLED = 'cancelled';
    public const MISSING = 'missing';

    public string $state = self::PENDING;

    /** The recorded operation identity of the winning consume, if any. */
    public ?string $identity = null;

    /** The live recovery-claim owner token, or null when unclaimed. */
    public ?string $claimOwner = null;

    /** The claim lease deadline; 0 = no live lease. */
    public int $claimUntil = 0;

    /** The number of fresh derivations this record saw. */
    public int $derivations = 0;

    /** The number of fresh valid grants this record saw. */
    public int $freshSuccesses = 0;

    /** The number of identity-gated stored-success replays. */
    public int $grantedReplays = 0;

    /** The number of consume-transition winners (at most one). */
    public int $winCount = 0;

    /** Whether the record ever left the pending state. */
    public bool $everConsumed = false;

    public static function fresh(): self
    {
        return new self();
    }

    /**
     * The canonical configuration key (the BFS visited-set identity): the
     * observable state plus the bounded counters the invariants quantify
     * over. The unbounded grantedReplays counter stays out of the key.
     */
    public function configKey(): string
    {
        return implode('|', [
            $this->state,
            $this->identity ?? '-',
            $this->claimOwner ?? '-',
            $this->claimUntil > 0 ? '1' : '0',
            (string) $this->derivations,
            (string) $this->freshSuccesses,
            (string) $this->winCount,
            $this->everConsumed ? '1' : '0',
        ]);
    }

    /**
     * Apply one transition with the documented guards.
     *
     * @param array<string, mixed> $args keys: identity|valid|owner|ttl
     */
    public function apply(string $transition, array $args): mixed
    {
        return match ($transition) {
            'consume' => $this->consume(isset($args['identity']) ? (string) $args['identity'] : null),
            'derive' => $this->derive((bool) ($args['valid'] ?? false)),
            'commit' => $this->commit((bool) ($args['valid'] ?? false), isset($args['owner']) ? (string) $args['owner'] : null),
            'claim' => $this->claim((string) ($args['owner'] ?? 'no-owner'), (int) ($args['ttl'] ?? 60)),
            'claim-expire' => $this->claimExpire(),
            'release' => $this->release((string) ($args['owner'] ?? '')),
            'replay' => $this->replay(isset($args['identity']) ? (string) $args['identity'] : null),
            'vanish' => $this->vanish(),
            'cancel' => $this->cancel(),
            default => throw new \LogicException(sprintf('unknown model transition %s', $transition)),
        };
    }

    /**
     * The consume transition: pending flips to consumed_resultless and
     * the caller wins exactly once; an already-consumed record answers
     * the lose outcome without mutation; a cancelled or missing record
     * answers null.
     */
    private function consume(?string $identity): mixed
    {
        if ($this->state === self::MISSING || $this->state === self::CANCELLED) {
            return null;
        }
        if ($this->state === self::PENDING) {
            $this->state = self::CONSUMED_RESULTLESS;
            $this->identity = $identity;
            $this->everConsumed = true;
            ++$this->winCount;

            return 'win';
        }

        return 'lose';
    }

    /**
     * The fresh derivation transition (the verifier's fused derive plus
     * commit): only a resultless consumed record derives, exactly once.
     * A committed result is never re-derived: every other state refuses.
     */
    private function derive(bool $valid): string
    {
        if ($this->state !== self::CONSUMED_RESULTLESS) {
            return 'refused';
        }
        ++$this->derivations;
        $this->state = $valid ? self::COMMITTED_VALID : self::COMMITTED_INVALID;
        if ($valid) {
            ++$this->freshSuccesses;
        }

        return 'committed';
    }

    /**
     * The storage commit primitive: resultless commits the result, with
     * an owner token requiring a live lease held by exactly that owner
     * (the claim-bearing commit, which clears the lease in the same
     * transition). A committed record refuses (a committed result is
     * never re-derived). The plain commit on a leased record keeps the
     * lease, exactly like the raw storage boundary.
     */
    private function commit(bool $valid, ?string $owner): string
    {
        if ($this->state !== self::CONSUMED_RESULTLESS) {
            return 'refused';
        }
        if ($owner !== null && $owner !== '') {
            if ($this->claimOwner !== $owner || $this->claimUntil <= 0) {
                return 'refused';
            }
            $this->claimOwner = null;
            $this->claimUntil = 0;
        }
        $this->state = $valid ? self::COMMITTED_VALID : self::COMMITTED_INVALID;

        return 'committed';
    }

    /**
     * The recovery-claim transition: a resultless consumed record with
     * no live lease claims the re-derivation ownership and returns the
     * owner token. A live lease refuses; an expired lease is stripped
     * and re-claimable. Every other state refuses.
     */
    private function claim(string $owner, int $ttl): ?string
    {
        if ($this->state !== self::CONSUMED_RESULTLESS) {
            return null;
        }
        if ($this->claimOwner !== null && $this->claimUntil > 0) {
            return null;
        }
        $this->claimOwner = $owner;
        $this->claimUntil = max(1, $ttl);

        return $owner;
    }

    /** The lease expiry transition: a live lease lapses, a dead or absent lease stays. */
    private function claimExpire(): bool
    {
        if ($this->claimOwner !== null && $this->claimUntil > 0) {
            $this->claimUntil = 0;

            return true;
        }

        return false;
    }

    /**
     * The compare-and-delete release: only the lease owner clears the
     * lease; a foreign owner is an atomic no-op (a stale owner can never
     * delete a newer recovery's lease).
     */
    private function release(string $owner): bool
    {
        if ($this->claimOwner !== $owner) {
            return false;
        }
        $this->claimOwner = null;
        $this->claimUntil = 0;

        return true;
    }

    /**
     * The verifier-level resolution of an already-consumed record: the
     * identity-gated stored-success replay. A stored invalid outcome
     * replays deterministically to any caller; a stored valid outcome is
     * an authorization grant that replays only under the exact identity
     * gate; a resultless record is intrinsically indeterminate.
     */
    private function replay(?string $identity): string
    {
        if ($this->state === self::CONSUMED_RESULTLESS) {
            return 'indeterminate';
        }
        if ($this->state === self::COMMITTED_INVALID) {
            return 'insufficient';
        }
        if ($this->state === self::COMMITTED_VALID) {
            if ($identity === 'exact' && $this->identity !== null) {
                ++$this->grantedReplays;

                return 'granted';
            }

            return 'already_consumed';
        }

        return 'not_consumed';
    }

    /** The TTL sweep: the record and its lease vanish. */
    private function vanish(): bool
    {
        $this->state = self::MISSING;
        $this->claimOwner = null;
        $this->claimUntil = 0;

        return true;
    }

    /** The cancel transition: pending flips to cancelled; consumed records are finalized. */
    private function cancel(): ?string
    {
        if ($this->state === self::PENDING) {
            $this->state = self::CANCELLED;

            return 'cancelled-now';
        }
        if ($this->state === self::CONSUMED_RESULTLESS || $this->state === self::COMMITTED_VALID || $this->state === self::COMMITTED_INVALID) {
            return 'consumed';
        }
        if ($this->state === self::CANCELLED) {
            return 'cancelled';
        }

        return null;
    }

    /**
     * The state-machine invariants, checked after every transition of
     * every explored sequence:
     *
     *  - I1 exactly one consume winner per record: the win fires only
     *    from pending and at most once.
     *  - I2 a committed result is never re-derived: the derivation
     *    transition fires only from the resultless state and at most
     *    once; the commit refuses every committed record.
     *  - I3 the resultless recovery: a live lease refuses a second
     *    claim, an expired lease is re-claimable, only the exact owner
     *    may release, and the claim-bearing commit clears the lease.
     *  - I4 a vanished record answers the missing vocabulary only:
     *    consume and claim null, derive and commit refused, release
     *    false, replay not_consumed, cancel null.
     *  - I5 no double success and no replay outside the identity gate: a
     *    fresh valid grant happens at most once, and a stored success
     *    replays only when the record carries a recorded identity and
     *    the caller presents the exact one.
     *  - I6 the recorded identity never changes after the winning
     *    consume.
     *
     * @param array<string, mixed> $args
     */
    public static function assertInvariants(self $from, self $to, mixed $outcome, string $transition, array $args, string $context): void
    {
        // I1 — exactly one consume winner per record.
        if ($outcome === 'win') {
            Assert::assertSame(self::PENDING, $from->state, $context.': a consume win requires the pending state');
            Assert::assertSame(1, $to->winCount, $context.': exactly one consume winner per record');
            Assert::assertTrue($to->everConsumed, $context.': the win consumes the record');
            Assert::assertSame($args['identity'] ?? null, $to->identity, $context.': the win records the presented identity');
        }
        Assert::assertLessThanOrEqual(1, $to->winCount, $context.': a second consume winner is impossible');

        // I2 — a committed result is never re-derived.
        if ($outcome === 'committed' && $transition === 'derive') {
            Assert::assertSame(self::CONSUMED_RESULTLESS, $from->state, $context.': a derivation requires the resultless state');
            Assert::assertSame(1, $to->derivations, $context.': exactly one fresh derivation');
            Assert::assertSame($args['valid'] ? self::COMMITTED_VALID : self::COMMITTED_INVALID, $to->state, $context.': the derivation commits its outcome');
            if ($args['valid']) {
                Assert::assertSame(1, $to->freshSuccesses, $context.': a fresh valid grant happens exactly once');
            }
        }
        if ($transition === 'derive' && $outcome === 'refused') {
            Assert::assertNotSame(self::CONSUMED_RESULTLESS, $from->state, $context.': a refused derivation is never a resultless record');
        }
        Assert::assertLessThanOrEqual(1, $to->derivations, $context.': a record can never derive twice');

        // I3 — the resultless recovery lease discipline.
        if ($transition === 'claim') {
            if ($outcome !== null) {
                Assert::assertSame(self::CONSUMED_RESULTLESS, $from->state, $context.': only a resultless record claims');
                Assert::assertTrue($from->claimOwner === null || $from->claimUntil <= 0, $context.': a claim requires no live lease');
                Assert::assertSame($outcome, $to->claimOwner, $context.': the claim returns the owner token');
                Assert::assertGreaterThan(0, $to->claimUntil, $context.': the claim carries a live lease');
            } else {
                Assert::assertTrue(
                    $from->state !== self::CONSUMED_RESULTLESS || ($from->claimOwner !== null && $from->claimUntil > 0),
                    $context.': a refused claim is either a live-leased resultless record or any other state',
                );
            }
        }
        if ($transition === 'claim-expire' && $outcome === true) {
            Assert::assertTrue($from->claimUntil > 0 && $to->claimUntil <= 0, $context.': the lease expiry lapses a live lease');
            Assert::assertSame($from->claimOwner, $to->claimOwner, $context.': the lease expiry keeps the owner marker');
        }
        if ($transition === 'release' && $outcome === true) {
            Assert::assertSame($from->claimOwner, $args['owner'], $context.': only the exact owner releases');
            Assert::assertNull($to->claimOwner, $context.': the release clears the lease owner');
        }
        if ($transition === 'commit' && $outcome === 'committed' && isset($args['owner']) && $args['owner'] !== '') {
            Assert::assertSame($from->claimOwner, $args['owner'], $context.': the claim-bearing commit requires the exact owner');
            Assert::assertTrue($from->claimUntil > 0, $context.': the claim-bearing commit requires a live lease');
            Assert::assertNull($to->claimOwner, $context.': the claim-bearing commit clears the lease');
            Assert::assertSame(0, $to->claimUntil, $context.': the claim-bearing commit clears the lease deadline');
        }

        // I4 — the vanished-record vocabulary.
        if ($from->state === self::MISSING && $transition !== 'vanish') {
            Assert::assertSame(self::MISSING, $to->state, $context.': a vanished record stays missing');
            Assert::assertTrue(
                $outcome === null
                || $outcome === false
                || $outcome === 'refused'
                || $outcome === 'not_consumed',
                $context.': a vanished record answers the missing vocabulary only',
            );
        }

        // I5 — no double success, no replay outside the identity gate.
        Assert::assertLessThanOrEqual(1, $to->freshSuccesses, $context.': a record grants a fresh success at most once');
        if ($outcome === 'granted') {
            Assert::assertSame(self::COMMITTED_VALID, $from->state, $context.': a stored success requires the committed-valid state');
            Assert::assertNotNull($from->identity, $context.': a stored success replays only when an identity was recorded');
            Assert::assertSame('exact', $args['identity'] ?? null, $context.': a stored success replays only under the exact identity gate');
            Assert::assertSame($from->identity, $to->identity, $context.': the replay never changes the recorded identity');
            Assert::assertSame($from->derivations, $to->derivations, $context.': a stored replay is never a re-derivation');
        }
        if ($outcome === 'already_consumed') {
            Assert::assertNotSame(self::COMMITTED_INVALID, $from->state, $context.': a stored invalid outcome never answers already_consumed');
        }

        // I6 — the recorded identity is immutable after the winning consume.
        if ($from->identity !== null) {
            Assert::assertSame($from->identity, $to->identity, $context.': the recorded identity never changes');
        }
        if ($transition === 'consume' && $outcome === 'lose') {
            Assert::assertSame($from->identity, $to->identity, $context.': a losing consume never overwrites the recorded identity');
            Assert::assertSame($from->state, $to->state, $context.': a losing consume never mutates the state');
        }
    }

    /**
     * The concrete-state equality checks: the stored record's observable
     * shape equals the model configuration field by field.
     *
     * @param array<string, mixed>|null $read the driver read-back, or
     *                                        null when the record is absent
     */
    public static function assertConcreteMatchesModel(self $m, ?array $read, string $context): void
    {
        if ($m->state === self::MISSING) {
            Assert::assertNull($read, $context.': a missing model record has no stored bytes');

            return;
        }
        Assert::assertIsArray($read, $context.': a live model record has stored bytes');
        Assert::assertSame($m->state, $read['state'], $context.': the concrete state equals the model state');
        Assert::assertSame($m->identity, $read['identity'], $context.': the concrete identity equals the model identity');
        Assert::assertSame($m->claimOwner, $read['claimOwner'], $context.': the concrete lease owner equals the model lease owner');
        Assert::assertSame($m->claimUntil > 0, $read['claimLive'], $context.': the concrete lease liveness equals the model lease liveness');
        if ($m->state === self::COMMITTED_VALID) {
            Assert::assertTrue($read['resultValid'] === true, $context.': a committed-valid model record stores a valid result');
        } elseif ($m->state === self::COMMITTED_INVALID) {
            Assert::assertTrue($read['resultValid'] === false, $context.': a committed-invalid model record stores an invalid result');
        } else {
            Assert::assertNull($read['resultValid'], $context.': every other state stores no result');
        }
    }
}
