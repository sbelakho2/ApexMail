<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Marks;

use KiwiCaptcha\Risk\Storage\OutcomeMarksStoreInterface;

/**
 * The marks view of one request: every mark found on the requesting
 * identity's own dimensions (session, principal, agent, asn) plus, when
 * the request presents a login target, the mark on that target
 * dimension. The view is a resolved value: whatever produced it (a
 * reader, a test, the simulator) has already decided which dimensions
 * the request addresses; read() builds it from any marks store.
 */
final class MarksView
{
    /**
     * @param array<string, array{kind: string, count: int, first_ms: int, last_ms: int}> $own marks keyed by mark dimension
     * @param array{kind: string, count: int, first_ms: int, last_ms: int}|null $target
     * @param FirstAttemptEvidence          $firstAttempt          first-attempt prevention evidence (P0-1), neutral by default
     */
    private function __construct(
        private readonly array $own,
        private readonly ?array $target,
        private readonly FirstAttemptEvidence $firstAttempt = new FirstAttemptEvidence(),
    ) {
    }

    /**
     * The view from already-resolved marks.
     *
     * @param array<string, array{kind: string, count: int, first_ms: int, last_ms: int}> $own
     * @param array{kind: string, count: int, first_ms: int, last_ms: int}|null $target
     */
    public static function fromParts(array $own, ?array $target): self
    {
        return new self($own, $target);
    }

    /** The empty view: no own marks, no target mark. */
    public static function empty(): self
    {
        return new self([], null);
    }

    /**
     * Replaces the target entry with a reader-derived record: the shape
     * a deployment compiles from the target-failure signal of the
     * evidence plane when no target mark was written to the store.
     *
     * @param array{kind: string, count: int, first_ms: int, last_ms: int}|null $target
     */
    public function withTarget(?array $target): self
    {
        return new self($this->own, $target, $this->firstAttempt);
    }

    /** Attaches the first-attempt prevention evidence (P0-1). */
    public function withFirstAttempt(FirstAttemptEvidence $evidence): self
    {
        return new self($this->own, $this->target, $evidence);
    }

    /** The attached first-attempt evidence (neutral when none). */
    public function firstAttempt(): FirstAttemptEvidence
    {
        return $this->firstAttempt;
    }

    /**
     * Reads the view from a marks store: one lookup per own dimension
     * (absent marks simply drop out) plus the target lookup when the
     * request presents a target pseudonym.
     *
     * @param array<string, string> $own dimension => identifier
     *
     * @throws \KiwiCaptcha\Risk\Storage\RiskStoreException when any
     *                                   lookup fails; the caller treats
     *                                   an unreadable view fail-closed
     *                                   via MarksEscalation::applyUnreadable()
     */
    public static function read(OutcomeMarksStoreInterface $store, array $own, ?string $target): self
    {
        $marks = [];
        foreach ($own as $dimension => $id) {
            $mark = $store->readMark($dimension, $id);
            if ($mark !== null) {
                $marks[$dimension] = $mark;
            }
        }

        $targetMark = null;
        if ($target !== null) {
            $targetMark = $store->readMark('target', $target);
            if ($targetMark === null && $store instanceof \KiwiCaptcha\Risk\Storage\TargetStateStoreInterface) {
                // The engine compiles the attacked-target record from its
                // own failure state (the counter the outcome bridge
                // maintains); callers never inject it.
                $state = $store->readTargetState($target);
                if ($state['fails'] >= MarksEscalation::TARGET_ATTACK_THRESHOLD) {
                    $targetMark = [
                        'kind' => 'targetUnderAttack',
                        'last_kind' => 'targetUnderAttack',
                        'count' => $state['fails'],
                        'first_ms' => $state['first_ms'],
                        'last_ms' => $state['last_ms'],
                    ];
                }
            }
        }

        return new self($marks, $targetMark);
    }

    /**
     * Every own-dimension mark still inside its TTL window, keyed by
     * mark dimension (the quarantine selection reads the kinds of the
     * whole live set, not only the freshest entry).
     *
     * @return array<string, array{kind: string, count: int, first_ms: int, last_ms: int}>
     */
    public function ownInTtl(int $nowMs, int $ttlMs): array
    {
        $live = [];
        foreach ($this->own as $dimension => $mark) {
            if (self::inTtl($mark, $nowMs, $ttlMs)) {
                $live[$dimension] = $mark;
            }
        }

        return $live;
    }

    /**
     * The freshest own-dimension mark still inside its TTL window (the
     * one backing the longest remaining deny window).
     *
     * @return array{kind: string, count: int, first_ms: int, last_ms: int}|null
     */
    public function freshestOwnInTtl(int $nowMs, int $ttlMs): ?array
    {
        $freshest = null;
        foreach ($this->own as $mark) {
            if (self::inTtl($mark, $nowMs, $ttlMs)
                && ($freshest === null || $mark['last_ms'] > $freshest['last_ms'])) {
                $freshest = $mark;
            }
        }

        return $freshest;
    }

    /**
     * The target mark when it is still inside its TTL window.
     *
     * @return array{kind: string, count: int, first_ms: int, last_ms: int}|null
     */
    public function targetInTtl(int $nowMs, int $ttlMs): ?array
    {
        return $this->target !== null && self::inTtl($this->target, $nowMs, $ttlMs)
            ? $this->target
            : null;
    }

    /** True when at least one own dimension carries an in-TTL mark. */
    public function ownMarked(int $nowMs, int $ttlMs): bool
    {
        return $this->freshestOwnInTtl($nowMs, $ttlMs) !== null;
    }

    /**
     * A mark is live while now < last_ms + ttl (strict, matching the
     * deny window). A negative last_ms (a corrupt record) is expired,
     * never a zero-epoch live mark.
     *
     * @param array{kind: string, count: int, first_ms: int, last_ms: int} $mark
     */
    private static function inTtl(array $mark, int $nowMs, int $ttlMs): bool
    {
        return $mark['last_ms'] >= 0 && $nowMs < $mark['last_ms'] + $ttlMs;
    }
}
