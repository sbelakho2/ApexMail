<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use PHPUnit\Framework\Assert;

/**
 * The clean-room abstract model of the transactional chained-challenge
 * state machine (docs/chained-challenges.md), written independently from
 * the stores so the implementations can be checked against it.
 *
 * Per-chain generation state:
 *
 *  - state: absent -> available -> reserved(owner, short lease) ->
 *    issued(stage2Nonce). The terminal transitions: verified(nonce)
 *    (the Pass, atomically clearing the obligation), step_up_required
 *    (obligation kept) and denied (obligation kept). The rearm is
 *    issued(nonce) -> available, nonce-pinned and never a stage-1. The
 *    nonce-agnostic obligation-bound transaction terminalizations:
 *    available|reserved|issued -> step_up_required|denied, preserving
 *    the stage-2 nonce when one exists.
 *  - expire() is the TTL transition: the record and its obligation
 *    mapping vanish (absent), so every redemption answers missing/false.
 *  - advanceLease() models the short reservation lease running out: a
 *    reserve by another owner then takes the reservation over.
 *
 * Every transition returns the documented outcome string of the stores
 * ('available', 'retry', 'busy', 'taken_over', 'issued', 'verified',
 * 'step_up_required', 'denied', 'missing', 'issued_new', 'issued_same',
 * 'verified_same', 'conflict', 'not_owner', 'verified_new',
 * 'step_up_required_new', 'step_up_required_same', 'denied_new',
 * 'denied_same', 'already_completed', 'already_verified',
 * 'obligation_moved', true/false, null). The 'completed' legacy state is
 * the historical name of 'issued' (semantic alias, never written by the
 * transactional contract).
 *
 * The model carries the per-generation counters the security invariants
 * are stated over: verifiedNewCount (a successful Pass), issuedNewCount
 * (a fresh stage-2 mint), verifiedNonces (the challenge nonces already
 * consumed) and everTerminal (the chain reached a terminal state).
 */
final class ChainModel
{
    public const ABSENT = 'absent';
    public const AVAILABLE = 'available';
    public const RESERVED = 'reserved';
    public const ISSUED = 'issued';
    public const VERIFIED = 'verified';
    public const STEP_UP_REQUIRED = 'step_up_required';
    public const DENIED = 'denied';

    public const TERMINAL = [self::VERIFIED, self::STEP_UP_REQUIRED, self::DENIED];

    public string $state = self::ABSENT;

    /** The reservation owner token (the only handle that may issue/release). */
    public ?string $owner = null;

    /** The short reservation lease is live (now < leaseUntil). */
    public bool $leaseLive = false;

    /** The pinned stage-2 challenge nonce of the issued/terminal states. */
    public ?string $nonce = null;

    /** The transaction obligation mapping exists and points at this chain. */
    public bool $obligationPresent = false;

    /** The chain lifetime: false once the TTL/expiry transition ran. */
    public bool $alive = true;

    /** The monotonic required-rank floor (never lowered). */
    public int $rank = 1;

    /** The chain's own obligation id (the mapping key it was created under). */
    public string $obligationId;

    public bool $everTerminal = false;

    /** @var list<string> the stage-2 nonces already consumed by a Pass */
    public array $verifiedNonces = [];

    /** The number of successful Pass transitions in this generation. */
    public int $verifiedNewCount = 0;

    /** The number of fresh stage-2 mints in this generation. */
    public int $issuedNewCount = 0;

    /** The immutable identity triple (never altered by any transition). */
    public string $scope = 'login';

    public string $binding = 'txn-alpha';

    public int $policyVersion = 1;

    public function __construct(string $obligationId)
    {
        $this->obligationId = $obligationId;
    }

    public static function fresh(string $obligationId): self
    {
        return new self($obligationId);
    }

    /**
     * The canonical configuration key (the BFS visited-set identity): the
     * observable state plus the per-generation history the invariants
     * quantify over.
     */
    public function configKey(): string
    {
        $verified = $this->verifiedNonces;
        sort($verified);

        return implode('|', [
            $this->state,
            $this->owner ?? '-',
            $this->leaseLive ? '1' : '0',
            $this->nonce ?? '-',
            $this->obligationPresent ? '1' : '0',
            $this->alive ? '1' : '0',
            (string) $this->rank,
            $this->everTerminal ? '1' : '0',
            implode(',', $verified),
            (string) $this->verifiedNewCount,
        ]);
    }

    /**
     * Apply one transition with the documented guards.
     *
     * @param array<string, mixed> $args keys: owner|nonce|rank|obligationId
     */
    public function apply(string $transition, array $args): mixed
    {
        return match ($transition) {
            'createOrGet' => $this->createOrGet((int) $args['rank']),
            'reserve' => $this->reserve((string) $args['owner']),
            'release' => $this->release((string) $args['owner']),
            'markIssued' => $this->markIssued((string) $args['owner'], (string) $args['nonce']),
            'markVerified' => $this->markVerified((string) $args['nonce']),
            'markStepUpRequired' => $this->markStepUpRequired((string) $args['nonce']),
            'markDenied' => $this->markDenied((string) $args['nonce']),
            'markTransactionDenied' => $this->markTransactionDenied((string) $args['obligationId']),
            'markTransactionStepUpRequired' => $this->markTransactionStepUpRequired((string) $args['obligationId']),
            'rearmIssued' => $this->rearmIssued((string) $args['nonce']),
            'deleteObligation' => $this->deleteObligation(),
            'complete' => $this->complete((string) $args['owner'], (string) $args['nonce']),
            'advanceLease' => $this->advanceLease(),
            'expire' => $this->expire(),
            default => throw new \LogicException(sprintf('unknown model transition %s', $transition)),
        };
    }

    /**
     * Atomic create-or-get over the chain + obligation: an existing live
     * obligation returns the existing chain (raising the required-rank
     * floor, never lowering); a missing obligation creates the chain in
     * the available state. The fresh creation is a new chain generation
     * (the ticket service always mints a fresh random chain id), so the
     * per-generation history starts clean: the verified nonces, the Pass
     * count, the fresh-mint count, the terminal flag. An old
     * generation's consumed nonces can never authorize in the new one.
     */
    private function createOrGet(int $rank): string
    {
        if ($this->alive && $this->obligationPresent && $this->state !== self::ABSENT) {
            $this->rank = max($this->rank, $rank);

            return 'existing';
        }
        $this->state = self::AVAILABLE;
        $this->owner = null;
        $this->leaseLive = false;
        $this->nonce = null;
        $this->obligationPresent = true;
        $this->alive = true;
        // A fresh generation starts at the reassessed floor: the rank
        // monotonicity is per-chain-record, never carried across
        // generations (a fresh chain of the same transaction can start
        // weaker after a weaker reassessment).
        $this->rank = max(1, $rank);
        $this->everTerminal = false;
        $this->verifiedNonces = [];
        $this->verifiedNewCount = 0;
        $this->issuedNewCount = 0;

        return 'created';
    }

    private function reserve(string $owner): string
    {
        if (!$this->alive || $this->state === self::ABSENT) {
            return 'missing';
        }
        if ($this->state === self::ISSUED) {
            return 'issued';
        }
        if ($this->state === self::VERIFIED) {
            return 'verified';
        }
        if ($this->state === self::STEP_UP_REQUIRED) {
            return 'step_up_required';
        }
        if ($this->state === self::DENIED) {
            return 'denied';
        }
        if ($this->state === self::RESERVED) {
            if ($this->owner === $owner) {
                return 'retry';
            }
            if ($this->leaseLive) {
                return 'busy';
            }
            $this->owner = $owner;
            $this->leaseLive = true;

            return 'taken_over';
        }
        $this->owner = $owner;
        $this->leaseLive = true;
        $this->state = self::RESERVED;

        return 'available';
    }

    private function release(string $owner): void
    {
        if ($this->state !== self::RESERVED || $this->owner !== $owner) {
            return;
        }
        $this->state = self::AVAILABLE;
        $this->owner = null;
        $this->leaseLive = false;
    }

    private function markIssued(string $owner, string $nonce): string
    {
        if (!$this->alive || $this->state === self::ABSENT) {
            return 'missing';
        }
        if ($this->state === self::RESERVED) {
            if ($this->owner !== $owner) {
                return 'not_owner';
            }
            $this->state = self::ISSUED;
            $this->nonce = $nonce;
            $this->owner = null;
            $this->leaseLive = false;
            ++$this->issuedNewCount;

            return 'issued_new';
        }
        if ($this->state === self::ISSUED) {
            return $this->nonce === $nonce ? 'issued_same' : 'conflict';
        }
        if ($this->state === self::VERIFIED) {
            return $this->nonce === $nonce ? 'verified_same' : 'conflict';
        }
        if ($this->state === self::STEP_UP_REQUIRED || $this->state === self::DENIED) {
            return 'conflict';
        }

        return 'not_owner';
    }

    private function markVerified(string $nonce): string
    {
        if (!$this->alive || $this->state === self::ABSENT) {
            return 'missing';
        }
        if ($this->state === self::VERIFIED) {
            return $this->nonce === $nonce ? 'verified_same' : 'conflict';
        }
        if ($this->state !== self::ISSUED || $this->nonce !== $nonce) {
            return 'conflict';
        }
        $this->state = self::VERIFIED;
        $this->obligationPresent = false;
        $this->everTerminal = true;
        $this->verifiedNonces[] = $nonce;
        ++$this->verifiedNewCount;

        return 'verified_new';
    }

    private function markStepUpRequired(string $nonce): string
    {
        if (!$this->alive || $this->state === self::ABSENT) {
            return 'missing';
        }
        if ($this->state === self::STEP_UP_REQUIRED) {
            return $this->nonce === $nonce ? 'step_up_required_same' : 'conflict';
        }
        if ($this->state !== self::ISSUED || $this->nonce !== $nonce) {
            return 'conflict';
        }
        $this->state = self::STEP_UP_REQUIRED;
        $this->everTerminal = true;

        return 'step_up_required_new';
    }

    private function markDenied(string $nonce): string
    {
        if (!$this->alive || $this->state === self::ABSENT) {
            return 'missing';
        }
        if ($this->state === self::DENIED) {
            return $this->nonce === $nonce ? 'denied_same' : 'conflict';
        }
        if ($this->state !== self::ISSUED || $this->nonce !== $nonce) {
            return 'conflict';
        }
        $this->state = self::DENIED;
        $this->everTerminal = true;

        return 'denied_new';
    }

    /**
     * Obligation-bound, nonce-agnostic transaction terminalization: the
     * record must agree on the obligation id, the mapping must still
     * exist and point at this chain, and the state must be an open
     * obligation (available|reserved|issued). The stage-2 nonce and the
     * obligation mapping are preserved.
     */
    private function markTransactionDenied(string $obligationId): string
    {
        if (!$this->alive || $this->state === self::ABSENT) {
            return 'missing';
        }
        if ($obligationId !== $this->obligationId) {
            return 'obligation_moved';
        }
        if (!$this->obligationPresent) {
            return 'already_completed';
        }
        if ($this->state === self::DENIED) {
            return 'denied_same';
        }
        if ($this->state === self::STEP_UP_REQUIRED) {
            return 'conflict';
        }
        if ($this->state === self::VERIFIED) {
            return 'already_verified';
        }
        if (!\in_array($this->state, [self::AVAILABLE, self::RESERVED, self::ISSUED], true)) {
            return 'conflict';
        }
        $this->state = self::DENIED;
        $this->owner = null;
        $this->leaseLive = false;
        $this->everTerminal = true;

        return 'denied_new';
    }

    private function markTransactionStepUpRequired(string $obligationId): string
    {
        if (!$this->alive || $this->state === self::ABSENT) {
            return 'missing';
        }
        if ($obligationId !== $this->obligationId) {
            return 'obligation_moved';
        }
        if (!$this->obligationPresent) {
            return 'already_completed';
        }
        if ($this->state === self::STEP_UP_REQUIRED) {
            return 'step_up_required_same';
        }
        if ($this->state === self::DENIED) {
            return 'conflict';
        }
        if ($this->state === self::VERIFIED) {
            return 'already_verified';
        }
        if (!\in_array($this->state, [self::AVAILABLE, self::RESERVED, self::ISSUED], true)) {
            return 'conflict';
        }
        $this->state = self::STEP_UP_REQUIRED;
        $this->owner = null;
        $this->leaseLive = false;
        $this->everTerminal = true;

        return 'step_up_required_new';
    }

    private function rearmIssued(string $nonce): bool
    {
        if (!$this->alive || $this->state === self::ABSENT) {
            return false;
        }
        if ($this->state !== self::ISSUED || $this->nonce !== $nonce) {
            return false;
        }
        $this->state = self::AVAILABLE;
        $this->nonce = null;
        $this->owner = null;
        $this->leaseLive = false;

        return true;
    }

    private function deleteObligation(): void
    {
        if ($this->obligationPresent) {
            $this->obligationPresent = false;
        }
    }

    /**
     * The deprecated legacy completion: the historical name of the
     * issued transition, reserved(me) -> completed(nonce) — semantically
     * identical to markIssued. Returns the sentinel 'completed' on the
     * transition, null on a refusal.
     */
    private function complete(string $owner, string $nonce): ?string
    {
        if (!$this->alive || $this->state === self::ABSENT) {
            return null;
        }
        if ($this->state !== self::RESERVED || $this->owner !== $owner) {
            return null;
        }
        $this->state = self::ISSUED;
        $this->nonce = $nonce;
        $this->owner = null;
        $this->leaseLive = false;

        return 'completed';
    }

    private function advanceLease(): void
    {
        if ($this->state === self::RESERVED && $this->leaseLive) {
            $this->leaseLive = false;
        }
    }

    private function expire(): void
    {
        $this->alive = false;
        $this->state = self::ABSENT;
        $this->obligationPresent = false;
        $this->owner = null;
        $this->nonce = null;
        $this->leaseLive = false;
    }

    /**
     * The security invariants, checked after every transition of every
     * explored sequence:
     *
     *  - I1 single-use per challenge: a stage-2 nonce can be consumed by
     *    a Pass at most once, and the chain succeeds at most once per
     *    generation (verifiedNewCount <= 1).
     *  - I2 no fresh mint on a consumed chain: after the chain went
     *    terminal, markIssued can never answer 'issued_new' (and every
     *    other redemption path only reports the terminal state).
     *  - I3 the issued nonce is immutable until the nonce-pinned rearm.
     *  - I4 expiry: an expired chain answers missing/false only and is
     *    never mutated.
     *  - I5 terminal absorption: no transition but expire mutates a
     *    terminal state (the obligation compare-delete is the sole
     *    exception and only clears the mapping).
     *  - I6 obligation lifecycle: verified_new and expire clear the
     *    obligation; the disposition terminalizations keep it; the
     *    mapping never reappears on the same generation.
     *  - I7 the strict v2 schema invariants of the record.
     *  - I8 the identity triple (scope, binding, policy epoch) is
     *    immutable.
     *  - I9 the required-rank floor is monotone (never lowered).
     *
     * @param array<string, mixed> $args
     */
    public static function assertInvariants(self $from, self $to, mixed $outcome, string $transition, array $args, string $context): void
    {
        // I1 — single-use per challenge nonce; at most one Pass per generation.
        if ($outcome === 'verified_new') {
            Assert::assertSame(self::ISSUED, $from->state, $context.': verified_new requires the issued state');
            Assert::assertNotNull($from->nonce, $context.': verified_new requires a pinned stage-2 nonce');
            Assert::assertNotContains($from->nonce, $from->verifiedNonces, $context.': a challenge nonce can never verify twice');
            Assert::assertContains($from->nonce, $to->verifiedNonces, $context.': the consumed nonce is recorded');
            Assert::assertSame($from->verifiedNewCount + 1, $to->verifiedNewCount, $context.': the Pass count increments exactly once');
            Assert::assertSame(1, $to->verifiedNewCount, $context.': a chain generation can succeed at most ONCE — a double success is impossible');
            Assert::assertTrue($to->everTerminal, $context.': the Pass is a terminal transition');
            Assert::assertFalse($to->obligationPresent, $context.': the Pass atomically clears the obligation');
            Assert::assertSame($from->nonce, $to->nonce, $context.': the Pass preserves the exact nonce');
        }
        // I2 — no fresh mint on a consumed chain.
        if ($outcome === 'issued_new') {
            Assert::assertFalse($from->everTerminal, $context.': a terminal chain can never mint a fresh stage-2 challenge');
            Assert::assertSame(self::RESERVED, $from->state, $context.': a fresh mint requires the owner reservation');
            Assert::assertSame($from->owner, $args['owner'] ?? null, $context.': the mint is owner-scoped');
            Assert::assertSame($from->issuedNewCount + 1, $to->issuedNewCount, $context.': exactly one fresh mint');
            Assert::assertSame($args['nonce'] ?? null, $to->nonce, $context.': the mint pins the exact nonce');
        }
        // I3 — the issued nonce is immutable until the nonce-pinned rearm.
        if ($from->state === self::ISSUED && $to->state === self::ISSUED) {
            Assert::assertSame($from->nonce, $to->nonce, $context.': the issued nonce never changes in place');
        }
        // I4 — expiry: missing/false only, zero mutation (the fresh
        // create-or-get is the exception: it starts a NEW generation).
        if (!$from->alive && $transition !== 'createOrGet') {
            Assert::assertSame(self::ABSENT, $to->state, $context.': an expired chain is absent');
            Assert::assertFalse($to->obligationPresent, $context.': an expired chain has no obligation');
            if ($outcome !== null) {
                Assert::assertTrue($outcome === 'missing' || $outcome === false, $context.': an expired chain answers missing/false only');
            }
        }
        // I5 — terminal absorption.
        if (\in_array($from->state, self::TERMINAL, true) && $transition !== 'expire') {
            Assert::assertSame($from->state, $to->state, $context.': a terminal state never leaves its state');
            Assert::assertSame($from->nonce, $to->nonce, $context.': a terminal state never changes its nonce');
            Assert::assertSame($from->owner, $to->owner, $context.': a terminal state never re-acquires a reservation');
            Assert::assertSame($from->leaseLive, $to->leaseLive, $context.': a terminal state never holds a lease');
            if ($transition === 'deleteObligation') {
                Assert::assertFalse($to->obligationPresent, $context.': the obligation compare-delete only clears the mapping');
            } else {
                Assert::assertSame($from->obligationPresent, $to->obligationPresent, $context.': a terminal state never gains/loses the obligation');
            }
        }
        // I6 — obligation lifecycle.
        if ($transition === 'expire') {
            Assert::assertFalse($to->obligationPresent, $context.': expiry drops the obligation');
        } elseif ($transition === 'deleteObligation') {
            Assert::assertFalse($to->obligationPresent, $context.': the compare-delete clears the obligation');
        } elseif (\in_array($outcome, ['denied_new', 'step_up_required_new'], true)
            && \in_array($transition, ['markTransactionDenied', 'markTransactionStepUpRequired'], true)
        ) {
            Assert::assertTrue($to->obligationPresent, $context.': the transaction terminalizations KEEP the obligation');
            Assert::assertSame($from->nonce, $to->nonce, $context.': the nonce-agnostic terminalization preserves the stage-2 nonce');
        }
        if (!$from->obligationPresent && $from->state !== self::ABSENT && $to->state !== self::ABSENT && $transition !== 'createOrGet') {
            Assert::assertFalse($to->obligationPresent, $context.': a cleared obligation never reappears on the same generation');
        }
        // I7 — the strict schema invariants on the target configuration.
        self::assertSchemaInvariants($to, $context);
        // I8 — the identity triple is immutable.
        Assert::assertSame($from->scope, $to->scope, $context.': the scope never changes');
        Assert::assertSame($from->binding, $to->binding, $context.': the authoritative binding never changes');
        Assert::assertSame($from->policyVersion, $to->policyVersion, $context.': the policy epoch never changes');
        // I9 — the required-rank floor is monotone within a generation
        // (a fresh generation starts at its own reassessed floor).
        if (!($transition === 'createOrGet' && $outcome === 'created')) {
            Assert::assertGreaterThanOrEqual($from->rank, $to->rank, $context.': the required rank can never be lowered');
        }
        // Guard consistency of the reservation transitions.
        if ($transition === 'reserve') {
            if ($outcome === 'available') {
                Assert::assertSame(self::AVAILABLE, $from->state, $context.': available requires the available state');
                Assert::assertSame($args['owner'], $to->owner, $context.': the reservation is taken by the caller');
            } elseif ($outcome === 'taken_over') {
                Assert::assertSame(self::RESERVED, $from->state, $context.': a takeover requires a reservation');
                Assert::assertNotSame($from->owner, $args['owner'], $context.': a takeover requires a different owner');
                Assert::assertFalse($from->leaseLive, $context.': a takeover requires an expired lease');
                Assert::assertSame($args['owner'], $to->owner, $context.': the takeover transfers the reservation');
                Assert::assertTrue($to->leaseLive, $context.': the takeover holds a fresh lease');
            } elseif ($outcome === 'retry') {
                Assert::assertSame($from->owner, $args['owner'], $context.': retry requires the same owner');
            } elseif ($outcome === 'busy') {
                Assert::assertNotSame($from->owner, $args['owner'], $context.': busy requires a different owner');
                Assert::assertTrue($from->leaseLive, $context.': busy requires a live lease');
            }
        }
        // Guard consistency of the owner-scoped release.
        if ($transition === 'release') {
            if ($from->state === self::RESERVED && $from->owner === $args['owner']) {
                Assert::assertSame(self::AVAILABLE, $to->state, $context.': the owner release returns the chain to available');
                Assert::assertNull($to->owner, $context.': the release clears the owner');
                Assert::assertFalse($to->leaseLive, $context.': the release clears the lease');
            } else {
                Assert::assertSame($from->state, $to->state, $context.': a non-owner release is an atomic no-op');
            }
        }
        // Guard consistency of the legacy completion.
        if ($transition === 'complete' && $outcome === 'completed') {
            Assert::assertSame(self::RESERVED, $from->state, $context.': the legacy completion requires the reservation');
            Assert::assertSame($from->owner, $args['owner'], $context.': the legacy completion is owner-scoped');
            Assert::assertSame($args['nonce'], $to->nonce, $context.': the legacy completion pins the exact nonce');
        }
        // The create-or-get guard: an existing obligation never changes state.
        if ($transition === 'createOrGet' && $outcome === 'existing') {
            Assert::assertSame($from->state, $to->state, $context.': the create-or-get recovery never mutates the chain state');
            Assert::assertSame($from->owner, $to->owner, $context.': the create-or-get recovery never mutates the reservation');
            Assert::assertSame($from->nonce, $to->nonce, $context.': the create-or-get recovery never mutates the nonce');
            Assert::assertSame($from->obligationPresent, $to->obligationPresent, $context.': the create-or-get recovery keeps the obligation');
        }
    }

    /**
     * The strict v2 record-schema invariants: state-dependent
     * owner/lease/nonce consistency (the decode of
     * RedisChainedChallengeStateStore / ArrayChainedChallengeStateStore
     * fails closed on any violation).
     */
    public static function assertSchemaInvariants(self $m, string $context): void
    {
        if ($m->state === self::RESERVED) {
            Assert::assertNotNull($m->owner, $context.': reserved requires an owner');
        } else {
            Assert::assertNull($m->owner, $context.': owner must be null outside the reserved state');
            Assert::assertFalse($m->leaseLive, $context.': no live lease outside the reserved state');
        }
        if ($m->state === self::ISSUED || $m->state === self::VERIFIED) {
            Assert::assertNotNull($m->nonce, $context.': issued/verified require the pinned stage-2 nonce');
        } elseif ($m->state === self::AVAILABLE || $m->state === self::RESERVED) {
            Assert::assertNull($m->nonce, $context.': no stage-2 nonce in the available/reserved states');
        } elseif ($m->state === self::ABSENT) {
            Assert::assertNull($m->nonce, $context.': no stage-2 nonce on an absent chain');
        }
        if ($m->state === self::VERIFIED) {
            Assert::assertFalse($m->obligationPresent, $context.': a verified chain has no obligation mapping');
        }
        if ($m->state === self::ABSENT) {
            Assert::assertFalse($m->obligationPresent, $context.': an absent chain has no obligation mapping');
            Assert::assertNull($m->owner, $context.': an absent chain has no reservation owner');
        }
        Assert::assertGreaterThanOrEqual(1, $m->rank, $context.': the required rank is a positive integer');
        Assert::assertLessThanOrEqual(6, $m->rank, $context.': the required rank is bounded by the Argon64 rung');
    }
}
