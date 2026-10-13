<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The effects journal of a durable authorized settlement. The
 * authorization terminal is the crash boundary of the completion
 * lifecycle: the challenge is spent and the demand is terminal before
 * the effects book. A crash in between must be recoverable without a
 * second factor. The effects: the outcome credit, the session restore,
 * the trust marker. The journal names, per effect, the unix second it
 * landed, riding the demand record itself ("store on the demand
 * hash"): the durable authorization carries its own effects state.
 *
 * The four entries:
 *
 *  - authorization_settled: the terminal compare-and-set landed.
 *  - outcome_credited: the stepUpCompleted outcome reported.
 *  - session_restored: the pending login unwrapped (a session with no
 *    pending token counts: there is nothing to restore).
 *  - trust_written: the enrollment bootstrap markers written.
 *
 * The journal write follows its effect, so a crash between the two
 * retries exactly the missing one. A record authorized before the
 * journal existed carries none; the finalizer then treats every effect
 * as missing and re-runs them (each effect is idempotent by design).
 * A missing entry is a false, an unknown entry corrupts the record.
 */
final class StepUpEffectsJournal
{
    public const SETTLED = 'authorization_settled';

    public const OUTCOME_CREDITED = 'outcome_credited';

    public const SESSION_RESTORED = 'session_restored';

    public const TRUST_WRITTEN = 'trust_written';

    /** @var list<string> */
    private const EFFECTS = [self::SETTLED, self::OUTCOME_CREDITED, self::SESSION_RESTORED, self::TRUST_WRITTEN];

    private function __construct(
        public readonly ?int $settledAt = null,
        public readonly ?int $outcomeCreditedAt = null,
        public readonly ?int $sessionRestoredAt = null,
        public readonly ?int $trustWrittenAt = null,
    ) {
    }

    public static function none(): self
    {
        return new self();
    }

    /** Whether the value names a journalable effect. */
    public static function isEffect(string $effect): bool
    {
        return \in_array($effect, self::EFFECTS, true);
    }

    /** The journal after one effect landed, stamped with its time. */
    public function withEffect(string $effect, int $at): self
    {
        if (!self::isEffect($effect)) {
            throw new \InvalidArgumentException('The effects journal names a known effect only');
        }

        return new self(
            $effect === self::SETTLED ? $at : $this->settledAt,
            $effect === self::OUTCOME_CREDITED ? $at : $this->outcomeCreditedAt,
            $effect === self::SESSION_RESTORED ? $at : $this->sessionRestoredAt,
            $effect === self::TRUST_WRITTEN ? $at : $this->trustWrittenAt,
        );
    }

    public function settled(): bool
    {
        return $this->settledAt !== null;
    }

    public function outcomeCredited(): bool
    {
        return $this->outcomeCreditedAt !== null;
    }

    public function sessionRestored(): bool
    {
        return $this->sessionRestoredAt !== null;
    }

    public function trustWritten(): bool
    {
        return $this->trustWrittenAt !== null;
    }

    /** Whether every effect of the journal has landed. */
    public function complete(): bool
    {
        return $this->settled() && $this->outcomeCredited() && $this->sessionRestored() && $this->trustWritten();
    }

    /**
     * The canonical wire form (the value of the demand record's `fx`
     * key): every landed effect names its unix second.
     *
     * @return array<string, int>
     */
    public function toArray(): array
    {
        $fx = [];
        if ($this->settledAt !== null) {
            $fx[self::SETTLED] = $this->settledAt;
        }
        if ($this->outcomeCreditedAt !== null) {
            $fx[self::OUTCOME_CREDITED] = $this->outcomeCreditedAt;
        }
        if ($this->sessionRestoredAt !== null) {
            $fx[self::SESSION_RESTORED] = $this->sessionRestoredAt;
        }
        if ($this->trustWrittenAt !== null) {
            $fx[self::TRUST_WRITTEN] = $this->trustWrittenAt;
        }

        return $fx;
    }

    /**
     * The strict decode of a demand record's `fx` value. Absent answers
     * null (a record with no journal); a wrong shape, an unknown effect
     * or a non-integer stamp answers null too, so a corrupt journal can
     * never impersonate completed effects.
     *
     * @param mixed $fx the decoded `fx` value
     */
    public static function fromArray(mixed $fx): ?self
    {
        if ($fx === null) {
            return null;
        }
        if (!\is_array($fx)) {
            return null;
        }
        $journal = self::none();
        foreach ($fx as $effect => $at) {
            if (!\is_string($effect) || !self::isEffect($effect) || !\is_int($at) || $at < 0) {
                return null;
            }
            $journal = $journal->withEffect($effect, $at);
        }

        return $journal;
    }
}
