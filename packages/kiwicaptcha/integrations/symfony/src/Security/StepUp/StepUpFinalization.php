<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The typed answer of the shared {@see StepUpDemandFinalizer}: whether
 * the completed demand settled authorized, and under which reason
 * otherwise. A refusal reason names the failed stage (the recipe
 * rerun, the lifecycle state, the reassessment denial, an absent or
 * unbound demand) so the calling lane answers the right failure and
 * the log tells the operator which gate closed. The escalated reason
 * names the assurance escalation: the fresh assessment re-raised the
 * step-up over the completed factor, the parent demand was superseded
 * by its strictly stronger child, and the child demand id rides as the
 * finalization's demand.
 */
final class StepUpFinalization
{
    public const AUTHORIZED = 'authorized';
    public const AUTHORIZED_REPLAY = 'authorized_replay';
    public const ESCALATED = 'escalated';
    public const REFUSED_UNBOUND = 'refused_unbound';
    public const REFUSED_ABSENT = 'refused_absent';
    public const REFUSED_DIGEST = 'refused_digest';
    public const REFUSED_STATE = 'refused_state';
    public const REFUSED_DENIED = 'refused_denied';

    private function __construct(
        public readonly bool $authorized,
        public readonly string $reason,
        public readonly ?StepUpDemand $demand,
        /**
         * The effects journal after the authorized settlement's
         * completion effects ran, null on a refusal, an escalation and
         * every authorized settlement with no effect surface (no
         * principal to book). An authorized journal that is incomplete
         * is the crash boundary made visible: the calling lane answers
         * the retryable failure and the demand-bound retry completes
         * the missing effects without a second factor.
         */
        public readonly ?StepUpEffectsJournal $effects = null,
    ) {
    }

    /** This finalization with the effects journal attached. */
    public function withEffects(?StepUpEffectsJournal $effects): self
    {
        return new self($this->authorized, $this->reason, $this->demand, $effects);
    }

    /**
     * Whether an authorized settlement carries a complete journal.
     * Null effects (no surface ran) counts as complete for the caller
     * that never had an effect surface; a non-null incomplete journal
     * counts as incomplete and is retryable.
     */
    public function effectsComplete(): bool
    {
        return $this->effects === null || $this->effects->complete();
    }

    public static function authorized(StepUpDemand $demand): self
    {
        return new self(true, self::AUTHORIZED, $demand);
    }

    /** The demand was already settled authorized by a previous owner; the effects replay idempotently. */
    public static function authorizedReplay(StepUpDemand $demand): self
    {
        return new self(true, self::AUTHORIZED_REPLAY, $demand);
    }

    /**
     * The fresh assessment re-raised the step-up over the completed
     * factor: the parent was superseded by its strictly stronger child
     * in one atomic store transaction, and the child is the demand the
     * calling lane now owes a proof for. Never authorized.
     */
    public static function escalated(StepUpDemand $child): self
    {
        return new self(false, self::ESCALATED, $child);
    }

    public static function refusedUnbound(): self
    {
        return new self(false, self::REFUSED_UNBOUND, null);
    }

    public static function refusedAbsent(): self
    {
        return new self(false, self::REFUSED_ABSENT, null);
    }

    public static function refusedDigest(): self
    {
        return new self(false, self::REFUSED_DIGEST, null);
    }

    public static function refusedState(): self
    {
        return new self(false, self::REFUSED_STATE, null);
    }

    public static function refusedDenied(): self
    {
        return new self(false, self::REFUSED_DENIED, null);
    }
}
