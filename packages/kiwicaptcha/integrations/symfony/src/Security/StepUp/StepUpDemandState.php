<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The lifecycle state of a step-up demand record. The transitions are
 * all store-side compare-and-set moves, so every state is reached by
 * exactly one winner:
 *
 *  open -> completed   the factor+demand completion: the factor proved
 *                      the second factor and the demand is spent as the
 *                      authorization candidate. Nothing else happens in
 *                      this transition.
 *  completed -> finalizing
 *                      the finalizer's acquisition: exactly one owner
 *                      runs the reassessment. A stale claim (an owner
 *                      that died inside its claim window) may be
 *                      retaken once its deadline passes.
 *  finalizing -> authorized | denied
 *                      the terminal compare-and-set after the
 *                      reassessment: authorized books the completion
 *                      effects, denied closes the demand.
 *  open|completed -> superseded
 *                      a live parent demand is replaced by its
 *                      pre-minted escalation child; the parent keeps
 *                      its record (and the child's id) as durable
 *                      proof, never deleted.
 *
 * The authorized terminal is durable and retains the operation binding
 * (identity digest and content digest), the decision, the quarantine
 * flag, the completed factor and the settlement timestamp. The same
 * logical operation with the same contents reproduces the authorization
 * idempotently; a different operation or changed contents is rejected.
 * A denied or superseded demand authorizes nothing ever again.
 */
enum StepUpDemandState: string
{
    case Open = 'open';
    case Completed = 'completed';
    case Finalizing = 'finalizing';
    case Authorized = 'authorized';
    case Denied = 'denied';
    case Superseded = 'superseded';

    /** Whether the demand still funds a code delivery or a begin. */
    public function isOpen(): bool
    {
        return $this === self::Open;
    }

    /** Whether the demand reached a terminal state (durable, never deleted). */
    public function isTerminal(): bool
    {
        return $this === self::Authorized
            || $this === self::Denied
            || $this === self::Superseded;
    }

    /** The state of a wire value, null when the value names no state. */
    public static function of(string $value): ?self
    {
        return self::tryFrom($value);
    }
}
