<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Outcomes;

/**
 * The sealed handle dimensions of the typed outcomes API: the six ways
 * an application can address the subject of an outcome.
 *
 * Nonce and DecisionId are the ledger dimensions: they address the
 * always-on outcome-ledger entry of one assessed decision. The four
 * identity dimensions (Principal, Target, Session, Agent) address a
 * long-memory subject by its pseudonym.
 */
enum OutcomeHandleDimension: string
{
    case Nonce = 'nonce';
    case DecisionId = 'decisionId';
    case Principal = 'principal';
    case Target = 'target';
    case Session = 'session';
    case Agent = 'agent';

    /** True for the two ledger dimensions (the outcome-ledger path). */
    public function isLedger(): bool
    {
        return $this === self::Nonce || $this === self::DecisionId;
    }

    /** True for the four identity dimensions (feedback + long-memory marks). */
    public function isIdentity(): bool
    {
        return !$this->isLedger();
    }

    /** The key segment of the dimension inside a long-memory mark key. */
    public function markDimension(): ?string
    {
        return match ($this) {
            self::Principal, self::Target, self::Session, self::Agent => $this->value,
            self::Nonce, self::DecisionId => null,
        };
    }
}
