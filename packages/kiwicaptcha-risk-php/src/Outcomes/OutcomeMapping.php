<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Outcomes;

use KiwiCaptcha\Risk\RiskEventKind;

/**
 * One row of the versioned outcome mapping table: how a single outcome
 * resolves onto the existing surfaces. The row is immutable and total —
 * every outcome has exactly one channel event, one ledger action, one
 * mark behavior and one polarity class.
 */
final readonly class OutcomeMapping
{
    /**
     * @param RiskEventKind      $channel         the existing risk-v1 event the
     *                                            outcome books on the feedback
     *                                            path
     * @param bool|null          $ledgerLegitimate null = no ledger semantics.
     *                                            True confirms L. False confirms
     *                                            A.
     * @param bool               $writesAbuseMark whether the outcome writes a
     *                                            long-memory abuse mark on
     *                                            identity handles
     * @param bool               $serverConfirmed whether the outcome is a
     *                                            server-side assertion. Raw
     *                                            client input can never produce
     *                                            it directly.
     * @param bool               $maySubtractRisk whether any path of the outcome
     *                                            may lower risk. This is the
     *                                            trust polarity.
     * @param list<OutcomeHandleDimension> $acceptedHandles the handle dimensions
     *                                            the outcome can be reported
     *                                            with
     */
    public function __construct(
        public readonly Outcome $outcome,
        public readonly RiskEventKind $channel,
        public readonly ?bool $ledgerLegitimate,
        public readonly bool $writesAbuseMark,
        public readonly bool $serverConfirmed,
        public readonly bool $maySubtractRisk,
        public readonly array $acceptedHandles,
    ) {
    }

    public function accepts(OutcomeHandleDimension $dimension): bool
    {
        return \in_array($dimension, $this->acceptedHandles, true);
    }

    /**
     * The mark kind the outcome writes on identity handles: the outcome's
     * own wire name when the mapping carries an abuse mark, null when it
     * never writes one.
     */
    public function markKind(): ?string
    {
        return $this->writesAbuseMark ? $this->outcome->value : null;
    }

    /**
     * True when the outcome has a ledger action (a nonce or decision id
     * can confirm it through the always-on outcome ledger).
     */
    public function hasLedgerAction(): bool
    {
        return $this->ledgerLegitimate !== null;
    }
}
