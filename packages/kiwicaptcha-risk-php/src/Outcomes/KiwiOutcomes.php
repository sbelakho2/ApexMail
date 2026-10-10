<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Outcomes;

use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\Storage\OutcomeMarksStoreInterface;

/**
 * The typed outcomes facade: reports the eight application outcomes and
 * serves the erasure path, resolving every report through the one
 * versioned mapping table onto the existing engine surfaces.
 *
 * report() resolves the handle to the existing store paths. A ledger
 * handle (nonce or decision id) drives the always-on outcome-ledger
 * confirmation; the mapping's ledger row (L for confirmedLegitimate,
 * A for the confirmed-abuse outcomes) decides the flip, and the shared
 * accepted-outcome status comes back on the receipt. An identity handle
 * drives the existing feedback channel the mapping names and writes the
 * long-memory mark when the mapping carries one. The session and
 * principal pseudonyms of the handle ride the observation directly, so
 * the report addresses exactly the identity the caller named.
 *
 * A report context is optional: deferred outcomes (a chargeback webhook,
 * a ban decision) have no request to observe, so they settle the ledger
 * and the marks and leave the short-memory feedback channels alone.
 * When a context is given, the mapped reputation event is booked with
 * the caller's idempotency key, deduped by the engine's event id.
 *
 * forget() removes the long-memory marks of the handle's dimensions,
 * constructing the exact keys without any scan, and returns the number
 * of marks removed. A ledger handle names no mark dimension and always
 * answers 0.
 */
final class KiwiOutcomes
{
    public function __construct(
        private readonly AdaptiveRiskEngine $engine,
        private readonly OutcomeMarksStoreInterface $marks,
    ) {
    }

    /**
     * Reports one typed outcome for one handle.
     *
     * @throws \InvalidArgumentException when the mapping accepts no such
     *                                   handle dimension for the outcome
     * @throws \KiwiCaptcha\Risk\Storage\RiskStoreException when a mark
     *                                   write fails on the identity path (a
     *                                   failed mark must surface, never
     *                                   silently drop)
     */
    public function report(
        Outcome $outcome,
        OutcomeHandle $handle,
        ?string $idempotencyKey = null,
        ?RiskContext $context = null,
    ): OutcomeReceipt {
        $mapping = OutcomeMap::for($outcome);
        if (!$mapping->accepts($handle->dimension)) {
            throw new \InvalidArgumentException(sprintf(
                'Outcome %s cannot be reported on a %s handle (accepted: %s)',
                $outcome->value,
                $handle->dimension->value,
                implode(', ', array_map(static fn (OutcomeHandleDimension $d): string => $d->value, $mapping->acceptedHandles)),
            ));
        }

        $nowMs = (int) floor(microtime(true) * 1000);
        $status = 0;
        $channelBooked = false;
        $marksWritten = 0;
        $markCount = 0;
        $eventId = null;

        if ($handle->dimension->isLedger()) {
            $legitimate = $mapping->ledgerLegitimate === true;
            $status = $this->engine->confirmOutcome($handle->id, $legitimate);
            // Reputation authorization: statuses 1 and 2 always; status
            // 3 (a capped label) only for abuse outcomes — a capped
            // trust label must never mint unlimited reputation credit
            // (status 4 is the v2 confirm's trust cap and never
            // authorizes).
            $authorize = $status === 1 || $status === 2 || ($status === 3 && !$legitimate);
            if ($authorize && $context !== null) {
                $receipt = $this->engine->recordOutcomeFeedback($mapping->channel, $context, $idempotencyKey);
                $eventId = $receipt->eventId;
                $channelBooked = true;
            }
        } else {
            // The outcome-bridge write path of target-account
            // protection: an authentication failure reported against a
            // target registers the failure in the engine's target state;
            // a completed step-up clears the counter (change.md 3.4.2).
            // The clear is gated on a non-empty idempotency key: only
            // the step-up completion credit path (which always derives
            // one from the consumed challenge) may reset a target's
            // failure counter. A bare report with no key is not proof of
            // completion and must never launder a victim's state.
            if ($handle->dimension === OutcomeHandleDimension::Target && $this->marks instanceof \KiwiCaptcha\Risk\Storage\TargetStateStoreInterface) {
                if ($outcome === Outcome::AuthenticationFailure) {
                    [$source, $asn] = $this->engine->targetSpreadElements($handle->id, $context);
                    $this->marks->registerTargetFailure($handle->id, $source, $asn);
                } elseif ($outcome === Outcome::StepUpCompleted && $idempotencyKey !== null && $idempotencyKey !== '') {
                    $this->marks->clearTargetFailures($handle->id);
                }
            }
            if ($mapping->writesAbuseMark) {
                // The mark write dedupes on the report's own event id
                // (the same one the feedback channel books), so a
                // retried report never double-counts the mark. No
                // idempotency key yields '' (dedupe disabled).
                $markEventId = $this->engine->deriveOutcomeEventId(
                    $idempotencyKey,
                    $context?->scope ?? 0,
                    $mapping->channel,
                );
                $markCount = $this->marks->writeMark(
                    (string) $handle->dimension->markDimension(),
                    $handle->id,
                    (string) $mapping->markKind(),
                    $nowMs,
                    $markEventId,
                );
                $marksWritten = 1;
            }
            if ($context !== null) {
                $sessionPseudonym = $handle->dimension === OutcomeHandleDimension::Session ? $handle->id : null;
                $principalPseudonym = $handle->dimension === OutcomeHandleDimension::Principal ? $handle->id : null;
                $receipt = $this->engine->recordOutcomeFeedback(
                    $mapping->channel,
                    $context,
                    $idempotencyKey,
                    $sessionPseudonym,
                    $principalPseudonym,
                );
                $eventId = $receipt->eventId;
                $channelBooked = true;
            }
        }

        return new OutcomeReceipt(
            outcome: $outcome,
            handleDimension: $handle->dimension,
            status: $status,
            channelBooked: $channelBooked,
            marksWritten: $marksWritten,
            markCount: $markCount,
            eventId: $eventId,
        );
    }

    /**
     * Removes the long-memory marks of the handle's dimensions and
     * returns the number of marks removed. Constructed from the exact
     * keys, scan-free; a ledger handle names no mark and answers 0.
     *
     * @throws \KiwiCaptcha\Risk\Storage\RiskStoreException when the
     *                                   state backend fails
     */
    public function forget(OutcomeHandle $handle): int
    {
        $dimension = $handle->dimension->markDimension();
        if ($dimension === null) {
            return 0;
        }

        return $this->marks->forgetMarks($dimension, $handle->id);
    }
}
