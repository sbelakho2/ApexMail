<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;
use KiwiCaptcha\Risk\Outcomes\OutcomeReceipt;
use KiwiCaptcha\Risk\RiskContext;

/**
 * The bundle's seam onto the typed outcomes facade, the report method
 * of KiwiOutcomes.
 *
 * The facade itself is final, so the framework bridge depends on this
 * narrow interface instead: the default binding is the thin
 * {@see KiwiOutcomeReporter} adapter over the facade, and tests (or an
 * application) can substitute any reporter without touching the bridge.
 * The signature is the facade's own report contract, verbatim: one
 * outcome, one handle, the caller's idempotency key and an optional
 * report context.
 */
interface OutcomeReporterInterface
{
    /**
     * Reports one typed outcome for one handle.
     *
     * @param string|null $idempotencyKey the caller's dedupe authority:
     *                                     the same key books the same
     *                                     mapped event exactly once
     * @param RiskContext|null $context   the observation context; null =
     *                                     a deferred outcome with no
     *                                     request to observe
     */
    public function report(
        Outcome $outcome,
        OutcomeHandle $handle,
        ?string $idempotencyKey = null,
        ?RiskContext $context = null,
    ): OutcomeReceipt;
}
