<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Risk\Outcomes\KiwiOutcomes;
use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;
use KiwiCaptcha\Risk\Outcomes\OutcomeReceipt;
use KiwiCaptcha\Risk\RiskContext;

/**
 * The default {@see OutcomeReporterInterface} binding: a thin adapter
 * over the risk package's typed outcomes facade. Every report resolves
 * through the one versioned mapping table, so the bundle never builds a
 * second mapping of its own.
 */
final class KiwiOutcomeReporter implements OutcomeReporterInterface
{
    public function __construct(
        private readonly KiwiOutcomes $outcomes,
    ) {
    }

    public function report(
        Outcome $outcome,
        OutcomeHandle $handle,
        ?string $idempotencyKey = null,
        ?RiskContext $context = null,
    ): OutcomeReceipt {
        return $this->outcomes->report($outcome, $handle, $idempotencyKey, $context);
    }
}
