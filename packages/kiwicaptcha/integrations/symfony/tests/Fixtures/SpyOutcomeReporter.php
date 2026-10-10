<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandle;
use KiwiCaptcha\Risk\Outcomes\OutcomeReceipt;
use KiwiCaptcha\Risk\RiskContext;

/**
 * Outcome reporter spy: records every report call of the bridge so the
 * tests can assert handles, idempotency keys and contexts without a
 * state backend. Optionally throws, to prove the never-break contract
 * of the listener.
 */
final class SpyOutcomeReporter implements \BelConsulting\KiwiCaptchaBundle\Risk\OutcomeReporterInterface
{
    /** @var list<array{outcome: Outcome, handle: OutcomeHandle, idempotencyKey: ?string, context: ?RiskContext}> */
    public array $reports = [];

    public ?\Throwable $throwOnReport = null;

    public function report(
        Outcome $outcome,
        OutcomeHandle $handle,
        ?string $idempotencyKey = null,
        ?RiskContext $context = null,
    ): OutcomeReceipt {
        if ($this->throwOnReport !== null) {
            throw $this->throwOnReport;
        }
        $this->reports[] = ['outcome' => $outcome, 'handle' => $handle, 'idempotencyKey' => $idempotencyKey, 'context' => $context];

        return new OutcomeReceipt(
            outcome: $outcome,
            handleDimension: $handle->dimension,
            status: 0,
            channelBooked: $context !== null,
            marksWritten: 0,
            markCount: 0,
            eventId: null,
        );
    }

    /**
     * @return list<Outcome>
     */
    public function outcomes(): array
    {
        return array_map(static fn (array $r): Outcome => $r['outcome'], $this->reports);
    }
}
