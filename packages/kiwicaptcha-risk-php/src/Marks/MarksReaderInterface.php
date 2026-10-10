<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Marks;

/**
 * The marks reader seam of the engine wiring: given the identity
 * picture the engine derived, answer the marks view of the request and
 * the TTL window the stage must honor (the reader's store may carry a
 * custom mark TTL). The default implementation over a marks store is
 * StoreMarksReader; deployments that resolve the agent, ASN or target
 * dimensions supply their own.
 */
interface MarksReaderInterface
{
    /**
     * The marks view of one request.
     *
     * @throws \KiwiCaptcha\Risk\Storage\RiskStoreException when the
     *                                   underlying marks surface fails;
     *                                   the engine then applies
     *                                   MarksEscalation::applyUnreadable()
     *                                   fail-closed
     */
    public function requestMarks(MarksRequest $request): MarksView;

    /** The mark TTL window (ms) the stage honors for this reader's store. */
    public function markTtlMs(): int;
}
