<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Pricing;

/**
 * The price-context seam of the engine wiring (the marks-reader
 * precedent): given the identity picture the engine derived, answer the
 * pricing inputs of the request. The bucket trust is the same record the
 * trust plane reads; the value class is the deployment's own mapping of
 * the scope or form to what the action protects.
 */
interface PriceContextSourceInterface
{
    /**
     * The pricing inputs of one request.
     *
     * @throws \Throwable when the underlying surface fails; the engine
     *                   then prices the request with
     *                   PriceInputs::failClosed() so an unreadable trust
     *                   record escalates instead of discounting
     */
    public function priceInputs(PriceRequest $request): PriceInputs;
}
