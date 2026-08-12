<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use KiwiCaptcha\Risk\ResourcePressure;

/**
 * Supplies the live resource-pressure snapshot fed into every risk-v1
 * assessment ({@see \KiwiCaptcha\Risk\RiskContext::$resources}).
 *
 * The engine's policy consults this snapshot for its capacity-denial paths
 * (issuanceCapacity < 100 denies, argonCapacity < 300 degrades Argon actions
 * to Sha20). A provider that cannot observe a source must report the
 * nominal 1000 for it — pressure is an availability signal, and an
 * unavailable source must never fabricate artificial scarcity.
 */
interface ResourcePressureProviderInterface
{
    /**
     * Current fixed-point (0..1000) resource pressure snapshot.
     *
     * @throws \Throwable only if no degraded snapshot is possible — the
     *                    engine expects this call to stay on the fast path
     */
    public function snapshot(): ResourcePressure;
}
