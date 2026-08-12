<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

use KiwiCaptcha\Risk\Network\NetworkFlags;

/**
 * Inputs of one risk assessment.
 */
final class RiskContext
{
    public function __construct(
        public readonly int $scope,
        public readonly string $sourceIp,
        public readonly ?string $sessionId,
        public readonly ?string $principalId,
        public readonly RiskEventKind $event,
        public readonly NetworkFlags $networkFlags,
        public readonly ResourcePressure $resources,
    ) {
    }
}
