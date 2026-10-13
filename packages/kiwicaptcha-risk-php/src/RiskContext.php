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
        /**
         * The raw trusted-device cookie value (32 lowercase hex chars), or
         * null when the request presents none. The engine derives the keyed
         * device pseudonym itself (buildObservation); like the session
         * value, the raw bytes never reach storage.
         */
        public readonly ?string $deviceId = null,
        /**
         * The request's submitted form field values keyed by field name:
         * the input the engine's target resolver reads when a resolver is
         * wired, so the assessment's target dimension (failure counter
         * and spread) rides the decision path. Only the resolved HMAC
         * pseudonym ever leaves the engine; the raw field values are
         * never stored, logged or passed to the state backend.
         *
         * @var array<string, string>
         */
        public readonly array $targetFields = [],
    ) {
    }
}
