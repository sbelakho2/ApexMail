<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * One immutable observation applied atomically to the risk state.
 *
 * sourceId/subnetId are 16-byte hex pseudonyms (32 hex chars) from
 * RiskIdentityFactory; sessionId/principalId are the same, or null when the
 * request carries no session/principal. eventId is 16 random bytes in hex
 * and is the dedupe key (an identical event_id never double-increments).
 */
final class RiskObservation
{
    public function __construct(
        public readonly RiskEventKind $event,
        public readonly int $scope,
        public readonly string $sourceId,
        public readonly string $subnetId,
        public readonly ?string $sessionId,
        public readonly ?string $principalId,
        public readonly string $eventId,
        public readonly int $networkRisk,
        public readonly int $nowMs,
    ) {
        foreach ([$sourceId, $subnetId] as $id) {
            if (!preg_match('/^[0-9a-f]{32}$/', $id)) {
                throw new \InvalidArgumentException('sourceId/subnetId must be 16-byte hex pseudonyms');
            }
        }
        if (($sessionId !== null && !preg_match('/^[0-9a-f]{32}$/', $sessionId))
            || ($principalId !== null && !preg_match('/^[0-9a-f]{32}$/', $principalId))) {
            throw new \InvalidArgumentException('sessionId/principalId must be 16-byte hex pseudonyms or null');
        }
        if (!preg_match('/^[0-9a-f]{32}$/', $eventId)) {
            throw new \InvalidArgumentException('eventId must be 16 random bytes in hex');
        }
        if ($networkRisk < 0 || $networkRisk > 1000) {
            throw new \InvalidArgumentException('networkRisk must be within 0..1000');
        }
        if ($nowMs < 0) {
            throw new \InvalidArgumentException('nowMs must be >= 0');
        }
    }

    public static function newEventId(): string
    {
        return bin2hex(random_bytes(16));
    }
}
