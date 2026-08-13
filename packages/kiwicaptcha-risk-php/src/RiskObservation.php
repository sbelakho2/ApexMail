<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

/**
 * One immutable observation applied atomically to the risk state.
 *
 * Each source/subnet identity carries its epoch plus the pseudonyms for
 * epoch-1 (previous boundary), the current epoch and epoch+1 (next
 * boundary) — every epoch key uses the pseudonym HMAC'd with ITS OWN
 * epoch, never the current-epoch pseudonym. sessionId/principalId are the
 * same 16-byte hex pseudonyms, or null when the request carries no
 * session/principal. eventId is either 16 random bytes in hex (no caller
 * idempotency key) or the 64-hex HMAC-SHA256 of the event+scope domain-
 * separated caller idempotency key (keyed by the master-derived event
 * key; the raw key never appears in Redis and low-entropy keys are not
 * dictionary-recoverable) and is the dedupe key (an identical event_id
 * never double-increments).
 */
final class RiskObservation
{
    public function __construct(
        public readonly RiskEventKind $event,
        public readonly int $scope,
        public readonly int $sourceEpoch,
        public readonly string $sourceIdPrev,
        public readonly string $sourceId,
        public readonly string $sourceIdNext,
        public readonly int $subnetEpoch,
        public readonly string $subnetIdPrev,
        public readonly string $subnetId,
        public readonly string $subnetIdNext,
        public readonly ?string $sessionId,
        public readonly ?string $principalId,
        public readonly string $eventId,
        public readonly int $networkRisk,
        public readonly int $nowMs,
    ) {
        foreach ([$sourceIdPrev, $sourceId, $sourceIdNext, $subnetIdPrev, $subnetId, $subnetIdNext] as $id) {
            if (!preg_match('/^[0-9a-f]{32}$/', $id)) {
                throw new \InvalidArgumentException('source/subnet pseudonyms must be 16-byte hex');
            }
        }
        if (($sessionId !== null && !preg_match('/^[0-9a-f]{32}$/', $sessionId))
            || ($principalId !== null && !preg_match('/^[0-9a-f]{32}$/', $principalId))) {
            throw new \InvalidArgumentException('sessionId/principalId must be 16-byte hex pseudonyms or null');
        }
        if (!preg_match('/^[0-9a-f]{32}$|^[0-9a-f]{64}$/', $eventId)) {
            throw new \InvalidArgumentException('eventId must be 16 random bytes in hex or a normalized 32-byte sha256 in hex');
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
