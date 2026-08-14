<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

/**
 * Raised when Redis WAIT cannot confirm the configured replica-acknowledge
 * threshold after a durability-critical write (challenge issuance, the
 * pending→consumed transition, or the deterministic-result commit).
 *
 * With `waitReplicas > 0` the storage layer makes a HARD durability
 * promise: the caller only learns the write "succeeded" once at least
 * `waitReplicas` replicas acknowledged it. A replica-less or lagging
 * replica set therefore FAILS CLOSED — the challenge is never handed to
 * the client (issuance), the consumed transition reports the intrinsically
 * ambiguous indeterminate state (verification), and a result commit stays
 * best-effort. Silently proceeding on a weaker acknowledgement is what
 * opened the failover replay window this barrier exists to close.
 */
final class ReplicaWaitException extends \RuntimeException
{
}
