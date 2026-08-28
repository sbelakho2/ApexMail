<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

/**
 * Thrown when a required PSR-6 rate-limit window write fails: PSR-6 permits
 * `CacheItemPoolInterface::save()` to return false without raising, and a
 * silent false would let an admit decision stand with its accounting never
 * persisted. The limiter therefore fails closed: any save returning false on
 * an admit path raises this exception, and the challenge controller converts
 * it to the retryable structured 503 (SERVICE_UNAVAILABLE), exactly like a
 * Redis outage. A denied request writes nothing and never raises.
 *
 * Partial charging is acceptable and conservative: when an admit must
 * persist two windows (the per-client item and the deployment-global
 * `kr_global` item) and the first save lands before the second fails, the
 * exception still propagates and the request is refused. The next request
 * re-reads the current state and prunes with a newer clock, so a partially
 * charged window is never double-counted beyond the documented best-effort
 * semantics of a generic PSR-6 pool.
 *
 * `getItem()` failures already propagate as CacheException (PSR-6 contract)
 * and are not re-wrapped; this exception is exclusively the false-save case.
 */
final class RateLimitStorageException extends \RuntimeException
{
}
