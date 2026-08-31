<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Authority;

/**
 * The runtime classification of a Redis client's authority-transition
 * semantics, judged from the actual constructed instance (never the
 * definition shape): the connection object a Predis client built, or
 * the absence of any inspectable connection.
 *
 * - Safe: a single-node direct connection. The serving authority is
 *   the one node; there is no promotion machinery that could change
 *   it under the client.
 * - Unsafe: a proven automatic-failover aggregate (Predis Sentinel or
 *   master-slave replication, or Redis Cluster). Commands route
 *   through promotion machinery, so the authority can change without
 *   the bundle noticing, and a stale replica can re-enable a replay
 *   of an acknowledged security-final transition.
 * - Unknown: the client cannot be inspected. An opaque product, a
 *   custom-factory result, a decorator, a phpredis \Redis client, a
 *   non-Predis abstraction, or a client whose connection cannot be
 *   read. Under the fail_closed posture unknown is unsafe until
 *   proven safe; under the weaker postures it serves and the doctor
 *   carries the deployment contract.
 */
enum AuthorityClassification: string
{
    case Safe = 'safe';
    case Unsafe = 'unsafe';
    case Unknown = 'unknown';
}
