<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * The canonical authority-safety classification of a Redis client
 * (docs/ha-authority.md), shared by the verified-WAIT guard, the
 * runtime authority classifier and the pinned-primary authority guard.
 *
 * The classification is judged from the actual constructed instance,
 * never from a definition shape: the live connection object a Predis
 * client built, or the absence of any inspectable connection.
 *
 * - Safe: a single-node direct connection with client-side reconnect
 *   retries disabled. The serving authority is the one node, there is
 *   no promotion machinery that could change it under the client, and
 *   a failed write can never be re-executed on a replacement
 *   connection whose write offset is empty.
 * - Unsafe: a proven automatic-failover aggregate (Predis Sentinel,
 *   master-slave replication or Redis Cluster). Commands route through
 *   promotion machinery, so the authority can change without the
 *   bundle noticing. A direct connection with retries enabled is also
 *   Unsafe: a lost response can transparently re-execute a
 *   durability-critical mutation on a fresh connection.
 * - Unknown: the client cannot be inspected. An opaque product, a
 *   custom-factory result, a decorator, a non-Redis abstraction, or a
 *   client whose connection cannot be read. Under the fail_closed and
 *   pinned_primary postures unknown is refused until proven safe; the
 *   verified-WAIT guard treats unknown as pass, because its refusal
 *   surface is the proven-unsafe topology and an in-memory stand-in
 *   without a connection object must keep constructing.
 */
enum AuthoritySafety
{
    case Safe;
    case Unsafe;
    case Unknown;
}
