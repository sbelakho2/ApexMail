<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * A storage that can establish a causal replication fence at an
 * acceptance point.
 *
 * The failed-barrier replay hole: a security mutation can land on the
 * primary and its WAIT can still fail (fewer replicas acknowledged than
 * configured). A later retry on a DIFFERENT worker and Redis connection
 * must not accept the mutated state without proving its durability: a
 * bare WAIT on a connection that wrote nothing proves nothing about
 * another connection's write (Redis defines WAIT relative to the
 * writes sent by the current connection).
 *
 * The fence is a fresh write on the ACCEPTING connection immediately
 * before the WAIT: Redis replication is ordered, so a replica that has
 * acknowledged the later fence write has advanced through the preceding
 * primary replication stream, including the originally unproven
 * mutation. A shortfall THROWS and the acceptance fails closed instead
 * of returning an unproven success. When waitReplicas <= 0 (the
 * default), the fence is a no-op and the behavior is unchanged.
 */
interface ReplicationBarrierInterface
{
    public function establishReplicationFence(string $what): void;
}
