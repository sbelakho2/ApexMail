<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * A storage that can RE-ESTABLISH the verified replica-WAIT barrier at an
 * acceptance point.
 *
 * The failed-barrier replay hole: a security mutation can land on the
 * primary and its WAIT can still fail (fewer replicas acked than
 * configured). A later "same-state/read-only" retry that ACCEPTS the
 * mutated state — the stored-result replay, a completed idempotency
 * record, a recovered stage-2 challenge, a final disposition — must not
 * return success on replication-unproven state: a promotion could lose
 * it. Every such acceptance path calls confirmReplication() first: the
 * barrier waits for the configured replica count to catch up to the
 * server's current write offset (which includes the earlier mutation),
 * and a shortfall THROWS — the acceptance fails closed instead of
 * returning an unproven success. When waitReplicas <= 0 (the default),
 * the barrier is a no-op and the behavior is unchanged.
 */
interface ReplicationBarrierInterface
{
    public function confirmReplication(string $what): void;
}
