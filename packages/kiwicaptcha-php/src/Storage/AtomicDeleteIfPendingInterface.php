<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Optional storage capability: the cheap-failure cleanup decision and
 * the delete itself are one atomic transition, closing the
 * check-then-delete race of a separate
 * {@see ConsumedStateReadableInterface::consumedState()} read followed
 * by {@see StorageInterface::delete()}.
 *
 * Without the fused transition, a concurrent redeemer can consume (and
 * commit) a record between the verifier's retained-state read and its
 * best-effort delete — the delete would then erase the committed
 * recovery evidence. The fused script decides atomically. A missing
 * record reports missing; a pending record is deleted (the one-shot
 * cheap-failure policy) and reports deleted-pending. A consumed record
 * is kept untouched, and its retained state (the committed result and
 * the recorded operation identity) rides back on the answer, so the
 * caller needs no second lookup.
 *
 * Implemented by {@see \KiwiCaptcha\Storage\RedisStorage} (one Lua
 * script) and {@see \KiwiCaptcha\Storage\ArrayStorage} (the
 * in-process array makes the read-decide-delete sequence de-facto
 * atomic — the same tri-state contract without a script).
 */
interface AtomicDeleteIfPendingInterface extends ConsumedStateReadableInterface
{
    /**
     * The atomic cleanup transition. Never deletes a consumed record.
     *
     * @return DeleteIfPendingResult 'missing' | 'deleted-pending' |
     *                               'consumed' (with the retained
     *                               {@see ConsumedRecord} carrying the
     *                               committed result and the recorded
     *                               operation identity)
     */
    public function deleteIfPending(string $nonce): DeleteIfPendingResult;
}
