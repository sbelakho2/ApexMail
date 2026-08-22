<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Optional capability for storages that can atomically transition a
 * `pending` challenge record to the terminal `cancelled` state. Not part
 * of {@see StorageInterface}: third-party adapters are not required to
 * implement it.
 *
 * A cancelled record is a server-side admission break: the widget
 * abandoned the challenge (its bounded solve search exhausted on a
 * stochastic tail). The server marks the record dead, unverifiable and
 * unrecoverable, while retaining it until its TTL. The envelope state is
 * written by the storage layer exactly like the pending->consumed
 * transition (the runtime `state` field), so the canonical
 * {@see ChallengeRecord} schema is untouched and the Rust reader sees
 * the same marker.
 *
 * The transition is atomic and durability-critical: a record flipped to
 * cancelled must never resurrect as pending on a promoted stale replica
 * (it would be redeemable). A backend with a verified-replica-wait
 * barrier applies it to this transition too.
 */
interface CancellableStorageInterface
{
    /**
     * Atomically transition a `pending` record to `cancelled`. The record
     * is kept until its TTL: the one-shot marker is the state, not
     * absence.
     *
     * Returns null when the record does not exist (a cancellation of a
     * never-issued or expired nonce, idempotent success upstream).
     *
     * The transition is refused for a consumed record (finalized: a
     * solved challenge can never be cancelled) and is a no-op for an
     * already-cancelled record. The caller must not read any record
     * contents from the result: a cancellation acknowledges state, it
     * never discloses the record.
     *
     * @throws \Throwable on a storage failure (fail closed: the caller
     *                    must not report a cancellation that could not be
     *                    established)
     */
    public function cancel(string $nonce): ?CancellationResult;
}
