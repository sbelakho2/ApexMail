<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

/**
 * The narrow APCu backend seam every {@see ApcuStorage} state access
 * goes through: fetch, store, add and delete over string keys carrying
 * a TTL in seconds.
 *
 * The seam exists so the storage's atomicity discipline is proven
 * against a faithful in-process emulation in the test suite even where
 * the APCu extension is absent, while production runs the real
 * {@see RealApcuBackend}. The contract each implementation must hold:
 *
 *  - `add` is atomic create-if-absent: it returns true for exactly one
 *    caller when several race on one key, and a TTL-expired entry
 *    counts as absent. This is the primitive the storage's transition
 *    lock is built on, the role `apcu_add()` plays on the real backend
 *    and a kernel semaphore guards in the emulated one.
 *  - `store` is an unconditional overwrite installing the new TTL.
 *  - `fetch` answers a TTL-expired entry exactly like a missing key.
 *  - `delete` removes the key and reports whether a live entry went.
 *
 * No compare-and-swap sits in the seam on purpose: the APCu function of
 * that name, `apcu_cas()`, only exchanges integers, so it cannot carry
 * a record envelope. Every compare-and-swap the storage needs is
 * expressed as add-guarded or lock-guarded read-decide-write instead,
 * which the seam's four operations express completely.
 */
interface ApcuBackendInterface
{
    /**
     * Fetch one key's live value.
     */
    public function fetch(string $key): ApcuFetchOutcome;

    /**
     * Overwrite one key unconditionally, installing the given TTL.
     *
     * @param int  $ttlSecs the entry lifetime in seconds; the backend
     *                      collects the entry after it passes
     *
     * @return bool true when the write landed, false on a backend
     *              refusal the caller must resolve as a failure
     */
    public function store(string $key, mixed $value, int $ttlSecs): bool;

    /**
     * Atomically create the entry only when no live entry exists.
     *
     * @return bool true when this caller created the entry, false when
     *              a live entry already held the key
     */
    public function add(string $key, mixed $value, int $ttlSecs): bool;

    /**
     * Remove one key.
     *
     * @return bool true when a live entry was removed, false when the
     *              key held no live entry
     */
    public function delete(string $key): bool;
}
