<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

use KiwiCaptcha\AtomicDeleteIfPendingInterface;
use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\ConsumedStateReadableInterface;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;

/**
 * The storage capability Siteverify idempotency crash recovery requires.
 *
 * Crash reconstruction reads the retained consumed state of the token
 * (the committed deterministic outcome) and compares the consumed
 * record's own operation identity against the claiming request's
 * fingerprint. The identity is written atomically with the
 * pending→consumed transition, so it is provably the actual atomic
 * consume winner's. A custom AtomicStorageInterface without the
 * identity-aware consume capability is refused at container compile time
 * for Siteverify idempotency: the takeover path could never prove that a
 * claim is the nonce's original logical operation, so reconstruction
 * would silently refuse everything. The refusal closes the silent gap
 * where the core's consumed-state reconstruction returns null —
 * ordinary verification remains compatible with any StorageInterface.
 *
 * The full capability set is four interfaces, and the marker extends
 * every one of them. A class cannot claim the marker while implementing
 * only a subset, and the boot guard checks the same four.
 *
 *  - {@see AtomicStorageInterface}: the one-success consume transition;
 *  - {@see ConsumedStateReadableInterface}: the retained-state read;
 *  - {@see OperationIdentityAwareStorageInterface}: the identity-bearing
 *    consume;
 *  - {@see AtomicDeleteIfPendingInterface}: the fused cheap-failure
 *    cleanup. A custom store lacking it keeps the read-then-delete race
 *    on the cleanup path. A concurrent redeemer can consume (and
 *    commit) between the retained-state read and the best-effort delete,
 *    and the delete then erases the committed recovery evidence the
 *    whole reconstruction depends on. A store implementing only the
 *    first three passes the capability check as a recovery-capable
 *    backend while still destroying evidence under concurrency, so the
 *    fourth capability is required exactly like the others.
 *
 * The bundled KiwiCaptcha\Storage\ArrayStorage and
 * KiwiCaptcha\Storage\RedisStorage satisfy all four capabilities
 * directly.
 */
interface SiteVerifyRecoveryCapableStorageInterface extends
    AtomicStorageInterface,
    ConsumedStateReadableInterface,
    OperationIdentityAwareStorageInterface,
    AtomicDeleteIfPendingInterface
{
}
