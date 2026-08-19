<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;

/**
 * The storage capability Siteverify idempotency crash recovery requires.
 *
 * Crash reconstruction reads the retained consumed state of the token
 * (the committed deterministic outcome) AND compares the consumed
 * record's OWN operation identity against the claiming request's
 * fingerprint — the identity is written ATOMICALLY with the
 * pending→consumed transition, so it is provably the ACTUAL atomic
 * consume winner's. A custom AtomicStorageInterface WITHOUT the
 * identity-aware consume capability is refused at container compile time
 * for Siteverify idempotency: the takeover path could never prove that a
 * claim is the nonce's original logical operation, so reconstruction
 * would silently refuse everything. The refusal closes the silent gap
 * where {@see \KiwiCaptcha\ConsumedOutcomeRecovery} returns null —
 * ordinary verification remains compatible with any StorageInterface.
 *
 * The bundled KiwiCaptcha\Storage\ArrayStorage and
 * KiwiCaptcha\Storage\RedisStorage satisfy all base capabilities
 * directly.
 */
interface SiteVerifyRecoveryCapableStorageInterface extends AtomicStorageInterface, OperationIdentityAwareStorageInterface
{
}
