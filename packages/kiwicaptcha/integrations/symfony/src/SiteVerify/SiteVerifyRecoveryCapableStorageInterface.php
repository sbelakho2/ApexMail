<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\ConsumedStateReadableInterface;

/**
 * The storage capability Siteverify idempotency crash recovery requires.
 *
 * Crash reconstruction reads the retained consumed state of the token
 * (the committed deterministic outcome) — a read-only capability that
 * not every atomic storage has. A custom AtomicStorageInterface WITHOUT
 * the consumed-state capability is refused at container compile time for
 * Siteverify idempotency: the takeover path could never reconstruct a
 * crashed owner's committed outcome. The refusal closes the silent gap
 * where {@see \KiwiCaptcha\ConsumedOutcomeRecovery} returns null —
 * ordinary verification remains compatible with any StorageInterface.
 *
 * The bundled KiwiCaptcha\Storage\ArrayStorage and
 * KiwiCaptcha\Storage\RedisStorage satisfy both base capabilities
 * directly.
 */
interface SiteVerifyRecoveryCapableStorageInterface extends AtomicStorageInterface, ConsumedStateReadableInterface
{
}
