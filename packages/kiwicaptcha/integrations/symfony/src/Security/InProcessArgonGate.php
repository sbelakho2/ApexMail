<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

use KiwiCaptcha\VerificationAdmissionGate;

/**
 * In-process Argon2id admission gate (token-set based).
 *
 * Caps concurrent Argon2id verifications within the current PHP process via
 * a static set of live lease tokens, implementing the core's
 * {@see \KiwiCaptcha\VerificationAdmissionGate}: acquire() returns an opaque
 * token and release() removes exactly that token. A stale or double release
 * is a no-op that can never remove a newer lease.
 *
 * Documented limitation: PHP-FPM workers are separate processes with no
 * shared memory, so this bounds concurrency per worker, not per deployment.
 * Multi-worker deployments must use the Redis-backed
 * {@see RedisAdmissionSemaphore} (cross-worker, tokenized leases) whenever a
 * Redis client is available; the bundle's rate limiting bounds the inflow
 * that reaches verification in every case.
 */
final class InProcessArgonGate implements VerificationAdmissionGate
{
    /** @var array<string, true> live lease tokens, per process */
    private static array $leases = [];

    public function __construct(private readonly int $maxConcurrent)
    {
    }

    public function acquire(): ?string
    {
        if ($this->maxConcurrent <= 0) {
            return 'disabled';
        }
        // PHP-FPM workers are single-threaded per request, so within one
        // process there is no concurrent acquire to race.
        if (\count(self::$leases) >= $this->maxConcurrent) {
            return null;
        }
        $token = bin2hex(random_bytes(16));
        self::$leases[$token] = true;

        return $token;
    }

    public function release(string $lease): void
    {
        if ($lease === 'disabled') {
            return;
        }
        unset(self::$leases[$lease]);
    }

    /** @internal test hook: live lease count in the current process. */
    public static function activeCount(): int
    {
        return \count(self::$leases);
    }

    /** @internal test hook: clear all leases held by the current process. */
    public static function resetForTests(): void
    {
        self::$leases = [];
    }
}
