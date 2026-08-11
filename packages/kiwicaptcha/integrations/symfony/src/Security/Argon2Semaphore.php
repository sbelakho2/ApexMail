<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

/**
 * In-process semaphore capping concurrent Argon2id verifications.
 *
 * Each Argon2id verification allocates `argon_m_kib` of memory per hash, so
 * unbounded concurrent verifications can exhaust the worker's memory. This
 * static semaphore caps how many verifications may be in flight in the
 * current PHP process, polling for a slot for up to MAX_WAIT_SECS before
 * rejecting.
 *
 * LIMITATION (documented): PHP-FPM workers are separate processes with no
 * shared memory, so this bounds concurrency per worker, not per deployment.
 * Multi-worker deployments must additionally gate at the platform level
 * (process/workercount limits or Redis-backed admission control) — the
 * bundle's Redis-backed rate limiting bounds the inflow that reaches
 * verification.
 */
final class Argon2Semaphore
{
    private const POLL_INTERVAL_US = 50_000;

    private static float $maxWaitSecs = 5.0;

    private static int $active = 0;

    /**
     * @internal test hook: shorten the acquire wait so rejection paths can be
     *           exercised without sleeping for the production bound.
     */
    public static function setMaxWaitSecsForTests(float $secs): void
    {
        self::$maxWaitSecs = $secs;
    }

    /**
     * @internal test hook: restore the production wait bound and reset the
     *           in-process counter after tests that intentionally hold slots.
     */
    public static function resetForTests(): void
    {
        self::$maxWaitSecs = 5.0;
        self::$active = 0;
    }

    /**
     * @param int $maxConcurrent maximum concurrent verifications (<= 0 = no cap)
     */
    public static function acquire(int $maxConcurrent): bool
    {
        if ($maxConcurrent <= 0) {
            return true;
        }
        $deadline = microtime(true) + self::$maxWaitSecs;
        while (true) {
            if (self::$active < $maxConcurrent) {
                self::$active++;

                return true;
            }
            if (microtime(true) >= $deadline) {
                return false;
            }
            usleep(self::POLL_INTERVAL_US);
        }
    }

    public static function release(): void
    {
        self::$active = max(0, self::$active - 1);
    }

    public static function active(): int
    {
        return self::$active;
    }
}
