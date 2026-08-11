<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

use Psr\Cache\CacheItemPoolInterface;

/**
 * Per-client-IP rate limiter for challenge issuance.
 *
 * Deployment hardening: challenge issuance must be rate-limited, otherwise an
 * attacker can mint unlimited challenges and drive unbounded aggregate
 * verification work (each challenge costs the server an HMAC re-check and,
 * for Argon2id, a memory-hard hash on every submit attempt).
 *
 * Two backends, both best-effort by design:
 *
 *  - PSR-6 pool (`rate_limit_cache` config option): shared across processes
 *    (e.g. a Redis-backed Symfony Cache pool). PSR-6 cannot express an atomic
 *    read-modify-write counter, so concurrent requests may briefly exceed the
 *    limit — a bound, not a gate.
 *  - In-memory sliding window (default): no shared state, single-process only
 *    (PHP-FPM workers share no memory). Documented as best-effort; production
 *    multi-worker deployments should configure a shared PSR-6 pool or rate
 *    limit at the platform level.
 */
final class IssuanceRateLimiter
{
    private const CACHE_KEY_PREFIX = 'kiwi_rate_';

    /** @var array<string, list<float>> sliding-window hit timestamps, per process */
    private array $hits = [];

    /**
     * @param int         $maxChallenges 0 disables the limiter
     * @param int         $windowSecs    sliding-window size in seconds
     * @param \Closure|null $now           epoch-seconds clock override for tests
     */
    public function __construct(
        private readonly int $maxChallenges,
        private readonly int $windowSecs,
        private readonly ?CacheItemPoolInterface $pool = null,
        private readonly ?\Closure $now = null,
    ) {
    }

    public function allow(string $clientIp): bool
    {
        if ($this->maxChallenges <= 0) {
            return true;
        }
        // An unknown client IP must never bypass the limit: bucket it with
        // the other unidentifiable clients instead (conservative, shared
        // budget).
        $key = $clientIp === '' ? 'unknown' : $clientIp;

        return $this->pool !== null ? $this->allowShared($key) : $this->allowLocal($key);
    }

    private function allowLocal(string $clientIp): bool
    {
        $now = $this->now();
        $hits = $this->hits[$clientIp] ?? [];

        // Prune expired timestamps (sliding window).
        $cutoff = $now - $this->windowSecs;
        $hits = array_values(array_filter($hits, static fn (float $ts): bool => $ts >= $cutoff));

        if (\count($hits) >= $this->maxChallenges) {
            $this->hits[$clientIp] = $hits;

            return false;
        }
        $hits[] = $now;
        $this->hits[$clientIp] = $hits;

        return true;
    }

    private function allowShared(string $clientIp): bool
    {
        // PSR-6 reserves `{}()/\@:` in keys; IPv6 literals contain ':'.
        $key = self::CACHE_KEY_PREFIX.preg_replace('/[^A-Za-z0-9_.]/', '_', $clientIp);

        $item = $this->pool->getItem($key);
        $state = $item->isHit() ? $item->get() : null;
        $windowStart = \is_array($state) ? (float) ($state['window_start'] ?? 0.0) : 0.0;
        $hits = \is_array($state) ? (int) ($state['hits'] ?? 0) : 0;

        $now = $this->now();
        if ($now - $windowStart > $this->windowSecs) {
            $hits = 0;
            $windowStart = $now;
        }
        if ($hits >= $this->maxChallenges) {
            return false;
        }

        $item->set(['hits' => $hits + 1, 'window_start' => $windowStart]);
        $item->expiresAfter($this->windowSecs + 1);
        $this->pool->save($item);

        return true;
    }

    private function now(): float
    {
        return $this->now !== null ? (float) ($this->now)() : microtime(true);
    }
}
