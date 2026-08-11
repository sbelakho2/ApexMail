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
 * PRIVACY: raw client IPs are never stored. Every key (both the shared
 * PSR-6 key and the in-memory bucket key) is a peppered HMAC of the IP —
 * `hash_hmac('sha256', $clientIp, $pepper)` — where the pepper defaults to
 * the bundle secret key (`rate_limit_pepper` overrides it). The same HMAC is
 * used by both backends so a shared pool and a local bucket agree on the
 * same identity.
 *
 * True sliding window (both backends): the state is the list of hit
 * timestamps (JSON `{"t": [ts, ...]}` in the shared pool), pruned to
 * `[now - window, now]` on every check, and the hit count is the number of
 * timestamps inside the window. There is no fixed [window_start, hits]
 * bucket, so a burst straddling a window boundary can never double the
 * allowed rate. Cost: the timestamp list grows with the allowed rate —
 * `rate_limit` entries per window — which is small for sane limits; each
 * check rewrites the pruned list.
 *
 * Both backends are best-effort by design: a PSR-6 pool cannot express an
 * atomic read-modify-write, so concurrent requests may briefly exceed the
 * limit — a bound, not a gate (documented in the README).
 */
final class IssuanceRateLimiter
{
    private const CACHE_KEY_PREFIX = 'kiwi_rate_';

    /** @var array<string, list<float>> sliding-window hit timestamps, per process */
    private array $hits = [];

    /**
     * @param int          $maxChallenges 0 disables the limiter
     * @param int          $windowSecs    sliding-window size in seconds
     * @param CacheItemPoolInterface|null $pool shared multi-process state
     * @param \Closure|null $now          epoch-seconds clock override for tests
     */
    public function __construct(
        private readonly int $maxChallenges,
        private readonly int $windowSecs,
        private readonly ?CacheItemPoolInterface $pool = null,
        private readonly ?\Closure $now = null,
        private readonly string $pepper = 'kiwicaptcha-rate-limit',
    ) {
    }

    public function allow(string $clientIp): bool
    {
        if ($this->maxChallenges <= 0) {
            return true;
        }
        // An unknown client IP must never bypass the limit: bucket it with
        // the other unidentifiable clients instead (conservative, shared
        // budget). The IP itself is never used as a key — only the HMAC.
        $identity = $clientIp === '' ? 'unknown' : $clientIp;
        $key = hash_hmac('sha256', $identity, $this->pepper);

        return $this->pool !== null ? $this->allowShared($key) : $this->allowLocal($key);
    }

    private function allowLocal(string $key): bool
    {
        $now = $this->now();
        $hits = $this->hits[$key] ?? [];

        $hits = $this->prune($hits, $now);

        if (\count($hits) >= $this->maxChallenges) {
            $this->hits[$key] = $hits;

            return false;
        }
        $hits[] = $now;
        $this->hits[$key] = $hits;

        return true;
    }

    private function allowShared(string $key): bool
    {
        $cacheKey = self::CACHE_KEY_PREFIX.$key;

        $item = $this->pool->getItem($cacheKey);
        $state = $item->isHit() ? $item->get() : null;
        $hits = \is_array($state) ? $this->timestamps($state) : [];

        $now = $this->now();
        $hits = $this->prune($hits, $now);

        if (\count($hits) >= $this->maxChallenges) {
            $item->set(['t' => $hits]);
            $item->expiresAfter($this->windowSecs + 1);
            $this->pool->save($item);

            return false;
        }
        $hits[] = $now;

        $item->set(['t' => $hits]);
        $item->expiresAfter($this->windowSecs + 1);
        $this->pool->save($item);

        return true;
    }

    /**
     * @param array<string, mixed> $state
     *
     * @return list<float>
     */
    private function timestamps(array $state): array
    {
        $raw = $state['t'] ?? [];
        if (!\is_array($raw)) {
            return [];
        }
        $ts = [];
        foreach ($raw as $v) {
            $ts[] = (float) $v;
        }

        return $ts;
    }

    /**
     * @param list<float> $hits
     *
     * @return list<float>
     */
    private function prune(array $hits, float $now): array
    {
        $cutoff = $now - $this->windowSecs;

        return array_values(array_filter($hits, static fn (float $ts): bool => $ts >= $cutoff));
    }

    private function now(): float
    {
        return $this->now !== null ? (float) ($this->now)() : microtime(true);
    }
}
