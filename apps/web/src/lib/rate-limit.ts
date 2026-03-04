/**
 * Redis-backed sliding-window rate limiter for API routes.
 *
 * Uses Redis INCR + EXPIRE for distributed, crash-safe counters that
 * survive restarts and are shared across all Next.js instances.
 *
 * Falls back to an in-memory counter when Redis is unavailable so that
 * the app remains functional (but rate limits are per-process only).
 *
 * Key format: apexmail:rl:{prefix}:{ip}:{window_ts}
 */

// @ts-expect-error - ioredis types are bundled but may not resolve in all environments
import Redis from 'ioredis';
import type { NextRequest } from 'next/server';

// ─── Redis singleton (lazy, reconnecting) ─────────────────────

let redisInstance: Redis | null = null;
let redisUnavailable = false;

function getRedis(): Redis | null {
    if (redisUnavailable) return null;

    if (redisInstance) {
        return redisInstance.status === 'ready' ? redisInstance : null;
    }

    const url = process.env.REDIS_URL;
    const host = process.env.REDIS_HOST;
    if (!url && !host) {
        // No Redis configured — use in-memory silently
        redisUnavailable = true;
        return null;
    }

    try {
        redisInstance = url
            ? new Redis(url, {
                  maxRetriesPerRequest: 1,
                  connectTimeout: 3000,
                  enableReadyCheck: true,
                  lazyConnect: false,
              })
            : new Redis({
                  host: host ?? 'localhost',
                  port: parseInt(process.env.REDIS_PORT ?? '6379', 10),
                  password: process.env.REDIS_PASSWORD ?? undefined,
                  db: parseInt(process.env.REDIS_DB ?? '0', 10),
                  maxRetriesPerRequest: 1,
                  connectTimeout: 3000,
                  enableReadyCheck: true,
                  lazyConnect: false,
              });

        redisInstance.on('error', () => {
            // Swallowed — we check `status` before every call
        });

        return redisInstance.status === 'ready' ? redisInstance : null;
    } catch {
        redisUnavailable = true;
        return null;
    }
}

// ─── Client IP extraction ─────────────────────────────────────

function getClientIp(request: NextRequest): string {
    // Rightmost X-Forwarded-For IP is set by the closest trusted proxy
    const forwardedFor = request.headers.get('x-forwarded-for');
    if (forwardedFor) {
        const parts = forwardedFor.split(',');
        const rightmostIp = parts[parts.length - 1]?.trim();
        if (rightmostIp) return rightmostIp;
    }

    const realIp = request.headers.get('x-real-ip');
    return realIp?.trim() || 'unknown';
}

// ─── In-memory fallback ───────────────────────────────────────

const fallbackBuckets = new Map<string, { count: number; resetAt: number }>();
const MAX_FALLBACK_BUCKETS = 10_000;

function checkInMemory(key: string, maxRequests: number, windowMs: number): boolean {
    const now = Date.now();
    const bucket = fallbackBuckets.get(key);

    if (bucket && bucket.resetAt > now) {
        bucket.count++;
        return bucket.count > maxRequests;
    }

    // New window
    fallbackBuckets.set(key, { count: 1, resetAt: now + windowMs });

    // Evict stale entries to cap memory
    if (fallbackBuckets.size > MAX_FALLBACK_BUCKETS) {
        const keys = Array.from(fallbackBuckets.keys());
        for (const k of keys) {
            const v = fallbackBuckets.get(k);
            if (v && v.resetAt <= now) fallbackBuckets.delete(k);
        }
    }

    return false;
}

// ─── Public API ───────────────────────────────────────────────

interface RateLimitConfig {
    /** Maximum number of requests allowed within the window. */
    maxRequests: number;
    /** Time window in milliseconds. */
    windowMs: number;
}

/**
 * Create a named rate limiter backed by Redis (with in-memory fallback).
 *
 * @param prefix - Unique namespace for this limiter (e.g. `"auth:login"`)
 * @param config - Rate limit configuration
 *
 * @example
 * ```ts
 * const limiter = createRateLimiter('auth:login', { maxRequests: 10, windowMs: 15 * 60 * 1000 });
 *
 * export async function POST(request: NextRequest) {
 *   if (await limiter.check(request)) {
 *     return NextResponse.json({ error: 'Rate limited' }, { status: 429 });
 *   }
 *   // ...
 * }
 * ```
 */
export function createRateLimiter(prefix: string, config: RateLimitConfig) {
    const { maxRequests, windowMs } = config;
    const windowSeconds = Math.ceil(windowMs / 1000);

    return {
        /**
         * Returns `true` if the request should be rate-limited (rejected).
         */
        async check(request: NextRequest): Promise<boolean> {
            const ip = getClientIp(request);
            const windowKey = Math.floor(Date.now() / windowMs);
            const redisKey = `apexmail:rl:${prefix}:${ip}:${windowKey}`;

            const client = getRedis();
            if (client) {
                try {
                    const pipeline = client.pipeline();
                    pipeline.incr(redisKey);
                    // TTL = window + 1s buffer to avoid key leaks
                    pipeline.expire(redisKey, windowSeconds + 1);
                    const results = await pipeline.exec();
                    const count = (results?.[0]?.[1] as number) ?? 0;
                    return count > maxRequests;
                } catch {
                    // Redis call failed — fall through to in-memory
                }
            }

            return checkInMemory(redisKey, maxRequests, windowMs);
        },
    };
}
