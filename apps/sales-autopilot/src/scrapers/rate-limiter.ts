/**
 * Rate Limiter for Ethical Web Scraping
 * Implements token bucket algorithm with per-domain limits
 * 
 * FIX-500-153: Backed by Redis for cross-instance consistency.
 * Falls back to in-memory when Redis is unavailable.
 */

import { createLogger } from '@apexmail/lib/logger';
import { config } from '../config.js';
import { getRedisClient } from '../redis.js';
import { getCrawlDelay } from './robots-service.js';

const logger = createLogger({ name: 'rate-limiter', level: 'info' });

interface DomainBucket {
    tokens: number;
    lastRefill: number;
    crawlDelay: number | null;
    lastRequest: number;
}

// Local fallback when Redis is down
const localDomainBuckets = new Map<string, DomainBucket>();

const localGlobalTokens = {
    tokens: config.scraper.requestsPerMinute,
    lastRefill: Date.now(),
};

const REDIS_PREFIX = 'ratelimit:';
const BUCKET_TTL = 600; // 10 minutes auto-expire

/**
 * FIX-500-247: Periodic pruning of stale local fallback entries.
 * Evicts buckets that haven't been used in BUCKET_TTL seconds.
 */
setInterval(() => {
    const now = Date.now();
    const staleThreshold = BUCKET_TTL * 1000; // Convert to ms
    let pruned = 0;
    for (const [domain, bucket] of localDomainBuckets) {
        if (now - bucket.lastRequest > staleThreshold && now - bucket.lastRefill > staleThreshold) {
            localDomainBuckets.delete(domain);
            pruned++;
        }
    }
    if (pruned > 0) {
        logger.info('Pruned stale local rate-limiter buckets', { pruned, remaining: localDomainBuckets.size });
    }
}, 5 * 60 * 1000).unref(); // Every 5 minutes

/**
 * FIX-500-153: Get/create domain bucket from Redis (or local fallback).
 */
async function getDomainBucket(domain: string): Promise<DomainBucket> {
    const crawlDelay = await getCrawlDelay(domain);
    const now = Date.now();

    try {
        const redis = getRedisClient();
        const key = `${REDIS_PREFIX}domain:${domain}`;
        const data = await redis.hgetall(key);

        let bucket: DomainBucket;
        if (data && data.tokens !== undefined) {
            bucket = {
                tokens: Number(data.tokens),
                lastRefill: Number(data.lastRefill),
                crawlDelay: data.crawlDelay === 'null' ? null : Number(data.crawlDelay),
                lastRequest: Number(data.lastRequest),
            };
        } else {
            bucket = { tokens: 10, lastRefill: now, crawlDelay, lastRequest: 0 };
            await redis.hmset(key,
                'tokens', String(bucket.tokens),
                'lastRefill', String(bucket.lastRefill),
                'crawlDelay', String(bucket.crawlDelay ?? 'null'),
                'lastRequest', String(bucket.lastRequest)
            );
            await redis.expire(key, BUCKET_TTL);
        }

        // Refill tokens (10 tokens per minute per domain)
        const elapsed = now - bucket.lastRefill;
        const refillAmount = Math.floor(elapsed / 6000);
        if (refillAmount > 0) {
            bucket.tokens = Math.min(10, bucket.tokens + refillAmount);
            bucket.lastRefill = now;
            await redis.hmset(key, 'tokens', String(bucket.tokens), 'lastRefill', String(bucket.lastRefill));
            await redis.expire(key, BUCKET_TTL);
        }

        return bucket;
    } catch {
        // Redis unavailable — use local fallback
        let bucket = localDomainBuckets.get(domain);
        if (!bucket) {
            bucket = { tokens: 10, lastRefill: now, crawlDelay, lastRequest: 0 };
            localDomainBuckets.set(domain, bucket);
        }
        const elapsed = now - bucket.lastRefill;
        const refillAmount = Math.floor(elapsed / 6000);
        if (refillAmount > 0) {
            bucket.tokens = Math.min(10, bucket.tokens + refillAmount);
            bucket.lastRefill = now;
        }
        return bucket;
    }
}

/**
 * FIX-500-153: Persist domain bucket updates to Redis.
 */
async function saveDomainBucket(domain: string, bucket: DomainBucket): Promise<void> {
    try {
        const redis = getRedisClient();
        const key = `${REDIS_PREFIX}domain:${domain}`;
        await redis.hmset(key,
            'tokens', String(bucket.tokens),
            'lastRefill', String(bucket.lastRefill),
            'crawlDelay', String(bucket.crawlDelay ?? 'null'),
            'lastRequest', String(bucket.lastRequest)
        );
        await redis.expire(key, BUCKET_TTL);
    } catch {
        // local bucket already updated in-place
    }
}

/**
 * FIX-500-153: Get/refill global tokens from Redis.
 */
async function getGlobalTokens(): Promise<{ tokens: number; lastRefill: number }> {
    const now = Date.now();
    try {
        const redis = getRedisClient();
        const key = `${REDIS_PREFIX}global`;
        const data = await redis.hgetall(key);

        let tokens: number;
        let lastRefill: number;

        if (data && data.tokens !== undefined) {
            tokens = Number(data.tokens);
            lastRefill = Number(data.lastRefill);
        } else {
            tokens = config.scraper.requestsPerMinute;
            lastRefill = now;
        }

        const elapsed = now - lastRefill;
        const refillAmount = Math.floor((elapsed / 60000) * config.scraper.requestsPerMinute);
        if (refillAmount > 0) {
            tokens = Math.min(config.scraper.requestsPerMinute, tokens + refillAmount);
            lastRefill = now;
        }

        await redis.hmset(key, 'tokens', String(tokens), 'lastRefill', String(lastRefill));
        await redis.expire(key, BUCKET_TTL);

        return { tokens, lastRefill };
    } catch {
        // Local fallback
        const elapsed = now - localGlobalTokens.lastRefill;
        const refillAmount = Math.floor((elapsed / 60000) * config.scraper.requestsPerMinute);
        if (refillAmount > 0) {
            localGlobalTokens.tokens = Math.min(config.scraper.requestsPerMinute, localGlobalTokens.tokens + refillAmount);
            localGlobalTokens.lastRefill = now;
        }
        return { ...localGlobalTokens };
    }
}

async function saveGlobalTokens(tokens: number, lastRefill: number): Promise<void> {
    try {
        const redis = getRedisClient();
        const key = `${REDIS_PREFIX}global`;
        await redis.hmset(key, 'tokens', String(tokens), 'lastRefill', String(lastRefill));
        await redis.expire(key, BUCKET_TTL);
    } catch {
        localGlobalTokens.tokens = tokens;
        localGlobalTokens.lastRefill = lastRefill;
    }
}

/**
 * Acquires a rate limit token for a domain
 * Returns the number of milliseconds to wait, or 0 if can proceed immediately
 */
export async function acquireToken(domain: string): Promise<number> {
    const bucket = await getDomainBucket(domain);
    const now = Date.now();

    // Check crawl delay from robots.txt
    if (bucket.crawlDelay !== null && bucket.lastRequest > 0) {
        const timeSinceLastRequest = now - bucket.lastRequest;
        const requiredDelay = bucket.crawlDelay * 1000;

        if (timeSinceLastRequest < requiredDelay) {
            const waitTime = requiredDelay - timeSinceLastRequest;
            logger.debug('Respecting crawl delay', { domain, waitTime });
            return waitTime;
        }
    }

    // Check per-domain limit
    if (bucket.tokens < 1) {
        const waitTime = 6000 - (now - bucket.lastRefill);
        logger.debug('Domain rate limit reached', { domain, waitTime });
        return Math.max(0, waitTime);
    }

    // Check global limit
    const global = await getGlobalTokens();
    if (global.tokens < 1) {
        const waitTime =
            60000 / config.scraper.requestsPerMinute -
            (now - global.lastRefill);
        logger.debug('Global rate limit reached', { waitTime });
        return Math.max(0, waitTime);
    }

    // Consume tokens
    bucket.tokens--;
    bucket.lastRequest = now;
    global.tokens--;

    await saveDomainBucket(domain, bucket);
    await saveGlobalTokens(global.tokens, global.lastRefill);

    return 0;
}

/**
 * Waits for rate limit and returns when ready
 */
export async function waitForRateLimit(domain: string): Promise<void> {
    let waitTime = await acquireToken(domain);

    while (waitTime > 0) {
        logger.debug('Rate limiting', { domain, waitMs: waitTime });
        await new Promise((resolve) => setTimeout(resolve, waitTime));
        waitTime = await acquireToken(domain);
    }
}

/**
 * Gets current rate limit status
 * FIX-500-153: Reads from Redis (or local fallback).
 */
export async function getRateLimitStatus(): Promise<{
    globalTokens: number;
    domainBuckets: Map<string, { tokens: number; crawlDelay: number | null }>;
}> {
    const global = await getGlobalTokens();
    const buckets = new Map<string, { tokens: number; crawlDelay: number | null }>();

    // List known domains from local cache (Redis SCAN would be heavier)
    for (const [domain] of localDomainBuckets.entries()) {
        const bucket = await getDomainBucket(domain);
        buckets.set(domain, { tokens: bucket.tokens, crawlDelay: bucket.crawlDelay });
    }

    return {
        globalTokens: global.tokens,
        domainBuckets: buckets,
    };
}

/**
 * Resets rate limits (useful for testing)
 * FIX-500-153: Also clears Redis keys.
 */
export async function resetRateLimits(): Promise<void> {
    localDomainBuckets.clear();
    localGlobalTokens.tokens = config.scraper.requestsPerMinute;
    localGlobalTokens.lastRefill = Date.now();

    try {
        const redis = getRedisClient();
        // Delete global key
        await redis.del(`${REDIS_PREFIX}global`);
        // Scan and delete domain keys
        let cursor = '0';
        do {
            const [newCursor, keys] = await redis.scan(cursor, 'MATCH', `${REDIS_PREFIX}domain:*`, 'COUNT', '100');
            cursor = newCursor;
            if (keys.length > 0) {
                await redis.del(...keys);
            }
        } while (cursor !== '0');
    } catch {
        // Redis unavailable — local already cleared
    }
}
