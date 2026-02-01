/**
 * Rate Limiter for Ethical Web Scraping
 * Implements token bucket algorithm with per-domain limits
 */

import { createLogger } from '@apexmail/lib';
import { config } from '../config.js';
import { getCrawlDelay } from './robots-service.js';

const logger = createLogger({ name: 'rate-limiter', level: 'info' });

interface DomainBucket {
    tokens: number;
    lastRefill: number;
    crawlDelay: number | null;
    lastRequest: number;
}

const domainBuckets = new Map<string, DomainBucket>();

// Global rate limit
const globalTokens = {
    tokens: config.scraper.requestsPerMinute,
    lastRefill: Date.now(),
};

/**
 * Initializes or gets the bucket for a domain
 */
async function getDomainBucket(domain: string): Promise<DomainBucket> {
    let bucket = domainBuckets.get(domain);

    if (!bucket) {
        const crawlDelay = await getCrawlDelay(domain);
        bucket = {
            tokens: 10, // Per-domain limit
            lastRefill: Date.now(),
            crawlDelay,
            lastRequest: 0,
        };
        domainBuckets.set(domain, bucket);
    }

    // Refill tokens (10 tokens per minute per domain)
    const now = Date.now();
    const elapsed = now - bucket.lastRefill;
    const refillAmount = Math.floor(elapsed / 6000); // 1 token per 6 seconds

    if (refillAmount > 0) {
        bucket.tokens = Math.min(10, bucket.tokens + refillAmount);
        bucket.lastRefill = now;
    }

    return bucket;
}

/**
 * Refills global tokens
 */
function refillGlobalTokens(): void {
    const now = Date.now();
    const elapsed = now - globalTokens.lastRefill;
    const refillAmount = Math.floor(
        (elapsed / 60000) * config.scraper.requestsPerMinute
    );

    if (refillAmount > 0) {
        globalTokens.tokens = Math.min(
            config.scraper.requestsPerMinute,
            globalTokens.tokens + refillAmount
        );
        globalTokens.lastRefill = now;
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
    refillGlobalTokens();
    if (globalTokens.tokens < 1) {
        const waitTime =
            60000 / config.scraper.requestsPerMinute -
            (now - globalTokens.lastRefill);
        logger.debug('Global rate limit reached', { waitTime });
        return Math.max(0, waitTime);
    }

    // Consume tokens
    bucket.tokens--;
    bucket.lastRequest = now;
    globalTokens.tokens--;

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
 */
export function getRateLimitStatus(): {
    globalTokens: number;
    domainBuckets: Map<string, { tokens: number; crawlDelay: number | null }>;
} {
    const buckets = new Map<string, { tokens: number; crawlDelay: number | null }>();

    for (const [domain, bucket] of domainBuckets.entries()) {
        buckets.set(domain, {
            tokens: bucket.tokens,
            crawlDelay: bucket.crawlDelay,
        });
    }

    return {
        globalTokens: globalTokens.tokens,
        domainBuckets: buckets,
    };
}

/**
 * Resets rate limits (useful for testing)
 */
export function resetRateLimits(): void {
    domainBuckets.clear();
    globalTokens.tokens = config.scraper.requestsPerMinute;
    globalTokens.lastRefill = Date.now();
}
