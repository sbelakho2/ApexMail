/**
 * Robots.txt Parser Service
 * Ensures ethical scraping by respecting robots.txt directives
 *
 * FIX-500-154: Raw robots.txt text cached in Redis (L2) with 1hr TTL.
 * Local Map serves as L1 cache. On L1 miss, check Redis before fetching.
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const robotsParser = require('robots-parser') as (url: string, txt: string) => RobotsParser;
import { createLogger } from '@apexmail/lib/logger';
import { config } from '../config.js';
import { getRedisClient } from '../redis.js';

const logger = createLogger({ name: 'robots-service', level: 'info' });

interface RobotsParser {
    isAllowed(url: string, userAgent?: string): boolean | undefined;
    getCrawlDelay(userAgent?: string): number | undefined;
    getSitemaps(): string[];
}

interface RobotsCache {
    parser: RobotsParser;
    fetchedAt: number;
}

const robotsCache = new Map<string, RobotsCache>();
const CACHE_TTL_MS = 3600000; // 1 hour
const REDIS_KEY_PREFIX = 'robots:';

/**
 * Fetches and parses robots.txt for a given domain
 * FIX-500-154: Checks Redis L2 cache before making HTTP request.
 */
export async function fetchRobotsTxt(domain: string): Promise<RobotsParser> {
    // L1: local cache
    const cached = robotsCache.get(domain);
    if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
        return cached.parser;
    }

    const robotsUrl = `https://${domain}/robots.txt`;

    // L2: Redis cache
    try {
        const redis = getRedisClient();
        const redisKey = `${REDIS_KEY_PREFIX}${domain}`;
        const cachedTxt = await redis.get(redisKey);
        if (cachedTxt !== null) {
            const parser = robotsParser(robotsUrl, cachedTxt);
            robotsCache.set(domain, { parser, fetchedAt: Date.now() });
            logger.debug('Loaded robots.txt from Redis cache', { domain });
            return parser;
        }
    } catch {
        // Redis unavailable — continue to HTTP fetch
    }

    // L3: HTTP fetch
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.scraper.timeoutMs);

        const response = await fetch(robotsUrl, {
            headers: {
                'User-Agent': config.scraper.userAgent,
            },
            signal: controller.signal,
        });

        clearTimeout(timeoutId);

        let robotsTxt = '';
        if (response.ok) {
            robotsTxt = await response.text();
        }

        const parser = robotsParser(robotsUrl, robotsTxt);
        robotsCache.set(domain, { parser, fetchedAt: Date.now() });

        // FIX-500-154: Cache raw text in Redis with TTL
        try {
            const redis = getRedisClient();
            await redis.set(`${REDIS_KEY_PREFIX}${domain}`, robotsTxt, 'EX', Math.floor(CACHE_TTL_MS / 1000));
        } catch {
            // Redis unavailable — local cache is sufficient
        }

        logger.debug('Fetched robots.txt', { domain, statusCode: response.status });

        return parser;
    } catch (error) {
        logger.warn('Failed to fetch robots.txt, assuming allowed', { domain, error });

        // If we can't fetch robots.txt, create permissive parser
        const parser = robotsParser(robotsUrl, '');
        robotsCache.set(domain, { parser, fetchedAt: Date.now() });

        return parser;
    }
}

/**
 * Checks if a URL is allowed to be crawled by our user agent
 */
export async function isUrlAllowed(url: string): Promise<boolean> {
    if (!config.scraper.respectRobotsTxt) {
        return true;
    }

    try {
        const urlObj = new URL(url);
        const parser = await fetchRobotsTxt(urlObj.hostname);
        const allowed = parser.isAllowed(url, config.scraper.userAgent);
        
        if (!allowed) {
            logger.info('URL disallowed by robots.txt', { url });
        }

        return allowed ?? true;
    } catch (error) {
        logger.error('Error checking robots.txt', { url, error });
        return true; // Allow if we can't check
    }
}

/**
 * Gets the crawl delay specified in robots.txt
 */
export async function getCrawlDelay(domain: string): Promise<number | null> {
    try {
        const parser = await fetchRobotsTxt(domain);
        const delay = parser.getCrawlDelay(config.scraper.userAgent);
        return delay ?? null;
    } catch {
        return null;
    }
}

/**
 * Gets the sitemap URLs from robots.txt
 */
export async function getSitemapUrls(domain: string): Promise<string[]> {
    try {
        const parser = await fetchRobotsTxt(domain);
        return parser.getSitemaps();
    } catch {
        return [];
    }
}

/**
 * Clears the robots.txt cache for a specific domain or all domains
 * FIX-500-154: Also clears Redis cache.
 */
export async function clearRobotsCache(domain?: string): Promise<void> {
    if (domain) {
        robotsCache.delete(domain);
        try {
            const redis = getRedisClient();
            await redis.del(`${REDIS_KEY_PREFIX}${domain}`);
        } catch { /* Redis unavailable */ }
    } else {
        robotsCache.clear();
        try {
            const redis = getRedisClient();
            let cursor = '0';
            do {
                const [newCursor, keys] = await redis.scan(cursor, 'MATCH', `${REDIS_KEY_PREFIX}*`, 'COUNT', '100');
                cursor = newCursor;
                if (keys.length > 0) await redis.del(...keys);
            } while (cursor !== '0');
        } catch { /* Redis unavailable */ }
    }
}
