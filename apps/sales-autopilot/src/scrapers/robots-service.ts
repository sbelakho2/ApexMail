/**
 * Robots.txt Parser Service
 * Ensures ethical scraping by respecting robots.txt directives
 */

// eslint-disable-next-line @typescript-eslint/no-require-imports
const robotsParser = require('robots-parser') as (url: string, txt: string) => RobotsParser;
import { createLogger } from '@apexmail/lib';
import { config } from '../config.js';

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

/**
 * Fetches and parses robots.txt for a given domain
 */
export async function fetchRobotsTxt(domain: string): Promise<RobotsParser> {
    const cached = robotsCache.get(domain);
    if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
        return cached.parser;
    }

    const robotsUrl = `https://${domain}/robots.txt`;

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
 */
export function clearRobotsCache(domain?: string): void {
    if (domain) {
        robotsCache.delete(domain);
    } else {
        robotsCache.clear();
    }
}
