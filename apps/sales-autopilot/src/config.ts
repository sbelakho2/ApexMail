/**
 * Sales Autopilot Configuration
 * 
 * CONTROL PLANE SERVICE - PROCESS ISOLATION
 * ==========================================
 * 
 * This service runs as a SEPARATE PROCESS from the customer-facing API.
 * 
 * Port Allocation:
 * - Customer Console (web):     port 3000
 * - Customer API (api):         port 3001
 * - Sales Autopilot (control):  port 3010 <-- THIS SERVICE
 * - Compliance (control):       port 3011
 * - Control Plane UI:           port 3020
 * 
 * Data Isolation:
 * - This service stores OWNER's leads, not customer data
 * - Uses separate tables: autopilot_leads, autopilot_campaigns, etc.
 * - Never accesses tenant-specific email/message data
 * 
 * Authentication:
 * - Uses internal API keys, NOT tenant API keys
 * - Control Plane UI authenticates with owner credentials
 */

import { z } from 'zod';

const configSchema = z.object({
    nodeEnv: z.enum(['development', 'production', 'test']).default('development'),
    port: z.coerce.number().default(3010),

    database: z.object({
        host: z.string().default('localhost'),
        port: z.coerce.number().default(5432),
        name: z.string().default('apexmail'),
        user: z.string().default('postgres'),
        password: z.string().default(''),
        maxConnections: z.coerce.number().default(10),
    }),

    redis: z.object({
        url: z.string().default('redis://localhost:6379'),
        keyPrefix: z.string().default('autopilot:'),
    }),

    scraper: z.object({
        // Rate limiting for ethical scraping
        requestsPerMinute: z.coerce.number().default(30),
        userAgent: z.string().default('ApexMail-LeadFinder/1.0 (https://apexmail.ee; contact@apexmail.ee)'),
        respectRobotsTxt: z.boolean().default(true),
        maxConcurrent: z.coerce.number().default(5),
        timeoutMs: z.coerce.number().default(10000),
    }),

    enrichment: z.object({
        // Company enrichment settings
        maxRetries: z.coerce.number().default(3),
        cacheHours: z.coerce.number().default(168), // 1 week
    }),

    drip: z.object({
        // Drip campaign settings
        defaultJitterMinutes: z.coerce.number().default(5),
        maxSequenceSteps: z.coerce.number().default(10),
        checkIntervalMs: z.coerce.number().default(60000), // 1 minute
    }),

    inbox: z.object({
        // Inbox monitoring
        pollIntervalMs: z.coerce.number().default(30000), // 30 seconds
        imapHost: z.string().optional(),
        imapPort: z.coerce.number().default(993),
        imapUser: z.string().optional(),
        imapPassword: z.string().optional(),
    }),

    calendar: z.object({
        // Demo scheduling
        slotDurationMinutes: z.coerce.number().default(30),
        availableHoursStart: z.coerce.number().default(9),
        availableHoursEnd: z.coerce.number().default(17),
        timezone: z.string().default('Europe/Tallinn'),
        bufferMinutes: z.coerce.number().default(15),
    }),

    promo: z.object({
        // Promotional injection
        enabled: z.boolean().default(true),
        affiliateLinks: z.record(z.string()).default({}),
    }),
});

export type Config = z.infer<typeof configSchema>;

export function loadConfig(): Config {
    return configSchema.parse({
        nodeEnv: process.env['NODE_ENV'],
        port: process.env['AUTOPILOT_PORT'],

        database: {
            host: process.env['DB_HOST'],
            port: process.env['DB_PORT'],
            name: process.env['DB_NAME'],
            user: process.env['DB_USER'],
            password: process.env['DB_PASSWORD'],
            maxConnections: process.env['DB_MAX_CONNECTIONS'],
        },

        redis: {
            url: process.env['REDIS_URL'],
            keyPrefix: process.env['REDIS_KEY_PREFIX'],
        },

        scraper: {
            requestsPerMinute: process.env['SCRAPER_REQUESTS_PER_MINUTE'],
            userAgent: process.env['SCRAPER_USER_AGENT'],
            respectRobotsTxt: process.env['SCRAPER_RESPECT_ROBOTS'] !== 'false',
            maxConcurrent: process.env['SCRAPER_MAX_CONCURRENT'],
            timeoutMs: process.env['SCRAPER_TIMEOUT_MS'],
        },

        enrichment: {
            maxRetries: process.env['ENRICHMENT_MAX_RETRIES'],
            cacheHours: process.env['ENRICHMENT_CACHE_HOURS'],
        },

        drip: {
            defaultJitterMinutes: process.env['DRIP_JITTER_MINUTES'],
            maxSequenceSteps: process.env['DRIP_MAX_STEPS'],
            checkIntervalMs: process.env['DRIP_CHECK_INTERVAL_MS'],
        },

        inbox: {
            pollIntervalMs: process.env['INBOX_POLL_INTERVAL_MS'],
            imapHost: process.env['INBOX_IMAP_HOST'],
            imapPort: process.env['INBOX_IMAP_PORT'],
            imapUser: process.env['INBOX_IMAP_USER'],
            imapPassword: process.env['INBOX_IMAP_PASSWORD'],
        },

        calendar: {
            slotDurationMinutes: process.env['CALENDAR_SLOT_DURATION'],
            availableHoursStart: process.env['CALENDAR_HOURS_START'],
            availableHoursEnd: process.env['CALENDAR_HOURS_END'],
            timezone: process.env['CALENDAR_TIMEZONE'],
            bufferMinutes: process.env['CALENDAR_BUFFER_MINUTES'],
        },

        promo: {
            enabled: process.env['PROMO_ENABLED'] !== 'false',
            affiliateLinks: parseJSON(process.env['PROMO_AFFILIATE_LINKS'], {}),
        },
    });
}

function parseJSON<T>(value: string | undefined, defaultValue: T): T {
    if (!value) return defaultValue;
    try {
        return JSON.parse(value) as T;
    } catch {
        console.warn(`Invalid JSON in config: ${value.substring(0, 50)}...`);
        return defaultValue;
    }
}

export const config = loadConfig();
