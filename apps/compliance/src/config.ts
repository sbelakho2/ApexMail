/**
 * Compliance Service Configuration
 */

import { z } from 'zod';

const configSchema = z.object({
    nodeEnv: z.enum(['development', 'production', 'test']).default('development'),
    port: z.coerce.number().default(3011),

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
        keyPrefix: z.string().default('compliance:'),
    }),

    riskScoring: z.object({
        spamThreshold: z.coerce.number().default(0.7),
        phishingThreshold: z.coerce.number().default(0.5),
        abuseThreshold: z.coerce.number().default(0.6),
        maxDailyEmails: z.coerce.number().default(10000),
        newTenantDailyLimit: z.coerce.number().default(100),
        warmupDays: z.coerce.number().default(30),
    }),

    contentScanning: z.object({
        enabled: z.boolean().default(true),
        ocrEnabled: z.boolean().default(true),
        maxImageSizeBytes: z.coerce.number().default(10485760), // 10MB
        bannedDomains: z.array(z.string()).default([]),
    }),

    auditLog: z.object({
        retentionDays: z.coerce.number().default(365),
        signatureAlgorithm: z.string().default('SHA-256'),
        hashChainEnabled: z.boolean().default(true),
    }),

    gdpr: z.object({
        dataRetentionDays: z.coerce.number().default(730), // 2 years
        exportFormat: z.enum(['json', 'csv']).default('json'),
        deletionGracePeriodDays: z.coerce.number().default(30),
    }),

    secrets: z.object({
        encryptionKey: z.string().default(''),
        rotationDays: z.coerce.number().default(90),
    }),
});

export type Config = z.infer<typeof configSchema>;

export function loadConfig(): Config {
    return configSchema.parse({
        nodeEnv: process.env['NODE_ENV'],
        port: process.env['COMPLIANCE_PORT'],

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

        riskScoring: {
            spamThreshold: process.env['RISK_SPAM_THRESHOLD'],
            phishingThreshold: process.env['RISK_PHISHING_THRESHOLD'],
            abuseThreshold: process.env['RISK_ABUSE_THRESHOLD'],
            maxDailyEmails: process.env['RISK_MAX_DAILY_EMAILS'],
            newTenantDailyLimit: process.env['RISK_NEW_TENANT_LIMIT'],
            warmupDays: process.env['RISK_WARMUP_DAYS'],
        },

        contentScanning: {
            enabled: process.env['CONTENT_SCANNING_ENABLED'] !== 'false',
            ocrEnabled: process.env['CONTENT_OCR_ENABLED'] !== 'false',
            maxImageSizeBytes: process.env['CONTENT_MAX_IMAGE_SIZE'],
            bannedDomains: process.env['CONTENT_BANNED_DOMAINS']
                ? process.env['CONTENT_BANNED_DOMAINS'].split(',')
                : [],
        },

        auditLog: {
            retentionDays: process.env['AUDIT_RETENTION_DAYS'],
            signatureAlgorithm: process.env['AUDIT_SIGNATURE_ALGORITHM'],
            hashChainEnabled: process.env['AUDIT_HASH_CHAIN'] !== 'false',
        },

        gdpr: {
            dataRetentionDays: process.env['GDPR_RETENTION_DAYS'],
            exportFormat: process.env['GDPR_EXPORT_FORMAT'] as any,
            deletionGracePeriodDays: process.env['GDPR_DELETION_GRACE_PERIOD'],
        },

        secrets: {
            encryptionKey: process.env['SECRETS_ENCRYPTION_KEY'] || '',
            rotationDays: process.env['SECRETS_ROTATION_DAYS'],
        },
    });
}

export const config = loadConfig();
