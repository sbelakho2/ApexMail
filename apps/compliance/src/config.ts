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
        weights: z.object({
            spamComplaints: z.coerce.number().default(1.5),
            bounceRate: z.coerce.number().default(1.2),
            phishingDetection: z.coerce.number().default(2.0),
            contentViolation: z.coerce.number().default(1.5),
            sendingPattern: z.coerce.number().default(1.0),
            accountAge: z.coerce.number().default(0.8),
            verificationStatus: z.coerce.number().default(0.7),
            paymentHistory: z.coerce.number().default(0.9),
            listQuality: z.coerce.number().default(1.1),
            engagementRate: z.coerce.number().default(0.6),
        }).default({}),
        thresholds: z.object({
            spamComplaintRate: z.coerce.number().default(0.1),
            bounceRate: z.coerce.number().default(5.0),
        }).default({}),
        baseLimits: z.object({
            maxDailyEmails: z.coerce.number().default(10000),
            maxHourlyEmails: z.coerce.number().default(1000),
            maxRecipients: z.coerce.number().default(500),
            maxAttachmentSizeMb: z.coerce.number().default(25),
        }).default({}),
    }),

    contentScanning: z.object({
        enabled: z.boolean().default(true),
        ocrEnabled: z.boolean().default(true),
        maxImageSizeBytes: z.coerce.number().default(10485760), // 10MB
        bannedDomains: z.array(z.string()).default([]),
        maxOcrImages: z.coerce.number().default(5),
        spamThreshold: z.coerce.number().default(50),
        maxAttachmentSize: z.coerce.number().default(26214400), // 25MB
    }),

    auditLog: z.object({
        retentionDays: z.coerce.number().default(365),
        signatureAlgorithm: z.string().default('SHA-256'),
        hashChainEnabled: z.boolean().default(true),
        signingKey: z.string().default(''),
    }),

    gdpr: z.object({
        dataRetentionDays: z.coerce.number().default(730), // 2 years
        exportFormat: z.enum(['json', 'csv']).default('json'),
        deletionGracePeriodDays: z.coerce.number().default(30),
        requestExpirationDays: z.coerce.number().default(30),
        exportExpirationDays: z.coerce.number().default(7),
        exportBaseUrl: z.string().default('https://exports.apexmail.ee'),
        verifyBaseUrl: z.string().default('https://gdpr.apexmail.ee'),
    }),

    secrets: z.object({
        encryptionKey: z.string().default(''),
        rotationDays: z.coerce.number().default(90),
        maxVersionsToKeep: z.coerce.number().default(10),
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
            weights: {
                spamComplaints: process.env['RISK_WEIGHT_SPAM_COMPLAINTS'],
                bounceRate: process.env['RISK_WEIGHT_BOUNCE_RATE'],
                phishingDetection: process.env['RISK_WEIGHT_PHISHING'],
                contentViolation: process.env['RISK_WEIGHT_CONTENT_VIOLATION'],
                sendingPattern: process.env['RISK_WEIGHT_SENDING_PATTERN'],
                accountAge: process.env['RISK_WEIGHT_ACCOUNT_AGE'],
                verificationStatus: process.env['RISK_WEIGHT_VERIFICATION'],
                paymentHistory: process.env['RISK_WEIGHT_PAYMENT'],
                listQuality: process.env['RISK_WEIGHT_LIST_QUALITY'],
                engagementRate: process.env['RISK_WEIGHT_ENGAGEMENT'],
            },
            thresholds: {
                spamComplaintRate: process.env['RISK_THRESHOLD_SPAM_RATE'],
                bounceRate: process.env['RISK_THRESHOLD_BOUNCE_RATE'],
            },
            baseLimits: {
                maxDailyEmails: process.env['RISK_BASE_MAX_DAILY'],
                maxHourlyEmails: process.env['RISK_BASE_MAX_HOURLY'],
                maxRecipients: process.env['RISK_BASE_MAX_RECIPIENTS'],
                maxAttachmentSizeMb: process.env['RISK_BASE_MAX_ATTACHMENT_SIZE'],
            },
        },

        contentScanning: {
            enabled: process.env['CONTENT_SCANNING_ENABLED'] !== 'false',
            ocrEnabled: process.env['CONTENT_OCR_ENABLED'] !== 'false',
            maxImageSizeBytes: process.env['CONTENT_MAX_IMAGE_SIZE'],
            bannedDomains: process.env['CONTENT_BANNED_DOMAINS']
                ? process.env['CONTENT_BANNED_DOMAINS'].split(',')
                : [],
            maxOcrImages: process.env['CONTENT_MAX_OCR_IMAGES'],
            spamThreshold: process.env['CONTENT_SPAM_THRESHOLD'],
            maxAttachmentSize: process.env['CONTENT_MAX_ATTACHMENT_SIZE'],
        },

        auditLog: {
            retentionDays: process.env['AUDIT_RETENTION_DAYS'],
            signatureAlgorithm: process.env['AUDIT_SIGNATURE_ALGORITHM'],
            hashChainEnabled: process.env['AUDIT_HASH_CHAIN'] !== 'false',
            signingKey: process.env['AUDIT_SIGNING_KEY'] || '',
        },

        gdpr: {
            dataRetentionDays: process.env['GDPR_RETENTION_DAYS'],
            exportFormat: process.env['GDPR_EXPORT_FORMAT'],
            deletionGracePeriodDays: process.env['GDPR_DELETION_GRACE_PERIOD'],
            requestExpirationDays: process.env['GDPR_REQUEST_EXPIRATION_DAYS'],
            exportExpirationDays: process.env['GDPR_EXPORT_EXPIRATION_DAYS'],
            exportBaseUrl: process.env['GDPR_EXPORT_BASE_URL'],
            verifyBaseUrl: process.env['GDPR_VERIFY_BASE_URL'],
        },

        secrets: {
            encryptionKey: process.env['SECRETS_ENCRYPTION_KEY'] || '',
            rotationDays: process.env['SECRETS_ROTATION_DAYS'],
            maxVersionsToKeep: process.env['SECRETS_MAX_VERSIONS'],
        },
    });
}

export const config = loadConfig();
export const complianceConfig = config;
