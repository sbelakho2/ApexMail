/**
 * ApexMail Compliance Service
 *
 * Security, compliance, and privacy automation service providing:
 * - Tenant risk scoring and monitoring
 * - Content scanning (spam, phishing, malware)
 * - Hash-chain audit logging
 * - Secret management with rotation
 * - GDPR automation and consent management
 */

import { serve } from '@hono/node-server';
import { CronJob } from 'cron';
import { Pool } from 'pg';
import { Redis } from 'ioredis';
import * as fs from 'fs/promises';
import * as path from 'path';
import { fileURLToPath } from 'url';

import app from './routes';
import { RiskScoringEngine } from './risk';
import { ContentScanner } from './content';
import { AuditLogger } from './audit';
import { SecretManager } from './secrets';
import { GDPRAutomation } from './gdpr';
import { complianceConfig } from './config';
import { createLogger } from '@apexmail/lib';

// D-117/D-118: Use structured logger instead of console.log/error
const logger = createLogger({ name: 'compliance' });

// Initialize database and Redis
const db = new Pool({
    host: complianceConfig.database.host,
    port: complianceConfig.database.port,
    database: complianceConfig.database.name,
    user: complianceConfig.database.user,
    password: complianceConfig.database.password,
    max: complianceConfig.database.maxConnections,
});
const redis = new Redis(complianceConfig.redis.url);

// Initialize services
const riskEngine = new RiskScoringEngine(db, redis);
const contentScanner = new ContentScanner(db, redis);
// FIX-500-416: The signingKey is passed as a plain string from config.
// JavaScript cannot reliably zero-out strings from heap memory.
// In production, consider using a hardware security module (HSM) or
// KMS-backed signing via an external service rather than holding keys in-process.
const auditLogger = new AuditLogger(db, redis, complianceConfig.auditLog.signingKey);
// FIX-500-417: The encryptionKey is passed as a plain string from config.
// JavaScript cannot reliably zero-out strings from heap memory.
// In production, consider using envelope encryption with a KMS-backed master key
// rather than holding the raw encryption key in-process memory.
const secretManager = new SecretManager(db, redis, complianceConfig.secrets.encryptionKey);
const gdprAutomation = new GDPRAutomation(db, redis);

/**
 * Process GDPR request queue
 */
/**
 * FIX-014: Use LMOVE to atomically move the item to a processing queue
 * before processing. Previously RPOP removed the item before processing —
 * a crash between pop and completion permanently lost the GDPR request.
 * Now the item stays in the processing queue until successfully handled,
 * and can be recovered on restart.
 */
async function processGDPRQueue(): Promise<void> {
    const PROCESSING_QUEUE = 'gdpr:requests:processing';
    // FIX-500-419: Process at most MAX_GDPR_BATCH items per cron tick to avoid
    // blocking the event loop and starving other cron jobs.
    const MAX_GDPR_BATCH = 10;
    let processed = 0;
    while (processed < MAX_GDPR_BATCH) {
        // Atomically move from main queue to processing queue
        const item = await redis.lmove(
            'gdpr:requests:queue',
            PROCESSING_QUEUE,
            'RIGHT',
            'LEFT'
        );
        if (!item) break;

        try {
            const { requestId } = JSON.parse(item);
            await gdprAutomation.processRequest(requestId);
            // Only remove from processing queue after successful completion
            await redis.lrem(PROCESSING_QUEUE, 1, item);
            logger.info('GDPR request processed', { requestId });
        } catch (err) {
            logger.error('GDPR error processing request', { error: err });
            // Move from processing to failed queue for manual review
            await redis.lrem(PROCESSING_QUEUE, 1, item);
            await redis.lpush('gdpr:requests:failed', item);
        }
        processed++;
    }
}

/**
 * Process automatic secret rotations
 */
async function processSecretRotations(): Promise<void> {
    try {
        const result = await secretManager.processAutoRotations();
        logger.info('Secret rotations completed', {
            rotated: result.rotated.length,
            notified: result.notified.length,
            errors: result.errors.length,
        });
    } catch (err) {
        logger.error('Error processing rotations', { error: err });
    }
}

/**
 * Process risk reassessments for due tenants
 */
async function processRiskAssessments(): Promise<void> {
    try {
        // Get tenants due for reassessment
        const result = await db.query(
            `SELECT tenant_id FROM risk_profiles
            WHERE next_assessment_at <= NOW()
            LIMIT 100`
        );

        for (const row of result.rows) {
            try {
                await riskEngine.forceReassessment(row.tenant_id);
                logger.info('Risk reassessed tenant', { tenantId: row.tenant_id });
            } catch (err) {
                logger.error('Risk error reassessing tenant', { tenantId: row.tenant_id, error: err });
            }
        }
    } catch (err) {
        logger.error('Risk error processing assessments', { error: err });
    }
}

/**
 * Archive old audit logs
 */
async function archiveAuditLogs(): Promise<void> {
    try {
        const retentionDays = complianceConfig.auditLog.retentionDays;
        const olderThan = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);

        const result = await auditLogger.archive(olderThan);
        logger.info('Audit logs archived', { archivedCount: result.archivedCount, olderThan: olderThan.toISOString() });
    } catch (err) {
        logger.error('Error archiving audit logs', { error: err });
    }
}

/**
 * Verify audit chain integrity
 */
async function verifyAuditChains(): Promise<void> {
    try {
        // Verify global chain
        const result = await auditLogger.verifyChain();
        if (!result.valid) {
            logger.error('Audit chain integrity check FAILED', { error: result.error });
            // Alert operations team
            // FIX-500-480: Fallback to stderr if Redis is unavailable
            const alertPayload = JSON.stringify({
                type: 'audit_chain_invalid',
                error: result.error,
                firstInvalidEntry: result.firstInvalidEntry,
                timestamp: new Date().toISOString(),
            });
            try {
                await redis.lpush('alerts:queue', alertPayload);
            } catch (redisErr) {
                logger.error('Failed to push audit alert to Redis, writing to stderr', { error: redisErr instanceof Error ? redisErr.message : String(redisErr) });
                process.stderr.write(`CRITICAL AUDIT ALERT: ${alertPayload}\n`);
            }
        } else {
            logger.info('Audit chain integrity verified', { entriesChecked: result.entriesChecked });
        }
    } catch (err) {
        logger.error('Error verifying audit chain', { error: err });
    }
}

/**
 * Initialize database schema
 *
 * FIX-500-420: This ~245 lines of inline DDL should be extracted into versioned
 * migration files under apps/compliance/migrations/ (matching the pattern used by
 * billing, devex, observability, etc.). Inline DDL at startup is fragile and
 * prevents proper schema versioning, rollbacks, and CI/CD validation.
 */
async function initializeSchema(): Promise<void> {
    await db.query(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
            id TEXT PRIMARY KEY,
            checksum TEXT NOT NULL,
            applied_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
    `);

    const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../migrations');
    const files = (await fs.readdir(migrationsDir))
        .filter((name) => name.endsWith('.sql'))
        .sort();

    for (const file of files) {
        const migrationId = file;
        const content = await fs.readFile(path.join(migrationsDir, file), 'utf8');
        const checksum = String(content.length);

        const alreadyApplied = await db.query<{ id: string; checksum: string }>(
            `SELECT id, checksum FROM schema_migrations WHERE id = $1`,
            [migrationId],
        );

        if (alreadyApplied.rows.length > 0) {
            continue;
        }

        await db.query('BEGIN');
        try {
            await db.query(content);
            await db.query(
                `INSERT INTO schema_migrations (id, checksum, applied_at)
                 VALUES ($1, $2, NOW())`,
                [migrationId, checksum],
            );
            await db.query('COMMIT');
            logger.info('Applied compliance migration', { migrationId });
        } catch (error) {
            await db.query('ROLLBACK');
            throw error;
        }
    }

    logger.info('Database schema initialized');
}

/**
 * Start background jobs
 * FIX-500-180: Store CronJob references so they can be stopped on shutdown.
 */
const cronJobs: Array<{ name: string; job: InstanceType<typeof CronJob> }> = [];

function startBackgroundJobs(): void {
    // Process GDPR queue every minute
    cronJobs.push({ name: 'gdpr-queue', job: new CronJob('* * * * *', processGDPRQueue, null, true) });

    // Process secret rotations every hour
    cronJobs.push({ name: 'secret-rotations', job: new CronJob('0 * * * *', processSecretRotations, null, true) });

    // Process risk assessments every 5 minutes
    cronJobs.push({ name: 'risk-assessments', job: new CronJob('*/5 * * * *', processRiskAssessments, null, true) });

    // Archive audit logs daily at 2 AM
    cronJobs.push({ name: 'archive-audit-logs', job: new CronJob('0 2 * * *', archiveAuditLogs, null, true) });

    // Verify audit chain integrity daily at 3 AM
    cronJobs.push({ name: 'verify-audit-chains', job: new CronJob('0 3 * * *', verifyAuditChains, null, true) });

    logger.info('Background jobs started', { count: cronJobs.length });
}

/**
 * Start the compliance service
 */
async function start(): Promise<void> {
    try {
        // Initialize schema
        await initializeSchema();

        // Initialize services
        await auditLogger.initialize();
        await contentScanner.initializeOCR();

        // Start background jobs
        startBackgroundJobs();

        // Start HTTP server
        const port = complianceConfig.port;
        serve({
            fetch: app.fetch,
            port,
        });

        logger.info('Compliance service started', { port });

        // Log startup
        await auditLogger.log(
            'configure',
            'settings',
            null,
            { action: 'service_start', port },
            'success',
            null,
            {}
        );
    } catch (err) {
        logger.fatal('Failed to start compliance service', { error: err });
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
    logger.info('Compliance shutting down (SIGTERM)');
    // FIX-500-180: Stop all CronJobs before closing connections
    for (const { name, job } of cronJobs) {
        job.stop();
        logger.info(`Stopped cron job: ${name}`);
    }
    await contentScanner.shutdownOCR();
    await db.end();
    await redis.quit();
    process.exit(0);
});

process.on('SIGINT', async () => {
    logger.info('Compliance shutting down (SIGINT)');
    // FIX-500-180: Stop all CronJobs before closing connections
    for (const { name, job } of cronJobs) {
        job.stop();
        logger.info(`Stopped cron job: ${name}`);
    }
    await contentScanner.shutdownOCR();
    await db.end();
    await redis.quit();
    process.exit(0);
});

// Start the service
start();

export {
    RiskScoringEngine,
    ContentScanner,
    AuditLogger,
    SecretManager,
    GDPRAutomation,
};
