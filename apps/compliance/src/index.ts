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
 * TODO: Extract to numbered migration files and use the shared migrate tool.
 */
async function initializeSchema(): Promise<void> {
    await db.query(`
        -- Risk profiles table
        CREATE TABLE IF NOT EXISTS risk_profiles (
            tenant_id VARCHAR(36) PRIMARY KEY,
            risk_score INTEGER NOT NULL,
            risk_level VARCHAR(20) NOT NULL,
            factors JSONB NOT NULL,
            limits JSONB NOT NULL,
            flags JSONB NOT NULL DEFAULT '[]',
            last_assessed_at TIMESTAMP NOT NULL,
            next_assessment_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL
        );

        -- Scan results table
        CREATE TABLE IF NOT EXISTS scan_results (
            id VARCHAR(36) PRIMARY KEY,
            tenant_id VARCHAR(36) NOT NULL,
            message_id VARCHAR(255) NOT NULL,
            scanned_at TIMESTAMP NOT NULL,
            results JSONB NOT NULL,
            overall_verdict VARCHAR(20) NOT NULL,
            actions JSONB NOT NULL,
            spam_detected BOOLEAN DEFAULT FALSE,
            phishing_detected BOOLEAN DEFAULT FALSE
        );

        CREATE INDEX IF NOT EXISTS idx_scan_results_tenant ON scan_results(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_scan_results_message ON scan_results(message_id);

        -- Audit logs table
        CREATE TABLE IF NOT EXISTS audit_logs (
            id VARCHAR(36) PRIMARY KEY,
            tenant_id VARCHAR(36),
            user_id VARCHAR(36),
            session_id VARCHAR(36),
            action VARCHAR(50) NOT NULL,
            resource VARCHAR(50) NOT NULL,
            resource_id VARCHAR(255),
            details JSONB NOT NULL,
            ip_address VARCHAR(45),
            user_agent TEXT,
            outcome VARCHAR(20) NOT NULL,
            error_message TEXT,
            timestamp TIMESTAMP NOT NULL,
            hash VARCHAR(64) NOT NULL,
            previous_hash VARCHAR(64),
            signature VARCHAR(64) NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant ON audit_logs(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

        -- Audit logs archive
        CREATE TABLE IF NOT EXISTS audit_logs_archive (LIKE audit_logs INCLUDING ALL);

        -- Audit webhooks
        CREATE TABLE IF NOT EXISTS audit_webhooks (
            id VARCHAR(36) PRIMARY KEY,
            tenant_id VARCHAR(36) NOT NULL,
            url TEXT NOT NULL,
            events JSONB NOT NULL,
            active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- Secrets table
        CREATE TABLE IF NOT EXISTS secrets (
            id VARCHAR(36) PRIMARY KEY,
            tenant_id VARCHAR(36) NOT NULL,
            name VARCHAR(255) NOT NULL,
            type VARCHAR(50) NOT NULL,
            encrypted_value TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            rotation_schedule JSONB,
            last_rotated_at TIMESTAMP,
            next_rotation_at TIMESTAMP,
            created_by VARCHAR(36) NOT NULL,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL,
            expires_at TIMESTAMP,
            UNIQUE(tenant_id, name)
        );

        CREATE INDEX IF NOT EXISTS idx_secrets_tenant ON secrets(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_secrets_rotation ON secrets(next_rotation_at);

        -- Secret versions history
        CREATE TABLE IF NOT EXISTS secret_versions (
            id SERIAL PRIMARY KEY,
            secret_id VARCHAR(36) NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
            version INTEGER NOT NULL,
            encrypted_value TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(secret_id, version)
        );

        -- Secret access grants
        CREATE TABLE IF NOT EXISTS secret_access (
            id VARCHAR(36) PRIMARY KEY,
            secret_id VARCHAR(36) NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
            user_id VARCHAR(36) NOT NULL,
            access_type VARCHAR(20) NOT NULL,
            granted_by VARCHAR(36) NOT NULL,
            granted_at TIMESTAMP NOT NULL,
            expires_at TIMESTAMP,
            revoked_at TIMESTAMP,
            UNIQUE(secret_id, user_id)
        );

        -- Secret access log
        CREATE TABLE IF NOT EXISTS secret_access_log (
            id SERIAL PRIMARY KEY,
            secret_id VARCHAR(36) NOT NULL,
            user_id VARCHAR(36) NOT NULL,
            action VARCHAR(50) NOT NULL,
            timestamp TIMESTAMP DEFAULT NOW()
        );

        -- Secrets archive
        CREATE TABLE IF NOT EXISTS secrets_archive (LIKE secrets INCLUDING ALL);

        -- Data subject requests
        CREATE TABLE IF NOT EXISTS data_subject_requests (
            id VARCHAR(36) PRIMARY KEY,
            tenant_id VARCHAR(36) NOT NULL,
            request_type VARCHAR(50) NOT NULL,
            email VARCHAR(255) NOT NULL,
            verification_token VARCHAR(64) NOT NULL,
            verified BOOLEAN DEFAULT FALSE,
            verified_at TIMESTAMP,
            status VARCHAR(50) NOT NULL,
            requested_at TIMESTAMP NOT NULL,
            processed_at TIMESTAMP,
            completed_at TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            result JSONB
        );

        CREATE INDEX IF NOT EXISTS idx_dsr_tenant ON data_subject_requests(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_dsr_email ON data_subject_requests(email);

        -- Consent records
        CREATE TABLE IF NOT EXISTS consent_records (
            id VARCHAR(36) PRIMARY KEY,
            tenant_id VARCHAR(36) NOT NULL,
            subscriber_id VARCHAR(36) NOT NULL,
            email VARCHAR(255) NOT NULL,
            consent_type VARCHAR(50) NOT NULL,
            granted BOOLEAN NOT NULL,
            granted_at TIMESTAMP,
            revoked_at TIMESTAMP,
            source VARCHAR(50) NOT NULL,
            ip_address VARCHAR(45),
            user_agent TEXT,
            proof_document TEXT,
            expires_at TIMESTAMP,
            metadata JSONB DEFAULT '{}',
            UNIQUE(tenant_id, subscriber_id, consent_type)
        );

        CREATE INDEX IF NOT EXISTS idx_consent_tenant ON consent_records(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_consent_email ON consent_records(email);

        -- Consent changelog
        CREATE TABLE IF NOT EXISTS consent_changelog (
            id SERIAL PRIMARY KEY,
            consent_id VARCHAR(36) NOT NULL,
            tenant_id VARCHAR(36) NOT NULL,
            email VARCHAR(255) NOT NULL,
            consent_type VARCHAR(50) NOT NULL,
            granted BOOLEAN NOT NULL,
            changed_at TIMESTAMP DEFAULT NOW()
        );

        -- Double opt-in tokens
        CREATE TABLE IF NOT EXISTS double_optin_tokens (
            token VARCHAR(64) PRIMARY KEY,
            tenant_id VARCHAR(36) NOT NULL,
            subscriber_id VARCHAR(36) NOT NULL,
            email VARCHAR(255) NOT NULL,
            consent_types JSONB NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            confirmed_at TIMESTAMP
        );

        -- GDPR exports
        -- FIX-500-181: Use JSONB for structured data, add access_token_hash for secure retrieval
        CREATE TABLE IF NOT EXISTS gdpr_exports (
            request_id VARCHAR(36) PRIMARY KEY,
            filename VARCHAR(255) NOT NULL,
            data JSONB NOT NULL,
            access_token_hash VARCHAR(64),
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- GDPR deletion log
        CREATE TABLE IF NOT EXISTS gdpr_deletion_log (
            id SERIAL PRIMARY KEY,
            tenant_id VARCHAR(36) NOT NULL,
            email VARCHAR(255) NOT NULL,
            records_deleted INTEGER NOT NULL,
            deleted_at TIMESTAMP DEFAULT NOW()
        );

        -- Processing objections
        CREATE TABLE IF NOT EXISTS processing_objections (
            id SERIAL PRIMARY KEY,
            tenant_id VARCHAR(36) NOT NULL,
            email VARCHAR(255) NOT NULL,
            request_id VARCHAR(36) NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- Content policies
        CREATE TABLE IF NOT EXISTS content_policies (
            id VARCHAR(36) PRIMARY KEY,
            tenant_id VARCHAR(36) NOT NULL,
            name VARCHAR(255) NOT NULL,
            rules JSONB NOT NULL,
            active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT NOW()
        );

        -- Flag resolutions
        CREATE TABLE IF NOT EXISTS flag_resolutions (
            id SERIAL PRIMARY KEY,
            tenant_id VARCHAR(36) NOT NULL,
            flag_type VARCHAR(50) NOT NULL,
            resolution TEXT NOT NULL,
            resolved_at TIMESTAMP DEFAULT NOW()
        );
    `);

    // FIX-500-181: Migrate existing gdpr_exports tables to new schema
    await db.query(`
        ALTER TABLE gdpr_exports
            ALTER COLUMN data TYPE JSONB USING data::jsonb;
    `).catch(() => { /* column already JSONB or table fresh */ });
    await db.query(`
        ALTER TABLE gdpr_exports
            ADD COLUMN IF NOT EXISTS access_token_hash VARCHAR(64),
            ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;
    `).catch(() => { /* columns already exist */ });

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
