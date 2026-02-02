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
const auditLogger = new AuditLogger(db, redis, complianceConfig.auditLog.signingKey);
const secretManager = new SecretManager(db, redis, complianceConfig.secrets.encryptionKey);
const gdprAutomation = new GDPRAutomation(db, redis);

/**
 * Process GDPR request queue
 */
async function processGDPRQueue(): Promise<void> {
    // eslint-disable-next-line no-constant-condition
    while (true) {
        const item = await redis.rpop('gdpr:requests:queue');
        if (!item) break;

        try {
            const { requestId } = JSON.parse(item);
            await gdprAutomation.processRequest(requestId);
            console.log(`[GDPR] Processed request: ${requestId}`);
        } catch (err) {
            console.error('[GDPR] Error processing request:', err);
            // Requeue on failure with delay
            await redis.lpush('gdpr:requests:failed', item);
        }
    }
}

/**
 * Process automatic secret rotations
 */
async function processSecretRotations(): Promise<void> {
    try {
        const result = await secretManager.processAutoRotations();
        console.log(
            `[Secrets] Rotations: ${result.rotated.length} rotated, ${result.notified.length} notified, ${result.errors.length} errors`
        );
    } catch (err) {
        console.error('[Secrets] Error processing rotations:', err);
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
                console.log(`[Risk] Reassessed tenant: ${row.tenant_id}`);
            } catch (err) {
                console.error(`[Risk] Error reassessing tenant ${row.tenant_id}:`, err);
            }
        }
    } catch (err) {
        console.error('[Risk] Error processing assessments:', err);
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
        console.log(`[Audit] Archived ${result.archivedCount} entries older than ${olderThan.toISOString()}`);
    } catch (err) {
        console.error('[Audit] Error archiving logs:', err);
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
            console.error('[Audit] Chain integrity check FAILED:', result.error);
            // Alert operations team
            await redis.lpush(
                'alerts:queue',
                JSON.stringify({
                    type: 'audit_chain_invalid',
                    error: result.error,
                    firstInvalidEntry: result.firstInvalidEntry,
                    timestamp: new Date().toISOString(),
                })
            );
        } else {
            console.log(`[Audit] Chain integrity verified: ${result.entriesChecked} entries`);
        }
    } catch (err) {
        console.error('[Audit] Error verifying chain:', err);
    }
}

/**
 * Initialize database schema
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
        CREATE TABLE IF NOT EXISTS gdpr_exports (
            request_id VARCHAR(36) PRIMARY KEY,
            filename VARCHAR(255) NOT NULL,
            data TEXT NOT NULL,
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

    console.log('[Schema] Database schema initialized');
}

/**
 * Start background jobs
 */
function startBackgroundJobs(): void {
    // Process GDPR queue every minute
    new CronJob('* * * * *', processGDPRQueue, null, true);

    // Process secret rotations every hour
    new CronJob('0 * * * *', processSecretRotations, null, true);

    // Process risk assessments every 5 minutes
    new CronJob('*/5 * * * *', processRiskAssessments, null, true);

    // Archive audit logs daily at 2 AM
    new CronJob('0 2 * * *', archiveAuditLogs, null, true);

    // Verify audit chain integrity daily at 3 AM
    new CronJob('0 3 * * *', verifyAuditChains, null, true);

    console.log('[Jobs] Background jobs started');
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

        console.log(`[Compliance] Service started on port ${port}`);

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
        console.error('[Compliance] Failed to start:', err);
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('[Compliance] Shutting down...');
    await contentScanner.shutdownOCR();
    await db.end();
    await redis.quit();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('[Compliance] Shutting down...');
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
