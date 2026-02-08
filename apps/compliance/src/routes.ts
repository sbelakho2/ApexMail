/**
 * Compliance API Routes
 *
 * REST API for compliance functionality including risk assessment,
 * content scanning, audit logs, secrets management, and GDPR automation.
 */

import crypto from 'crypto';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { Pool } from 'pg';
import { Redis } from 'ioredis';
import { createLogger } from '@apexmail/lib';

import { RiskScoringEngine } from './risk';
import { ContentScanner } from './content';
import { AuditLogger } from './audit';
import { SecretManager } from './secrets';
import { GDPRAutomation } from './gdpr';
import { complianceConfig } from './config';
import type { RiskFlagType, ConsentType, AuditAction, AuditResource } from './types';

const routeLogger = createLogger({ name: 'compliance-routes' });

// Type validation helpers
const RISK_FLAG_TYPES: readonly RiskFlagType[] = [
    'high_bounce_rate',
    'spam_trap_hit',
    'blocklist_detected',
    'unusual_sending_pattern',
    'phishing_content',
    'malware_attachment',
    'suspended_account',
    'payment_failed',
] as const;

const CONSENT_TYPES: readonly ConsentType[] = [
    'marketing',
    'transactional',
    'analytics',
    'profiling',
    'third_party',
    'data_processing',
] as const;

const AUDIT_ACTIONS: readonly AuditAction[] = [
    'create',
    'read',
    'update',
    'delete',
    'export',
    'import',
    'login',
    'logout',
    'send',
    'receive',
    'configure',
    'approve',
    'reject',
    'escalate',
] as const;

const AUDIT_RESOURCES: readonly AuditResource[] = [
    'tenant',
    'user',
    'domain',
    'api_key',
    'message',
    'campaign',
    'list',
    'subscriber',
    'template',
    'webhook',
    'settings',
    'billing',
    'consent',
] as const;

type AuditOutcome = 'success' | 'failure';
const AUDIT_OUTCOMES: readonly AuditOutcome[] = ['success', 'failure'] as const;

function isRiskFlagType(value: string): value is RiskFlagType {
    return RISK_FLAG_TYPES.includes(value as RiskFlagType);
}

function isConsentType(value: string): value is ConsentType {
    return CONSENT_TYPES.includes(value as ConsentType);
}

function isAuditAction(value: string | undefined): value is AuditAction {
    return value !== undefined && AUDIT_ACTIONS.includes(value as AuditAction);
}

function isAuditResource(value: string | undefined): value is AuditResource {
    return value !== undefined && AUDIT_RESOURCES.includes(value as AuditResource);
}

function isAuditOutcome(value: string | undefined): value is AuditOutcome {
    return value !== undefined && AUDIT_OUTCOMES.includes(value as AuditOutcome);
}

// Initialize dependencies
const db = new Pool({
    host: complianceConfig.database.host,
    port: complianceConfig.database.port,
    database: complianceConfig.database.name,
    user: complianceConfig.database.user,
    password: complianceConfig.database.password,
    max: complianceConfig.database.maxConnections,
});
const redis = new Redis(complianceConfig.redis.url);
const riskEngine = new RiskScoringEngine(db, redis);
const contentScanner = new ContentScanner(db, redis);
const auditLogger = new AuditLogger(db, redis, complianceConfig.auditLog.signingKey);
const secretManager = new SecretManager(db, redis, complianceConfig.secrets.encryptionKey);
const gdprAutomation = new GDPRAutomation(db, redis);

const app = new Hono();

// Middleware
app.use('*', cors());
app.use('*', logger());

// FIX-007: Authentication middleware — the compliance API was completely
// unauthenticated, exposing risk profiles, GDPR data, audit logs, and
// secrets to any network-reachable client.
app.use('*', async (c, next) => {
    // Allow health check endpoints without auth
    const path = new URL(c.req.url).pathname;
    if (path === '/health' || path === '/ready') {
        return next();
    }

    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return c.json({ error: 'Unauthorized: missing or invalid Authorization header' }, 401);
    }

    const token = authHeader.slice(7);
    if (!token) {
        return c.json({ error: 'Unauthorized: empty bearer token' }, 401);
    }

    // A-020: Validate bearer token value against expected service token.
    // Previously only checked for presence, not correctness.
    const expectedToken = process.env['COMPLIANCE_AUTH_TOKEN'];
    if (!expectedToken) {
        routeLogger.error('COMPLIANCE_AUTH_TOKEN environment variable is not set — rejecting all requests');
        return c.json({ error: 'Internal server error: auth not configured' }, 500);
    }

    // FIX-500-027: Use timing-safe comparison to prevent timing side-channel attacks
    const tokenBuf = Buffer.from(token);
    const expectedBuf = Buffer.from(expectedToken);
    if (tokenBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(tokenBuf, expectedBuf)) {
        routeLogger.warn('Invalid bearer token presented', { path });
        return c.json({ error: 'Unauthorized: invalid bearer token' }, 401);
    }

    await next();
});

// ==================== Risk Assessment Routes ====================

app.get('/api/risk/:tenantId', async (c) => {
    const { tenantId } = c.req.param();

    const profile = await riskEngine.getProfile(tenantId);
    if (!profile) {
        return c.json({ error: 'Risk profile not found' }, 404);
    }

    return c.json(profile);
});

app.post('/api/risk/:tenantId/assess', async (c) => {
    const { tenantId } = c.req.param();

    const profile = await riskEngine.assessTenant(tenantId);

    await auditLogger.log(
        'update',
        'tenant',
        tenantId,
        { action: 'risk_assessment', riskScore: profile.riskScore },
        'success',
        null,
        { tenantId }
    );

    return c.json(profile);
});

app.patch('/api/risk/:tenantId/limits', async (c) => {
    const { tenantId } = c.req.param();
    const limits = await c.req.json();

    await riskEngine.updateLimits(tenantId, limits);

    await auditLogger.log(
        'update',
        'tenant',
        tenantId,
        { action: 'update_limits', limits },
        'success',
        null,
        { tenantId }
    );

    return c.json({ success: true });
});

app.post('/api/risk/:tenantId/flags/:flagType/resolve', async (c) => {
    const { tenantId, flagType } = c.req.param();
    const { resolution } = await c.req.json();

    if (!isRiskFlagType(flagType)) {
        return c.json({ error: 'Invalid flag type' }, 400);
    }

    await riskEngine.resolveFlag(tenantId, flagType, resolution);

    await auditLogger.log(
        'update',
        'tenant',
        tenantId,
        { action: 'resolve_flag', flagType, resolution },
        'success',
        null,
        { tenantId }
    );

    return c.json({ success: true });
});

app.get('/api/risk/critical', async (c) => {
    const tenants = await riskEngine.getCriticalRiskTenants();
    return c.json(tenants);
});

app.get('/api/risk/stats', async (c) => {
    // C-123: Cache expensive aggregate risk stats for 5 minutes
    const cacheKey = 'compliance:cache:risk_stats';
    const cached = await redis.get(cacheKey);
    if (cached) {
        try { return c.json(JSON.parse(cached)); }
        catch { await redis.del(cacheKey); }
    }
    const stats = await riskEngine.getRiskStats();
    await redis.setex(cacheKey, 300, JSON.stringify(stats));
    return c.json(stats);
});

// ==================== Content Scanning Routes ====================

app.post('/api/scan', async (c) => {
    const content = await c.req.json();

    const result = await contentScanner.scanEmail(content);

    await auditLogger.log(
        'create',
        'message',
        content.messageId,
        { action: 'content_scan', verdict: result.overallVerdict },
        'success',
        null,
        { tenantId: content.tenantId }
    );

    return c.json(result);
});

app.get('/api/scan/:resultId', async (c) => {
    const { resultId } = c.req.param();

    const result = await contentScanner.getResult(resultId);
    if (!result) {
        return c.json({ error: 'Scan result not found' }, 404);
    }

    return c.json(result);
});

app.get('/api/scan/stats', async (c) => {
    const tenantId = c.req.query('tenantId');
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');

    // FIX-500-418: Hash user-supplied query params to prevent cache key injection.
    // Raw user input could contain ':' or newlines that pollute the Redis key namespace.
    const keyInput = `${tenantId ?? 'all'}:${startDate ?? ''}:${endDate ?? ''}`;
    const keyHash = crypto.createHash('sha256').update(keyInput).digest('hex').slice(0, 16);
    const cacheKey = `compliance:cache:scan_stats:${keyHash}`;
    const cached = await redis.get(cacheKey);
    if (cached) {
        try { return c.json(JSON.parse(cached)); }
        catch { await redis.del(cacheKey); }
    }

    const stats = await contentScanner.getStats(
        tenantId,
        startDate ? new Date(startDate) : undefined,
        endDate ? new Date(endDate) : undefined
    );

    await redis.setex(cacheKey, 300, JSON.stringify(stats));
    return c.json(stats);
});

// ==================== Audit Log Routes ====================

app.get('/api/audit', async (c) => {
    const actionParam = c.req.query('action');
    const resourceParam = c.req.query('resource');
    const outcomeParam = c.req.query('outcome');

    const query = {
        tenantId: c.req.query('tenantId'),
        userId: c.req.query('userId'),
        action: isAuditAction(actionParam) ? actionParam : undefined,
        resource: isAuditResource(resourceParam) ? resourceParam : undefined,
        resourceId: c.req.query('resourceId'),
        startDate: c.req.query('startDate') ? new Date(c.req.query('startDate')!) : undefined,
        endDate: c.req.query('endDate') ? new Date(c.req.query('endDate')!) : undefined,
        outcome: isAuditOutcome(outcomeParam) ? outcomeParam : undefined,
        limit: c.req.query('limit') ? parseInt(c.req.query('limit')!, 10) || 50 : 50,
        offset: c.req.query('offset') ? parseInt(c.req.query('offset')!, 10) || 0 : 0,
    };

    const result = await auditLogger.query(query);
    return c.json(result);
});

app.get('/api/audit/:entryId', async (c) => {
    const { entryId } = c.req.param();

    const entry = await auditLogger.getEntry(entryId);
    if (!entry) {
        return c.json({ error: 'Audit entry not found' }, 404);
    }

    return c.json(entry);
});

app.post('/api/audit/verify', async (c) => {
    const { tenantId, startDate, endDate } = await c.req.json();

    const result = await auditLogger.verifyChain(
        tenantId,
        startDate ? new Date(startDate) : undefined,
        endDate ? new Date(endDate) : undefined
    );

    return c.json(result);
});

app.post('/api/audit/export', async (c) => {
    const { format, ...query } = await c.req.json();

    const exportResult = await auditLogger.export(query, format);

    // Log the export - using 'settings' resource as audit log exports are admin operations
    await auditLogger.logExport('settings', null, { format, query, exportType: 'audit_logs' }, {});

    return c.json(exportResult);
});

app.get('/api/audit/stats', async (c) => {
    const tenantId = c.req.query('tenantId');
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');

    // FIX-500-418: Hash user-supplied query params to prevent cache key injection.
    const auditKeyInput = `${tenantId ?? 'all'}:${startDate ?? ''}:${endDate ?? ''}`;
    const auditKeyHash = crypto.createHash('sha256').update(auditKeyInput).digest('hex').slice(0, 16);
    const cacheKey = `compliance:cache:audit_stats:${auditKeyHash}`;
    const cached = await redis.get(cacheKey);
    if (cached) {
        try { return c.json(JSON.parse(cached)); }
        catch { await redis.del(cacheKey); }
    }

    const stats = await auditLogger.getStats(
        tenantId,
        startDate ? new Date(startDate) : undefined,
        endDate ? new Date(endDate) : undefined
    );

    await redis.setex(cacheKey, 300, JSON.stringify(stats));
    return c.json(stats);
});

app.post('/api/audit/webhooks', async (c) => {
    const { tenantId, url, events } = await c.req.json();

    const webhookId = await auditLogger.registerWebhook(tenantId, url, events);

    return c.json({ id: webhookId });
});

app.post('/api/audit/archive', async (c) => {
    const { olderThan } = await c.req.json();

    const result = await auditLogger.archive(new Date(olderThan));

    return c.json(result);
});

// ==================== Secrets Management Routes ====================

app.post('/api/secrets', async (c) => {
    const input = await c.req.json();
    const userId = c.req.header('X-User-ID') || 'system';

    const secret = await secretManager.createSecret({
        ...input,
        createdBy: userId,
    });

    await auditLogger.log(
        'create',
        'api_key',
        secret.id,
        { name: secret.name, type: secret.type },
        'success',
        null,
        { tenantId: input.tenantId, userId }
    );

    // Don't return the encrypted value
    const { encryptedValue, ...safeSecret } = secret;
    return c.json(safeSecret, 201);
});

app.get('/api/secrets/:secretId', async (c) => {
    const { secretId } = c.req.param();
    const userId = c.req.header('X-User-ID') || 'system';

    const result = await secretManager.getSecret(secretId, userId);
    if (!result) {
        return c.json({ error: 'Secret not found' }, 404);
    }

    const { secret, value } = result;
    const { encryptedValue, ...safeSecret } = secret;

    return c.json({ ...safeSecret, value });
});

app.get('/api/secrets', async (c) => {
    const tenantId = c.req.query('tenantId');
    const typeParam = c.req.query('type');

    if (!tenantId) {
        return c.json({ error: 'tenantId is required' }, 400);
    }

    // Validate type parameter if provided
    const validTypes = ['api_key', 'smtp_password', 'webhook_secret', 'encryption_key', 'oauth_token', 'certificate'] as const;
    type SecretType = typeof validTypes[number];
    const secretType: SecretType | undefined = typeParam && validTypes.includes(typeParam as SecretType) 
        ? typeParam as SecretType 
        : undefined;

    const secrets = await secretManager.listSecrets(tenantId, secretType);
    return c.json(secrets);
});

app.patch('/api/secrets/:secretId', async (c) => {
    const { secretId } = c.req.param();
    const userId = c.req.header('X-User-ID') || 'system';
    const update = await c.req.json();

    const secret = await secretManager.updateSecret(secretId, userId, update);

    await auditLogger.log(
        'update',
        'api_key',
        secretId,
        { updated: Object.keys(update) },
        'success',
        null,
        { tenantId: secret.tenantId, userId }
    );

    const { encryptedValue, ...safeSecret } = secret;
    return c.json(safeSecret);
});

app.post('/api/secrets/:secretId/rotate', async (c) => {
    const { secretId } = c.req.param();
    const userId = c.req.header('X-User-ID') || 'system';
    const { newValue } = await c.req.json();

    const { secret, value } = await secretManager.rotateSecret(secretId, userId, newValue);

    await auditLogger.log(
        'update',
        'api_key',
        secretId,
        { action: 'rotate' },
        'success',
        null,
        { tenantId: secret.tenantId, userId }
    );

    const { encryptedValue, ...safeSecret } = secret;
    return c.json({ ...safeSecret, value });
});

app.delete('/api/secrets/:secretId', async (c) => {
    const { secretId } = c.req.param();
    const userId = c.req.header('X-User-ID') || 'system';

    await secretManager.deleteSecret(secretId, userId);

    await auditLogger.log(
        'delete',
        'api_key',
        secretId,
        {},
        'success',
        null,
        { userId }
    );

    return c.json({ success: true });
});

app.post('/api/secrets/:secretId/access', async (c) => {
    const { secretId } = c.req.param();
    const grantedBy = c.req.header('X-User-ID') || 'system';
    const { userId, accessType, expiresAt } = await c.req.json();

    const access = await secretManager.grantAccess(
        secretId,
        userId,
        accessType,
        grantedBy,
        expiresAt ? new Date(expiresAt) : undefined
    );

    return c.json(access);
});

app.delete('/api/secrets/:secretId/access/:userId', async (c) => {
    const { secretId, userId } = c.req.param();
    const revokedBy = c.req.header('X-User-ID') || 'system';

    await secretManager.revokeAccess(secretId, userId, revokedBy);

    return c.json({ success: true });
});

app.get('/api/secrets/:secretId/history', async (c) => {
    const { secretId } = c.req.param();
    const userId = c.req.header('X-User-ID') || 'system';

    const history = await secretManager.getVersionHistory(secretId, userId);
    return c.json(history);
});

app.post('/api/secrets/:secretId/rollback', async (c) => {
    const { secretId } = c.req.param();
    const userId = c.req.header('X-User-ID') || 'system';
    const { version } = await c.req.json();

    const secret = await secretManager.rollbackToVersion(secretId, version, userId);

    const { encryptedValue, ...safeSecret } = secret;
    return c.json(safeSecret);
});

// ==================== GDPR Routes ====================

app.post('/api/gdpr/requests', async (c) => {
    const { tenantId, requestType, email } = await c.req.json();

    const request = await gdprAutomation.createRequest(tenantId, requestType, email);

    await auditLogger.log(
        'create',
        'consent',
        request.id,
        { requestType, email: email.substring(0, 3) + '***' },
        'success',
        null,
        { tenantId }
    );

    return c.json({
        id: request.id,
        status: request.status,
        expiresAt: request.expiresAt,
    }, 201);
});

app.post('/api/gdpr/requests/:requestId/verify', async (c) => {
    const { requestId } = c.req.param();
    const { token } = await c.req.json();

    const request = await gdprAutomation.verifyRequest(requestId, token);
    if (!request) {
        return c.json({ error: 'Invalid or expired verification' }, 400);
    }

    return c.json({
        id: request.id,
        status: request.status,
        verified: request.verified,
    });
});

app.post('/api/gdpr/requests/:requestId/process', async (c) => {
    const { requestId } = c.req.param();

    const result = await gdprAutomation.processRequest(requestId);

    return c.json(result);
});

app.get('/api/gdpr/requests/:requestId', async (c) => {
    const { requestId } = c.req.param();
    
    const request = await gdprAutomation.getRequest(requestId);
    
    if (!request) {
        return c.json({ error: 'Request not found' }, 404);
    }
    
    return c.json({ request });
});

app.get('/api/gdpr/stats', async (c) => {
    const tenantId = c.req.query('tenantId');
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');

    const stats = await gdprAutomation.getStats(
        tenantId,
        startDate ? new Date(startDate) : undefined,
        endDate ? new Date(endDate) : undefined
    );

    return c.json(stats);
});

// Consent endpoints
app.post('/api/gdpr/consent', async (c) => {
    const body = await c.req.json();

    const consent = await gdprAutomation.recordConsent(
        body.tenantId,
        body.subscriberId,
        body.email,
        body.consentType,
        body.granted,
        body.source,
        body.ipAddress,
        body.userAgent,
        body.proofDocument,
        body.expiresAt ? new Date(body.expiresAt) : undefined,
        body.metadata
    );

    await auditLogger.log(
        'update',
        'consent',
        consent.id,
        { consentType: consent.consentType, granted: consent.granted },
        'success',
        null,
        { tenantId: body.tenantId }
    );

    return c.json(consent, 201);
});

app.delete('/api/gdpr/consent/:tenantId/:subscriberId/:consentType', async (c) => {
    const { tenantId, subscriberId, consentType } = c.req.param();

    if (!isConsentType(consentType)) {
        return c.json({ error: 'Invalid consent type' }, 400);
    }

    await gdprAutomation.revokeConsent(tenantId, subscriberId, consentType);

    await auditLogger.log(
        'update',
        'consent',
        `${subscriberId}-${consentType}`,
        { action: 'revoke', consentType },
        'success',
        null,
        { tenantId }
    );

    return c.json({ success: true });
});

app.get('/api/gdpr/consent/:tenantId/:subscriberId', async (c) => {
    const { tenantId, subscriberId } = c.req.param();

    const consents = await gdprAutomation.getConsents(tenantId, subscriberId);
    return c.json(consents);
});

app.get('/api/gdpr/consent/:tenantId/:subscriberId/:consentType/check', async (c) => {
    const { tenantId, subscriberId, consentType } = c.req.param();

    if (!isConsentType(consentType)) {
        return c.json({ error: 'Invalid consent type' }, 400);
    }

    const hasConsent = await gdprAutomation.hasConsent(
        tenantId,
        subscriberId,
        consentType
    );

    return c.json({ hasConsent });
});

// Double opt-in endpoints
app.post('/api/gdpr/double-optin/send', async (c) => {
    const { tenantId, subscriberId, email, consentTypes } = await c.req.json();

    await gdprAutomation.sendDoubleOptIn(tenantId, subscriberId, email, consentTypes);

    return c.json({ success: true, message: 'Double opt-in email sent' });
});

app.post('/api/gdpr/double-optin/confirm', async (c) => {
    const { token } = await c.req.json();

    const confirmed = await gdprAutomation.confirmDoubleOptIn(token);
    if (!confirmed) {
        return c.json({ error: 'Invalid or expired token' }, 400);
    }

    return c.json({ success: true });
});

// ==================== Health Check ====================

app.get('/health', async (c) => {
    const checks = {
        database: false,
        redis: false,
    };

    try {
        await db.query('SELECT 1');
        checks.database = true;
    } catch {
        // Database check failed
    }

    try {
        await redis.ping();
        checks.redis = true;
    } catch {
        // Redis check failed
    }

    const healthy = checks.database && checks.redis;

    return c.json(
        {
            status: healthy ? 'healthy' : 'unhealthy',
            checks,
            timestamp: new Date().toISOString(),
        },
        healthy ? 200 : 503
    );
});

// ==================== Error Handler ====================

app.onError((err, c) => {
    routeLogger.error('Compliance API error', { error: err.message, stack: err.stack });

    return c.json(
        {
            error: err.message || 'Internal server error',
            timestamp: new Date().toISOString(),
        },
        500
    );
});

export default app;
export { app };
