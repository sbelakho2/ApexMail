/**
 * Isolation Routes
 * 
 * HTTP endpoints for multi-tenant isolation features
 */

import { Hono } from 'hono';
import { TenantService, TenantRole, TenantStatus } from '../services/tenant.js';
import { DataIsolationService, IsolationContext } from '../services/data-isolation.js';
import { EncryptionService } from '../services/encryption.js';
import { RateLimitService } from '../services/rate-limit.js';
import { AuditService, AuditEventType, AuditSeverity } from '../services/audit.js';
import { IsolationLevel } from '../config.js';

export function createIsolationRoutes(
  tenants: TenantService,
  isolation: DataIsolationService,
  encryption: EncryptionService,
  rateLimit: RateLimitService,
  audit: AuditService
): Hono {
  const app = new Hono();

  // ==================== Organization Routes ====================

  /**
   * Create organization
   */
  app.post('/organizations', async (c) => {
    const body = await c.req.json();
    const userId = c.req.header('X-User-ID');

    if (!userId) {
      return c.json({ error: 'User ID required' }, 401);
    }

    const result = await tenants.createOrganization({
      name: body.name,
      slug: body.slug,
      billingEmail: body.billingEmail,
      plan: body.plan,
      isolationLevel: body.isolationLevel as IsolationLevel,
      ownerId: userId,
    });

    if (!result.ok) {
      return c.json({ error: result.error.message }, 400);
    }

    return c.json(result.value, 201);
  });

  /**
   * Get organization
   */
  app.get('/organizations/:orgId', async (c) => {
    const orgId = c.req.param('orgId');

    const result = await tenants.getOrganization(orgId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 404);
    }

    return c.json(result.value);
  });

  /**
   * Update organization
   */
  app.put('/organizations/:orgId', async (c) => {
    const orgId = c.req.param('orgId');
    const body = await c.req.json();
    const userId = c.req.header('X-User-ID') || 'system';

    const result = await tenants.updateOrganization(orgId, body);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 400);
    }

    // Log audit event
    await audit.log({
      organizationId: orgId,
      workspaceId: null,
      type: AuditEventType.ORG_UPDATED,
      severity: AuditSeverity.INFO,
      actorId: userId,
      actorType: 'user',
      actorIp: c.req.header('X-Forwarded-For') || null,
      actorUserAgent: c.req.header('User-Agent') || null,
      resource: 'organization',
      resourceId: orgId,
      action: 'update',
      details: body,
      metadata: {},
    });

    return c.json(result.value);
  });

  /**
   * Suspend organization
   */
  app.post('/organizations/:orgId/suspend', async (c) => {
    const orgId = c.req.param('orgId');
    const body = await c.req.json();
    const userId = c.req.header('X-User-ID') || 'system';

    const result = await tenants.suspendOrganization(orgId, body.reason, userId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 400);
    }

    return c.json({ success: true });
  });

  // ==================== Workspace Routes ====================

  /**
   * Create workspace
   */
  app.post('/organizations/:orgId/workspaces', async (c) => {
    const orgId = c.req.param('orgId');
    const body = await c.req.json();
    const userId = c.req.header('X-User-ID');

    if (!userId) {
      return c.json({ error: 'User ID required' }, 401);
    }

    const result = await tenants.createWorkspace({
      organizationId: orgId,
      name: body.name,
      slug: body.slug,
      creatorId: userId,
      quota: body.quota,
    });

    if (!result.ok) {
      return c.json({ error: result.error.message }, 400);
    }

    return c.json(result.value, 201);
  });

  /**
   * List workspaces
   */
  app.get('/organizations/:orgId/workspaces', async (c) => {
    const orgId = c.req.param('orgId');

    const result = await tenants.listWorkspaces(orgId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ workspaces: result.value });
  });

  /**
   * Get workspace
   */
  app.get('/workspaces/:workspaceId', async (c) => {
    const workspaceId = c.req.param('workspaceId');

    const result = await tenants.getWorkspace(workspaceId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 404);
    }

    return c.json(result.value);
  });

  /**
   * Update workspace
   */
  app.put('/workspaces/:workspaceId', async (c) => {
    const workspaceId = c.req.param('workspaceId');
    const body = await c.req.json();

    const result = await tenants.updateWorkspace(workspaceId, body);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 400);
    }

    return c.json(result.value);
  });

  /**
   * Delete workspace
   */
  app.delete('/workspaces/:workspaceId', async (c) => {
    const workspaceId = c.req.param('workspaceId');
    const userId = c.req.header('X-User-ID') || 'system';

    const result = await tenants.deleteWorkspace(workspaceId, userId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 400);
    }

    return c.json({ success: true });
  });

  // ==================== Member Routes ====================

  /**
   * Add workspace member
   */
  app.post('/workspaces/:workspaceId/members', async (c) => {
    const workspaceId = c.req.param('workspaceId');
    const body = await c.req.json();
    const inviterId = c.req.header('X-User-ID') || 'system';

    const result = await tenants.addWorkspaceMember(
      workspaceId,
      body.userId,
      body.role as TenantRole,
      inviterId
    );

    if (!result.ok) {
      return c.json({ error: result.error.message }, 400);
    }

    return c.json({ success: true }, 201);
  });

  /**
   * Remove workspace member
   */
  app.delete('/workspaces/:workspaceId/members/:userId', async (c) => {
    const workspaceId = c.req.param('workspaceId');
    const userId = c.req.param('userId');
    const removerId = c.req.header('X-User-ID') || 'system';

    const result = await tenants.removeWorkspaceMember(workspaceId, userId, removerId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 400);
    }

    return c.json({ success: true });
  });

  /**
   * Check member access
   */
  app.get('/workspaces/:workspaceId/members/:userId/access', async (c) => {
    const workspaceId = c.req.param('workspaceId');
    const userId = c.req.param('userId');

    const result = await tenants.checkMemberAccess(workspaceId, userId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // ==================== Quota Routes ====================

  /**
   * Check quota
   */
  app.get('/workspaces/:workspaceId/quota/:metric', async (c) => {
    const workspaceId = c.req.param('workspaceId');
    const metric = c.req.param('metric');

    const wsResult = await tenants.getWorkspace(workspaceId);
    if (!wsResult.ok) {
      return c.json({ error: wsResult.error.message }, 404);
    }

    const result = await rateLimit.checkWorkspaceQuota(
      workspaceId,
      metric as keyof typeof wsResult.value.quota,
      wsResult.value.quota
    );

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({
      allowed: result.value.allowed,
      remaining: result.value.remaining,
      limit: result.value.limit,
      resetAt: result.value.resetAt,
    });
  });

  /**
   * Update quota
   */
  app.put('/workspaces/:workspaceId/quota', async (c) => {
    const workspaceId = c.req.param('workspaceId');
    const body = await c.req.json();

    const wsResult = await tenants.getWorkspace(workspaceId);
    if (!wsResult.ok) {
      return c.json({ error: wsResult.error.message }, 404);
    }

    const result = await tenants.updateWorkspace(workspaceId, {
      quota: { ...wsResult.value.quota, ...body },
    });

    if (!result.ok) {
      return c.json({ error: result.error.message }, 400);
    }

    return c.json(result.value.quota);
  });

  // ==================== Rate Limit Routes ====================

  /**
   * Check rate limit
   */
  app.get('/workspaces/:workspaceId/rate-limit', async (c) => {
    const workspaceId = c.req.param('workspaceId');

    const wsResult = await tenants.getWorkspace(workspaceId);
    if (!wsResult.ok) {
      return c.json({ error: wsResult.error.message }, 404);
    }

    const configs = rateLimit.getWorkspaceRateLimitConfigs(wsResult.value.quota);
    const result = await rateLimit.getRateLimitStatus(`${workspaceId}:api`, configs.api);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Reset rate limit
   */
  app.post('/workspaces/:workspaceId/rate-limit/reset', async (c) => {
    const workspaceId = c.req.param('workspaceId');

    const result = await rateLimit.resetRateLimit(`${workspaceId}:api`);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ success: true });
  });

  // ==================== Encryption Routes ====================

  /**
   * Rotate encryption key
   */
  app.post('/organizations/:orgId/encryption/rotate', async (c) => {
    const orgId = c.req.param('orgId');
    const userId = c.req.header('X-User-ID') || 'system';

    const result = await encryption.rotateKey(orgId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    // Log audit event
    await audit.log({
      organizationId: orgId,
      workspaceId: null,
      type: AuditEventType.SETTINGS_CHANGED,
      severity: AuditSeverity.INFO,
      actorId: userId,
      actorType: 'user',
      actorIp: c.req.header('X-Forwarded-For') || null,
      actorUserAgent: null,
      resource: 'encryption',
      resourceId: result.value.id,
      action: 'key_rotated',
      details: { version: result.value.version },
      metadata: {},
    });

    return c.json({
      keyId: result.value.id,
      version: result.value.version,
      expiresAt: result.value.expiresAt,
    });
  });

  /**
   * Create encryption policy
   */
  app.post('/encryption/policies', async (c) => {
    const body = await c.req.json();

    const result = await encryption.createPolicy({
      name: body.name,
      resource: body.resource,
      fields: body.fields,
      algorithm: body.algorithm || 'AES-256-GCM',
      keyRotationDays: body.keyRotationDays || 90,
    });

    if (!result.ok) {
      return c.json({ error: result.error.message }, 400);
    }

    return c.json(result.value, 201);
  });

  // ==================== Isolation Routes ====================

  /**
   * Check data access
   */
  app.post('/isolation/check-access', async (c) => {
    const body = await c.req.json();

    const context: IsolationContext = {
      organizationId: body.organizationId,
      workspaceId: body.workspaceId,
      userId: body.userId,
      isolationLevel: body.isolationLevel || IsolationLevel.SHARED,
      schemaName: body.schemaName,
      permissions: body.permissions || [],
    };

    const result = await isolation.checkResourceAccess(
      context,
      body.resource,
      body.resourceId,
      body.action
    );

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    // Audit the access attempt
    await isolation.auditAccessAttempt(
      context,
      body.targetWorkspaceId || body.workspaceId,
      body.resource,
      body.action,
      result.value
    );

    return c.json({ allowed: result.value });
  });

  /**
   * Migrate isolation level
   */
  app.post('/workspaces/:workspaceId/isolation/migrate', async (c) => {
    const workspaceId = c.req.param('workspaceId');
    const body = await c.req.json();

    const wsResult = await tenants.getWorkspace(workspaceId);
    if (!wsResult.ok) {
      return c.json({ error: wsResult.error.message }, 404);
    }

    const orgResult = await tenants.getOrganization(wsResult.value.organizationId);
    if (!orgResult.ok) {
      return c.json({ error: orgResult.error.message }, 404);
    }

    const result = await isolation.migrateIsolationLevel(
      workspaceId,
      orgResult.value.isolationLevel,
      body.targetLevel as IsolationLevel
    );

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ success: true });
  });

  /**
   * Set up RLS for a table
   */
  app.post('/isolation/rls', async (c) => {
    const body = await c.req.json();

    const result = await isolation.setupRLS(body.tableName, body.schemaName);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ success: true });
  });

  // ==================== Audit Routes ====================

  /**
   * Query audit logs
   */
  app.get('/organizations/:orgId/audit', async (c) => {
    const orgId = c.req.param('orgId');
    const workspaceId = c.req.query('workspaceId');
    const types = c.req.query('types')?.split(',') as AuditEventType[] | undefined;
    const severity = c.req.query('severity') as AuditSeverity | undefined;
    const actorId = c.req.query('actorId');
    const resource = c.req.query('resource');
    const startTime = c.req.query('startTime') ? new Date(c.req.query('startTime')!) : undefined;
    const endTime = c.req.query('endTime') ? new Date(c.req.query('endTime')!) : undefined;
    const limit = c.req.query('limit') ? parseInt(c.req.query('limit')!) : 100;
    const offset = c.req.query('offset') ? parseInt(c.req.query('offset')!) : 0;

    const result = await audit.query({
      organizationId: orgId,
      workspaceId,
      types,
      severity,
      actorId,
      resource,
      startTime,
      endTime,
      limit,
      offset,
    });

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Get audit statistics
   */
  app.get('/organizations/:orgId/audit/stats', async (c) => {
    const orgId = c.req.param('orgId');
    const days = c.req.query('days') ? parseInt(c.req.query('days')!) : 30;

    const result = await audit.getStats(orgId, days);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Export audit logs
   */
  app.get('/organizations/:orgId/audit/export', async (c) => {
    const orgId = c.req.param('orgId');
    const format = (c.req.query('format') || 'json') as 'json' | 'csv';
    const startTime = c.req.query('startTime') ? new Date(c.req.query('startTime')!) : undefined;
    const endTime = c.req.query('endTime') ? new Date(c.req.query('endTime')!) : undefined;

    const result = await audit.export({
      organizationId: orgId,
      startTime,
      endTime,
    }, format);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    const contentType = format === 'json' ? 'application/json' : 'text/csv';
    const filename = `audit-logs-${orgId}-${new Date().toISOString()}.${format}`;

    c.header('Content-Type', contentType);
    c.header('Content-Disposition', `attachment; filename="${filename}"`);

    return c.text(result.value);
  });

  return app;
}
