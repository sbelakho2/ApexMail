/**
 * Suppressions Routes - Manage email suppression lists
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv, AppContext } from '../app.js';
import { SuppressionsRepository, AuditLogsRepository, type SuppressionType, type SuppressionScope } from '@apexmail/db';
import { ApiError } from '../middleware/error-handler.js';
import { requireScopes } from '../middleware/auth.js';
import { sha256 } from '@apexmail/lib/crypto';

const addSuppressionSchema = z.object({
  email: z.string().email().max(254), // RFC 5321 max email length
  reason: z.enum(['bounce', 'complaint', 'unsubscribe', 'manual']),
  bounceType: z.enum(['hard', 'soft', 'undetermined']).optional(),
  bounceSubtype: z.string().max(50).optional(),
  source: z.string().max(100).optional(),
  sourceMessageId: z.string().uuid().optional(),
  domainId: z.string().uuid().optional(),
  campaignId: z.string().max(100).optional(),
  notes: z.string().max(1000).optional(),
  metadata: z.record(z.unknown()).optional(),
});

const bulkAddSuppressionSchema = z.object({
  suppressions: z.array(addSuppressionSchema).min(1).max(10000),
});

const bulkRemoveSuppressionSchema = z.object({
  emails: z.array(z.string().email().max(254)).min(1).max(10000), // RFC 5321 max email length
});

const bulkCheckSuppressionSchema = z.object({
  emails: z.array(z.string().email().max(254)).min(1).max(10000), // RFC 5321 max email length
});

export function suppressionsRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const suppressionsRepo = new SuppressionsRepository(ctx.db);
  const auditRepo = new AuditLogsRepository(ctx.db);

  // Add suppression
  router.post('/', requireScopes('suppressions:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const logger = c.get('logger');

    const body = await c.req.json();
    const input = addSuppressionSchema.parse(body);

    // Check if already suppressed
    const existing = await suppressionsRepo.findByEmail(input.email, tenantId);
    if (existing.ok && existing.value && existing.value.length > 0) {
      const firstSuppression = existing.value[0]!;
      return c.json({
        suppression: {
          id: firstSuppression.id,
          email: maskEmail(input.email),
          reason: firstSuppression.reason,
          alreadyExists: true,
          createdAt: firstSuppression.createdAt,
        },
      });
    }

    const result = await suppressionsRepo.create({
      tenantId,
      email: input.email,
      type: input.reason, // route's 'reason' maps to repo's 'type'
      reason: input.notes, // route's notes maps to repo's reason
      bounceType: input.bounceType as 'hard' | 'soft' | undefined,
      bounceCode: input.bounceSubtype,
      source: input.source ?? 'api',
      originalMessageId: input.sourceMessageId,
      scopeId: input.domainId ?? input.campaignId,
      scope: input.domainId ? 'domain' : (input.campaignId ? 'campaign' : 'tenant'),
      metadata: input.metadata,
    });

    if (!result.ok) {
      logger.error('Failed to add suppression', { error: result.error });
      throw ApiError.internal('Failed to add suppression');
    }

    const suppression = result.value;

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'suppression.created',
      resourceType: 'suppression',
      resourceId: suppression.id,
      metadata: {
        reason: input.reason,
        source: input.source ?? 'api',
        emailHash: hashEmail(input.email),
      },
    });

    logger.info('Suppression added', {
      suppressionId: suppression.id,
      reason: input.reason,
    });

    return c.json({
      suppression: {
        id: suppression.id,
        email: maskEmail(input.email),
        reason: suppression.reason,
        createdAt: suppression.createdAt,
      },
    }, 201);
  });

  // Bulk add suppressions
  router.post('/bulk', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const logger = c.get('logger');

    const body = await c.req.json();
    const { suppressions } = bulkAddSuppressionSchema.parse(body);

    const items = suppressions.map((s) => ({
      tenantId,
      email: s.email,
      type: s.reason as SuppressionType, // route's reason = repo's type
      bounceType: s.bounceType as 'hard' | 'soft' | undefined,
      bounceCode: s.bounceSubtype,
      source: s.source ?? 'api',
      originalMessageId: s.sourceMessageId,
      scopeId: s.domainId ?? s.campaignId,
      scope: (s.domainId ? 'domain' : (s.campaignId ? 'campaign' : 'tenant')) as SuppressionScope,
      reason: s.notes,
      metadata: s.metadata,
    }));

    const result = await suppressionsRepo.importBulk(items);

    if (!result.ok) {
      logger.error('Failed to bulk add suppressions', { error: result.error });
      throw ApiError.internal('Failed to add suppressions');
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'suppression.bulk_created',
      resourceType: 'suppression',
      resourceId: tenantId,
      metadata: {
        count: result.value.imported,
        skipped: result.value.duplicates,
      },
    });

    logger.info('Bulk suppressions added', {
      created: result.value.imported,
      skipped: result.value.duplicates,
    });

    return c.json({
      result: {
        created: result.value.imported,
        skipped: result.value.duplicates,
        total: suppressions.length,
      },
    }, 201);
  });

  // Check single email
  router.get('/check/:email', async (c) => {
    const tenantId = c.get('tenantId');
    const email = decodeURIComponent(c.req.param('email'));

    // Validate email format with RFC 5321 max length
    const emailSchema = z.string().email().max(254);
    const parsed = emailSchema.safeParse(email);
    if (!parsed.success) {
      throw ApiError.badRequest('Invalid email format');
    }

    const result = await suppressionsRepo.findByEmail(email, tenantId);

    if (!result.ok) {
      throw ApiError.internal('Failed to check suppression');
    }

    if (!result.value || result.value.length === 0) {
      return c.json({
        suppressed: false,
        email: maskEmail(email),
      });
    }

    const firstSuppression = result.value[0]!;
    return c.json({
      suppressed: true,
      email: maskEmail(email),
      reason: firstSuppression.reason,
      bounceType: firstSuppression.bounceType,
      createdAt: firstSuppression.createdAt,
    });
  });

  // Bulk check emails
  router.post('/check', async (c) => {
    const tenantId = c.get('tenantId');

    const body = await c.req.json();
    const { emails } = bulkCheckSuppressionSchema.parse(body);

    const result = await suppressionsRepo.checkBulkSuppression(emails, tenantId);

    if (!result.ok) {
      throw ApiError.internal('Failed to check suppressions');
    }

    // Convert Map to object for JSON response
    const suppressedEmails: Record<string, { reason: string | null; bounceType?: string | null }> = {};
    for (const [email, data] of result.value.entries()) {
      if (data) {
        suppressedEmails[maskEmail(email)] = {
          reason: data.reason,
          bounceType: data.bounceType,
        };
      }
    }

    const suppressedCount = Object.keys(suppressedEmails).length;

    return c.json({
      total: emails.length,
      suppressed: suppressedCount,
      clean: emails.length - suppressedCount,
      suppressedEmails,
    });
  });

  // List suppressions
  router.get('/', requireScopes('suppressions:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const type = c.req.query('reason') as SuppressionType | undefined; // reason maps to type
    const scope = c.req.query('scope') as SuppressionScope | undefined;
    const includeExpired = c.req.query('includeExpired') === 'true';
    const limit = parseInt(c.req.query('limit') ?? '50', 10);
    const offset = parseInt(c.req.query('offset') ?? '0', 10);

    const result = await suppressionsRepo.listByTenant(tenantId, {
      type,
      scope,
      includeExpired,
      limit: Math.min(limit, 1000),
      offset,
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch suppressions');
    }

    return c.json({
      suppressions: result.value.suppressions.map((s) => ({
        id: s.id,
        email: maskEmail(s.email),
        emailHash: s.emailHash,
        type: s.type,
        scope: s.scope,
        scopeId: s.scopeId,
        reason: s.reason,
        bounceType: s.bounceType,
        bounceCode: s.bounceCode,
        source: s.source,
        createdAt: s.createdAt,
      })),
      pagination: {
        total: result.value.total,
        limit,
        offset,
        hasMore: offset + result.value.suppressions.length < result.value.total,
      },
    });
  });

  // Get suppression stats
  router.get('/stats', async (c) => {
    const tenantId = c.get('tenantId');
    const since = c.req.query('since');
    const until = c.req.query('until');

    const result = await suppressionsRepo.getStats(tenantId, {
      since: since ? new Date(since) : undefined,
      until: until ? new Date(until) : undefined,
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch stats');
    }

    return c.json({
      stats: result.value,
    });
  });

  // Get suppression by ID
  router.get('/:id', async (c) => {
    const tenantId = c.get('tenantId');
    const suppressionId = c.req.param('id');

    const result = await suppressionsRepo.findById(suppressionId);

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch suppression');
    }

    if (!result.value || result.value.tenantId !== tenantId) {
      throw ApiError.notFound('Suppression');
    }

    const s = result.value;

    return c.json({
      suppression: {
        id: s.id,
        email: maskEmail(s.email),
        emailHash: s.emailHash,
        type: s.type,
        scope: s.scope,
        scopeId: s.scopeId,
        reason: s.reason,
        bounceType: s.bounceType,
        bounceCode: s.bounceCode,
        feedbackType: s.feedbackType,
        source: s.source,
        originalMessageId: s.originalMessageId,
        metadata: s.metadata,
        expiresAt: s.expiresAt,
        createdAt: s.createdAt,
      },
    });
  });

  // Remove suppression by ID
  router.delete('/:id', requireScopes('suppressions:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const suppressionId = c.req.param('id');
    const logger = c.get('logger');

    // Verify ownership
    const existing = await suppressionsRepo.findById(suppressionId);
    if (!existing.ok || !existing.value || existing.value.tenantId !== tenantId) {
      throw ApiError.notFound('Suppression');
    }

    const result = await suppressionsRepo.remove(suppressionId);

    if (!result.ok) {
      throw ApiError.internal('Failed to remove suppression');
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'suppression.deleted',
      resourceType: 'suppression',
      resourceId: suppressionId,
      metadata: {
        reason: existing.value.reason,
        emailHash: existing.value.emailHash,
      },
    });

    logger.info('Suppression removed', { suppressionId });

    return c.json({ success: true });
  });

  // Remove suppression by email
  router.delete('/email/:email', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const email = decodeURIComponent(c.req.param('email'));
    const logger = c.get('logger');

    // Validate email format with RFC 5321 max length
    const emailSchema = z.string().email().max(254);
    const parsed = emailSchema.safeParse(email);
    if (!parsed.success) {
      throw ApiError.badRequest('Invalid email format');
    }

    // Find suppression
    const existing = await suppressionsRepo.findByEmail(email, tenantId);
    if (!existing.ok || !existing.value || existing.value.length === 0) {
      throw ApiError.notFound('Suppression');
    }

    const firstSuppression = existing.value[0]!;
    const result = await suppressionsRepo.remove(firstSuppression.id);

    if (!result.ok) {
      throw ApiError.internal('Failed to remove suppression');
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'suppression.deleted',
      resourceType: 'suppression',
      resourceId: firstSuppression.id,
      metadata: {
        reason: firstSuppression.reason,
        emailHash: firstSuppression.emailHash,
      },
    });

    logger.info('Suppression removed by email', { emailHash: hashEmail(email) });

    return c.json({ success: true });
  });

  // Bulk remove suppressions
  router.post('/bulk/remove', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const logger = c.get('logger');

    const body = await c.req.json();
    const { emails } = bulkRemoveSuppressionSchema.parse(body);

    // Use removeByEmail for each email since bulkDelete doesn't exist
    let deleted = 0;
    let notFound = 0;

    for (const email of emails) {
      const result = await suppressionsRepo.removeByEmail(email, tenantId);
      if (result.ok) {
        if (result.value > 0) {
          deleted += result.value;
        } else {
          notFound++;
        }
      } else {
        notFound++;
      }
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'suppression.bulk_deleted',
      resourceType: 'suppression',
      resourceId: tenantId,
      metadata: {
        count: deleted,
        notFound: notFound,
      },
    });

    logger.info('Bulk suppressions removed', {
      deleted,
      notFound,
    });

    return c.json({
      result: {
        deleted,
        notFound,
        total: emails.length,
      },
    });
  });

  // Export suppressions
  router.get('/export', async (c) => {
    const tenantId = c.get('tenantId');
    const format = c.req.query('format') ?? 'json';
    const type = c.req.query('type') as SuppressionType | undefined;

    if (format !== 'json' && format !== 'csv') {
      throw ApiError.badRequest('Format must be json or csv');
    }

    // Use listByTenant with high limit for export
    const result = await suppressionsRepo.listByTenant(tenantId, {
      type,
      limit: 100000,
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to export suppressions');
    }

    const suppressions = result.value.suppressions;

    if (format === 'csv') {
      const csv = convertToCSV(suppressions);
      c.header('Content-Type', 'text/csv');
      c.header('Content-Disposition', `attachment; filename="suppressions-${Date.now()}.csv"`);
      return c.body(csv);
    }

    return c.json({
      suppressions: suppressions.map((s) => ({
        emailHash: s.emailHash,
        type: s.type,
        reason: s.reason,
        bounceType: s.bounceType,
        source: s.source,
        createdAt: s.createdAt,
      })),
      total: suppressions.length,
      exportedAt: new Date().toISOString(),
    });
  });

  // Import suppressions
  router.post('/import', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const logger = c.get('logger');

    const contentType = c.req.header('content-type') ?? '';
    
    let emails: Array<{ email: string; reason: string }> = [];

    if (contentType.includes('application/json')) {
      const body = await c.req.json();
      const schema = z.object({
        suppressions: z.array(z.object({
          email: z.string().email().max(254), // RFC 5321 max email length
          reason: z.enum(['bounce', 'complaint', 'unsubscribe', 'manual']).default('manual'),
        })).min(1).max(100000),
      });
      const parsed = schema.parse(body);
      emails = parsed.suppressions;
    } else if (contentType.includes('text/csv')) {
      const text = await c.req.text();
      const lines = text.split('\n').filter(line => line.trim());
      
      // Skip header if present
      const startIndex = lines[0]?.toLowerCase().includes('email') ? 1 : 0;
      
      for (let i = startIndex; i < lines.length; i++) {
        const line = lines[i];
        if (!line) continue;
        const parts = line.split(',').map(p => p.trim().replace(/^["']|["']$/g, ''));
        // Validate email with RFC 5321 max length
        if (parts[0] && parts[0].length <= 254 && z.string().email().safeParse(parts[0]).success) {
          const reason = (['bounce', 'complaint', 'unsubscribe', 'manual'].includes(parts[1] ?? ''))
            ? parts[1] as 'bounce' | 'complaint' | 'unsubscribe' | 'manual'
            : 'manual';
          emails.push({ email: parts[0], reason });
        }
      }

      if (emails.length === 0) {
        throw ApiError.badRequest('No valid emails found in CSV');
      }

      if (emails.length > 100000) {
        throw ApiError.badRequest('Maximum 100000 emails per import');
      }
    } else {
      throw ApiError.badRequest('Content-Type must be application/json or text/csv');
    }

    const items = emails.map((e) => ({
      tenantId,
      email: e.email,
      type: e.reason as SuppressionType,
      source: 'import',
    }));

    const result = await suppressionsRepo.importBulk(items);

    if (!result.ok) {
      throw ApiError.internal('Failed to import suppressions');
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'suppression.imported',
      resourceType: 'suppression',
      resourceId: tenantId,
      metadata: {
        created: result.value.imported,
        skipped: result.value.duplicates,
      },
    });

    logger.info('Suppressions imported', {
      created: result.value.imported,
      skipped: result.value.duplicates,
    });

    return c.json({
      result: {
        created: result.value.imported,
        skipped: result.value.duplicates,
        total: emails.length,
      },
    }, 201);
  });

  return router;
}

function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  if (!local || !domain) return email;
  
  const maskedLocal = local.length <= 2
    ? local[0] + '*'
    : local[0] + '*'.repeat(Math.min(local.length - 2, 5)) + local[local.length - 1];
  
  return `${maskedLocal}@${domain}`;
}

function hashEmail(email: string): string {
  return sha256(email.toLowerCase().trim());
}

import type { Suppression } from '@apexmail/db';

function convertToCSV(data: Suppression[]): string {
  const headers = ['emailHash', 'type', 'reason', 'bounceType', 'source', 'createdAt'];
  const rows = data.map(row => [
    row.emailHash,
    row.type,
    row.reason ?? '',
    row.bounceType ?? '',
    row.source,
    row.createdAt.toISOString(),
  ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));

  return [headers.join(','), ...rows].join('\n');
}
