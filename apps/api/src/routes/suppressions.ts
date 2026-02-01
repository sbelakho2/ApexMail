/**
 * Suppressions Routes - Manage email suppression lists
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv, AppContext } from '../app.js';
import { SuppressionsRepository, AuditLogsRepository } from '@apexmail/db';
import { ApiError } from '../middleware/error-handler.js';
import { createHash } from 'crypto';

const addSuppressionSchema = z.object({
  email: z.string().email(),
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
  emails: z.array(z.string().email()).min(1).max(10000),
});

const bulkCheckSuppressionSchema = z.object({
  emails: z.array(z.string().email()).min(1).max(10000),
});

export function suppressionsRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const suppressionsRepo = new SuppressionsRepository(ctx.db);
  const auditRepo = new AuditLogsRepository(ctx.db);

  // Add suppression
  router.post('/', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const logger = c.get('logger');

    const body = await c.req.json();
    const input = addSuppressionSchema.parse(body);

    // Check if already suppressed
    const existing = await suppressionsRepo.findByEmail(input.email, tenantId);
    if (existing.ok && existing.value) {
      return c.json({
        suppression: {
          id: existing.value.id,
          email: maskEmail(input.email),
          reason: existing.value.reason,
          alreadyExists: true,
          createdAt: existing.value.createdAt,
        },
      });
    }

    const result = await suppressionsRepo.create({
      tenantId,
      email: input.email,
      reason: input.reason,
      bounceType: input.bounceType,
      bounceSubtype: input.bounceSubtype,
      source: input.source ?? 'api',
      sourceMessageId: input.sourceMessageId,
      domainId: input.domainId,
      campaignId: input.campaignId,
      notes: input.notes,
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
      reason: s.reason,
      bounceType: s.bounceType,
      bounceSubtype: s.bounceSubtype,
      source: s.source ?? 'api',
      sourceMessageId: s.sourceMessageId,
      domainId: s.domainId,
      campaignId: s.campaignId,
      notes: s.notes,
      metadata: s.metadata,
    }));

    const result = await suppressionsRepo.bulkCreate(items);

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
        count: result.value.created,
        skipped: result.value.skipped,
      },
    });

    logger.info('Bulk suppressions added', {
      created: result.value.created,
      skipped: result.value.skipped,
    });

    return c.json({
      result: {
        created: result.value.created,
        skipped: result.value.skipped,
        total: suppressions.length,
      },
    }, 201);
  });

  // Check single email
  router.get('/check/:email', async (c) => {
    const tenantId = c.get('tenantId');
    const email = decodeURIComponent(c.req.param('email'));

    // Validate email format
    const emailSchema = z.string().email();
    const parsed = emailSchema.safeParse(email);
    if (!parsed.success) {
      throw ApiError.badRequest('Invalid email format');
    }

    const result = await suppressionsRepo.findByEmail(email, tenantId);

    if (!result.ok) {
      throw ApiError.internal('Failed to check suppression');
    }

    if (!result.value) {
      return c.json({
        suppressed: false,
        email: maskEmail(email),
      });
    }

    return c.json({
      suppressed: true,
      email: maskEmail(email),
      reason: result.value.reason,
      bounceType: result.value.bounceType,
      createdAt: result.value.createdAt,
    });
  });

  // Bulk check emails
  router.post('/check', async (c) => {
    const tenantId = c.get('tenantId');

    const body = await c.req.json();
    const { emails } = bulkCheckSuppressionSchema.parse(body);

    const result = await suppressionsRepo.bulkCheck(emails, tenantId);

    if (!result.ok) {
      throw ApiError.internal('Failed to check suppressions');
    }

    // Convert Map to object for JSON response
    const suppressedEmails: Record<string, { reason: string; bounceType?: string }> = {};
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
  router.get('/', async (c) => {
    const tenantId = c.get('tenantId');
    const reason = c.req.query('reason') as 'bounce' | 'complaint' | 'unsubscribe' | 'manual' | undefined;
    const bounceType = c.req.query('bounceType') as 'hard' | 'soft' | 'undetermined' | undefined;
    const source = c.req.query('source');
    const domainId = c.req.query('domainId');
    const campaignId = c.req.query('campaignId');
    const since = c.req.query('since');
    const until = c.req.query('until');
    const limit = parseInt(c.req.query('limit') ?? '50', 10);
    const offset = parseInt(c.req.query('offset') ?? '0', 10);

    const result = await suppressionsRepo.listByTenant(tenantId, {
      reason,
      bounceType,
      source,
      domainId,
      campaignId,
      since: since ? new Date(since) : undefined,
      until: until ? new Date(until) : undefined,
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
        reason: s.reason,
        bounceType: s.bounceType,
        bounceSubtype: s.bounceSubtype,
        source: s.source,
        domainId: s.domainId,
        campaignId: s.campaignId,
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
        reason: s.reason,
        bounceType: s.bounceType,
        bounceSubtype: s.bounceSubtype,
        source: s.source,
        sourceMessageId: s.sourceMessageId,
        domainId: s.domainId,
        campaignId: s.campaignId,
        notes: s.notes,
        metadata: s.metadata,
        createdAt: s.createdAt,
      },
    });
  });

  // Remove suppression by ID
  router.delete('/:id', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const suppressionId = c.req.param('id');
    const logger = c.get('logger');

    // Verify ownership
    const existing = await suppressionsRepo.findById(suppressionId);
    if (!existing.ok || !existing.value || existing.value.tenantId !== tenantId) {
      throw ApiError.notFound('Suppression');
    }

    const result = await suppressionsRepo.delete(suppressionId);

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

    // Validate email format
    const emailSchema = z.string().email();
    const parsed = emailSchema.safeParse(email);
    if (!parsed.success) {
      throw ApiError.badRequest('Invalid email format');
    }

    // Find suppression
    const existing = await suppressionsRepo.findByEmail(email, tenantId);
    if (!existing.ok || !existing.value) {
      throw ApiError.notFound('Suppression');
    }

    const result = await suppressionsRepo.delete(existing.value.id);

    if (!result.ok) {
      throw ApiError.internal('Failed to remove suppression');
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'suppression.deleted',
      resourceType: 'suppression',
      resourceId: existing.value.id,
      metadata: {
        reason: existing.value.reason,
        emailHash: existing.value.emailHash,
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

    const result = await suppressionsRepo.bulkDelete(emails, tenantId);

    if (!result.ok) {
      throw ApiError.internal('Failed to remove suppressions');
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'suppression.bulk_deleted',
      resourceType: 'suppression',
      resourceId: tenantId,
      metadata: {
        count: result.value.deleted,
        notFound: result.value.notFound,
      },
    });

    logger.info('Bulk suppressions removed', {
      deleted: result.value.deleted,
      notFound: result.value.notFound,
    });

    return c.json({
      result: {
        deleted: result.value.deleted,
        notFound: result.value.notFound,
        total: emails.length,
      },
    });
  });

  // Export suppressions
  router.get('/export', async (c) => {
    const tenantId = c.get('tenantId');
    const format = c.req.query('format') ?? 'json';
    const reason = c.req.query('reason') as 'bounce' | 'complaint' | 'unsubscribe' | 'manual' | undefined;
    const since = c.req.query('since');
    const until = c.req.query('until');

    if (format !== 'json' && format !== 'csv') {
      throw ApiError.badRequest('Format must be json or csv');
    }

    const result = await suppressionsRepo.export(tenantId, {
      reason,
      since: since ? new Date(since) : undefined,
      until: until ? new Date(until) : undefined,
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to export suppressions');
    }

    if (format === 'csv') {
      const csv = convertToCSV(result.value);
      c.header('Content-Type', 'text/csv');
      c.header('Content-Disposition', `attachment; filename="suppressions-${Date.now()}.csv"`);
      return c.body(csv);
    }

    return c.json({
      suppressions: result.value.map((s) => ({
        emailHash: s.emailHash,
        reason: s.reason,
        bounceType: s.bounceType,
        source: s.source,
        createdAt: s.createdAt,
      })),
      total: result.value.length,
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
          email: z.string().email(),
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
        const parts = lines[i].split(',').map(p => p.trim().replace(/^["']|["']$/g, ''));
        if (parts[0] && z.string().email().safeParse(parts[0]).success) {
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
      reason: e.reason as 'bounce' | 'complaint' | 'unsubscribe' | 'manual',
      source: 'import',
    }));

    const result = await suppressionsRepo.bulkCreate(items);

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
        created: result.value.created,
        skipped: result.value.skipped,
      },
    });

    logger.info('Suppressions imported', {
      created: result.value.created,
      skipped: result.value.skipped,
    });

    return c.json({
      result: {
        created: result.value.created,
        skipped: result.value.skipped,
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
  return createHash('sha256').update(email.toLowerCase().trim()).digest('hex');
}

interface SuppressionExport {
  emailHash: string;
  reason: string;
  bounceType?: string;
  source: string;
  createdAt: Date;
}

function convertToCSV(data: SuppressionExport[]): string {
  const headers = ['emailHash', 'reason', 'bounceType', 'source', 'createdAt'];
  const rows = data.map(row => [
    row.emailHash,
    row.reason,
    row.bounceType ?? '',
    row.source,
    row.createdAt.toISOString(),
  ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));

  return [headers.join(','), ...rows].join('\n');
}
