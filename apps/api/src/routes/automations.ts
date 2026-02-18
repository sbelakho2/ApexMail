/**
 * Automations Routes — Email automation workflows
 *
 * Handles creation, management, and monitoring of automated email sequences.
 * Routes mounted at /v1/automations via app.ts.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv, AppContext } from '../app.js';
import { AuditLogsRepository } from '@apexmail/db';
import { ApiError } from '../middleware/error-handler.js';
import { requireScopes } from '../middleware/auth.js';

// ── Schemas ──────────────────────────────────────────────────────

const triggerSchema = z.enum([
  'on_subscribe',
  'on_event',
  'on_tag',
  'on_date',
  'on_inactivity',
  'on_link_click',
  'manual',
]);

const createAutomationSchema = z.object({
  name: z.string().min(1).max(255),
  trigger: triggerSchema.optional().default('manual'),
  triggerConfig: z.record(z.unknown()).optional(),
  steps: z.array(z.object({
    type: z.enum(['send_email', 'wait', 'condition', 'tag', 'webhook']),
    config: z.record(z.unknown()),
    delayMinutes: z.number().int().min(0).optional(),
  })).optional(),
  enabled: z.boolean().optional().default(false),
});

const updateAutomationSchema = createAutomationSchema.partial();

export function automationsRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const auditRepo = new AuditLogsRepository(ctx.db);

  // POST / — Create a new automation
  router.post('/', requireScopes('automations:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const body = createAutomationSchema.parse(await c.req.json());

    const result = await ctx.db.query(
      `INSERT INTO automations (tenant_id, name, trigger_type, trigger_config, steps, enabled)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [tenantId, body.name, body.trigger, body.triggerConfig ?? {}, JSON.stringify(body.steps ?? []), body.enabled]
    );
    if (!result.ok) throw ApiError.internal('Failed to create automation');
    const created = result.value.rows[0];
    if (!created) throw ApiError.internal('Failed to create automation');

    await auditRepo.create({
      tenantId, userId: userId ?? undefined,
      action: 'automation.created',
      resourceType: 'automation',
      resourceId: created.id as string,
      metadata: { name: body.name, trigger: body.trigger },
    });

    return c.json({ data: created }, 201);
  });

  // GET / — List automations
  router.get('/', requireScopes('automations:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const limit = Math.min(Number(c.req.query('limit') ?? 50), 100);
    const offset = Number(c.req.query('offset') ?? 0);

    const result = await ctx.db.query(
      `SELECT * FROM automations WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [tenantId, limit, offset]
    );
    if (!result.ok) throw ApiError.internal('Failed to list automations');

    const countResult = await ctx.db.query(
      `SELECT COUNT(*)::int as total FROM automations WHERE tenant_id = $1`,
      [tenantId]
    );

    return c.json({
      data: result.value.rows,
      pagination: {
        total: countResult.ok ? Number(countResult.value.rows[0]?.total ?? 0) : 0,
        limit,
        offset,
      },
    });
  });

  // GET /:id — Get automation details
  router.get('/:id', requireScopes('automations:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const id = c.req.param('id');

    const result = await ctx.db.query(
      `SELECT * FROM automations WHERE id = $1 AND tenant_id = $2`,
      [id, tenantId]
    );
    if (!result.ok) throw ApiError.internal('Failed to fetch automation');

    if (result.value.rowCount === 0) {
      throw ApiError.notFound('Automation');
    }

    return c.json({ data: result.value.rows[0] });
  });

  // PATCH /:id — Update an automation
  router.patch('/:id', requireScopes('automations:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const id = c.req.param('id');
    const body = updateAutomationSchema.parse(await c.req.json());

    // Verify ownership
    const existing = await ctx.db.query(
      `SELECT id FROM automations WHERE id = $1 AND tenant_id = $2`,
      [id, tenantId]
    );
    if (!existing.ok || existing.value.rowCount === 0) {
      throw ApiError.notFound('Automation');
    }

    const sets: string[] = [];
    const values: unknown[] = [id, tenantId];
    let idx = 3;

    if (body.name !== undefined) { sets.push(`name = $${idx++}`); values.push(body.name); }
    if (body.trigger !== undefined) { sets.push(`trigger_type = $${idx++}`); values.push(body.trigger); }
    if (body.triggerConfig !== undefined) { sets.push(`trigger_config = $${idx++}`); values.push(body.triggerConfig); }
    if (body.steps !== undefined) { sets.push(`steps = $${idx++}`); values.push(JSON.stringify(body.steps)); }
    if (body.enabled !== undefined) { sets.push(`enabled = $${idx++}`); values.push(body.enabled); }

    if (sets.length === 0) {
      return c.json({ data: existing.value.rows[0] });
    }

    sets.push('updated_at = NOW()');

    const result = await ctx.db.query(
      `UPDATE automations SET ${sets.join(', ')} WHERE id = $1 AND tenant_id = $2 RETURNING *`,
      values
    );
    if (!result.ok) throw ApiError.internal('Failed to update automation');

    await auditRepo.create({
      tenantId, userId: userId ?? undefined,
      action: 'automation.updated',
      resourceType: 'automation',
      resourceId: id,
      metadata: body as Record<string, unknown>,
    });

    return c.json({ data: result.value.rows[0] });
  });

  // POST /:id/enable — Enable an automation
  router.post('/:id/enable', requireScopes('automations:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const id = c.req.param('id');

    const result = await ctx.db.query(
      `UPDATE automations SET enabled = true, updated_at = NOW() WHERE id = $1 AND tenant_id = $2 RETURNING *`,
      [id, tenantId]
    );
    if (!result.ok) throw ApiError.internal('Failed to enable automation');

    if (result.value.rowCount === 0) {
      throw ApiError.notFound('Automation');
    }

    await auditRepo.create({
      tenantId, userId: userId ?? undefined,
      action: 'automation.enabled',
      resourceType: 'automation',
      resourceId: id,
    });

    return c.json({ data: result.value.rows[0] });
  });

  // POST /:id/disable — Disable an automation
  router.post('/:id/disable', requireScopes('automations:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const id = c.req.param('id');

    const result = await ctx.db.query(
      `UPDATE automations SET enabled = false, updated_at = NOW() WHERE id = $1 AND tenant_id = $2 RETURNING *`,
      [id, tenantId]
    );
    if (!result.ok) throw ApiError.internal('Failed to disable automation');

    if (result.value.rowCount === 0) {
      throw ApiError.notFound('Automation');
    }

    await auditRepo.create({
      tenantId, userId: userId ?? undefined,
      action: 'automation.disabled',
      resourceType: 'automation',
      resourceId: id,
    });

    return c.json({ data: result.value.rows[0] });
  });

  // DELETE /:id — Delete an automation
  router.delete('/:id', requireScopes('automations:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const id = c.req.param('id');

    const result = await ctx.db.query(
      `DELETE FROM automations WHERE id = $1 AND tenant_id = $2`,
      [id, tenantId]
    );
    if (!result.ok) throw ApiError.internal('Failed to delete automation');

    if (result.value.rowCount === 0) {
      throw ApiError.notFound('Automation');
    }

    await auditRepo.create({
      tenantId, userId: userId ?? undefined,
      action: 'automation.deleted',
      resourceType: 'automation',
      resourceId: id,
    });

    return c.json({ message: 'Automation deleted' });
  });

  return router;
}
