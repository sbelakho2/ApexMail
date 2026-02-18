/**
 * Contacts Routes — Contact/subscriber management
 *
 * Handles individual & bulk contact operations, tagging, and list membership.
 * Routes mounted at /v1/contacts via app.ts.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv, AppContext } from '../app.js';
import { SuppressionsRepository, AuditLogsRepository } from '@apexmail/db';
import { ApiError } from '../middleware/error-handler.js';
import { requireScopes } from '../middleware/auth.js';

// ── Schemas ──────────────────────────────────────────────────────

const addContactSchema = z.object({
  email: z.string().email(),
  firstName: z.string().max(255).optional(),
  lastName: z.string().max(255).optional(),
  tags: z.array(z.string()).optional(),
  listId: z.string().uuid().optional(),
  metadata: z.record(z.unknown()).optional(),
});

const bulkContactsSchema = z.object({
  emails: z.array(z.string().email()).min(1).max(10_000),
  listName: z.string().optional(),
  listId: z.string().uuid().optional(),
  tags: z.array(z.string()).optional(),
});

const tagSchema = z.object({
  tag: z.string().min(1).max(100),
  listName: z.string().optional(),
  listId: z.string().uuid().optional(),
});

const importSchema = z.object({
  contacts: z.array(z.object({
    email: z.string().email(),
    firstName: z.string().optional(),
    lastName: z.string().optional(),
    tags: z.array(z.string()).optional(),
    metadata: z.record(z.unknown()).optional(),
  })).min(1).max(50_000),
  listId: z.string().uuid().optional(),
});

export function contactsRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const suppressionsRepo = new SuppressionsRepository(ctx.db);
  const auditRepo = new AuditLogsRepository(ctx.db);

  // POST / — Add a single contact
  router.post('/', requireScopes('contacts:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const body = addContactSchema.parse(await c.req.json());

    // Check suppression before adding
    const suppResult = await suppressionsRepo.checkSuppression(tenantId, body.email);
    if (suppResult.ok && suppResult.value.suppressed) {
      throw ApiError.badRequest(
        `${body.email} is on the suppression list. Remove suppression first.`,
        'CONTACT_SUPPRESSED'
      );
    }

    const result = await ctx.db.query(
      `INSERT INTO contacts (tenant_id, email, first_name, last_name, metadata, list_id)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (tenant_id, email) DO UPDATE SET
         first_name = COALESCE(EXCLUDED.first_name, contacts.first_name),
         last_name = COALESCE(EXCLUDED.last_name, contacts.last_name),
         metadata = COALESCE(EXCLUDED.metadata, contacts.metadata),
         updated_at = NOW()
       RETURNING *`,
      [tenantId, body.email, body.firstName, body.lastName, body.metadata ?? {}, body.listId]
    );
    if (!result.ok) throw ApiError.internal('Failed to add contact');

    await auditRepo.create({
      tenantId, userId: userId ?? undefined,
      action: 'contact.added',
      resourceType: 'contact',
      resourceId: body.email,
      metadata: { tags: body.tags },
    });

    return c.json({ data: result.value.rows[0] }, 201);
  });

  // POST /bulk — Add contacts in bulk
  router.post('/bulk', requireScopes('contacts:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const body = bulkContactsSchema.parse(await c.req.json());

    // Filter out suppressed contacts
    const suppressionChecks = await Promise.all(
      body.emails.map(async (email) => {
        const r = await suppressionsRepo.checkSuppression(tenantId, email);
        return { email, suppressed: r.ok && r.value.suppressed };
      })
    );

    const validEmails = suppressionChecks.filter(r => !r.suppressed).map(r => r.email);
    const suppressedEmails = suppressionChecks.filter(r => r.suppressed).map(r => r.email);

    // Batch insert valid contacts
    if (validEmails.length > 0) {
      const values = validEmails.map((_, i) => `($1, $${i + 2})`).join(', ');
      const insertResult = await ctx.db.query(
        `INSERT INTO contacts (tenant_id, email) VALUES ${values}
         ON CONFLICT (tenant_id, email) DO NOTHING`,
        [tenantId, ...validEmails]
      );
      if (!insertResult.ok) throw ApiError.internal('Failed to bulk add contacts');
    }

    await auditRepo.create({
      tenantId, userId: userId ?? undefined,
      action: 'contact.bulk_added',
      resourceType: 'contact',
      metadata: { added: validEmails.length, suppressed: suppressedEmails.length },
    });

    return c.json({
      data: {
        added: validEmails.length,
        skippedSuppressed: suppressedEmails.length,
        suppressedEmails: suppressedEmails.length > 0 ? suppressedEmails : undefined,
      },
    }, 201);
  });

  // DELETE /bulk — Remove contacts in bulk
  router.delete('/bulk', requireScopes('contacts:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const body = bulkContactsSchema.parse(await c.req.json());

    const result = await ctx.db.query(
      `DELETE FROM contacts WHERE tenant_id = $1 AND email = ANY($2) RETURNING email`,
      [tenantId, body.emails]
    );
    if (!result.ok) throw ApiError.internal('Failed to bulk remove contacts');

    await auditRepo.create({
      tenantId, userId: userId ?? undefined,
      action: 'contact.bulk_removed',
      resourceType: 'contact',
      metadata: { requested: body.emails.length, removed: result.value.rowCount },
    });

    return c.json({
      data: { removed: result.value.rowCount },
    });
  });

  // POST /tags — Tag all contacts in a list
  router.post('/tags', requireScopes('contacts:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const body = tagSchema.parse(await c.req.json());

    const listFilter = body.listId ? `AND list_id = '${body.listId}'` : '';
    const result = await ctx.db.query(
      `UPDATE contacts SET tags = array_append(tags, $2)
       WHERE tenant_id = $1 ${listFilter} AND NOT ($2 = ANY(tags))
       RETURNING email`,
      [tenantId, body.tag]
    );
    if (!result.ok) throw ApiError.internal('Failed to bulk tag contacts');

    await auditRepo.create({
      tenantId, userId: userId ?? undefined,
      action: 'contact.bulk_tagged',
      resourceType: 'contact',
      metadata: { tag: body.tag, tagged: result.value.rowCount },
    });

    return c.json({ data: { tagged: result.value.rowCount, tag: body.tag } });
  });

  // POST /:email/tags — Tag a specific contact
  router.post('/:email/tags', requireScopes('contacts:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const email = decodeURIComponent(c.req.param('email'));
    const body = tagSchema.parse(await c.req.json());

    const result = await ctx.db.query(
      `UPDATE contacts SET tags = array_append(tags, $3)
       WHERE tenant_id = $1 AND email = $2 AND NOT ($3 = ANY(tags))
       RETURNING *`,
      [tenantId, email, body.tag]
    );
    if (!result.ok) throw ApiError.internal('Failed to tag contact');

    if (result.value.rowCount === 0) {
      const exists = await ctx.db.query(
        `SELECT email FROM contacts WHERE tenant_id = $1 AND email = $2`,
        [tenantId, email]
      );
      if (!exists.ok || exists.value.rowCount === 0) {
        throw ApiError.notFound('Contact');
      }
      return c.json({ data: { email, tag: body.tag, message: 'Tag already applied' } });
    }

    await auditRepo.create({
      tenantId, userId: userId ?? undefined,
      action: 'contact.tagged',
      resourceType: 'contact',
      resourceId: email,
      metadata: { tag: body.tag },
    });

    return c.json({ data: result.value.rows[0] });
  });

  // POST /import — Import contacts from CSV/JSON
  router.post('/import', requireScopes('contacts:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const body = importSchema.parse(await c.req.json());

    let imported = 0;
    let skipped = 0;

    for (const contact of body.contacts) {
      const suppRes = await suppressionsRepo.checkSuppression(tenantId, contact.email);
      const suppressed = suppRes.ok && suppRes.value.suppressed;
      if (suppressed) {
        skipped++;
        continue;
      }

      const insertResult = await ctx.db.query(
        `INSERT INTO contacts (tenant_id, email, first_name, last_name, metadata, list_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (tenant_id, email) DO UPDATE SET
           first_name = COALESCE(EXCLUDED.first_name, contacts.first_name),
           last_name = COALESCE(EXCLUDED.last_name, contacts.last_name),
           updated_at = NOW()`,
        [tenantId, contact.email, contact.firstName, contact.lastName, contact.metadata ?? {}, body.listId]
      );
      if (insertResult.ok) imported++;
    }

    await auditRepo.create({
      tenantId, userId: userId ?? undefined,
      action: 'contact.imported',
      resourceType: 'contact',
      metadata: { imported, skipped, total: body.contacts.length },
    });

    return c.json({ data: { imported, skipped, total: body.contacts.length } }, 201);
  });

  // DELETE /:email — Remove a single contact
  router.delete('/:email', requireScopes('contacts:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const email = decodeURIComponent(c.req.param('email'));

    const result = await ctx.db.query(
      `DELETE FROM contacts WHERE tenant_id = $1 AND email = $2`,
      [tenantId, email]
    );
    if (!result.ok) throw ApiError.internal('Failed to remove contact');

    if (result.value.rowCount === 0) {
      throw ApiError.notFound('Contact');
    }

    await auditRepo.create({
      tenantId, userId: userId ?? undefined,
      action: 'contact.removed',
      resourceType: 'contact',
      resourceId: email,
    });

    return c.json({ message: `Contact ${email} removed` });
  });

  return router;
}
