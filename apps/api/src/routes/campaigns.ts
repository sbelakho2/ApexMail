/**
 * Campaigns Routes — Campaign lifecycle management
 *
 * Handles campaign creation, resume, stop, and lifecycle operations.
 * Routes mounted at /v1/campaigns via app.ts.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv, AppContext } from '../app.js';
import { MessagesRepository, AuditLogsRepository } from '@apexmail/db';
import { ApiError } from '../middleware/error-handler.js';
import { requireScopes } from '../middleware/auth.js';

// ── Schemas ──────────────────────────────────────────────────────

const createCampaignSchema = z.object({
  name: z.string().min(1).max(255),
  subject: z.string().min(1).max(998).optional(),
  listId: z.string().uuid().optional(),
  templateId: z.string().uuid().optional(),
  scheduledAt: z.string().datetime().optional(),
});

export function campaignsRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const messagesRepo = new MessagesRepository(ctx.db);
  const auditRepo = new AuditLogsRepository(ctx.db);

  // POST / — Create a new campaign
  router.post('/', requireScopes('messages:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const body = createCampaignSchema.parse(await c.req.json());

    const campaign = await messagesRepo.createCampaign({
      tenantId,
      name: body.name,
      subject: body.subject,
      listId: body.listId,
      templateId: body.templateId,
      scheduledAt: body.scheduledAt ? new Date(body.scheduledAt) : undefined,
      status: 'draft',
    });

    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'campaign.created',
      resourceType: 'campaign',
      resourceId: campaign.id,
      metadata: { name: body.name },
    });

    return c.json({ data: campaign }, 201);
  });

  // POST /:name/resume — Resume a paused campaign
  router.post('/:name/resume', requireScopes('messages:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const campaignName = decodeURIComponent(c.req.param('name'));

    const campaign = await messagesRepo.findCampaignByName(campaignName, tenantId);
    if (!campaign) {
      throw ApiError.notFound('Campaign');
    }

    if (campaign.status !== 'paused') {
      throw ApiError.badRequest(
        `Campaign "${campaignName}" is ${campaign.status}, not paused`,
        'INVALID_STATE'
      );
    }

    const updated = await messagesRepo.updateCampaignStatus(campaign.id, tenantId, 'sending');

    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'campaign.resumed',
      resourceType: 'campaign',
      resourceId: campaign.id,
      metadata: { name: campaignName, previousStatus: 'paused' },
    });

    return c.json({
      data: updated,
      message: `Campaign "${campaignName}" resumed`,
    });
  });

  // POST /:name/stop — Stop an active campaign
  router.post('/:name/stop', requireScopes('messages:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const campaignName = decodeURIComponent(c.req.param('name'));

    const campaign = await messagesRepo.findCampaignByName(campaignName, tenantId);
    if (!campaign) {
      throw ApiError.notFound('Campaign');
    }

    if (campaign.status === 'stopped' || campaign.status === 'completed') {
      throw ApiError.badRequest(
        `Campaign "${campaignName}" is already ${campaign.status}`,
        'INVALID_STATE'
      );
    }

    const updated = await messagesRepo.updateCampaignStatus(campaign.id, tenantId, 'stopped');

    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'campaign.stopped',
      resourceType: 'campaign',
      resourceId: campaign.id,
      metadata: { name: campaignName, previousStatus: campaign.status },
    });

    return c.json({
      data: updated,
      message: `Campaign "${campaignName}" stopped`,
    });
  });

  // POST /:name/pause — Pause an active campaign
  router.post('/:name/pause', requireScopes('messages:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const campaignName = decodeURIComponent(c.req.param('name'));

    const campaign = await messagesRepo.findCampaignByName(campaignName, tenantId);
    if (!campaign) {
      throw ApiError.notFound('Campaign');
    }

    if (campaign.status !== 'sending') {
      throw ApiError.badRequest(
        `Campaign "${campaignName}" is ${campaign.status}, not sending`,
        'INVALID_STATE'
      );
    }

    const updated = await messagesRepo.updateCampaignStatus(campaign.id, tenantId, 'paused');

    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'campaign.paused',
      resourceType: 'campaign',
      resourceId: campaign.id,
      metadata: { name: campaignName },
    });

    return c.json({
      data: updated,
      message: `Campaign "${campaignName}" paused`,
    });
  });

  // GET /:name/stats — Get campaign performance stats
  router.get('/:name/stats', requireScopes('messages:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const campaignName = decodeURIComponent(c.req.param('name'));

    const campaign = await messagesRepo.findCampaignByName(campaignName, tenantId);
    if (!campaign) {
      throw ApiError.notFound('Campaign');
    }

    const stats = await messagesRepo.getCampaignStats(campaign.id, tenantId);

    return c.json({
      data: {
        campaign: { id: campaign.id, name: campaignName, status: campaign.status },
        stats,
      },
    });
  });

  // DELETE /:name — Delete a draft/stopped campaign
  router.delete('/:name', requireScopes('messages:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const campaignName = decodeURIComponent(c.req.param('name'));

    const campaign = await messagesRepo.findCampaignByName(campaignName, tenantId);
    if (!campaign) {
      throw ApiError.notFound('Campaign');
    }

    if (campaign.status === 'sending') {
      throw ApiError.badRequest('Cannot delete a sending campaign. Stop it first.', 'INVALID_STATE');
    }

    await messagesRepo.deleteCampaign(campaign.id, tenantId);

    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'campaign.deleted',
      resourceType: 'campaign',
      resourceId: campaign.id,
      metadata: { name: campaignName },
    });

    return c.json({ message: `Campaign "${campaignName}" deleted` });
  });

  return router;
}
