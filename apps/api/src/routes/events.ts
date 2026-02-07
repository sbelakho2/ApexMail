/**
 * Events Routes - Email event tracking and querying
 *
 * F-213: Response envelope standard — see messages.ts header for full spec.
 * List: { events: T[], pagination: { total, limit, offset, hasMore } }
 * By message: { messageId, events: T[], timeline: T[] }
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv, AppContext } from '../app.js';
import { EventsRepository, type Event } from '@apexmail/db';
import { ApiError } from '../middleware/error-handler.js';
import { requireScopes } from '../middleware/auth.js';

const eventTypeSchema = z.enum([
  'queued',
  'sending',
  'sent',
  'delivered',
  'bounced',
  'deferred',
  'dropped',
  'opened',
  'clicked',
  'unsubscribed',
  'complained',
  'list_unsubscribe',
]);

const batchEventsSchema = z.object({
  events: z.array(z.object({
    messageId: z.string().uuid(),
    eventType: eventTypeSchema,
    timestamp: z.string().datetime().optional(),
    metadata: z.record(z.unknown()).optional(),
    deduplicationKey: z.string().max(255).optional(),
  })).min(1).max(1000),
});

export function eventsRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const eventsRepo = new EventsRepository(ctx.db);

  // List events
  router.get('/', requireScopes('events:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const messageId = c.req.query('messageId');
    const eventType = c.req.query('type');
    const recipientEmail = c.req.query('recipient');
    const since = c.req.query('since');
    const until = c.req.query('until');
    const limit = parseInt(c.req.query('limit') ?? '100', 10);
    const offset = parseInt(c.req.query('offset') ?? '0', 10);

    // Validate event type if provided
    if (eventType) {
      const parsed = eventTypeSchema.safeParse(eventType);
      if (!parsed.success) {
        throw ApiError.badRequest(`Invalid event type: ${eventType}`);
      }
    }

    const result = await eventsRepo.listByTenant(tenantId, {
      messageId,
      eventType: eventType as z.infer<typeof eventTypeSchema>,
      recipientEmail,
      startDate: since ? new Date(since) : undefined,
      endDate: until ? new Date(until) : undefined,
      limit: Math.min(limit, 1000),
      offset,
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch events');
    }

    return c.json({
      events: result.value.events.map((e) => ({
        id: e.id,
        messageId: e.messageId,
        eventType: e.eventType,
        recipientEmail: e.recipientEmail,
        timestamp: e.timestamp,
        metadata: e.metadata,
        userAgent: e.userAgent,
        ipAddress: e.ipAddress,
        linkUrl: e.linkUrl,
        bounceType: e.bounceType,
        bounceCode: e.bounceCode,
        bounceReason: e.bounceReason,
      })),
      pagination: {
        total: result.value.total,
        limit,
        offset,
        hasMore: offset + result.value.events.length < result.value.total,
      },
    });
  });

  // Get events for a specific message
  router.get('/message/:messageId', requireScopes('events:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const messageId = c.req.param('messageId');

    // SECURITY: Use tenant-scoped query for cross-tenant isolation
    const result = await eventsRepo.findByMessageId(messageId, tenantId);

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch events');
    }

    // If no events found for this tenant, return empty (don't leak that messageId exists)
    if (result.value.length === 0) {
      return c.json({
        messageId,
        events: [],
        timeline: [],
      });
    }

    return c.json({
      messageId,
      events: result.value.map((e) => ({
        id: e.id,
        eventType: e.eventType,
        timestamp: e.timestamp,
        metadata: e.metadata,
        userAgent: e.userAgent,
        ipAddress: e.ipAddress,
        linkUrl: e.linkUrl,
        bounceType: e.bounceType,
        bounceCode: e.bounceCode,
        bounceReason: e.bounceReason,
      })),
      timeline: buildTimeline(result.value),
    });
  });

  // Get event by ID
  router.get('/:id', requireScopes('events:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const eventId = c.req.param('id');

    // Use tenant-scoped query for database-level isolation
    const result = await eventsRepo.findById(eventId, tenantId);

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch event');
    }

    if (!result.value) {
      throw ApiError.notFound('Event');
    }

    const e = result.value;

    return c.json({
      event: {
        id: e.id,
        messageId: e.messageId,
        eventType: e.eventType,
        recipientEmail: e.recipientEmail,
        timestamp: e.timestamp,
        metadata: e.metadata,
        userAgent: e.userAgent,
        ipAddress: e.ipAddress,
        linkUrl: e.linkUrl,
        bounceType: e.bounceType,
        bounceCode: e.bounceCode,
        bounceReason: e.bounceReason,
        rawPayload: e.rawPayload,
        processedAt: e.processedAt,
      },
    });
  });

  // Get event statistics
  router.get('/stats/summary', requireScopes('events:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const campaignId = c.req.query('campaignId');
    const since = c.req.query('since');
    const until = c.req.query('until');

    const result = await eventsRepo.getStats(tenantId, {
      campaignId,
      since: since ? new Date(since) : undefined,
      until: until ? new Date(until) : undefined,
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch stats');
    }

    const stats = result.value;

    // Calculate rates
    const sent = stats.sent ?? 0;
    const delivered = stats.delivered ?? 0;
    const opened = stats.opened ?? 0;
    const clicked = stats.clicked ?? 0;
    const bounced = stats.bounced ?? 0;
    const complained = stats.complained ?? 0;
    const total = sent + bounced;

    return c.json({
      stats: {
        total,
        byType: stats,
        rates: {
          deliveryRate: sent > 0 ? ((delivered / sent) * 100).toFixed(2) + '%' : '0%',
          openRate: delivered > 0 ? ((opened / delivered) * 100).toFixed(2) + '%' : '0%',
          clickRate: opened > 0 ? ((clicked / opened) * 100).toFixed(2) + '%' : '0%',
          bounceRate: sent > 0 ? ((bounced / sent) * 100).toFixed(2) + '%' : '0%',
          complaintRate: delivered > 0 ? ((complained / delivered) * 100).toFixed(4) + '%' : '0%',
        },
      },
      period: {
        since: since ?? 'all-time',
        until: until ?? 'now',
      },
    });
  });

  // Get time series statistics
  router.get('/stats/timeseries', requireScopes('events:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const campaignId = c.req.query('campaignId');
    const interval = c.req.query('interval') ?? 'hour';
    const since = c.req.query('since');
    const until = c.req.query('until');

    if (!['minute', 'hour', 'day', 'week', 'month'].includes(interval)) {
      throw ApiError.badRequest('Invalid interval. Must be: minute, hour, day, week, month');
    }

    const result = await eventsRepo.getTimeSeries(tenantId, {
      campaignId,
      interval: interval as 'minute' | 'hour' | 'day' | 'week' | 'month',
      since: since ? new Date(since) : new Date(Date.now() - 24 * 60 * 60 * 1000),
      until: until ? new Date(until) : new Date(),
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch time series');
    }

    return c.json({
      timeseries: result.value,
      interval,
      period: {
        since: since ?? new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        until: until ?? new Date().toISOString(),
      },
    });
  });

  // Get bounce breakdown
  router.get('/stats/bounces', requireScopes('events:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const domainId = c.req.query('domainId');
    const since = c.req.query('since');
    const until = c.req.query('until');

    const result = await eventsRepo.getBounceBreakdown(tenantId, {
      domainId,
      since: since ? new Date(since) : undefined,
      until: until ? new Date(until) : undefined,
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch bounce breakdown');
    }

    return c.json({
      bounces: result.value,
      period: {
        since: since ?? 'all-time',
        until: until ?? 'now',
      },
    });
  });

  // Get engagement statistics by domain
  router.get('/stats/domains', requireScopes('events:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const since = c.req.query('since');
    const until = c.req.query('until');

    const result = await eventsRepo.getStatsByDomain(tenantId, {
      since: since ? new Date(since) : undefined,
      until: until ? new Date(until) : undefined,
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch domain stats');
    }

    return c.json({
      domains: result.value.map((d) => ({
        domainId: d.domainId,
        domainName: d.domainName,
        stats: {
          sent: d.sent,
          delivered: d.delivered,
          opened: d.opened,
          clicked: d.clicked,
          bounced: d.bounced,
          complained: d.complained,
        },
        rates: {
          deliveryRate: d.sent > 0 ? ((d.delivered / d.sent) * 100).toFixed(2) + '%' : '0%',
          openRate: d.delivered > 0 ? ((d.opened / d.delivered) * 100).toFixed(2) + '%' : '0%',
          bounceRate: d.sent > 0 ? ((d.bounced / d.sent) * 100).toFixed(2) + '%' : '0%',
        },
      })),
      period: {
        since: since ?? 'all-time',
        until: until ?? 'now',
      },
    });
  });

  // Get engagement statistics by campaign
  router.get('/stats/campaigns', requireScopes('events:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const since = c.req.query('since');
    const until = c.req.query('until');
    const limit = parseInt(c.req.query('limit') ?? '50', 10);

    const result = await eventsRepo.getStatsByCampaign(tenantId, {
      since: since ? new Date(since) : undefined,
      until: until ? new Date(until) : undefined,
      limit: Math.min(limit, 100),
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch campaign stats');
    }

    return c.json({
      campaigns: result.value.map((cam) => ({
        campaignId: cam.campaignId,
        stats: {
          sent: cam.sent,
          delivered: cam.delivered,
          opened: cam.opened,
          clicked: cam.clicked,
          bounced: cam.bounced,
          unsubscribed: cam.unsubscribed,
          complained: cam.complained,
        },
        rates: {
          deliveryRate: cam.sent > 0 ? ((cam.delivered / cam.sent) * 100).toFixed(2) + '%' : '0%',
          openRate: cam.delivered > 0 ? ((cam.opened / cam.delivered) * 100).toFixed(2) + '%' : '0%',
          clickRate: cam.opened > 0 ? ((cam.clicked / cam.opened) * 100).toFixed(2) + '%' : '0%',
          unsubscribeRate: cam.delivered > 0 ? ((cam.unsubscribed / cam.delivered) * 100).toFixed(4) + '%' : '0%',
        },
        firstEvent: cam.firstEvent,
        lastEvent: cam.lastEvent,
      })),
      period: {
        since: since ?? 'all-time',
        until: until ?? 'now',
      },
    });
  });

  // Batch create events (for internal use / webhooks)
  router.post('/batch', requireScopes('events:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const logger = c.get('logger');

    const body = await c.req.json();
    const { events } = batchEventsSchema.parse(body);

    const items = events.map((e) => ({
      tenantId,
      messageId: e.messageId,
      recipientEmail: '', // Will be filled from message lookup
      eventType: e.eventType as 'queued' | 'sending' | 'sent' | 'deferred' | 'delivered' | 'bounced' | 'dropped' | 'opened' | 'clicked' | 'unsubscribed' | 'complained' | 'list_unsubscribe',
      timestamp: e.timestamp ? new Date(e.timestamp) : new Date(),
      metadata: e.metadata,
    }));

    const result = await eventsRepo.createBulk(items);

    if (!result.ok) {
      logger.error('Failed to create batch events', { error: result.error });
      throw ApiError.internal('Failed to create events');
    }

    logger.info('Batch events created', {
      created: result.value.created,
      duplicates: result.value.duplicates,
    });

    return c.json({
      result: {
        created: result.value.created,
        duplicates: result.value.duplicates,
        total: events.length,
      },
    }, 201);
  });

  // Get recipient engagement history
  router.get('/recipient/:email', requireScopes('events:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const email = decodeURIComponent(c.req.param('email'));
    const limit = parseInt(c.req.query('limit') ?? '50', 10);
    const offset = parseInt(c.req.query('offset') ?? '0', 10);

    // Validate email format with RFC 5321 max length
    const emailSchema = z.string().email().max(254);
    const parsed = emailSchema.safeParse(email);
    if (!parsed.success) {
      throw ApiError.badRequest('Invalid email format');
    }

    // Use listByTenant with recipientEmail filter instead of getRecipientHistory
    const result = await eventsRepo.listByTenant(tenantId, {
      recipientEmail: email,
      limit: Math.min(limit, 100),
      offset,
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch recipient history');
    }

    // Calculate simple stats from events
    const events = result.value.events;
    const stats = {
      sent: events.filter(e => e.eventType === 'sent').length,
      delivered: events.filter(e => e.eventType === 'delivered').length,
      opened: events.filter(e => e.eventType === 'opened').length,
      clicked: events.filter(e => e.eventType === 'clicked').length,
      bounced: events.filter(e => e.eventType === 'bounced').length,
      complained: events.filter(e => e.eventType === 'complained').length,
    };

    return c.json({
      recipient: maskEmail(email),
      summary: {
        totalEvents: result.value.total,
        stats,
        engagementScore: calculateEngagementScore(stats),
      },
      recentEvents: events.map((e) => ({
        id: e.id,
        messageId: e.messageId,
        eventType: e.eventType,
        timestamp: e.timestamp,
      })),
      pagination: {
        total: result.value.total,
        limit,
        offset,
        hasMore: offset + events.length < result.value.total,
      },
    });
  });

  // Get click tracking details by message ID
  router.get('/clicks/:messageId', requireScopes('events:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const messageId = c.req.param('messageId');

    // SECURITY: Use tenant-scoped query to prevent cross-tenant data leak
    const result = await eventsRepo.getLinkStats(messageId, tenantId);

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch click stats');
    }

    const clicks = result.value;
    const totalClicks = clicks.reduce((sum, c) => sum + c.clicks, 0);
    const uniqueClicks = clicks.reduce((sum, c) => sum + c.uniqueClicks, 0);

    return c.json({
      messageId,
      links: clicks.map((click) => ({
        url: click.linkUrl,
        totalClicks: click.clicks,
        uniqueClicks: click.uniqueClicks,
      })),
      totals: {
        totalClicks,
        uniqueClicks,
        uniqueUrls: clicks.length,
      },
    });
  });

  return router;
}

function buildTimeline(events: Event[]): Array<{
  eventType: string;
  timestamp: Date;
  duration?: number;
}> {
  const sorted = [...events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  return sorted.map((e, i) => {
    const item: { eventType: string; timestamp: Date; duration?: number } = {
      eventType: e.eventType,
      timestamp: e.timestamp,
    };

    if (i > 0) {
      const prev = sorted[i - 1];
      if (prev) {
        item.duration = new Date(e.timestamp).getTime() - new Date(prev.timestamp).getTime();
      }
    }

    return item;
  });
}

function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  if (!local || !domain) return email;

  const maskedLocal = local.length <= 2
    ? local[0] + '*'
    : local[0] + '*'.repeat(Math.min(local.length - 2, 5)) + local[local.length - 1];

  return `${maskedLocal}@${domain}`;
}

interface EngagementStats {
  sent: number;
  delivered: number;
  opened: number;
  clicked: number;
  bounced: number;
  complained: number;
}

function calculateEngagementScore(stats: EngagementStats): number {
  // Engagement score from 0-100
  // Factors: open rate, click rate, bounce rate (negative), complaint rate (negative)
  
  if (stats.sent === 0) return 0;

  const deliveryRate = stats.delivered / stats.sent;
  const openRate = stats.delivered > 0 ? stats.opened / stats.delivered : 0;
  const clickRate = stats.opened > 0 ? stats.clicked / stats.opened : 0;
  const bounceRate = stats.bounced / stats.sent;
  const complaintRate = stats.delivered > 0 ? stats.complained / stats.delivered : 0;

  // Weighted score
  const score = (
    deliveryRate * 20 +
    openRate * 40 +
    clickRate * 30 +
    (1 - bounceRate) * 5 +
    (1 - complaintRate * 100) * 5
  );

  return Math.max(0, Math.min(100, Math.round(score)));
}
