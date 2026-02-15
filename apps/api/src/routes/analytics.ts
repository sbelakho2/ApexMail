/**
 * Analytics Routes - Reporting and statistics endpoints
 *
 * Uses Redis cache-aside to avoid repeatedly hitting PostgreSQL for
 * expensive aggregation queries. Each endpoint caches its JSON response
 * per tenant with a short TTL (30-60 s). Cache misses fall through to the
 * database transparently.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv, AppContext } from '../app.js';
import { EventsRepository, MessagesRepository, DomainsRepository, SuppressionsRepository } from '@apexmail/db';
import { ApiError } from '../middleware/error-handler.js';
import { requireScopes } from '../middleware/auth.js';
import { createHash } from 'crypto';

const intervalSchema = z.enum(['minute', 'hour', 'day', 'week', 'month']);

/** C-127: Maximum allowed date range for analytics queries (90 days). */
const MAX_DATE_RANGE_MS = 90 * 24 * 60 * 60 * 1000;

/**
 * C-127: Validate and parse analytics date range parameters.
 *
 * Ensures:
 *  1. Both dates are valid ISO-8601 strings (if provided)
 *  2. `since` is before `until`
 *  3. The range does not exceed 90 days
 *  4. `until` is not in the future (clamped to now)
 *
 * Returns a safe { since, until } period, falling back to sensible
 * defaults when parameters are omitted.
 */
function validateDateRange(
  sinceParam: string | undefined,
  untilParam: string | undefined,
  defaultSince: Date = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
): { since: Date; until: Date } {
  const now = new Date();

  let since = defaultSince;
  let until = now;

  if (sinceParam) {
    since = new Date(sinceParam);
    if (isNaN(since.getTime())) {
      throw ApiError.badRequest('Invalid "since" date. Provide a valid ISO-8601 date string.');
    }
  }

  if (untilParam) {
    until = new Date(untilParam);
    if (isNaN(until.getTime())) {
      throw ApiError.badRequest('Invalid "until" date. Provide a valid ISO-8601 date string.');
    }
  }

  // Clamp "until" to now — future dates are not meaningful for analytics
  if (until > now) {
    until = now;
  }

  // Ensure start is before end
  if (since >= until) {
    throw ApiError.badRequest('"since" must be before "until".');
  }

  // Enforce maximum range
  if (until.getTime() - since.getTime() > MAX_DATE_RANGE_MS) {
    throw ApiError.badRequest(
      `Date range must not exceed 90 days. Requested range: ${Math.ceil((until.getTime() - since.getTime()) / (24 * 60 * 60 * 1000))} days.`
    );
  }

  return { since, until };
}

/** Short hash of query params to partition cache per unique request. */
function cacheKey(tenantId: string, endpoint: string, params: Record<string, string | undefined>): string {
  const sorted = Object.entries(params)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('&');
  const hash = createHash('sha256').update(sorted).digest('hex').slice(0, 12);
  return `cache:analytics:${tenantId}:${endpoint}:${hash}`;
}

export function analyticsRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const redis = ctx.redis;
  const eventsRepo = new EventsRepository(ctx.db);
  const messagesRepo = new MessagesRepository(ctx.db);
  const domainsRepo = new DomainsRepository(ctx.db);
  const suppressionsRepo = new SuppressionsRepository(ctx.db);

  /**
   * IMP-009: Cache-aside helper with singleflight / thundering-herd protection.
   *
   * On a cache miss, only the *first* concurrent caller runs `compute()`.
   * All subsequent callers for the same key await the same in-flight promise
   * instead of each hitting the database independently. Once the promise
   * resolves, the result is cached normally and the in-flight entry is cleaned up.
   *
   * Also fixes TTL selection: historical data that doesn't change should use
   * longer TTLs (300-600 s) while real-time dashboards stay short (30 s).
   *
   * Degrades gracefully: if Redis is down, falls through to DB every time.
   */
  // FIX-500-441: Track creation time for each inflight entry so we can
  // periodically clean up entries that hang forever (e.g., DB connection dropped).
  const inflight = new Map<string, { promise: Promise<unknown>; createdAt: number }>();
  const INFLIGHT_MAX_AGE_MS = 120_000; // 2 minutes
  const inflightCleanup = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of inflight) {
      if (now - entry.createdAt > INFLIGHT_MAX_AGE_MS) {
        inflight.delete(key);
      }
    }
  }, 60_000);
  inflightCleanup.unref();

  async function cached<T>(key: string, ttlSeconds: number, compute: () => Promise<T>): Promise<T> {
    // Try reading from cache
    try {
      const hit = await redis.get(key);
      if (hit) return JSON.parse(hit) as T;
    } catch {
      // Redis error — fall through to DB
    }

    // Singleflight: if another request is already computing this key, reuse its result
    const existing = inflight.get(key);
    if (existing) return existing.promise as Promise<T>;

    const promise = (async () => {
      const value = await compute();
      // Write-behind: don’t block the response on cache write
      redis.setex(key, ttlSeconds, JSON.stringify(value)).catch(() => {});
      return value;
    })();

    inflight.set(key, { promise, createdAt: Date.now() });
    try {
      return await promise;
    } finally {
      inflight.delete(key);
    }
  }

  // Dashboard overview
  router.get('/dashboard', requireScopes('analytics:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const since = c.req.query('since');
    const until = c.req.query('until');

    // C-127: Validate and clamp date range
    const period = validateDateRange(since, until);

    const key = cacheKey(tenantId, 'dashboard', { since: period.since.toISOString(), until: period.until.toISOString() });

    const dashboard = await cached(key, 30, async () => {
      // Fetch all stats in parallel
      const [
        eventStatsResult,
        messageStatsResult,
        domainStatsResult,
        suppressionStatsResult,
      ] = await Promise.all([
        eventsRepo.getStats(tenantId, period),
        messagesRepo.getStats(tenantId, period),
        domainsRepo.getStats(tenantId),
        suppressionsRepo.getStats(tenantId, period),
      ]);

      if (!eventStatsResult.ok || !messageStatsResult.ok || !domainStatsResult.ok || !suppressionStatsResult.ok) {
        throw ApiError.internal('Failed to fetch dashboard stats');
      }

      const eventStats = eventStatsResult.value;
      const messageStats = messageStatsResult.value;
      const domainStats = domainStatsResult.value;
      const suppressionStats = suppressionStatsResult.value;

      // Calculate rates
      const sent = eventStats.sent ?? 0;
      const delivered = eventStats.delivered ?? 0;
      const opened = eventStats.opened ?? 0;
      const clicked = eventStats.clicked ?? 0;
      const bounced = eventStats.bounced ?? 0;
      const complained = eventStats.complained ?? 0;

      return {
        period: {
          since: period.since.toISOString(),
          until: period.until.toISOString(),
        },
        messages: {
          total: messageStats.total,
          queued: messageStats.queued,
          sent: messageStats.sent,
          delivered: messageStats.delivered,
          failed: messageStats.failed,
        },
        engagement: {
          sent,
          delivered,
          opened,
          clicked,
          bounced,
          complained,
          rates: {
            delivery: sent > 0 ? ((delivered / sent) * 100).toFixed(2) : '0.00',
            open: delivered > 0 ? ((opened / delivered) * 100).toFixed(2) : '0.00',
            click: opened > 0 ? ((clicked / opened) * 100).toFixed(2) : '0.00',
            bounce: sent > 0 ? ((bounced / sent) * 100).toFixed(2) : '0.00',
            complaint: delivered > 0 ? ((complained / delivered) * 100).toFixed(4) : '0.0000',
          },
        },
        domains: {
          total: domainStats.total,
          verified: domainStats.verified,
          pending: domainStats.pending,
          failed: domainStats.failed,
        },
        suppressions: {
          total: suppressionStats.total,
          bounces: suppressionStats.bounces,
          complaints: suppressionStats.complaints,
          unsubscribes: suppressionStats.unsubscribes,
          manual: suppressionStats.manual,
        },
        health: calculateHealthScore({
          deliveryRate: sent > 0 ? delivered / sent : 1,
          bounceRate: sent > 0 ? bounced / sent : 0,
          complaintRate: delivered > 0 ? complained / delivered : 0,
        }),
      };
    });

    return c.json({ dashboard });
  });

  // Sending volume over time
  router.get('/volume', requireScopes('analytics:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const interval = (c.req.query('interval') ?? 'day') as z.infer<typeof intervalSchema>;
    const since = c.req.query('since');
    const until = c.req.query('until');
    const domainId = c.req.query('domainId');

    // Validate interval
    const parsed = intervalSchema.safeParse(interval);
    if (!parsed.success) {
      throw ApiError.badRequest('Invalid interval. Must be: minute, hour, day, week, month');
    }

    // C-127: Validate and clamp date range
    const period = validateDateRange(since, until, getDefaultSince(interval));

    const key = cacheKey(tenantId, 'volume', { interval, since: period.since.toISOString(), until: period.until.toISOString(), domainId });

    const body = await cached(key, 30, async () => {
      const result = await messagesRepo.getVolumeTimeSeries(tenantId, {
        ...period,
        interval,
        domainId,
      });

      if (!result.ok) {
        throw ApiError.internal('Failed to fetch volume data');
      }

      return {
        volume: result.value.map((point) => ({
          timestamp: point.timestamp,
          sent: point.sent,
          delivered: point.delivered,
          bounced: point.bounced,
          failed: point.failed,
        })),
        interval,
        period: {
          since: period.since.toISOString(),
          until: period.until.toISOString(),
        },
      };
    });

    return c.json(body);
  });

  // Engagement metrics over time
  router.get('/engagement', requireScopes('analytics:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const interval = (c.req.query('interval') ?? 'day') as z.infer<typeof intervalSchema>;
    const since = c.req.query('since');
    const until = c.req.query('until');
    const domainId = c.req.query('domainId');
    const campaignId = c.req.query('campaignId');

    const parsed = intervalSchema.safeParse(interval);
    if (!parsed.success) {
      throw ApiError.badRequest('Invalid interval');
    }

    // C-127: Validate and clamp date range
    const period = validateDateRange(since, until, getDefaultSince(interval));

    const key = cacheKey(tenantId, 'engagement', { interval, since: period.since.toISOString(), until: period.until.toISOString(), domainId, campaignId });

    const body = await cached(key, 30, async () => {
      const result = await eventsRepo.getTimeSeries(tenantId, {
        ...period,
        interval,
        domainId,
        campaignId,
      });

      if (!result.ok) {
        throw ApiError.internal('Failed to fetch engagement data');
      }

      return {
        engagement: result.value.map((point) => ({
          timestamp: point.timestamp,
          delivered: point.delivered ?? 0,
          opened: point.opened ?? 0,
          clicked: point.clicked ?? 0,
          unsubscribed: point.unsubscribed ?? 0,
          complained: point.complained ?? 0,
          rates: {
            open: point.delivered ? ((point.opened ?? 0) / point.delivered * 100).toFixed(2) : '0.00',
            click: point.opened ? ((point.clicked ?? 0) / point.opened * 100).toFixed(2) : '0.00',
          },
        })),
        interval,
        period: {
          since: period.since.toISOString(),
          until: period.until.toISOString(),
        },
      };
    });

    return c.json(body);
  });

  // Domain performance comparison
  router.get('/domains', requireScopes('analytics:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const since = c.req.query('since');
    const until = c.req.query('until');
    const sortBy = c.req.query('sortBy') ?? 'sent';
    const limit = Math.max(1, Math.min(parseInt(c.req.query('limit') ?? '10', 10) || 10, 50));

    // F-208: Validate sort field against whitelist
    const validDomainSorts = ['sent', 'delivered', 'openRate', 'bounceRate'] as const;
    if (!validDomainSorts.includes(sortBy as any)) {
      throw ApiError.badRequest(`Invalid sortBy. Must be one of: ${validDomainSorts.join(', ')}`);
    }

    // C-127: Validate and clamp date range
    const period = validateDateRange(since, until);

    const key = cacheKey(tenantId, 'domains', { since: period.since.toISOString(), until: period.until.toISOString(), sortBy, limit: String(limit) });

    const body = await cached(key, 60, async () => {
      const result = await eventsRepo.getStatsByDomain(tenantId, period);

      if (!result.ok) {
        throw ApiError.internal('Failed to fetch domain stats');
      }

      // Sort and limit
      let domains = result.value;
      if (sortBy === 'sent') {
        domains.sort((a, b) => b.sent - a.sent);
      } else if (sortBy === 'delivered') {
        domains.sort((a, b) => b.delivered - a.delivered);
      } else if (sortBy === 'openRate') {
        domains.sort((a, b) => {
          const rateA = a.delivered > 0 ? a.opened / a.delivered : 0;
          const rateB = b.delivered > 0 ? b.opened / b.delivered : 0;
          return rateB - rateA;
        });
      } else if (sortBy === 'bounceRate') {
        domains.sort((a, b) => {
          const rateA = a.sent > 0 ? a.bounced / a.sent : 0;
          const rateB = b.sent > 0 ? b.bounced / b.sent : 0;
          return rateB - rateA;
        });
      }

      domains = domains.slice(0, Math.min(limit, 50));

      return {
        domains: domains.map((d) => ({
          domainId: d.domainId,
          domainName: d.domainName,
          metrics: {
            sent: d.sent,
            delivered: d.delivered,
            opened: d.opened,
            clicked: d.clicked,
            bounced: d.bounced,
            complained: d.complained,
          },
          rates: {
            delivery: d.sent > 0 ? ((d.delivered / d.sent) * 100).toFixed(2) : '0.00',
            open: d.delivered > 0 ? ((d.opened / d.delivered) * 100).toFixed(2) : '0.00',
            click: d.opened > 0 ? ((d.clicked / d.opened) * 100).toFixed(2) : '0.00',
            bounce: d.sent > 0 ? ((d.bounced / d.sent) * 100).toFixed(2) : '0.00',
            complaint: d.delivered > 0 ? ((d.complained / d.delivered) * 100).toFixed(4) : '0.0000',
          },
          health: calculateDomainHealth(d),
        })),
        period: {
          since: period.since.toISOString(),
          until: period.until.toISOString(),
        },
        sortBy,
      };
    });

    return c.json(body);
  });

  // Campaign performance
  router.get('/campaigns', requireScopes('analytics:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const since = c.req.query('since');
    const until = c.req.query('until');
    const sortBy = c.req.query('sortBy') ?? 'sent';
    const limit = Math.max(1, Math.min(parseInt(c.req.query('limit') ?? '20', 10) || 20, 100));

    // F-208: Validate sort field against whitelist
    const validCampaignSorts = ['sent', 'openRate', 'clickRate', 'bounceRate'] as const;
    if (!validCampaignSorts.includes(sortBy as any)) {
      throw ApiError.badRequest(`Invalid sortBy. Must be one of: ${validCampaignSorts.join(', ')}`);
    }

    // C-127: Validate and clamp date range
    const period = validateDateRange(since, until);

    // IMP-009: Cache campaign stats (previously uncached — every request hit DB)
    const key = cacheKey(tenantId, 'campaigns', { since: period.since.toISOString(), until: period.until.toISOString(), sortBy, limit: String(limit) });

    const body = await cached(key, 120, async () => {
    const result = await eventsRepo.getStatsByCampaign(tenantId, {
      ...period,
      limit: Math.min(limit, 100),
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch campaign stats');
    }

    const campaigns = result.value;

    // Sort
    if (sortBy === 'openRate') {
      campaigns.sort((a, b) => {
        const rateA = a.delivered > 0 ? a.opened / a.delivered : 0;
        const rateB = b.delivered > 0 ? b.opened / b.delivered : 0;
        return rateB - rateA;
      });
    } else if (sortBy === 'clickRate') {
      campaigns.sort((a, b) => {
        const rateA = a.opened > 0 ? a.clicked / a.opened : 0;
        const rateB = b.opened > 0 ? b.clicked / b.opened : 0;
        return rateB - rateA;
      });
    }

    return {
      campaigns: campaigns.map((cam) => ({
        campaignId: cam.campaignId,
        metrics: {
          sent: cam.sent,
          delivered: cam.delivered,
          opened: cam.opened,
          clicked: cam.clicked,
          bounced: cam.bounced,
          unsubscribed: cam.unsubscribed,
          complained: cam.complained,
        },
        rates: {
          delivery: cam.sent > 0 ? ((cam.delivered / cam.sent) * 100).toFixed(2) : '0.00',
          open: cam.delivered > 0 ? ((cam.opened / cam.delivered) * 100).toFixed(2) : '0.00',
          click: cam.opened > 0 ? ((cam.clicked / cam.opened) * 100).toFixed(2) : '0.00',
          clickToOpen: cam.delivered > 0 ? ((cam.clicked / cam.delivered) * 100).toFixed(2) : '0.00',
          bounce: cam.sent > 0 ? ((cam.bounced / cam.sent) * 100).toFixed(2) : '0.00',
          unsubscribe: cam.delivered > 0 ? ((cam.unsubscribed / cam.delivered) * 100).toFixed(4) : '0.0000',
        },
        timeline: {
          firstEvent: cam.firstEvent,
          lastEvent: cam.lastEvent,
        },
      })),
      period: {
        since: period.since.toISOString(),
        until: period.until.toISOString(),
      },
      sortBy,
    };
    });

    return c.json(body);
  });

  // Bounce analysis
  router.get('/bounces', requireScopes('analytics:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const since = c.req.query('since');
    const until = c.req.query('until');
    const domainId = c.req.query('domainId');

    // C-127: Validate and clamp date range
    const period = validateDateRange(since, until);

    // IMP-009: Cache bounce analysis (previously uncached)
    const key = cacheKey(tenantId, 'bounces', { since: period.since.toISOString(), until: period.until.toISOString(), domainId });

    const body = await cached(key, 120, async () => {
    const result = await eventsRepo.getBounceBreakdown(tenantId, {
      ...period,
      domainId,
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch bounce data');
    }

    const bounces = result.value;

    // Calculate totals
    const totalBounces = bounces.reduce((sum, b) => sum + b.count, 0);
    const hardBounces = bounces.filter(b => b.bounceType === 'hard').reduce((sum, b) => sum + b.count, 0);
    const softBounces = bounces.filter(b => b.bounceType === 'soft').reduce((sum, b) => sum + b.count, 0);

    return {
      bounces: {
        total: totalBounces,
        hard: hardBounces,
        soft: softBounces,
        undetermined: totalBounces - hardBounces - softBounces,
        breakdown: bounces.map((b) => ({
          bounceType: b.bounceType,
          bounceSubtype: b.bounceSubtype,
          count: b.count,
          percentage: totalBounces > 0 ? ((b.count / totalBounces) * 100).toFixed(2) : '0.00',
        })),
        recommendations: generateBounceRecommendations(bounces, totalBounces),
      },
      period: {
        since: period.since.toISOString(),
        until: period.until.toISOString(),
      },
    };
    });

    return c.json(body);
  });

  // Suppression trends
  router.get('/suppressions', requireScopes('analytics:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const interval = (c.req.query('interval') ?? 'day') as z.infer<typeof intervalSchema>;
    const since = c.req.query('since');
    const until = c.req.query('until');

    const parsed = intervalSchema.safeParse(interval);
    if (!parsed.success) {
      throw ApiError.badRequest('Invalid interval');
    }

    // C-127: Validate and clamp date range
    const period = validateDateRange(since, until, getDefaultSince(interval));

    // IMP-009: Cache suppression trends (previously uncached)
    const key = cacheKey(tenantId, 'suppressions', { interval, since: period.since.toISOString(), until: period.until.toISOString() });

    const body = await cached(key, 120, async () => {
    const result = await suppressionsRepo.getTimeSeries(tenantId, {
      ...period,
      interval,
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch suppression trends');
    }

    return {
      suppressions: result.value.map((point) => ({
        timestamp: point.timestamp,
        total: point.total,
        bounces: point.bounces,
        complaints: point.complaints,
        unsubscribes: point.unsubscribes,
        manual: point.manual,
      })),
      interval,
      period: {
        since: period.since.toISOString(),
        until: period.until.toISOString(),
      },
    };
    });

    return c.json(body);
  });

  // Deliverability report
  router.get('/deliverability', requireScopes('analytics:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const since = c.req.query('since');
    const until = c.req.query('until');

    // C-127: Validate and clamp date range
    const period = validateDateRange(since, until);

    const key = cacheKey(tenantId, 'deliverability', { since: period.since.toISOString(), until: period.until.toISOString() });

    // IMP-009: Historical deliverability data changes slowly — use longer TTL (300s)
    const body = await cached(key, 300, async () => {
      // Fetch data in parallel
      const [eventStats, bounceBreakdown, domainStats] = await Promise.all([
        eventsRepo.getStats(tenantId, period),
        eventsRepo.getBounceBreakdown(tenantId, period),
        eventsRepo.getStatsByDomain(tenantId, period),
      ]);

      if (!eventStats.ok || !bounceBreakdown.ok || !domainStats.ok) {
        throw ApiError.internal('Failed to fetch deliverability data');
      }

      const stats = eventStats.value;
      const bounces = bounceBreakdown.value;
      const domains = domainStats.value;

      const sent = stats.sent ?? 0;
      const delivered = stats.delivered ?? 0;
      const bounced = stats.bounced ?? 0;
      const complained = stats.complained ?? 0;

      // Calculate ISP breakdown from bounce data
      const ispBreakdown = analyzeISPPerformance(bounces);

      return {
        deliverability: {
          overview: {
            sent,
            delivered,
            bounced,
            complained,
            deliveryRate: sent > 0 ? ((delivered / sent) * 100).toFixed(2) : '0.00',
            bounceRate: sent > 0 ? ((bounced / sent) * 100).toFixed(2) : '0.00',
            complaintRate: delivered > 0 ? ((complained / delivered) * 100).toFixed(4) : '0.0000',
          },
          bounceAnalysis: {
            hard: bounces.filter(b => b.bounceType === 'hard').reduce((s, b) => s + b.count, 0),
            soft: bounces.filter(b => b.bounceType === 'soft').reduce((s, b) => s + b.count, 0),
            topReasons: bounces
              .sort((a, b) => b.count - a.count)
              .slice(0, 5)
              .map(b => ({
                type: b.bounceType,
                subtype: b.bounceSubtype,
                count: b.count,
              })),
          },
          domainPerformance: domains.slice(0, 5).map(d => ({
            domain: d.domainName,
            deliveryRate: d.sent > 0 ? ((d.delivered / d.sent) * 100).toFixed(2) : '0.00',
            bounceRate: d.sent > 0 ? ((d.bounced / d.sent) * 100).toFixed(2) : '0.00',
          })),
          ispBreakdown,
          score: calculateDeliverabilityScore({
            deliveryRate: sent > 0 ? delivered / sent : 1,
            bounceRate: sent > 0 ? bounced / sent : 0,
            complaintRate: delivered > 0 ? complained / delivered : 0,
            hardBounceRate: sent > 0 ? bounces.filter(b => b.bounceType === 'hard').reduce((s, b) => s + b.count, 0) / sent : 0,
          }),
          recommendations: generateDeliverabilityRecommendations({
            deliveryRate: sent > 0 ? delivered / sent : 1,
            bounceRate: sent > 0 ? bounced / sent : 0,
            complaintRate: delivered > 0 ? complained / delivered : 0,
            hardBounceRatio: bounced > 0 ? bounces.filter(b => b.bounceType === 'hard').reduce((s, b) => s + b.count, 0) / bounced : 0,
          }),
        },
        period: {
          since: period.since.toISOString(),
          until: period.until.toISOString(),
        },
      };
    });

    return c.json(body);
  });

  // Export report
  router.get('/export', requireScopes('analytics:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const format = c.req.query('format') ?? 'json';
    const reportType = c.req.query('type') ?? 'summary';
    const since = c.req.query('since');
    const until = c.req.query('until');

    if (!['json', 'csv'].includes(format)) {
      throw ApiError.badRequest('Format must be json or csv');
    }

    // C-127: Validate and clamp date range
    const period = validateDateRange(since, until);

    let data: unknown;

    switch (reportType) {
      case 'summary': {
        const [eventStats, messageStats] = await Promise.all([
          eventsRepo.getStats(tenantId, period),
          messagesRepo.getStats(tenantId, period),
        ]);
        
        if (!eventStats.ok || !messageStats.ok) {
          throw ApiError.internal('Failed to generate report');
        }

        data = {
          reportType: 'summary',
          period,
          events: eventStats.value,
          messages: messageStats.value,
          generatedAt: new Date().toISOString(),
        };
        break;
      }

      case 'campaigns': {
        const result = await eventsRepo.getStatsByCampaign(tenantId, { ...period, limit: 1000 });
        if (!result.ok) {
          throw ApiError.internal('Failed to generate report');
        }
        data = {
          reportType: 'campaigns',
          period,
          campaigns: result.value,
          generatedAt: new Date().toISOString(),
        };
        break;
      }

      case 'domains': {
        const result = await eventsRepo.getStatsByDomain(tenantId, period);
        if (!result.ok) {
          throw ApiError.internal('Failed to generate report');
        }
        data = {
          reportType: 'domains',
          period,
          domains: result.value,
          generatedAt: new Date().toISOString(),
        };
        break;
      }

      default:
        throw ApiError.badRequest('Invalid report type. Must be: summary, campaigns, domains');
    }

    if (format === 'csv') {
      // FIX-500-488: For large datasets, consider replacing this in-memory
      // CSV build with a streaming approach (ReadableStream + TransformStream)
      // to avoid large memory allocation. Current approach is acceptable for
      // typical report sizes but won't scale to millions of rows.
      const csv = convertReportToCSV(data as ReportData);
      c.header('Content-Type', 'text/csv');
      c.header('Content-Disposition', `attachment; filename="apexmail-${reportType}-${Date.now()}.csv"`);
      return c.body(csv);
    }

    return c.json(data);
  });

  return router;
}

// Helper functions

function getDefaultSince(interval: string): Date {
  const now = Date.now();
  switch (interval) {
    case 'minute':
      return new Date(now - 60 * 60 * 1000); // 1 hour
    case 'hour':
      return new Date(now - 24 * 60 * 60 * 1000); // 24 hours
    case 'day':
      return new Date(now - 30 * 24 * 60 * 60 * 1000); // 30 days
    case 'week':
      return new Date(now - 12 * 7 * 24 * 60 * 60 * 1000); // 12 weeks
    case 'month':
      return new Date(now - 12 * 30 * 24 * 60 * 60 * 1000); // 12 months
    default:
      return new Date(now - 30 * 24 * 60 * 60 * 1000);
  }
}

interface HealthScoreInput {
  deliveryRate: number;
  bounceRate: number;
  complaintRate: number;
}

function calculateHealthScore(input: HealthScoreInput): {
  score: number;
  grade: string;
  status: 'excellent' | 'good' | 'fair' | 'poor' | 'critical';
} {
  // Weighted score calculation
  const deliveryScore = Math.min(input.deliveryRate * 40, 40);
  const bounceScore = Math.max(0, 30 - input.bounceRate * 300);
  const complaintScore = Math.max(0, 30 - input.complaintRate * 3000);

  const score = Math.round(deliveryScore + bounceScore + complaintScore);

  let grade: string;
  let status: 'excellent' | 'good' | 'fair' | 'poor' | 'critical';

  if (score >= 90) {
    grade = 'A';
    status = 'excellent';
  } else if (score >= 80) {
    grade = 'B';
    status = 'good';
  } else if (score >= 70) {
    grade = 'C';
    status = 'fair';
  } else if (score >= 60) {
    grade = 'D';
    status = 'poor';
  } else {
    grade = 'F';
    status = 'critical';
  }

  return { score, grade, status };
}

interface DomainMetrics {
  sent: number;
  delivered: number;
  bounced: number;
  complained: number;
}

function calculateDomainHealth(metrics: DomainMetrics): {
  score: number;
  status: 'healthy' | 'warning' | 'critical';
} {
  if (metrics.sent === 0) {
    return { score: 100, status: 'healthy' };
  }

  const deliveryRate = metrics.delivered / metrics.sent;
  const bounceRate = metrics.bounced / metrics.sent;
  const complaintRate = metrics.delivered > 0 ? metrics.complained / metrics.delivered : 0;

  let score = 100;
  
  // Penalize for poor delivery rate
  if (deliveryRate < 0.95) score -= (0.95 - deliveryRate) * 100;
  
  // Penalize for bounces
  score -= bounceRate * 200;
  
  // Heavy penalty for complaints
  score -= complaintRate * 10000;

  score = Math.max(0, Math.min(100, Math.round(score)));

  let status: 'healthy' | 'warning' | 'critical';
  if (score >= 80) {
    status = 'healthy';
  } else if (score >= 60) {
    status = 'warning';
  } else {
    status = 'critical';
  }

  return { score, status };
}

interface BounceItem {
  bounceType: string;
  bounceSubtype: string;
  count: number;
}

function generateBounceRecommendations(bounces: BounceItem[], total: number): string[] {
  const recommendations: string[] = [];

  const hardBounces = bounces.filter(b => b.bounceType === 'hard').reduce((s, b) => s + b.count, 0);
  const softBounces = bounces.filter(b => b.bounceType === 'soft').reduce((s, b) => s + b.count, 0);

  if (total > 0) {
    const hardRate = hardBounces / total;
    const softRate = softBounces / total;

    if (hardRate > 0.05) {
      recommendations.push('High hard bounce rate detected. Clean your email list by removing invalid addresses.');
    }

    if (softRate > 0.10) {
      recommendations.push('High soft bounce rate. Consider implementing retry logic and monitoring recipient mailbox status.');
    }

    // Check for specific bounce subtypes
    const noMailbox = bounces.find(b => b.bounceSubtype === 'no-mailbox');
    if (noMailbox && noMailbox.count / total > 0.03) {
      recommendations.push('Many "mailbox not found" bounces. Implement email verification at signup.');
    }

    const overQuota = bounces.find(b => b.bounceSubtype === 'over-quota');
    if (overQuota && overQuota.count / total > 0.02) {
      recommendations.push('Recipients with full mailboxes. Consider segmenting inactive users.');
    }
  }

  if (recommendations.length === 0) {
    recommendations.push('Bounce rates are within acceptable limits. Continue monitoring.');
  }

  return recommendations;
}

function analyzeISPPerformance(bounces: BounceItem[]): Array<{
  isp: string;
  bounces: number;
  topIssue: string;
}> {
  // Group by common ISP patterns from bounce subtypes/messages
  const ispPatterns: Record<string, { bounces: number; issues: Record<string, number> }> = {
    gmail: { bounces: 0, issues: {} },
    outlook: { bounces: 0, issues: {} },
    yahoo: { bounces: 0, issues: {} },
    other: { bounces: 0, issues: {} },
  };

  // ISP detection patterns in bounce messages/subtypes
  const ispDetectionPatterns = {
    gmail: ['gmail', 'google', 'googlemail'],
    outlook: ['outlook', 'hotmail', 'live.com', 'msn.com', 'microsoft'],
    yahoo: ['yahoo', 'ymail', 'aol'],
  };

  // Analyze each bounce item
  for (const bounce of bounces) {
    const bounceText = `${bounce.bounceType} ${bounce.bounceSubtype}`.toLowerCase();
    
    // Try to detect ISP from bounce subtype
    let detectedISP = 'other';
    for (const [isp, patterns] of Object.entries(ispDetectionPatterns)) {
      if (patterns.some(pattern => bounceText.includes(pattern))) {
        detectedISP = isp;
        break;
      }
    }
    
    // Get or create ISP record
    const ispRecord = ispPatterns[detectedISP];
    if (ispRecord) {
      ispRecord.bounces += bounce.count;
      
      // Track issue types
      const issue = bounce.bounceSubtype || bounce.bounceType;
      ispRecord.issues[issue] = (ispRecord.issues[issue] ?? 0) + bounce.count;
    }
  }

  // Convert to output format, filtering out ISPs with no bounces
  return Object.entries(ispPatterns)
    .filter(([, data]) => data.bounces > 0)
    .map(([isp, data]) => {
      // Find the top issue for this ISP
      const issueEntries = Object.entries(data.issues);
      const topIssue = issueEntries.length > 0
        ? issueEntries.sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'unknown'
        : 'unknown';
      
      return {
        isp,
        bounces: data.bounces,
        topIssue,
      };
    })
    .sort((a, b) => b.bounces - a.bounces);
}

interface DeliverabilityScoreInput {
  deliveryRate: number;
  bounceRate: number;
  complaintRate: number;
  hardBounceRate: number;
}

function calculateDeliverabilityScore(input: DeliverabilityScoreInput): {
  score: number;
  rating: 'excellent' | 'good' | 'average' | 'poor' | 'critical';
} {
  let score = 100;

  // Delivery rate (max 40 points)
  score -= (1 - input.deliveryRate) * 40;

  // Bounce rate (max 25 points)
  score -= input.bounceRate * 250;

  // Hard bounce rate (max 20 points)
  score -= input.hardBounceRate * 400;

  // Complaint rate (max 15 points)
  score -= input.complaintRate * 1500;

  score = Math.max(0, Math.min(100, Math.round(score)));

  let rating: 'excellent' | 'good' | 'average' | 'poor' | 'critical';
  if (score >= 90) rating = 'excellent';
  else if (score >= 75) rating = 'good';
  else if (score >= 60) rating = 'average';
  else if (score >= 40) rating = 'poor';
  else rating = 'critical';

  return { score, rating };
}

interface DeliverabilityInput {
  deliveryRate: number;
  bounceRate: number;
  complaintRate: number;
  hardBounceRatio: number;
}

function generateDeliverabilityRecommendations(input: DeliverabilityInput): string[] {
  const recommendations: string[] = [];

  if (input.deliveryRate < 0.95) {
    recommendations.push('Delivery rate below 95%. Review DNS configuration and sender reputation.');
  }

  if (input.bounceRate > 0.05) {
    recommendations.push('Bounce rate exceeds 5%. Implement list hygiene practices.');
  }

  if (input.complaintRate > 0.001) {
    recommendations.push('Complaint rate above 0.1%. Review opt-in processes and email frequency.');
  }

  if (input.hardBounceRatio > 0.5) {
    recommendations.push('High proportion of hard bounces. Validate email addresses before sending.');
  }

  if (recommendations.length === 0) {
    recommendations.push('Deliverability metrics are healthy. Maintain current practices.');
  }

  return recommendations;
}

interface ReportData {
  reportType: string;
  period: { since: Date; until: Date };
  events?: Record<string, number>;
  messages?: Record<string, number>;
  campaigns?: Array<Record<string, unknown>>;
  domains?: Array<Record<string, unknown>>;
  generatedAt: string;
}

function toSafeCsvCell(value: unknown): string {
  const str = String(value ?? '');
  const escaped = str.replace(/"/g, '""');
  const formulaRisk = /^[=+\-@]/.test(escaped);
  const safe = formulaRisk ? `'${escaped}` : escaped;
  return `"${safe}"`;
}

function convertReportToCSV(data: ReportData): string {
  const lines: string[] = [];

  lines.push(`Report Type,${toSafeCsvCell(data.reportType)}`);
  lines.push(`Period Start,${toSafeCsvCell(data.period.since)}`);
  lines.push(`Period End,${toSafeCsvCell(data.period.until)}`);
  lines.push(`Generated At,${toSafeCsvCell(data.generatedAt)}`);
  lines.push('');

  if (data.events) {
    lines.push('Event Type,Count');
    for (const [key, value] of Object.entries(data.events)) {
      lines.push(`${toSafeCsvCell(key)},${toSafeCsvCell(value)}`);
    }
    lines.push('');
  }

  if (data.messages) {
    lines.push('Message Status,Count');
    for (const [key, value] of Object.entries(data.messages)) {
      lines.push(`${toSafeCsvCell(key)},${toSafeCsvCell(value)}`);
    }
    lines.push('');
  }

  if (data.campaigns && data.campaigns.length > 0) {
    const firstCampaign = data.campaigns[0];
    if (firstCampaign) {
      const headers = Object.keys(firstCampaign);
      lines.push(headers.map(toSafeCsvCell).join(','));
      for (const campaign of data.campaigns) {
        lines.push(headers.map(h => toSafeCsvCell(campaign[h] ?? '')).join(','));
      }
    }
  }

  if (data.domains && data.domains.length > 0) {
    const firstDomain = data.domains[0];
    if (firstDomain) {
      const headers = Object.keys(firstDomain);
      lines.push(headers.map(toSafeCsvCell).join(','));
      for (const domain of data.domains) {
        lines.push(headers.map(h => toSafeCsvCell(domain[h] ?? '')).join(','));
      }
    }
  }

  return lines.join('\n');
}
