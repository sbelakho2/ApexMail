/**
 * Enterprise Application
 * 
 * Main Hono application for enterprise features
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { secureHeaders } from 'hono/secure-headers';
import { Pool } from 'pg';
import Redis from 'ioredis';
import { createEnterpriseRoutes } from './routes/enterprise.js';
import { config } from './config.js';

// Service imports for background jobs
import { LogStreamingService } from './services/log-streaming.js';
import { SupportService } from './services/support.js';
import { TemplateApprovalService } from './services/template-approval.js';

export interface AppDependencies {
  pool: Pool;
  redis: Redis;
}

export function createApp(deps: AppDependencies) {
  const app = new Hono();
  const { pool, redis } = deps;

  // Middleware
  app.use('*', cors({
    origin: config.corsOrigins,
    allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Account-ID', 'X-Request-ID'],
    allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    exposeHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining'],
    maxAge: 86400,
    credentials: true,
  }));

  app.use('*', logger());
  app.use('*', prettyJSON());
  app.use('*', secureHeaders());

  // Request ID middleware
  app.use('*', async (c, next) => {
    const requestId = c.req.header('X-Request-ID') || crypto.randomUUID();
    c.set('requestId', requestId);
    c.header('X-Request-ID', requestId);
    await next();
  });

  // API key authentication middleware
  app.use('/api/*', async (c, next) => {
    const apiKey = c.req.header('X-API-Key');
    const authHeader = c.req.header('Authorization');
    
    // Skip auth for health check
    if (c.req.path === '/api/health') {
      return next();
    }

    // Allow Bearer token or API key
    if (!apiKey && !authHeader) {
      return c.json({ error: 'Authentication required' }, 401);
    }

    if (apiKey) {
      // Validate API key
      const keyData = await redis.get(`api_key:${apiKey}`);
      if (!keyData) {
        return c.json({ error: 'Invalid API key' }, 401);
      }
      const parsed = JSON.parse(keyData);
      c.set('accountId', parsed.accountId);
      c.set('scopes', parsed.scopes || []);
    } else if (authHeader?.startsWith('Bearer ')) {
      // Validate JWT token
      const token = authHeader.substring(7);
      const sessionData = await redis.get(`session:${token}`);
      if (!sessionData) {
        return c.json({ error: 'Invalid or expired token' }, 401);
      }
      const session = JSON.parse(sessionData);
      c.set('accountId', session.accountId);
      c.set('userId', session.userId);
      c.set('scopes', session.scopes || []);
    }

    await next();
  });

  // Rate limiting middleware
  app.use('/api/*', async (c, next) => {
    const accountId = c.get('accountId');
    if (!accountId) return next();

    const key = `rate_limit:enterprise:${accountId}`;
    const limit = 1000; // requests per minute
    const window = 60; // seconds

    const current = await redis.incr(key);
    if (current === 1) {
      await redis.expire(key, window);
    }

    const remaining = Math.max(0, limit - current);
    c.header('X-RateLimit-Limit', limit.toString());
    c.header('X-RateLimit-Remaining', remaining.toString());

    if (current > limit) {
      return c.json({ error: 'Rate limit exceeded', retryAfter: window }, 429);
    }

    await next();
  });

  // Mount routes
  const enterpriseRoutes = createEnterpriseRoutes(pool, redis);
  app.route('/api', enterpriseRoutes);

  // Root health check
  app.get('/', (c) => {
    return c.json({
      service: 'enterprise',
      version: '1.0.0',
      status: 'healthy',
      timestamp: new Date().toISOString(),
    });
  });

  // Error handler
  app.onError((err, c) => {
    console.error('Enterprise service error:', err);
    
    const requestId = c.get('requestId');
    
    if (err.message.includes('not found')) {
      return c.json({ 
        error: 'Resource not found', 
        requestId,
      }, 404);
    }
    
    if (err.message.includes('unauthorized') || err.message.includes('forbidden')) {
      return c.json({ 
        error: 'Access denied', 
        requestId,
      }, 403);
    }

    return c.json({ 
      error: 'Internal server error', 
      requestId,
      message: process.env.NODE_ENV === 'development' ? err.message : undefined,
    }, 500);
  });

  // Not found handler
  app.notFound((c) => {
    return c.json({ 
      error: 'Endpoint not found',
      path: c.req.path,
      method: c.req.method,
    }, 404);
  });

  return app;
}

// Background job scheduler
export class BackgroundJobScheduler {
  private pool: Pool;
  private redis: Redis;
  private logStreamingService: LogStreamingService;
  private supportService: SupportService;
  private templateApprovalService: TemplateApprovalService;
  private intervals: NodeJS.Timeout[] = [];

  constructor(pool: Pool, redis: Redis) {
    this.pool = pool;
    this.redis = redis;
    this.logStreamingService = new LogStreamingService(pool, redis);
    this.supportService = new SupportService(pool, redis);
    this.templateApprovalService = new TemplateApprovalService(pool, redis);
  }

  start() {
    // Process log stream batches every 30 seconds
    this.intervals.push(
      setInterval(() => this.processLogStreams(), 30 * 1000)
    );

    // Check SLA breaches every minute
    this.intervals.push(
      setInterval(() => this.checkSLABreaches(), 60 * 1000)
    );

    // Auto-escalate tickets every 5 minutes
    this.intervals.push(
      setInterval(() => this.autoEscalateTickets(), 5 * 60 * 1000)
    );

    // Process expired sessions every hour
    this.intervals.push(
      setInterval(() => this.cleanupExpiredSessions(), 60 * 60 * 1000)
    );

    // Process template auto-approvals every minute
    this.intervals.push(
      setInterval(() => this.processAutoApprovals(), 60 * 1000)
    );

    console.log('Background job scheduler started');
  }

  stop() {
    this.intervals.forEach(interval => clearInterval(interval));
    this.intervals = [];
    console.log('Background job scheduler stopped');
  }

  private async processLogStreams() {
    try {
      const result = await this.pool.query(
        `SELECT id FROM log_streams WHERE status = 'active' AND enabled = true`
      );

      for (const row of result.rows) {
        await this.logStreamingService.processBatch(row.id);
      }
    } catch (error) {
      console.error('Error processing log streams:', error);
    }
  }

  private async checkSLABreaches() {
    try {
      const result = await this.pool.query(`
        SELECT t.id, t.account_id, t.priority, t.created_at, t.first_response_at,
               ac.plan
        FROM support_tickets t
        JOIN accounts ac ON ac.id = t.account_id
        WHERE t.status NOT IN ('resolved', 'closed')
        AND t.sla_breached = false
      `);

      for (const ticket of result.rows) {
        const slaConfig = this.getSLAConfig(ticket.plan, ticket.priority);
        const elapsed = Date.now() - new Date(ticket.created_at).getTime();
        const elapsedMinutes = elapsed / (60 * 1000);

        // Check first response SLA
        if (!ticket.first_response_at && elapsedMinutes > slaConfig.firstResponseMinutes) {
          await this.pool.query(
            `UPDATE support_tickets SET sla_breached = true, sla_breach_type = 'first_response' WHERE id = $1`,
            [ticket.id]
          );
          await this.notifySLABreach(ticket.id, 'first_response');
        }
        // Check resolution SLA
        else if (elapsedMinutes > slaConfig.resolutionMinutes) {
          await this.pool.query(
            `UPDATE support_tickets SET sla_breached = true, sla_breach_type = 'resolution' WHERE id = $1`,
            [ticket.id]
          );
          await this.notifySLABreach(ticket.id, 'resolution');
        }
      }
    } catch (error) {
      console.error('Error checking SLA breaches:', error);
    }
  }

  private getSLAConfig(plan: string, priority: string): { firstResponseMinutes: number; resolutionMinutes: number } {
    const configs: Record<string, Record<string, { firstResponseMinutes: number; resolutionMinutes: number }>> = {
      enterprise: {
        critical: { firstResponseMinutes: 15, resolutionMinutes: 240 },
        high: { firstResponseMinutes: 60, resolutionMinutes: 480 },
        medium: { firstResponseMinutes: 240, resolutionMinutes: 1440 },
        low: { firstResponseMinutes: 480, resolutionMinutes: 2880 },
      },
      business: {
        critical: { firstResponseMinutes: 60, resolutionMinutes: 480 },
        high: { firstResponseMinutes: 240, resolutionMinutes: 960 },
        medium: { firstResponseMinutes: 480, resolutionMinutes: 2880 },
        low: { firstResponseMinutes: 1440, resolutionMinutes: 5760 },
      },
      starter: {
        critical: { firstResponseMinutes: 240, resolutionMinutes: 1440 },
        high: { firstResponseMinutes: 480, resolutionMinutes: 2880 },
        medium: { firstResponseMinutes: 1440, resolutionMinutes: 5760 },
        low: { firstResponseMinutes: 2880, resolutionMinutes: 10080 },
      },
    };

    return configs[plan]?.[priority] || configs.starter[priority] || configs.starter.low;
  }

  private async notifySLABreach(ticketId: string, breachType: string) {
    // Publish SLA breach event
    await this.redis.publish('sla_breach', JSON.stringify({
      ticketId,
      breachType,
      timestamp: new Date().toISOString(),
    }));
  }

  private async autoEscalateTickets() {
    try {
      // Escalate tickets that have been waiting too long
      const result = await this.pool.query(`
        SELECT t.id, t.priority, t.created_at, t.last_response_at
        FROM support_tickets t
        WHERE t.status = 'waiting_on_agent'
        AND t.escalation_level < 3
        AND (
          (t.priority = 'critical' AND EXTRACT(EPOCH FROM NOW() - COALESCE(t.last_response_at, t.created_at)) > 1800) OR
          (t.priority = 'high' AND EXTRACT(EPOCH FROM NOW() - COALESCE(t.last_response_at, t.created_at)) > 3600) OR
          (t.priority = 'medium' AND EXTRACT(EPOCH FROM NOW() - COALESCE(t.last_response_at, t.created_at)) > 7200)
        )
      `);

      for (const ticket of result.rows) {
        await this.supportService.escalateTicket(ticket.id, 'Auto-escalation due to response delay');
      }
    } catch (error) {
      console.error('Error auto-escalating tickets:', error);
    }
  }

  private async cleanupExpiredSessions() {
    try {
      // Redis handles TTL automatically, but we clean up database records
      await this.pool.query(`
        DELETE FROM sso_sessions 
        WHERE expires_at < NOW() - INTERVAL '1 day'
      `);
    } catch (error) {
      console.error('Error cleaning up sessions:', error);
    }
  }

  private async processAutoApprovals() {
    try {
      // Get pending templates that match auto-approval rules
      const pendingResult = await this.pool.query(`
        SELECT ts.id, ts.account_id, ts.template_type, ts.name, ts.subject_template, ts.content
        FROM template_submissions ts
        WHERE ts.status = 'pending'
        AND ts.submitted_at < NOW() - INTERVAL '1 minute'
      `);

      for (const submission of pendingResult.rows) {
        // Check for auto-approval rules
        const rulesResult = await this.pool.query(`
          SELECT * FROM template_approval_rules
          WHERE account_id = $1 AND enabled = true
          ORDER BY priority ASC
        `, [submission.account_id]);

        for (const rule of rulesResult.rows) {
          if (this.matchesAutoApprovalRule(submission, rule)) {
            if (rule.action === 'auto_approve') {
              await this.templateApprovalService.approveTemplate(
                submission.id, 
                'system', 
                `Auto-approved by rule: ${rule.name}`
              );
            }
            break;
          }
        }
      }
    } catch (error) {
      console.error('Error processing auto-approvals:', error);
    }
  }

  private matchesAutoApprovalRule(submission: any, rule: any): boolean {
    const conditions = rule.conditions || {};

    // Check template type condition
    if (conditions.templateTypes && !conditions.templateTypes.includes(submission.template_type)) {
      return false;
    }

    // Check spam score condition
    if (conditions.maxSpamScore !== undefined) {
      const spamScore = this.calculateSpamScore(submission);
      if (spamScore > conditions.maxSpamScore) {
        return false;
      }
    }

    // Check content length condition
    if (conditions.maxContentLength !== undefined) {
      if (submission.content.length > conditions.maxContentLength) {
        return false;
      }
    }

    // Check for forbidden patterns
    if (conditions.forbiddenPatterns) {
      const content = `${submission.subject_template || ''} ${submission.content}`.toLowerCase();
      for (const pattern of conditions.forbiddenPatterns) {
        if (content.includes(pattern.toLowerCase())) {
          return false;
        }
      }
    }

    return true;
  }

  private calculateSpamScore(submission: any): number {
    let score = 0;
    const content = `${submission.subject_template || ''} ${submission.content}`;

    // Check for spam keywords
    const spamKeywords = [
      'free', 'winner', 'congratulations', 'urgent', 'limited time',
      'act now', 'click here', 'unsubscribe', 'opt out', 'buy now',
      'order now', 'special offer', 'best price', 'lowest price',
      'guarantee', 'no obligation', 'risk free', 'satisfaction guaranteed',
    ];

    const lowerContent = content.toLowerCase();
    for (const keyword of spamKeywords) {
      if (lowerContent.includes(keyword)) {
        score += 5;
      }
    }

    // Check for excessive capitalization
    const upperCount = (content.match(/[A-Z]/g) || []).length;
    const letterCount = (content.match(/[a-zA-Z]/g) || []).length;
    if (letterCount > 0 && upperCount / letterCount > 0.3) {
      score += 15;
    }

    // Check for excessive exclamation marks
    const exclamationCount = (content.match(/!/g) || []).length;
    if (exclamationCount > 3) {
      score += exclamationCount * 2;
    }

    // Check for suspicious URLs
    const urlPattern = /https?:\/\/[^\s]+/gi;
    const urls = content.match(urlPattern) || [];
    for (const url of urls) {
      if (url.includes('bit.ly') || url.includes('tinyurl') || url.includes('goo.gl')) {
        score += 10;
      }
    }

    return Math.min(score, 100);
  }
}

export default createApp;
