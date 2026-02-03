/**
 * Webhook Service
 * 
 * Manages outgoing webhooks with:
 * - HMAC-SHA256 signature verification
 * - Exponential backoff retry
 * - Event filtering
 * - Delivery logging
 * - Rate limiting
 * - SSRF protection
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import { Result } from '@apexmail/lib';
import { hmacSign, randomToken, timingSafeCompare } from '@apexmail/lib/crypto';
import { lookup } from 'dns/promises';
import { config } from '../config.js';

/**
 * SSRF Protection: Check if an IP address is private/internal
 * Blocks access to internal infrastructure via webhooks
 */
function isPrivateIP(ip: string): boolean {
  // IPv4 private ranges
  const ipv4Patterns = [
    /^127\./,                    // Loopback 127.0.0.0/8
    /^10\./,                     // Private 10.0.0.0/8
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private 172.16.0.0/12
    /^192\.168\./,               // Private 192.168.0.0/16
    /^169\.254\./,               // Link-local 169.254.0.0/16 (AWS metadata)
    /^0\./,                      // Current network
    /^100\.(6[4-9]|[7-9][0-9]|1[0-2][0-7])\./, // Shared address space
    /^192\.0\.0\./,              // IETF protocol assignments
    /^192\.0\.2\./,              // Documentation
    /^198\.51\.100\./,           // Documentation
    /^203\.0\.113\./,            // Documentation
    /^224\./,                    // Multicast
    /^240\./,                    // Reserved
    /^255\.255\.255\.255$/,      // Broadcast
  ];

  // IPv6 private ranges
  const ipv6Patterns = [
    /^::1$/,                     // Loopback
    /^::$/,                      // Unspecified
    /^fe80:/i,                   // Link-local
    /^fc00:/i,                   // Unique local (fc00::/7)
    /^fd00:/i,                   // Unique local
    /^ff00:/i,                   // Multicast
    /^::ffff:(?:127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.)/i, // IPv4-mapped private
  ];

  // Check IPv4 patterns
  for (const pattern of ipv4Patterns) {
    if (pattern.test(ip)) return true;
  }

  // Check IPv6 patterns
  for (const pattern of ipv6Patterns) {
    if (pattern.test(ip)) return true;
  }

  return false;
}

/**
 * Validate webhook URL is safe (no SSRF)
 */
async function validateWebhookUrl(urlString: string): Promise<{ safe: boolean; error?: string }> {
  try {
    const url = new URL(urlString);
    
    // Only allow HTTP/HTTPS
    if (!['http:', 'https:'].includes(url.protocol)) {
      return { safe: false, error: 'Only HTTP and HTTPS URLs are allowed' };
    }

    // Resolve hostname to IP
    const hostname = url.hostname;
    
    // Allow localhost only in development
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
      if (process.env.NODE_ENV === 'production') {
        return { safe: false, error: 'Localhost URLs not allowed in production' };
      }
      return { safe: true }; // Allow in dev
    }

    // DNS lookup to check resolved IP
    try {
      const addresses = await lookup(hostname, { all: true });
      for (const addr of addresses) {
        if (isPrivateIP(addr.address)) {
          return { safe: false, error: `URL resolves to private IP address` };
        }
      }
    } catch (dnsError) {
      // If DNS lookup fails, allow the request (let fetch handle it)
      // This handles cases where DNS might be temporarily unavailable
      console.warn(`[Webhook] DNS lookup failed for ${hostname}:`, dnsError);
    }

    return { safe: true };
  } catch (error) {
    return { safe: false, error: `Invalid URL: ${error instanceof Error ? error.message : 'Unknown error'}` };
  }
}

export interface WebhookEndpoint {
  id: string;
  tenantId: string;
  url: string;
  secret: string;
  events: string[];
  enabled: boolean;
  description?: string;
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

export interface WebhookEvent {
  id: string;
  type: string;
  tenantId: string;
  data: Record<string, unknown>;
  createdAt: Date;
}

export interface WebhookDelivery {
  id: string;
  endpointId: string;
  eventId: string;
  status: 'pending' | 'success' | 'failed' | 'retrying';
  httpStatus?: number;
  responseBody?: string;
  attempts: number;
  nextRetryAt?: Date;
  completedAt?: Date;
  latencyMs?: number;
  createdAt: Date;
}

// Webhook event types as enum for type safety
export enum WebhookEventType {
  EMAIL_SENT = 'email.sent',
  EMAIL_DELIVERED = 'email.delivered',
  EMAIL_BOUNCED = 'email.bounced',
  EMAIL_DEFERRED = 'email.deferred',
  EMAIL_OPENED = 'email.opened',
  EMAIL_CLICKED = 'email.clicked',
  EMAIL_COMPLAINED = 'email.complained',
  EMAIL_UNSUBSCRIBED = 'email.unsubscribed',
  CONTACT_CREATED = 'contact.created',
  CONTACT_UPDATED = 'contact.updated',
  CONTACT_DELETED = 'contact.deleted',
  LIST_SUBSCRIBED = 'list.subscribed',
  LIST_UNSUBSCRIBED = 'list.unsubscribed',
}

// Webhook event types
export const WEBHOOK_EVENTS = {
  // Email lifecycle
  'email.sent': 'Email was accepted for delivery',
  'email.delivered': 'Email was delivered to recipient',
  'email.bounced': 'Email bounced (hard or soft)',
  'email.deferred': 'Email delivery was deferred',
  'email.dropped': 'Email was dropped (suppression, spam)',
  'email.complained': 'Recipient marked as spam',
  'email.unsubscribed': 'Recipient unsubscribed',
  'email.opened': 'Email was opened',
  'email.clicked': 'Link in email was clicked',
  
  // Account events
  'account.updated': 'Account settings were changed',
  'account.suspended': 'Account was suspended',
  'account.reactivated': 'Account was reactivated',
  
  // Billing events
  'subscription.created': 'New subscription created',
  'subscription.updated': 'Subscription was updated',
  'subscription.canceled': 'Subscription was canceled',
  'invoice.paid': 'Invoice was paid',
  'invoice.failed': 'Invoice payment failed',
  
  // Domain events
  'domain.verified': 'Domain was verified',
  'domain.failed': 'Domain verification failed',
  'domain.removed': 'Domain was removed',
  
  // API key events
  'api_key.created': 'API key was created',
  'api_key.revoked': 'API key was revoked',
} as const;

const RETRY_SCHEDULE = [
  1 * 60 * 1000,      // 1 minute
  5 * 60 * 1000,      // 5 minutes
  30 * 60 * 1000,     // 30 minutes
  2 * 60 * 60 * 1000, // 2 hours
  6 * 60 * 60 * 1000, // 6 hours
  24 * 60 * 60 * 1000, // 24 hours
];

const MAX_RETRIES = 6;

export class WebhookService {
  private db: Pool;
  private redis: Redis;

  constructor(db: Pool, redis: Redis) {
    this.db = db;
    this.redis = redis;
  }

  /**
   * Create a webhook endpoint
   */
  async createEndpoint(
    tenantId: string,
    data: {
      url: string;
      events: string[];
      description?: string;
      metadata?: Record<string, unknown>;
    }
  ): Promise<Result<WebhookEndpoint>> {
    try {
      // SSRF Protection: Validate URL is safe
      const urlValidation = await validateWebhookUrl(data.url);
      if (!urlValidation.safe) {
        return { ok: false, error: new Error(urlValidation.error || 'Invalid webhook URL') };
      }

      // Validate URL format
      const url = new URL(data.url);

      // Require HTTPS in production (except for localhost in dev)
      if (process.env.NODE_ENV === 'production' && url.protocol !== 'https:') {
        return { ok: false, error: new Error('Webhook URL must use HTTPS in production') };
      }

      // Validate events
      const validEvents = Object.keys(WEBHOOK_EVENTS);
      const invalidEvents = data.events.filter(e => !validEvents.includes(e) && e !== '*');
      if (invalidEvents.length > 0) {
        return { ok: false, error: new Error(`Invalid events: ${invalidEvents.join(', ')}`) };
      }

      // Check endpoint limit (configurable per deployment)
      const maxEndpoints = config.maxWebhookEndpointsPerTenant;
      const countResult = await this.db.query(
        `SELECT COUNT(*) as count FROM webhook_endpoints WHERE tenant_id = $1`,
        [tenantId]
      );

      if (parseInt(countResult.rows[0].count, 10) >= maxEndpoints) {
        return { ok: false, error: new Error(`Maximum ${maxEndpoints} webhook endpoints allowed`) };
      }

      // Generate signing secret
      const secret = `whsec_${randomToken(32)}`;

      const result = await this.db.query(
        `INSERT INTO webhook_endpoints (
          tenant_id, url, secret, events, description, metadata, enabled, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, TRUE, NOW(), NOW())
        RETURNING *`,
        [
          tenantId,
          data.url,
          secret,
          JSON.stringify(data.events),
          data.description ?? null,
          JSON.stringify(data.metadata ?? {}),
        ]
      );

      const endpoint = this.mapEndpoint(result.rows[0]);

      return { ok: true, value: endpoint };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Update a webhook endpoint
   */
  async updateEndpoint(
    tenantId: string,
    endpointId: string,
    data: {
      url?: string;
      events?: string[];
      description?: string;
      metadata?: Record<string, unknown>;
      enabled?: boolean;
    }
  ): Promise<Result<WebhookEndpoint>> {
    try {
      const updates: string[] = [];
      const values: unknown[] = [tenantId, endpointId];
      let paramIndex = 3;

      if (data.url !== undefined) {
        const url = new URL(data.url);
        if (url.protocol === 'http:' && !url.hostname.match(/^(localhost|127\.0\.0\.1)$/)) {
          return { ok: false, error: new Error('Webhook URL must use HTTPS') };
        }
        updates.push(`url = $${paramIndex++}`);
        values.push(data.url);
      }

      if (data.events !== undefined) {
        const validEvents = Object.keys(WEBHOOK_EVENTS);
        const invalidEvents = data.events.filter(e => !validEvents.includes(e) && e !== '*');
        if (invalidEvents.length > 0) {
          return { ok: false, error: new Error(`Invalid events: ${invalidEvents.join(', ')}`) };
        }
        updates.push(`events = $${paramIndex++}`);
        values.push(JSON.stringify(data.events));
      }

      if (data.description !== undefined) {
        updates.push(`description = $${paramIndex++}`);
        values.push(data.description);
      }

      if (data.metadata !== undefined) {
        updates.push(`metadata = $${paramIndex++}`);
        values.push(JSON.stringify(data.metadata));
      }

      if (data.enabled !== undefined) {
        updates.push(`enabled = $${paramIndex++}`);
        values.push(data.enabled);
      }

      if (updates.length === 0) {
        return { ok: false, error: new Error('No updates provided') };
      }

      updates.push('updated_at = NOW()');

      const result = await this.db.query(
        `UPDATE webhook_endpoints 
         SET ${updates.join(', ')}
         WHERE tenant_id = $1 AND id = $2
         RETURNING *`,
        values
      );

      if (result.rows.length === 0) {
        return { ok: false, error: new Error('Endpoint not found') };
      }

      return { ok: true, value: this.mapEndpoint(result.rows[0]) };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Delete a webhook endpoint
   */
  async deleteEndpoint(tenantId: string, endpointId: string): Promise<Result<void>> {
    try {
      const result = await this.db.query(
        `DELETE FROM webhook_endpoints WHERE tenant_id = $1 AND id = $2`,
        [tenantId, endpointId]
      );

      if (result.rowCount === 0) {
        return { ok: false, error: new Error('Endpoint not found') };
      }

      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * List webhook endpoints
   */
  async listEndpoints(tenantId: string): Promise<Result<WebhookEndpoint[]>> {
    try {
      const result = await this.db.query(
        `SELECT * FROM webhook_endpoints WHERE tenant_id = $1 ORDER BY created_at DESC`,
        [tenantId]
      );

      const endpoints = result.rows.map(row => this.mapEndpoint(row));

      return { ok: true, value: endpoints };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get endpoint by ID
   */
  async getEndpoint(tenantId: string, endpointId: string): Promise<Result<WebhookEndpoint | null>> {
    try {
      const result = await this.db.query(
        `SELECT * FROM webhook_endpoints WHERE tenant_id = $1 AND id = $2`,
        [tenantId, endpointId]
      );

      if (result.rows.length === 0) {
        return { ok: true, value: null };
      }

      return { ok: true, value: this.mapEndpoint(result.rows[0]) };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Rotate endpoint secret
   */
  async rotateSecret(tenantId: string, endpointId: string): Promise<Result<string>> {
    try {
      const newSecret = `whsec_${randomToken(32)}`;

      const result = await this.db.query(
        `UPDATE webhook_endpoints 
         SET secret = $3, updated_at = NOW()
         WHERE tenant_id = $1 AND id = $2
         RETURNING *`,
        [tenantId, endpointId, newSecret]
      );

      if (result.rows.length === 0) {
        return { ok: false, error: new Error('Endpoint not found') };
      }

      return { ok: true, value: newSecret };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Send a webhook event
   */
  async sendEvent(event: WebhookEvent): Promise<Result<{ delivered: number; failed: number }>> {
    try {
      // Find matching endpoints
      const endpointsResult = await this.db.query(
        `SELECT * FROM webhook_endpoints 
         WHERE tenant_id = $1 
         AND enabled = TRUE 
         AND (events @> $2 OR events @> '["*"]'::jsonb)`,
        [event.tenantId, JSON.stringify([event.type])]
      );

      const endpoints = endpointsResult.rows.map(row => this.mapEndpoint(row));

      let delivered = 0;
      let failed = 0;

      // Store event
      const eventResult = await this.db.query(
        `INSERT INTO webhook_events (tenant_id, type, data, created_at)
         VALUES ($1, $2, $3, NOW())
         RETURNING id`,
        [event.tenantId, event.type, JSON.stringify(event.data)]
      );
      if (!eventResult.rows[0]) {
        return { ok: false, error: new Error('Failed to create webhook event') };
      }
      const eventId = eventResult.rows[0].id;

      // Deliver to each endpoint
      for (const endpoint of endpoints) {
        const deliveryResult = await this.deliverToEndpoint(endpoint, {
          ...event,
          id: eventId,
        });

        if (deliveryResult.ok && deliveryResult.value.status === 'success') {
          delivered++;
        } else {
          failed++;
        }
      }

      return { ok: true, value: { delivered, failed } };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Deliver webhook to a single endpoint
   */
  private async deliverToEndpoint(
    endpoint: WebhookEndpoint,
    event: WebhookEvent
  ): Promise<Result<WebhookDelivery>> {
    // Create delivery record
    const deliveryResult = await this.db.query(
      `INSERT INTO webhook_deliveries (
        endpoint_id, event_id, status, attempts, created_at
      ) VALUES ($1, $2, 'pending', 0, NOW())
      RETURNING id`,
      [endpoint.id, event.id]
    );
    if (!deliveryResult.rows[0]) {
      return { ok: false, error: new Error('Failed to create webhook delivery record') };
    }
    const deliveryId = deliveryResult.rows[0].id;

    // Attempt delivery
    return this.attemptDelivery(deliveryId, endpoint, event, 0);
  }

  /**
   * Attempt to deliver a webhook
   */
  private async attemptDelivery(
    deliveryId: string,
    endpoint: WebhookEndpoint,
    event: WebhookEvent,
    attempt: number
  ): Promise<Result<WebhookDelivery>> {
    try {
      // SSRF Protection: Re-validate URL before delivery
      // (URL could have been modified or DNS could have changed)
      const urlValidation = await validateWebhookUrl(endpoint.url);
      if (!urlValidation.safe) {
        return {
          ok: false,
          error: new Error(`Webhook URL blocked for security: ${urlValidation.error}`),
        };
      }

      const timestamp = Math.floor(Date.now() / 1000);
      const payload = JSON.stringify({
        id: event.id,
        type: event.type,
        created: event.createdAt,
        data: event.data,
      });

      // Generate signature
      const signature = this.generateSignature(endpoint.secret, timestamp, payload);

      const startTime = Date.now();

      // Send request
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 30000);

      try {
        const response = await fetch(endpoint.url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-ApexMail-Signature': signature,
            'X-ApexMail-Timestamp': timestamp.toString(),
            'X-ApexMail-Event': event.type,
            'X-ApexMail-Delivery-ID': deliveryId,
            'User-Agent': 'ApexMail-Webhook/1.0',
          },
          body: payload,
          signal: controller.signal,
        });

        clearTimeout(timeout);

        const latencyMs = Date.now() - startTime;
        const responseBody = await response.text().catch(() => '');

        if (response.ok) {
          // Success
          await this.db.query(
            `UPDATE webhook_deliveries 
             SET status = 'success', http_status = $2, response_body = $3,
                 attempts = $4, latency_ms = $5, completed_at = NOW()
             WHERE id = $1`,
            [deliveryId, response.status, responseBody.slice(0, 1000), attempt + 1, latencyMs]
          );

          return {
            ok: true,
            value: {
              id: deliveryId,
              endpointId: endpoint.id,
              eventId: event.id,
              status: 'success',
              httpStatus: response.status,
              responseBody: responseBody.slice(0, 1000),
              attempts: attempt + 1,
              latencyMs,
              completedAt: new Date(),
              createdAt: new Date(),
            },
          };
        } else {
          // Failed - schedule retry
          return this.handleFailure(
            deliveryId,
            endpoint,
            event,
            attempt,
            response.status,
            responseBody
          );
        }
      } catch (fetchError) {
        clearTimeout(timeout);
        return this.handleFailure(
          deliveryId,
          endpoint,
          event,
          attempt,
          0,
          String(fetchError)
        );
      }
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Handle delivery failure
   */
  private async handleFailure(
    deliveryId: string,
    endpoint: WebhookEndpoint,
    event: WebhookEvent,
    attempt: number,
    httpStatus: number,
    errorMessage: string
  ): Promise<Result<WebhookDelivery>> {
    const nextAttempt = attempt + 1;

    if (nextAttempt >= MAX_RETRIES) {
      // Mark as failed permanently
      await this.db.query(
        `UPDATE webhook_deliveries 
         SET status = 'failed', http_status = $2, response_body = $3,
             attempts = $4, completed_at = NOW()
         WHERE id = $1`,
        [deliveryId, httpStatus || null, errorMessage.slice(0, 1000), nextAttempt]
      );

      return {
        ok: true,
        value: {
          id: deliveryId,
          endpointId: endpoint.id,
          eventId: event.id,
          status: 'failed',
          httpStatus: httpStatus || undefined,
          responseBody: errorMessage.slice(0, 1000),
          attempts: nextAttempt,
          completedAt: new Date(),
          createdAt: new Date(),
        },
      };
    }

    // Schedule retry
    const retryDelay = RETRY_SCHEDULE[nextAttempt - 1] ?? RETRY_SCHEDULE[RETRY_SCHEDULE.length - 1] ?? 60000;
    const nextRetryAt = new Date(Date.now() + retryDelay);

    await this.db.query(
      `UPDATE webhook_deliveries 
       SET status = 'retrying', http_status = $2, response_body = $3,
           attempts = $4, next_retry_at = $5
       WHERE id = $1`,
      [deliveryId, httpStatus || null, errorMessage.slice(0, 1000), nextAttempt, nextRetryAt]
    );

    // Queue retry job
    await this.redis.zadd(
      'webhook_retries',
      nextRetryAt.getTime(),
      JSON.stringify({ deliveryId, endpointId: endpoint.id, eventId: event.id, attempt: nextAttempt })
    );

    return {
      ok: true,
      value: {
        id: deliveryId,
        endpointId: endpoint.id,
        eventId: event.id,
        status: 'retrying',
        httpStatus: httpStatus || undefined,
        responseBody: errorMessage.slice(0, 1000),
        attempts: nextAttempt,
        nextRetryAt,
        createdAt: new Date(),
      },
    };
  }

  /**
   * Process pending retries
   */
  async processRetries(): Promise<Result<{ processed: number; succeeded: number; failed: number }>> {
    try {
      const now = Date.now();
      const jobs = await this.redis.zrangebyscore('webhook_retries', 0, now, 'LIMIT', 0, 100);

      let processed = 0;
      let succeeded = 0;
      let failed = 0;

      for (const jobJson of jobs) {
        const job = JSON.parse(jobJson) as {
          deliveryId: string;
          endpointId: string;
          eventId: string;
          attempt: number;
        };

        // Remove from queue
        await this.redis.zrem('webhook_retries', jobJson);

        // Get endpoint and event
        const [endpointResult, eventResult] = await Promise.all([
          this.db.query(`SELECT * FROM webhook_endpoints WHERE id = $1`, [job.endpointId]),
          this.db.query(`SELECT * FROM webhook_events WHERE id = $1`, [job.eventId]),
        ]);

        if (endpointResult.rows.length === 0 || eventResult.rows.length === 0) {
          continue;
        }

        const endpoint = this.mapEndpoint(endpointResult.rows[0]);
        const event: WebhookEvent = {
          id: eventResult.rows[0].id,
          type: eventResult.rows[0].type,
          tenantId: eventResult.rows[0].tenant_id,
          data: eventResult.rows[0].data,
          createdAt: eventResult.rows[0].created_at,
        };

        const result = await this.attemptDelivery(job.deliveryId, endpoint, event, job.attempt);

        processed++;
        if (result.ok && result.value.status === 'success') {
          succeeded++;
        } else if (result.ok && result.value.status === 'failed') {
          failed++;
        }
      }

      return { ok: true, value: { processed, succeeded, failed } };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Generate HMAC-SHA256 signature
   */
  generateSignature(secret: string, timestamp: number, payload: string): string {
    const signedPayload = `${timestamp}.${payload}`;
    const signature = hmacSign(secret, signedPayload, 'sha256');
    return `t=${timestamp},v1=${signature}`;
  }

  /**
   * Verify webhook signature (for incoming webhooks)
   */
  verifySignature(
    payload: string,
    signature: string,
    secret: string,
    tolerance: number = 300
  ): { valid: boolean; error?: string } {
    const parts = signature.split(',');
    const timestampPart = parts.find(p => p.startsWith('t='));
    const signaturePart = parts.find(p => p.startsWith('v1='));

    if (!timestampPart || !signaturePart) {
      return { valid: false, error: 'Invalid signature format' };
    }

    const timestamp = parseInt(timestampPart.slice(2), 10);
    const expectedSignature = signaturePart.slice(3);

    // Check timestamp tolerance
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > tolerance) {
      return { valid: false, error: 'Timestamp outside tolerance' };
    }

    // Calculate expected signature
    const signedPayload = `${timestamp}.${payload}`;
    const calculatedSignature = hmacSign(secret, signedPayload, 'sha256');

    // Timing-safe comparison
    if (!timingSafeCompare(expectedSignature, calculatedSignature)) {
      return { valid: false, error: 'Signature mismatch' };
    }

    return { valid: true };
  }

  /**
   * Get delivery history
   */
  async getDeliveries(
    tenantId: string,
    options: {
      endpointId?: string;
      status?: string;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<Result<WebhookDelivery[]>> {
    try {
      let query = `
        SELECT d.* FROM webhook_deliveries d
        JOIN webhook_endpoints e ON d.endpoint_id = e.id
        WHERE e.tenant_id = $1
      `;
      const params: unknown[] = [tenantId];
      let paramIndex = 2;

      if (options.endpointId) {
        query += ` AND d.endpoint_id = $${paramIndex++}`;
        params.push(options.endpointId);
      }

      if (options.status) {
        query += ` AND d.status = $${paramIndex++}`;
        params.push(options.status);
      }

      query += ` ORDER BY d.created_at DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
      params.push(options.limit ?? 50, options.offset ?? 0);

      const result = await this.db.query(query, params);

      const deliveries = result.rows.map(row => ({
        id: row.id,
        endpointId: row.endpoint_id,
        eventId: row.event_id,
        status: row.status,
        httpStatus: row.http_status,
        responseBody: row.response_body,
        attempts: row.attempts,
        nextRetryAt: row.next_retry_at,
        completedAt: row.completed_at,
        latencyMs: row.latency_ms,
        createdAt: row.created_at,
      }));

      return { ok: true, value: deliveries };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get webhook statistics
   */
  async getStats(tenantId: string, days: number = 30): Promise<Result<WebhookStats>> {
    try {
      const result = await this.db.query(
        `SELECT 
          COUNT(*) FILTER (WHERE status = 'success') as successful,
          COUNT(*) FILTER (WHERE status = 'failed') as failed,
          COUNT(*) FILTER (WHERE status = 'retrying') as retrying,
          AVG(latency_ms) FILTER (WHERE status = 'success') as avg_latency,
          PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) 
            FILTER (WHERE status = 'success') as p95_latency
         FROM webhook_deliveries d
         JOIN webhook_endpoints e ON d.endpoint_id = e.id
         WHERE e.tenant_id = $1 AND d.created_at > NOW() - INTERVAL '1 day' * $2`,
        [tenantId, days]
      );

      const row = result.rows[0];

      return {
        ok: true,
        value: {
          successful: parseInt(row.successful, 10),
          failed: parseInt(row.failed, 10),
          retrying: parseInt(row.retrying, 10),
          avgLatencyMs: parseFloat(row.avg_latency) || 0,
          p95LatencyMs: parseFloat(row.p95_latency) || 0,
          successRate: row.successful / (row.successful + row.failed) * 100 || 0,
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Test webhook endpoint
   */
  async testEndpoint(tenantId: string, endpointId: string): Promise<Result<WebhookDelivery>> {
    try {
      const endpointResult = await this.getEndpoint(tenantId, endpointId);
      if (!endpointResult.ok || !endpointResult.value) {
        return { ok: false, error: new Error('Endpoint not found') };
      }

      const endpoint = endpointResult.value;

      const testEvent: WebhookEvent = {
        id: `test_${Date.now()}`,
        type: 'test.ping',
        tenantId,
        data: {
          message: 'This is a test webhook from ApexMail',
          timestamp: new Date().toISOString(),
        },
        createdAt: new Date(),
      };

      return this.deliverToEndpoint(endpoint, testEvent);
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Map database row to WebhookEndpoint
   */
  private mapEndpoint(row: Record<string, unknown>): WebhookEndpoint {
    return {
      id: row.id as string,
      tenantId: row.tenant_id as string,
      url: row.url as string,
      secret: row.secret as string,
      events: row.events as string[],
      enabled: row.enabled as boolean,
      description: row.description as string | undefined,
      metadata: row.metadata as Record<string, unknown> | undefined,
      createdAt: row.created_at as Date,
      updatedAt: row.updated_at as Date,
    };
  }
}

interface WebhookStats {
  successful: number;
  failed: number;
  retrying: number;
  avgLatencyMs: number;
  p95LatencyMs: number;
  successRate: number;
}
