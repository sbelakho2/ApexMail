/**
 * Webhooks Routes - Manage webhook endpoints for event delivery
 * 
 * FIXED: Now uses database-backed WebhooksRepository instead of in-memory store
 * SECURITY: Added SSRF protection to prevent access to internal networks
 */

import { Hono } from 'hono';
import { z } from 'zod';
import * as dns from 'dns/promises';
import * as net from 'net';
import type { AppEnv, AppContext } from '../app.js';
import { AuditLogsRepository, WebhooksRepository, type Webhook, type WebhookInsert, type WebhookUpdate } from '@apexmail/db';
import { ApiError } from '../middleware/error-handler.js';
import { requireScopes } from '../middleware/auth.js';
import { hmacSign, randomToken, timingSafeCompareBuffers } from '@apexmail/lib/crypto';
import { generateId } from '@apexmail/lib';

/**
 * SSRF Protection - Check if IP address is internal/private
 * Blocks access to:
 * - Loopback (127.0.0.0/8, ::1)
 * - Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
 * - Link-local (169.254.0.0/16, fe80::/10)
 * - Cloud metadata endpoints (169.254.169.254)
 * - Multicast (224.0.0.0/4, ff00::/8)
 */
function isPrivateIP(ip: string): boolean {
  // Check IPv4
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const [a, b, c] = parts;
    
    // Ensure we have valid parts
    if (a === undefined || b === undefined || c === undefined) return false;
    
    // Loopback (127.0.0.0/8)
    if (a === 127) return true;
    
    // Private Class A (10.0.0.0/8)
    if (a === 10) return true;
    
    // Private Class B (172.16.0.0/12)
    if (a === 172 && b >= 16 && b <= 31) return true;
    
    // Private Class C (192.168.0.0/16)
    if (a === 192 && b === 168) return true;
    
    // Link-local (169.254.0.0/16) - includes AWS/GCP metadata
    if (a === 169 && b === 254) return true;
    
    // Multicast (224.0.0.0/4)
    if (a >= 224 && a <= 239) return true;
    
    // Reserved/broadcast
    if (a === 0 || a === 255) return true;
    
    // Documentation ranges (TEST-NET)
    if (a === 192 && b === 0 && c === 2) return true;    // 192.0.2.0/24
    if (a === 198 && b === 51 && c === 100) return true; // 198.51.100.0/24
    if (a === 203 && b === 0 && c === 113) return true;  // 203.0.113.0/24
    
    return false;
  }
  
  // Check IPv6
  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();
    
    // Loopback (::1)
    if (normalized === '::1') return true;
    
    // Unspecified (::)
    if (normalized === '::') return true;
    
    // Link-local (fe80::/10)
    if (normalized.startsWith('fe80:') || normalized.startsWith('fe8') || 
        normalized.startsWith('fe9') || normalized.startsWith('fea') || 
        normalized.startsWith('feb')) return true;
    
    // Unique local (fc00::/7) - like private IPv4
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
    
    // Multicast (ff00::/8)
    if (normalized.startsWith('ff')) return true;
    
    // IPv4-mapped IPv6 (::ffff:x.x.x.x) - check the IPv4 portion
    if (normalized.startsWith('::ffff:')) {
      const ipv4Part = normalized.slice(7);
      if (net.isIPv4(ipv4Part)) {
        return isPrivateIP(ipv4Part);
      }
    }
    
    return false;
  }
  
  // Unknown format - deny by default
  return true;
}

/**
 * Validate webhook URL for SSRF vulnerabilities
 * Performs DNS resolution and checks all resolved IPs
 */
async function validateWebhookUrl(urlString: string): Promise<void> {
  const url = new URL(urlString);
  const hostname = url.hostname;
  
  // Block localhost variations
  const blockedHostnames = [
    'localhost',
    'localhost.localdomain',
    '127.0.0.1',
    '::1',
    '0.0.0.0',
    '[::1]',
    'metadata.google.internal',        // GCP metadata
    'metadata.google.com',              // GCP
    'instance-data',                    // AWS alias
    'kubernetes.default',               // K8s internal
    'kubernetes.default.svc',
    'kubernetes.default.svc.cluster.local',
  ];
  
  if (blockedHostnames.some(h => hostname.toLowerCase() === h || hostname.toLowerCase().endsWith('.' + h))) {
    throw ApiError.badRequest('Webhook URL cannot point to internal/localhost addresses');
  }
  
  // Check if hostname is already an IP
  if (net.isIP(hostname)) {
    if (isPrivateIP(hostname)) {
      throw ApiError.badRequest('Webhook URL cannot point to private/internal IP addresses');
    }
    return;
  }
  
  // Resolve DNS and check all IPs
  try {
    const addresses = await dns.resolve4(hostname).catch(() => []);
    const addresses6 = await dns.resolve6(hostname).catch(() => []);
    const allAddresses = [...addresses, ...addresses6];
    
    if (allAddresses.length === 0) {
      throw ApiError.badRequest('Webhook URL hostname could not be resolved');
    }
    
    for (const ip of allAddresses) {
      if (isPrivateIP(ip)) {
        throw ApiError.badRequest(`Webhook URL resolves to private IP address (${ip}). This is not allowed for security reasons.`);
      }
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw ApiError.badRequest(`Failed to validate webhook URL: ${error instanceof Error ? error.message : 'DNS resolution failed'}`);
  }
}

const eventTypes = [
  'message.accepted',
  'message.queued',
  'message.sending',
  'message.sent',
  'message.delivered',
  'message.bounced',
  'message.deferred',
  'message.dropped',
  'message.opened',
  'message.clicked',
  'message.unsubscribed',
  'message.complained',
  'message.failed',
  'domain.verified',
  'domain.failed',
  'suppression.added',
  '*', // All events
] as const;

const createWebhookSchema = z.object({
  name: z.string().min(1).max(100),
  url: z.string().url().max(2000),
  events: z.array(z.enum(eventTypes)).min(1).max(eventTypes.length),
  description: z.string().max(500).optional(),
  secret: z.string().min(16).max(256).optional(),
  headers: z.record(z.string().max(1000), z.string().max(4000)).refine(
    (h) => Object.keys(h).length <= 20,
    { message: 'Too many custom headers (max 20)' }
  ).optional(), // Limit header key/value sizes and count
  enabled: z.boolean().default(true),
  retryPolicy: z.object({
    maxRetries: z.number().int().min(0).max(10).default(3),
    retryDelay: z.number().int().min(1000).max(3600000).default(60000),
    backoffMultiplier: z.number().min(1).max(5).default(2),
  }).optional(),
  /**
   * mTLS (Mutual TLS) Configuration
   * Enables client certificate authentication when delivering webhooks.
   * The webhook endpoint must be configured to require and verify client certificates.
   */
  mtls: z.object({
    /** PEM-encoded X.509 client certificate */
    certificate: z.string().min(100).max(16384).refine(
      (c) => c.includes('-----BEGIN CERTIFICATE-----'),
      { message: 'Certificate must be PEM-encoded' }
    ),
    /** PEM-encoded private key (RSA or EC) */
    privateKey: z.string().min(100).max(16384).refine(
      (k) => k.includes('-----BEGIN') && k.includes('PRIVATE KEY-----'),
      { message: 'Private key must be PEM-encoded' }
    ),
    /** Optional passphrase for encrypted private keys */
    passphrase: z.string().max(256).optional(),
    /** Optional CA certificate for server verification (self-signed endpoints) */
    caCertificate: z.string().max(32768).optional(),
    /** Skip server certificate verification (NOT recommended for production) */
    rejectUnauthorized: z.boolean().default(true),
  }).optional(),
  metadata: z.record(z.unknown()).refine(
    (m) => JSON.stringify(m).length <= 8192,
    { message: 'Metadata payload too large (max 8KB)' }
  ).optional(),
});

const updateWebhookSchema = createWebhookSchema.partial();

const testWebhookSchema = z.object({
  eventType: z.enum(eventTypes).default('message.delivered'),
});

/**
 * F-227: UUID format regex for route parameter validation.
 * Prevents malformed IDs from reaching DB queries.
 */
const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function matchesWebhookEvent(events: string[], event: string): boolean {
  return events.includes('*') || events.includes(event);
}

export function webhooksRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const webhooksRepo = new WebhooksRepository(ctx.db.getPool());
  const auditRepo = new AuditLogsRepository(ctx.db);

  // Create webhook
  router.post('/', requireScopes('webhooks:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const logger = c.get('logger');

    const body = await c.req.json();
    const input = createWebhookSchema.parse(body);

    // F-192: Enforce HTTPS for all webhook URLs (not just production).
    // HTTP endpoints expose webhook payloads (including secrets) in transit.
    const url = new URL(input.url);
    if (url.protocol !== 'https:') {
      throw ApiError.badRequest('Webhook URL must use HTTPS');
    }

    // SECURITY: Validate URL for SSRF vulnerabilities
    await validateWebhookUrl(input.url);

    // Generate or use provided secret
    const secret = input.secret ?? randomToken(32);

    const webhookInsert: WebhookInsert = {
      tenantId,
      name: input.name,
      url: input.url,
      secret,
      events: input.events,
      headers: input.headers,
    };

    const result = await webhooksRepo.create(webhookInsert);
    
    if (!result.ok) {
      logger.error('Failed to create webhook', { error: result.error.message });
      throw ApiError.internal('Failed to create webhook');
    }

    const webhook = result.value;

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'webhook.created',
      resourceType: 'webhook',
      resourceId: webhook.id,
      metadata: { name: input.name, url: input.url, events: input.events },
    });

    logger.info('Webhook created', { webhookId: webhook.id, name: input.name });

    return c.json({
      webhook: {
        id: webhook.id,
        name: webhook.name,
        url: webhook.url,
        events: webhook.events,
        secret: webhook.secret, // Only returned on creation
        enabled: webhook.enabled,
        headers: webhook.headers,
        createdAt: webhook.createdAt,
      },
    }, 201);
  });

  // Get webhook by ID
  router.get('/:id', requireScopes('webhooks:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const webhookId = c.req.param('id');

    // F-227: Validate ID format before passing to DB query
    if (!uuidRegex.test(webhookId)) {
      throw ApiError.badRequest('Invalid webhook ID format', 'INVALID_ID');
    }

    const webhook = await webhooksRepo.findById(webhookId, tenantId);
    if (!webhook) {
      throw ApiError.notFound('Webhook');
    }

    return c.json({
      webhook: {
        id: webhook.id,
        name: webhook.name,
        url: webhook.url,
        events: webhook.events,
        headers: webhook.headers,
        enabled: webhook.enabled,
        failureCount: webhook.failureCount,
        lastTriggeredAt: webhook.lastTriggeredAt,
        lastSuccessAt: webhook.lastSuccessAt,
        lastFailureAt: webhook.lastFailureAt,
        disabledReason: webhook.disabledReason,
        createdAt: webhook.createdAt,
        updatedAt: webhook.updatedAt,
      },
    });
  });

  // List webhooks
  // FIX-500-098: Push enabled/event filters to SQL instead of fetching all
  // and filtering in memory.
  router.get('/', requireScopes('webhooks:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const enabled = c.req.query('enabled');
    const event = c.req.query('event');
    const limit = Math.max(1, Math.min(parseInt(c.req.query('limit') ?? '50', 10) || 50, 200));
    const offset = Math.max(0, parseInt(c.req.query('offset') ?? '0', 10) || 0);

    const filters: { enabled?: boolean; event?: string } = {};
    if (enabled !== undefined) {
      filters.enabled = enabled === 'true';
    }
    if (event) {
      filters.event = event;
    }

    const compatibleRepo = webhooksRepo as unknown as {
      findByTenantFiltered?: (
        tenant: string,
        f?: { enabled?: boolean; event?: string },
        options?: { limit?: number; offset?: number },
      ) => Promise<{ webhooks: Webhook[]; total: number }>;
    };

    let webhooks: Webhook[];
    let total: number;

    if (typeof compatibleRepo.findByTenantFiltered === 'function') {
      const result = await compatibleRepo.findByTenantFiltered(tenantId, filters, { limit, offset });
      webhooks = result.webhooks;
      total = result.total;
    } else {
      const allWebhooks = await webhooksRepo.findByTenant(tenantId);
      const filtered = allWebhooks.filter((webhook) => {
        if (filters.enabled !== undefined && webhook.enabled !== filters.enabled) {
          return false;
        }
        if (filters.event && !matchesWebhookEvent(webhook.events, filters.event)) {
          return false;
        }
        return true;
      });
      total = filtered.length;
      webhooks = filtered.slice(offset, offset + limit);
    }

    return c.json({
      webhooks: webhooks.map(w => ({
        id: w.id,
        name: w.name,
        url: w.url,
        events: w.events,
        enabled: w.enabled,
        failureCount: w.failureCount,
        lastTriggeredAt: w.lastTriggeredAt,
        lastSuccessAt: w.lastSuccessAt,
        lastFailureAt: w.lastFailureAt,
        createdAt: w.createdAt,
        updatedAt: w.updatedAt,
      })),
      total,
      pagination: {
        limit,
        offset,
        hasMore: offset + webhooks.length < total,
      },
    });
  });

  // Update webhook
  router.patch('/:id', requireScopes('webhooks:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

    // F-227: Validate ID format before passing to DB query
    if (!uuidRegex.test(webhookId)) {
      throw ApiError.badRequest('Invalid webhook ID format', 'INVALID_ID');
    }

    // Check webhook exists
    const existing = await webhooksRepo.findById(webhookId, tenantId);
    if (!existing) {
      throw ApiError.notFound('Webhook');
    }

    const body = await c.req.json();
    const input = updateWebhookSchema.parse(body);

    // Validate URL if provided
    if (input.url) {
      // F-192: Enforce HTTPS for all webhook URLs (not just production)
      const url = new URL(input.url);
      if (url.protocol !== 'https:') {
        throw ApiError.badRequest('Webhook URL must use HTTPS');
      }
      // SECURITY: Validate URL for SSRF vulnerabilities
      await validateWebhookUrl(input.url);
    }

    const updateData: WebhookUpdate = {};
    if (input.name !== undefined) updateData.name = input.name;
    if (input.url !== undefined) updateData.url = input.url;
    if (input.events !== undefined) updateData.events = input.events;
    if (input.headers !== undefined) updateData.headers = input.headers;
    if (input.enabled !== undefined) updateData.enabled = input.enabled;

    const result = await webhooksRepo.update(webhookId, tenantId, updateData);
    
    if (!result.ok) {
      logger.error('Failed to update webhook', { error: result.error.message });
      throw ApiError.internal('Failed to update webhook');
    }

    const webhook = result.value;

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'webhook.updated',
      resourceType: 'webhook',
      resourceId: webhook.id,
      changes: { fields: Object.keys(input) },
    });

    logger.info('Webhook updated', { webhookId });

    return c.json({
      webhook: {
        id: webhook.id,
        name: webhook.name,
        url: webhook.url,
        events: webhook.events,
        enabled: webhook.enabled,
        updatedAt: webhook.updatedAt,
      },
    });
  });

  // Regenerate webhook secret
  router.post('/:id/rotate-secret', requireScopes('webhooks:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

    // F-227: Validate ID format before passing to DB query
    if (!uuidRegex.test(webhookId)) {
      throw ApiError.badRequest('Invalid webhook ID format', 'INVALID_ID');
    }

    const existing = await webhooksRepo.findById(webhookId, tenantId);
    if (!existing) {
      throw ApiError.notFound('Webhook');
    }

    const newSecret = randomToken(32);
    const result = await webhooksRepo.update(webhookId, tenantId, { secret: newSecret });
    
    if (!result.ok) {
      logger.error('Failed to rotate webhook secret', { error: result.error.message });
      throw ApiError.internal('Failed to rotate webhook secret');
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'webhook.secret_rotated',
      resourceType: 'webhook',
      resourceId: webhookId,
    });

    logger.info('Webhook secret rotated', { webhookId });

    return c.json({
      webhook: {
        id: webhookId,
        secret: newSecret,
        rotatedAt: new Date(),
      },
    });
  });

  // Test webhook
  router.post('/:id/test', requireScopes('webhooks:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

    // F-227: Validate ID format before passing to DB query
    if (!uuidRegex.test(webhookId)) {
      throw ApiError.badRequest('Invalid webhook ID format', 'INVALID_ID');
    }

    const webhook = await webhooksRepo.findById(webhookId, tenantId);
    if (!webhook) {
      throw ApiError.notFound('Webhook');
    }

    // SECURITY: Re-validate URL before making request (DNS may have changed)
    await validateWebhookUrl(webhook.url);

    const body = await c.req.json().catch(() => ({}));
    const { eventType } = testWebhookSchema.parse(body);

    // Create test payload
    const testPayload = createTestPayload(eventType, tenantId);
    
    // Sign the payload
    const timestamp = Date.now();
    const signature = signPayload(webhook.secret, timestamp, testPayload);

    try {
      const startTime = Date.now();
      const response = await fetch(webhook.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-ApexMail-Webhook-Id': webhook.id,
          'X-ApexMail-Signature': signature,
          'X-ApexMail-Timestamp': timestamp.toString(),
          'X-ApexMail-Event': eventType,
          'X-ApexMail-Delivery-Id': generateId('dlv'),
          'User-Agent': 'ApexMail-Webhook/1.0',
          ...webhook.headers,
        },
        body: JSON.stringify(testPayload),
        signal: AbortSignal.timeout(ctx.config.webhooks.timeoutMs),
      });

      const duration = Date.now() - startTime;
      // F-206: Consume response body but don't expose it (may contain sensitive data)
      await response.text().catch(() => '');

      // Record trigger in database
      await webhooksRepo.recordTrigger(webhook.id, response.ok, response.ok ? undefined : `HTTP ${response.status}`);

      logger.info('Webhook test completed', {
        webhookId,
        status: response.status,
        duration,
      });

      return c.json({
        success: response.ok,
        test: {
          eventType,
          url: webhook.url,
          statusCode: response.status,
          statusText: response.statusText,
          duration,
          // F-206: Redact response body — target endpoint may return sensitive data
          responseBody: '[redacted]',
          requestPayload: testPayload,
          headers: {
            'X-ApexMail-Signature': signature,
            'X-ApexMail-Timestamp': timestamp.toString(),
          },
        },
      // FIX-500-451: Return 502 when the test delivery fails instead of always 200
      }, response.ok ? 200 : 502);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      // Record failed trigger
      await webhooksRepo.recordTrigger(webhook.id, false, errorMessage);

      logger.warn('Webhook test failed', { webhookId, error: errorMessage });

      return c.json({
        success: false,
        test: {
          eventType,
          url: webhook.url,
          error: errorMessage,
          requestPayload: testPayload,
        },
      // FIX-500-451: Return 502 for failed webhook test delivery
      }, 502);
    }
  });

  // Get webhook deliveries
  router.get('/:id/deliveries', requireScopes('webhooks:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const webhookId = c.req.param('id');
    const status = c.req.query('status') as 'pending' | 'delivered' | 'failed' | undefined;
    const limit = Math.max(1, Math.min(parseInt(c.req.query('limit') ?? '50', 10) || 50, 200));
    const offset = Math.max(0, parseInt(c.req.query('offset') ?? '0', 10) || 0);

    if (status && !['pending', 'delivered', 'failed'].includes(status)) {
      throw ApiError.badRequest('Status must be one of: pending, delivered, failed');
    }

    // F-227: Validate ID format before passing to DB query
    if (!uuidRegex.test(webhookId)) {
      throw ApiError.badRequest('Invalid webhook ID format', 'INVALID_ID');
    }

    const webhook = await webhooksRepo.findById(webhookId, tenantId);
    if (!webhook) {
      throw ApiError.notFound('Webhook');
    }

    const deliveryConditions: string[] = ['tenant_id = $1', 'webhook_id = $2'];
    const deliveryParams: unknown[] = [tenantId, webhookId];
    let paramIndex = 3;

    if (status) {
      deliveryConditions.push(`status = $${paramIndex++}`);
      deliveryParams.push(status);
    }

    const countResult = await ctx.db.getPool().query<{ count: string }>(
      `SELECT COUNT(*)::text as count
       FROM webhook_queue
       WHERE ${deliveryConditions.join(' AND ')}`,
      deliveryParams,
    );

    const deliveryResult = await ctx.db.getPool().query<{
      id: string;
      event_type: string;
      status: 'pending' | 'delivered' | 'failed';
      attempt: number;
      max_attempts: number;
      response_status: number | null;
      error_message: string | null;
      created_at: Date;
      completed_at: Date | null;
    }>(
      `SELECT id, event_type, status, attempt, max_attempts, response_status, error_message, created_at, completed_at
       FROM webhook_queue
       WHERE ${deliveryConditions.join(' AND ')}
       ORDER BY created_at DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
      [...deliveryParams, limit, offset],
    );

    const deliveryTotal = parseInt(countResult.rows[0]?.count ?? '0', 10);
    const deliveryRows = deliveryResult.rows;

    // Get delivery stats from queue
    const stats = await webhooksRepo.getQueueStats(tenantId);

    return c.json({
      deliveries: deliveryRows.map((item) => ({
        id: item.id,
        eventType: item.event_type,
        status: item.status,
        attempt: item.attempt,
        maxAttempts: item.max_attempts,
        responseStatus: item.response_status,
        errorMessage: item.error_message,
        createdAt: item.created_at,
        completedAt: item.completed_at,
      })),
      summary: {
        pending: stats.pending,
        delivered: stats.delivered,
        failed: stats.failed,
        failureCount: webhook.failureCount,
        lastTriggeredAt: webhook.lastTriggeredAt,
        lastSuccessAt: webhook.lastSuccessAt,
        lastFailureAt: webhook.lastFailureAt,
        disabledReason: webhook.disabledReason,
      },
      limit,
      offset,
      total: deliveryTotal,
      status,
      hasMore: offset + deliveryRows.length < deliveryTotal,
    });
  });

  // Enable webhook
  router.post('/:id/enable', requireScopes('webhooks:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

    // F-227: Validate ID format before passing to DB query
    if (!uuidRegex.test(webhookId)) {
      throw ApiError.badRequest('Invalid webhook ID format', 'INVALID_ID');
    }

    const existing = await webhooksRepo.findById(webhookId, tenantId);
    if (!existing) {
      throw ApiError.notFound('Webhook');
    }

    const result = await webhooksRepo.update(webhookId, tenantId, { enabled: true });
    
    if (!result.ok) {
      throw ApiError.internal('Failed to enable webhook');
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'webhook.enabled',
      resourceType: 'webhook',
      resourceId: webhookId,
    });

    logger.info('Webhook enabled', { webhookId });

    return c.json({
      webhook: {
        id: webhookId,
        enabled: true,
        updatedAt: result.value.updatedAt,
      },
    });
  });

  // Disable webhook
  router.post('/:id/disable', requireScopes('webhooks:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

    // F-227: Validate ID format before passing to DB query
    if (!uuidRegex.test(webhookId)) {
      throw ApiError.badRequest('Invalid webhook ID format', 'INVALID_ID');
    }

    const existing = await webhooksRepo.findById(webhookId, tenantId);
    if (!existing) {
      throw ApiError.notFound('Webhook');
    }

    const result = await webhooksRepo.update(webhookId, tenantId, { enabled: false });
    
    if (!result.ok) {
      throw ApiError.internal('Failed to disable webhook');
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'webhook.disabled',
      resourceType: 'webhook',
      resourceId: webhookId,
    });

    logger.info('Webhook disabled', { webhookId });

    return c.json({
      webhook: {
        id: webhookId,
        enabled: false,
        updatedAt: result.value.updatedAt,
      },
    });
  });

  // Delete webhook
  router.delete('/:id', requireScopes('webhooks:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

    // F-227: Validate ID format before passing to DB query
    if (!uuidRegex.test(webhookId)) {
      throw ApiError.badRequest('Invalid webhook ID format', 'INVALID_ID');
    }

    const webhook = await webhooksRepo.findById(webhookId, tenantId);
    if (!webhook) {
      throw ApiError.notFound('Webhook');
    }

    const deleted = await webhooksRepo.delete(webhookId, tenantId);
    if (!deleted) {
      throw ApiError.internal('Failed to delete webhook');
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'webhook.deleted',
      resourceType: 'webhook',
      resourceId: webhookId,
      metadata: { name: webhook.name, url: webhook.url },
    });

    logger.info('Webhook deleted', { webhookId });

    return c.json({ success: true });
  });

  // Verify webhook signature (utility endpoint)
  // SECURITY FIX (FIX-031): No longer requires customers to send their secret
  // over the wire. Instead, looks up the webhook by ID and uses the stored secret.
  router.post('/verify-signature', requireScopes('webhooks:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const body = await c.req.json();
    const schema = z.object({
      webhookId: z.string().min(1).max(100),
      payload: z.unknown(),
      signature: z.string().max(512), // HMAC-SHA256 hex is 64 chars, allow margin
      timestamp: z.number(),
    });
    
    const { webhookId, payload, signature, timestamp } = schema.parse(body);

    // Look up webhook to get stored secret (never sent over the wire)
    const webhook = await webhooksRepo.findById(webhookId, tenantId);
    if (!webhook) {
      throw ApiError.notFound('Webhook');
    }

    // Check timestamp is within 5 minutes
    const now = Date.now();
    if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
      return c.json({
        valid: false,
        reason: 'Timestamp too old or in future',
      });
    }

    const expectedSignature = signPayload(webhook.secret, timestamp, payload);
    
    // Use timing-safe comparison to prevent timing attacks
    const valid = signature.length === expectedSignature.length && 
      timingSafeCompareBuffers(Buffer.from(signature), Buffer.from(expectedSignature));

    return c.json({
      valid,
      reason: valid ? 'Signature verified' : 'Signature mismatch',
    });
  });

  return router;
}

function signPayload(secret: string, timestamp: number, payload: unknown): string {
  const message = `${timestamp}.${JSON.stringify(payload)}`;
  return 'sha256=' + hmacSign(secret, message, 'sha256');
}

function createTestPayload(eventType: string, tenantId: string): Record<string, unknown> {
  const basePayload = {
    id: generateId('evt'),
    type: eventType,
    tenantId,
    timestamp: new Date().toISOString(),
    test: true,
  };

  switch (eventType) {
    case 'message.delivered':
      return {
        ...basePayload,
        data: {
          messageId: generateId('msg'),
          recipient: 'test@example.com',
          subject: 'Test Message',
          deliveredAt: new Date().toISOString(),
          smtp: {
            response: '250 OK',
            server: 'mx.example.com',
          },
        },
      };

    case 'message.bounced':
      return {
        ...basePayload,
        data: {
          messageId: generateId('msg'),
          recipient: 'bounced@example.com',
          subject: 'Test Message',
          bounceType: 'hard',
          bounceSubtype: 'no-mailbox',
          diagnosticCode: '550 5.1.1 User unknown',
          bouncedAt: new Date().toISOString(),
        },
      };

    case 'message.opened':
      return {
        ...basePayload,
        data: {
          messageId: generateId('msg'),
          recipient: 'test@example.com',
          subject: 'Test Message',
          openedAt: new Date().toISOString(),
          userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
          ipAddress: '192.168.1.1',
        },
      };

    case 'message.clicked':
      return {
        ...basePayload,
        data: {
          messageId: generateId('msg'),
          recipient: 'test@example.com',
          subject: 'Test Message',
          clickedAt: new Date().toISOString(),
          url: 'https://example.com/link',
          userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
          ipAddress: '192.168.1.1',
        },
      };

    default:
      return {
        ...basePayload,
        data: {
          messageId: generateId('msg'),
          recipient: 'test@example.com',
          subject: 'Test Message',
        },
      };
  }
}

// Export for webhook delivery service
export async function getWebhooksForEvent(
  webhooksRepo: WebhooksRepository,
  tenantId: string,
  eventType: string
): Promise<Webhook[]> {
  return webhooksRepo.findEnabledByEvent(tenantId, eventType);
}

export async function deliverWebhook(
  webhooksRepo: WebhooksRepository,
  webhook: Webhook,
  payload: Record<string, unknown>
): Promise<{ success: boolean; statusCode?: number; error?: string }> {
  const timeoutMs = Math.max(1000, parseInt(process.env.WEBHOOK_TIMEOUT_MS ?? '30000', 10) || 30000);
  const timestamp = Date.now();
  const signature = signPayload(webhook.secret, timestamp, payload);
  const deliveryId = generateId('dlv');

  try {
    const response = await fetch(webhook.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-ApexMail-Webhook-Id': webhook.id,
        'X-ApexMail-Signature': signature,
        'X-ApexMail-Timestamp': timestamp.toString(),
        'X-ApexMail-Event': (payload.type as string) ?? 'unknown',
        'X-ApexMail-Delivery-Id': deliveryId,
        'User-Agent': 'ApexMail-Webhook/1.0',
        ...webhook.headers,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
    });

    // Record trigger result in database
    await webhooksRepo.recordTrigger(
      webhook.id,
      response.ok,
      response.ok ? undefined : `HTTP ${response.status}: ${response.statusText}`
    );

    if (response.ok) {
      return { success: true, statusCode: response.status };
    } else {
      return { success: false, statusCode: response.status, error: `HTTP ${response.status}: ${response.statusText}` };
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    await webhooksRepo.recordTrigger(webhook.id, false, errorMessage);
    return { success: false, error: errorMessage };
  }
}
