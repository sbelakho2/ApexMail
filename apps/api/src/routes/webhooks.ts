/**
 * Webhooks Routes - Manage webhook endpoints for event delivery
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv, AppContext } from '../app.js';
import { AuditLogsRepository } from '@apexmail/db';
import { ApiError } from '../middleware/error-handler.js';
import { createHash, randomBytes, createHmac, timingSafeEqual } from 'crypto';
import { generateId } from '@apexmail/lib';

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
  headers: z.record(z.string()).optional(),
  enabled: z.boolean().default(true),
  retryPolicy: z.object({
    maxRetries: z.number().int().min(0).max(10).default(3),
    retryDelay: z.number().int().min(1000).max(3600000).default(60000),
    backoffMultiplier: z.number().min(1).max(5).default(2),
  }).optional(),
  metadata: z.record(z.unknown()).optional(),
});

const updateWebhookSchema = createWebhookSchema.partial();

const testWebhookSchema = z.object({
  eventType: z.enum(eventTypes).default('message.delivered'),
});

// In-memory webhook store (in production, use database)
interface WebhookRecord {
  id: string;
  tenantId: string;
  name: string;
  url: string;
  events: string[];
  description?: string;
  secret: string;
  secretHash: string;
  headers?: Record<string, string>;
  enabled: boolean;
  retryPolicy: {
    maxRetries: number;
    retryDelay: number;
    backoffMultiplier: number;
  };
  metadata?: Record<string, unknown>;
  stats: {
    totalDeliveries: number;
    successfulDeliveries: number;
    failedDeliveries: number;
    lastDeliveryAt?: Date;
    lastSuccessAt?: Date;
    lastFailureAt?: Date;
    lastError?: string;
  };
  createdAt: Date;
  updatedAt: Date;
}

const webhooksStore = new Map<string, WebhookRecord>();
const webhooksByTenant = new Map<string, Set<string>>();

export function webhooksRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const auditRepo = new AuditLogsRepository(ctx.db);

  // Create webhook
  router.post('/', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const logger = c.get('logger');

    const body = await c.req.json();
    const input = createWebhookSchema.parse(body);

    // Validate URL is HTTPS in production
    const url = new URL(input.url);
    if (process.env.NODE_ENV === 'production' && url.protocol !== 'https:') {
      throw ApiError.badRequest('Webhook URL must use HTTPS in production');
    }

    // Generate or use provided secret
    const secret = input.secret ?? randomBytes(32).toString('hex');
    const secretHash = createHash('sha256').update(secret).digest('hex');

    const webhook: WebhookRecord = {
      id: generateId('whk'),
      tenantId,
      name: input.name,
      url: input.url,
      events: input.events,
      description: input.description,
      secret,
      secretHash,
      headers: input.headers,
      enabled: input.enabled,
      retryPolicy: {
        maxRetries: input.retryPolicy?.maxRetries ?? 3,
        retryDelay: input.retryPolicy?.retryDelay ?? 60000,
        backoffMultiplier: input.retryPolicy?.backoffMultiplier ?? 2,
      },
      metadata: input.metadata,
      stats: {
        totalDeliveries: 0,
        successfulDeliveries: 0,
        failedDeliveries: 0,
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    webhooksStore.set(webhook.id, webhook);
    
    let tenantWebhooks = webhooksByTenant.get(tenantId);
    if (!tenantWebhooks) {
      tenantWebhooks = new Set();
      webhooksByTenant.set(tenantId, tenantWebhooks);
    }
    tenantWebhooks.add(webhook.id);

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
        description: webhook.description,
        secret: webhook.secret, // Only returned on creation
        enabled: webhook.enabled,
        retryPolicy: webhook.retryPolicy,
        createdAt: webhook.createdAt,
      },
    }, 201);
  });

  // Get webhook by ID
  router.get('/:id', async (c) => {
    const tenantId = c.get('tenantId');
    const webhookId = c.req.param('id');

    const webhook = webhooksStore.get(webhookId);
    if (!webhook || webhook.tenantId !== tenantId) {
      throw ApiError.notFound('Webhook');
    }

    return c.json({
      webhook: {
        id: webhook.id,
        name: webhook.name,
        url: webhook.url,
        events: webhook.events,
        description: webhook.description,
        headers: webhook.headers,
        enabled: webhook.enabled,
        retryPolicy: webhook.retryPolicy,
        stats: webhook.stats,
        createdAt: webhook.createdAt,
        updatedAt: webhook.updatedAt,
      },
    });
  });

  // List webhooks
  router.get('/', async (c) => {
    const tenantId = c.get('tenantId');
    const enabled = c.req.query('enabled');
    const event = c.req.query('event');

    const tenantWebhooks = webhooksByTenant.get(tenantId);
    if (!tenantWebhooks || tenantWebhooks.size === 0) {
      return c.json({ webhooks: [], total: 0 });
    }

    let webhooks = Array.from(tenantWebhooks)
      .map(id => webhooksStore.get(id)!)
      .filter(w => w !== undefined);

    // Filter by enabled status
    if (enabled !== undefined) {
      const isEnabled = enabled === 'true';
      webhooks = webhooks.filter(w => w.enabled === isEnabled);
    }

    // Filter by event type
    if (event) {
      webhooks = webhooks.filter(w => w.events.includes(event) || w.events.includes('*'));
    }

    return c.json({
      webhooks: webhooks.map(w => ({
        id: w.id,
        name: w.name,
        url: w.url,
        events: w.events,
        enabled: w.enabled,
        stats: {
          totalDeliveries: w.stats.totalDeliveries,
          successfulDeliveries: w.stats.successfulDeliveries,
          failedDeliveries: w.stats.failedDeliveries,
          lastDeliveryAt: w.stats.lastDeliveryAt,
        },
        createdAt: w.createdAt,
        updatedAt: w.updatedAt,
      })),
      total: webhooks.length,
    });
  });

  // Update webhook
  router.patch('/:id', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

    const webhook = webhooksStore.get(webhookId);
    if (!webhook || webhook.tenantId !== tenantId) {
      throw ApiError.notFound('Webhook');
    }

    const body = await c.req.json();
    const input = updateWebhookSchema.parse(body);

    // Validate URL if provided
    if (input.url) {
      const url = new URL(input.url);
      if (process.env.NODE_ENV === 'production' && url.protocol !== 'https:') {
        throw ApiError.badRequest('Webhook URL must use HTTPS in production');
      }
    }

    // Update fields
    if (input.name !== undefined) webhook.name = input.name;
    if (input.url !== undefined) webhook.url = input.url;
    if (input.events !== undefined) webhook.events = input.events;
    if (input.description !== undefined) webhook.description = input.description;
    if (input.headers !== undefined) webhook.headers = input.headers;
    if (input.enabled !== undefined) webhook.enabled = input.enabled;
    if (input.metadata !== undefined) webhook.metadata = input.metadata;
    if (input.retryPolicy) {
      webhook.retryPolicy = {
        maxRetries: input.retryPolicy.maxRetries ?? webhook.retryPolicy.maxRetries,
        retryDelay: input.retryPolicy.retryDelay ?? webhook.retryPolicy.retryDelay,
        backoffMultiplier: input.retryPolicy.backoffMultiplier ?? webhook.retryPolicy.backoffMultiplier,
      };
    }

    webhook.updatedAt = new Date();

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
  router.post('/:id/rotate-secret', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

    const webhook = webhooksStore.get(webhookId);
    if (!webhook || webhook.tenantId !== tenantId) {
      throw ApiError.notFound('Webhook');
    }

    const newSecret = randomBytes(32).toString('hex');
    webhook.secret = newSecret;
    webhook.secretHash = createHash('sha256').update(newSecret).digest('hex');
    webhook.updatedAt = new Date();

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'webhook.secret_rotated',
      resourceType: 'webhook',
      resourceId: webhook.id,
    });

    logger.info('Webhook secret rotated', { webhookId });

    return c.json({
      webhook: {
        id: webhook.id,
        secret: webhook.secret,
        rotatedAt: webhook.updatedAt,
      },
    });
  });

  // Test webhook
  router.post('/:id/test', async (c) => {
    const tenantId = c.get('tenantId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

    const webhook = webhooksStore.get(webhookId);
    if (!webhook || webhook.tenantId !== tenantId) {
      throw ApiError.notFound('Webhook');
    }

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
        signal: AbortSignal.timeout(30000),
      });

      const duration = Date.now() - startTime;
      const responseBody = await response.text().catch(() => '');

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
          responseBody: responseBody.substring(0, 1000),
          requestPayload: testPayload,
          headers: {
            'X-ApexMail-Signature': signature,
            'X-ApexMail-Timestamp': timestamp.toString(),
          },
        },
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      logger.warn('Webhook test failed', { webhookId, error: errorMessage });

      return c.json({
        success: false,
        test: {
          eventType,
          url: webhook.url,
          error: errorMessage,
          requestPayload: testPayload,
        },
      });
    }
  });

  // Get webhook deliveries
  router.get('/:id/deliveries', async (c) => {
    const tenantId = c.get('tenantId');
    const webhookId = c.req.param('id');
    const status = c.req.query('status');
    const limit = parseInt(c.req.query('limit') ?? '50', 10);

    const webhook = webhooksStore.get(webhookId);
    if (!webhook || webhook.tenantId !== tenantId) {
      throw ApiError.notFound('Webhook');
    }

    // In production, fetch from database
    // For now, return stats-based summary
    return c.json({
      deliveries: [],
      summary: {
        total: webhook.stats.totalDeliveries,
        successful: webhook.stats.successfulDeliveries,
        failed: webhook.stats.failedDeliveries,
        successRate: webhook.stats.totalDeliveries > 0
          ? ((webhook.stats.successfulDeliveries / webhook.stats.totalDeliveries) * 100).toFixed(2) + '%'
          : 'N/A',
        lastDeliveryAt: webhook.stats.lastDeliveryAt,
        lastSuccessAt: webhook.stats.lastSuccessAt,
        lastFailureAt: webhook.stats.lastFailureAt,
        lastError: webhook.stats.lastError,
      },
      limit,
      status,
    });
  });

  // Enable webhook
  router.post('/:id/enable', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

    const webhook = webhooksStore.get(webhookId);
    if (!webhook || webhook.tenantId !== tenantId) {
      throw ApiError.notFound('Webhook');
    }

    webhook.enabled = true;
    webhook.updatedAt = new Date();

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'webhook.enabled',
      resourceType: 'webhook',
      resourceId: webhook.id,
    });

    logger.info('Webhook enabled', { webhookId });

    return c.json({
      webhook: {
        id: webhook.id,
        enabled: webhook.enabled,
        updatedAt: webhook.updatedAt,
      },
    });
  });

  // Disable webhook
  router.post('/:id/disable', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

    const webhook = webhooksStore.get(webhookId);
    if (!webhook || webhook.tenantId !== tenantId) {
      throw ApiError.notFound('Webhook');
    }

    webhook.enabled = false;
    webhook.updatedAt = new Date();

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'webhook.disabled',
      resourceType: 'webhook',
      resourceId: webhook.id,
    });

    logger.info('Webhook disabled', { webhookId });

    return c.json({
      webhook: {
        id: webhook.id,
        enabled: webhook.enabled,
        updatedAt: webhook.updatedAt,
      },
    });
  });

  // Delete webhook
  router.delete('/:id', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

    const webhook = webhooksStore.get(webhookId);
    if (!webhook || webhook.tenantId !== tenantId) {
      throw ApiError.notFound('Webhook');
    }

    webhooksStore.delete(webhookId);
    webhooksByTenant.get(tenantId)?.delete(webhookId);

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
  router.post('/verify-signature', async (c) => {
    const body = await c.req.json();
    const schema = z.object({
      payload: z.unknown(),
      signature: z.string(),
      timestamp: z.number(),
      secret: z.string(),
    });
    
    const { payload, signature, timestamp, secret } = schema.parse(body);

    // Check timestamp is within 5 minutes
    const now = Date.now();
    if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
      return c.json({
        valid: false,
        reason: 'Timestamp too old or in future',
      });
    }

    const expectedSignature = signPayload(secret, timestamp, payload);
    
    try {
      const valid = timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
      );

      return c.json({
        valid,
        reason: valid ? 'Signature verified' : 'Signature mismatch',
      });
    } catch {
      return c.json({
        valid: false,
        reason: 'Invalid signature format',
      });
    }
  });

  return router;
}

function signPayload(secret: string, timestamp: number, payload: unknown): string {
  const message = `${timestamp}.${JSON.stringify(payload)}`;
  return 'sha256=' + createHmac('sha256', secret).update(message).digest('hex');
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
export function getWebhooksForEvent(
  tenantId: string,
  eventType: string
): WebhookRecord[] {
  const tenantWebhooks = webhooksByTenant.get(tenantId);
  if (!tenantWebhooks) return [];

  return Array.from(tenantWebhooks)
    .map(id => webhooksStore.get(id)!)
    .filter(w => w && w.enabled && (w.events.includes(eventType) || w.events.includes('*')));
}

export async function deliverWebhook(
  webhook: WebhookRecord,
  payload: Record<string, unknown>
): Promise<{ success: boolean; statusCode?: number; error?: string }> {
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
      signal: AbortSignal.timeout(30000),
    });

    // Update stats
    webhook.stats.totalDeliveries++;
    webhook.stats.lastDeliveryAt = new Date();

    if (response.ok) {
      webhook.stats.successfulDeliveries++;
      webhook.stats.lastSuccessAt = new Date();
      return { success: true, statusCode: response.status };
    } else {
      webhook.stats.failedDeliveries++;
      webhook.stats.lastFailureAt = new Date();
      webhook.stats.lastError = `HTTP ${response.status}: ${response.statusText}`;
      return { success: false, statusCode: response.status, error: webhook.stats.lastError };
    }
  } catch (error) {
    webhook.stats.totalDeliveries++;
    webhook.stats.failedDeliveries++;
    webhook.stats.lastFailureAt = new Date();
    webhook.stats.lastError = error instanceof Error ? error.message : 'Unknown error';
    return { success: false, error: webhook.stats.lastError };
  }
}
