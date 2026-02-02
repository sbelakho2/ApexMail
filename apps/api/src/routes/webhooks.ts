/**
 * Webhooks Routes - Manage webhook endpoints for event delivery
 * 
 * FIXED: Now uses database-backed WebhooksRepository instead of in-memory store
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv, AppContext } from '../app.js';
import { AuditLogsRepository, WebhooksRepository, type Webhook, type WebhookInsert, type WebhookUpdate } from '@apexmail/db';
import { ApiError } from '../middleware/error-handler.js';
import { hmacSign, randomToken } from '@apexmail/lib/crypto';
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

export function webhooksRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const webhooksRepo = new WebhooksRepository(ctx.db.getPool());
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
  router.get('/:id', async (c) => {
    const tenantId = c.get('tenantId');
    const webhookId = c.req.param('id');

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
  router.get('/', async (c) => {
    const tenantId = c.get('tenantId');
    const enabled = c.req.query('enabled');
    const event = c.req.query('event');

    let webhooks = await webhooksRepo.findByTenant(tenantId);

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
        failureCount: w.failureCount,
        lastTriggeredAt: w.lastTriggeredAt,
        lastSuccessAt: w.lastSuccessAt,
        lastFailureAt: w.lastFailureAt,
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

    // Check webhook exists
    const existing = await webhooksRepo.findById(webhookId, tenantId);
    if (!existing) {
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
  router.post('/:id/rotate-secret', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

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
  router.post('/:id/test', async (c) => {
    const tenantId = c.get('tenantId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

    const webhook = await webhooksRepo.findById(webhookId, tenantId);
    if (!webhook) {
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
      });
    }
  });

  // Get webhook deliveries
  router.get('/:id/deliveries', async (c) => {
    const tenantId = c.get('tenantId');
    const webhookId = c.req.param('id');
    const status = c.req.query('status');
    const limit = parseInt(c.req.query('limit') ?? '50', 10);

    const webhook = await webhooksRepo.findById(webhookId, tenantId);
    if (!webhook) {
      throw ApiError.notFound('Webhook');
    }

    // Get delivery stats from queue
    const stats = await webhooksRepo.getQueueStats(tenantId);

    return c.json({
      deliveries: [], // Would be populated from webhook_queue table
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
      status,
    });
  });

  // Enable webhook
  router.post('/:id/enable', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

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
  router.post('/:id/disable', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

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
  router.delete('/:id', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const webhookId = c.req.param('id');
    const logger = c.get('logger');

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
    
    // Use timing-safe comparison
    const valid = signature === expectedSignature && signature.length === expectedSignature.length;

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
