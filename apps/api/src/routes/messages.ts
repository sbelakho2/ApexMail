/**
 * Messages Routes - Core email sending API
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv, AppContext } from '../app.js';
import { 
  MessagesRepository, 
  SuppressionsRepository, 
  DomainsRepository,
  EventsRepository,
  AuditLogsRepository,
  type EmailRecipient 
} from '@apexmail/db';
import { ApiError } from '../middleware/error-handler.js';

const recipientSchema = z.object({
  email: z.string().email(),
  name: z.string().optional(),
  type: z.enum(['to', 'cc', 'bcc']).default('to'),
});

const sendMessageSchema = z.object({
  from: z.object({
    email: z.string().email(),
    name: z.string().optional(),
  }),
  replyTo: z.string().email().optional(),
  to: z.array(recipientSchema).min(1).max(50),
  cc: z.array(recipientSchema).max(50).optional(),
  bcc: z.array(recipientSchema).max(50).optional(),
  subject: z.string().min(1).max(998), // RFC 5322 limit
  html: z.string().max(10_000_000).optional(), // 10MB limit
  text: z.string().max(1_000_000).optional(), // 1MB limit
  templateId: z.string().uuid().optional(),
  templateData: z.record(z.unknown()).optional(),
  campaignId: z.string().uuid().optional(),
  tags: z.array(z.string()).max(10).optional(),
  priority: z.enum(['high', 'normal', 'low']).default('normal'),
  scheduledAt: z.string().datetime().optional(),
  metadata: z.record(z.unknown()).optional(),
}).refine(
  (data) => data.html || data.text || data.templateId,
  { message: 'Either html, text, or templateId must be provided' }
);

const batchSendSchema = z.object({
  messages: z.array(sendMessageSchema).min(1).max(1000),
});

export function messagesRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const messagesRepo = new MessagesRepository(ctx.db);
  const suppressionsRepo = new SuppressionsRepository(ctx.db);
  const domainsRepo = new DomainsRepository(ctx.db);
  const eventsRepo = new EventsRepository(ctx.db);
  const auditRepo = new AuditLogsRepository(ctx.db);

  // Send a single message
  router.post('/', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const logger = c.get('logger');
    const idempotencyKey = c.req.header('X-Idempotency-Key');

    const body = await c.req.json();
    const input = sendMessageSchema.parse(body);

    // Verify sending domain is verified
    const sendingDomain = input.from.email.split('@')[1] ?? '';
    const domainResult = await domainsRepo.findByDomain(sendingDomain, tenantId);
    
    if (!domainResult.ok) {
      throw ApiError.internal('Failed to verify domain');
    }

    if (!domainResult.value || domainResult.value.status !== 'verified') {
      throw ApiError.badRequest(
        `Domain ${sendingDomain} is not verified. Please add and verify the domain first.`,
        'DOMAIN_NOT_VERIFIED'
      );
    }

    // Combine all recipients
    const allRecipients: EmailRecipient[] = [
      ...input.to.map((r) => ({ ...r, type: r.type ?? 'to' as const })),
      ...(input.cc ?? []).map((r) => ({ ...r, type: 'cc' as const })),
      ...(input.bcc ?? []).map((r) => ({ ...r, type: 'bcc' as const })),
    ];

    // Check suppressions for all recipients
    const recipientEmails = allRecipients.map((r) => r.email);
    const suppressionResult = await suppressionsRepo.checkBulkSuppression(recipientEmails, tenantId);
    
    if (!suppressionResult.ok) {
      throw ApiError.internal('Failed to check suppressions');
    }

    // Filter out suppressed recipients
    const suppressedEmails: string[] = [];
    const validRecipients: EmailRecipient[] = [];

    for (const recipient of allRecipients) {
      const suppression = suppressionResult.value.get(recipient.email);
      if (suppression) {
        suppressedEmails.push(recipient.email);
        logger.info('Recipient suppressed', {
          email: recipient.email,
          suppressionType: suppression.type,
          suppressionId: suppression.id,
        });
      } else {
        validRecipients.push(recipient);
      }
    }

    // If all recipients are suppressed, return error
    if (validRecipients.length === 0) {
      throw ApiError.badRequest(
        'All recipients are suppressed',
        'ALL_RECIPIENTS_SUPPRESSED',
        { suppressedEmails }
      );
    }

    // Create the message
    const createResult = await messagesRepo.create({
      tenantId,
      userId: userId ?? undefined,
      idempotencyKey: idempotencyKey ?? undefined,
      fromEmail: input.from.email,
      fromName: input.from.name,
      replyTo: input.replyTo,
      recipients: validRecipients,
      subject: input.subject,
      htmlBody: input.html,
      textBody: input.text,
      templateId: input.templateId,
      templateData: input.templateData,
      campaignId: input.campaignId,
      tags: input.tags,
      priority: input.priority,
      scheduledAt: input.scheduledAt ? new Date(input.scheduledAt) : undefined,
      metadata: input.metadata,
    });

    if (!createResult.ok) {
      logger.error('Failed to create message', { error: createResult.error });
      throw ApiError.internal('Failed to queue message');
    }

    const message = createResult.value;

    // Create queued event
    await eventsRepo.create({
      tenantId,
      messageId: message.id,
      recipientEmail: validRecipients[0]?.email ?? '',
      eventType: 'queued',
      metadata: { recipientCount: validRecipients.length },
    });

    logger.info('Message queued', {
      messageId: message.id,
      recipientCount: validRecipients.length,
      suppressedCount: suppressedEmails.length,
      scheduled: !!input.scheduledAt,
    });

    return c.json({
      message: {
        id: message.id,
        messageId: message.messageId,
        status: message.status,
        recipients: validRecipients.length,
        scheduledAt: message.scheduledAt,
        createdAt: message.createdAt,
      },
      ...(suppressedEmails.length > 0 && {
        suppressed: {
          count: suppressedEmails.length,
          emails: suppressedEmails,
        },
      }),
    }, 202);
  });

  // Send batch messages
  router.post('/batch', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const logger = c.get('logger');

    const body = await c.req.json();
    const { messages } = batchSendSchema.parse(body);

    const results: Array<{
      index: number;
      success: boolean;
      messageId?: string;
      error?: string;
    }> = [];

    // Process each message
    for (let i = 0; i < messages.length; i++) {
      const input = messages[i];
      if (!input) continue;

      try {
        // Verify sending domain
        const sendingDomain = input.from.email.split('@')[1] ?? '';
        const domainResult = await domainsRepo.findByDomain(sendingDomain, tenantId);
        
        if (!domainResult.ok || !domainResult.value || domainResult.value.status !== 'verified') {
          results.push({
            index: i,
            success: false,
            error: `Domain ${sendingDomain} is not verified`,
          });
          continue;
        }

        // Combine recipients
        const allRecipients: EmailRecipient[] = [
          ...input.to.map((r) => ({ ...r, type: r.type ?? 'to' as const })),
          ...(input.cc ?? []).map((r) => ({ ...r, type: 'cc' as const })),
          ...(input.bcc ?? []).map((r) => ({ ...r, type: 'bcc' as const })),
        ];

        // Check suppressions
        const recipientEmails = allRecipients.map((r) => r.email);
        const suppressionResult = await suppressionsRepo.checkBulkSuppression(recipientEmails, tenantId);
        
        if (!suppressionResult.ok) {
          results.push({
            index: i,
            success: false,
            error: 'Failed to check suppressions',
          });
          continue;
        }

        // Filter suppressed
        const validRecipients = allRecipients.filter(
          (r) => !suppressionResult.value.get(r.email)
        );

        if (validRecipients.length === 0) {
          results.push({
            index: i,
            success: false,
            error: 'All recipients suppressed',
          });
          continue;
        }

        // Create message
        const createResult = await messagesRepo.create({
          tenantId,
          userId: userId ?? undefined,
          fromEmail: input.from.email,
          fromName: input.from.name,
          replyTo: input.replyTo,
          recipients: validRecipients,
          subject: input.subject,
          htmlBody: input.html,
          textBody: input.text,
          templateId: input.templateId,
          templateData: input.templateData,
          campaignId: input.campaignId,
          tags: input.tags,
          priority: input.priority,
          scheduledAt: input.scheduledAt ? new Date(input.scheduledAt) : undefined,
          metadata: input.metadata,
        });

        if (!createResult.ok) {
          results.push({
            index: i,
            success: false,
            error: 'Failed to queue message',
          });
          continue;
        }

        results.push({
          index: i,
          success: true,
          messageId: createResult.value.id,
        });
      } catch (error) {
        results.push({
          index: i,
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    }

    const successCount = results.filter((r) => r.success).length;
    logger.info('Batch send completed', {
      total: messages.length,
      success: successCount,
      failed: messages.length - successCount,
    });

    return c.json({
      results,
      summary: {
        total: messages.length,
        success: successCount,
        failed: messages.length - successCount,
      },
    }, 202);
  });

  // Get message by ID
  router.get('/:id', async (c) => {
    const tenantId = c.get('tenantId');
    const messageId = c.req.param('id');

    const result = await messagesRepo.findById(messageId);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to fetch message');
    }

    if (!result.value || result.value.tenantId !== tenantId) {
      throw ApiError.notFound('Message');
    }

    const message = result.value;

    // Get events for this message
    const eventsResult = await eventsRepo.findByMessageId(messageId);
    const events = eventsResult.ok ? eventsResult.value : [];

    return c.json({
      message: {
        id: message.id,
        messageId: message.messageId,
        status: message.status,
        from: {
          email: message.fromEmail,
          name: message.fromName,
        },
        recipients: message.recipients,
        subject: message.subject,
        templateId: message.templateId,
        campaignId: message.campaignId,
        tags: message.tags,
        priority: message.priority,
        scheduledAt: message.scheduledAt,
        sentAt: message.sentAt,
        deliveredAt: message.deliveredAt,
        bouncedAt: message.bouncedAt,
        bounceType: message.bounceType,
        bounceReason: message.bounceReason,
        attempts: message.attempts,
        metadata: message.metadata,
        createdAt: message.createdAt,
        updatedAt: message.updatedAt,
      },
      events: events.map((e) => ({
        id: e.id,
        type: e.eventType,
        timestamp: e.timestamp,
        ipAddress: e.ipAddress,
        userAgent: e.userAgent,
        location: e.location,
        linkUrl: e.linkUrl,
        bounceType: e.bounceType,
        bounceReason: e.bounceReason,
      })),
    });
  });

  // List messages
  router.get('/', async (c) => {
    const tenantId = c.get('tenantId');
    const status = c.req.query('status') as 'pending' | 'queued' | 'sending' | 'sent' | 'delivered' | 'bounced' | 'deferred' | 'failed' | undefined;
    const campaignId = c.req.query('campaignId');
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');
    const limit = parseInt(c.req.query('limit') ?? '50', 10);
    const offset = parseInt(c.req.query('offset') ?? '0', 10);

    const result = await messagesRepo.listByTenant(tenantId, {
      status,
      campaignId,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      limit: Math.min(limit, 100),
      offset,
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch messages');
    }

    return c.json({
      messages: result.value.messages.map((m) => ({
        id: m.id,
        messageId: m.messageId,
        status: m.status,
        from: m.fromEmail,
        subject: m.subject,
        recipientCount: m.recipients.length,
        campaignId: m.campaignId,
        scheduledAt: m.scheduledAt,
        sentAt: m.sentAt,
        createdAt: m.createdAt,
      })),
      pagination: {
        total: result.value.total,
        limit,
        offset,
        hasMore: offset + result.value.messages.length < result.value.total,
      },
    });
  });

  // Get message counts by status
  router.get('/stats/status', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await messagesRepo.countByStatus(tenantId);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to fetch status counts');
    }

    return c.json({ counts: result.value });
  });

  // Cancel scheduled message
  router.post('/:id/cancel', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const messageId = c.req.param('id');
    const logger = c.get('logger');

    const result = await messagesRepo.findById(messageId);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to fetch message');
    }

    if (!result.value || result.value.tenantId !== tenantId) {
      throw ApiError.notFound('Message');
    }

    const message = result.value;

    // Can only cancel pending (scheduled) messages
    if (message.status !== 'pending') {
      throw ApiError.badRequest(
        `Cannot cancel message with status '${message.status}'`,
        'INVALID_STATUS'
      );
    }

    // Mark as failed/cancelled
    const updateResult = await messagesRepo.markFailed(messageId, 'Cancelled by user');
    
    if (!updateResult.ok) {
      throw ApiError.internal('Failed to cancel message');
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'message.sent',
      resourceType: 'message',
      resourceId: messageId,
      metadata: { cancelled: true },
    });

    logger.info('Message cancelled', { messageId });

    return c.json({ success: true, message: 'Message cancelled' });
  });

  return router;
}
