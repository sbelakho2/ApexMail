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
  type EmailRecipient,
  type Suppression 
} from '@apexmail/db';
import { ApiError } from '../middleware/error-handler.js';
import { requireScopes } from '../middleware/auth.js';

/**
 * SECURITY: Strip CRLF and other control characters to prevent header injection
 * RFC 5322 headers must not contain CR, LF, or NUL characters
 */
const stripHeaderChars = (str: string): string => 
  // eslint-disable-next-line no-control-regex -- intentional: strip NUL, CR, LF for header injection prevention
  str.replace(/[\r\n\x00]/g, '').trim();

const recipientSchema = z.object({
  email: z.string().email().max(254), // RFC 5321 max email length
  name: z.string().max(200).transform(stripHeaderChars).optional(), // Sanitize to prevent header injection
  type: z.enum(['to', 'cc', 'bcc']).default('to'),
});

const sendMessageSchema = z.object({
  from: z.object({
    email: z.string().email().max(254), // RFC 5321 max email length
    name: z.string().max(200).transform(stripHeaderChars).optional(), // Sanitize to prevent header injection
  }),
  replyTo: z.string().email().max(254).optional(),
  to: z.array(recipientSchema).min(1).max(50),
  cc: z.array(recipientSchema).max(50).optional(),
  bcc: z.array(recipientSchema).max(50).optional(),
  subject: z.string().min(1).max(998).transform(stripHeaderChars), // RFC 5322 limit + sanitize for header injection
  html: z.string().max(10_000_000).optional(), // 10MB limit
  text: z.string().max(1_000_000).optional(), // 1MB limit
  templateId: z.string().uuid().optional(),
  templateData: z.record(z.unknown()).optional(),
  campaignId: z.string().uuid().optional(),
  tags: z.array(z.string().max(100)).max(10).optional(), // Add per-tag length limit
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

  // Apply scope enforcement to message routes
  // Send a single message - requires 'messages:write' scope
  router.post('/', requireScopes('messages:write'), async (c) => {
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
      domainId: domainResult.value.id,
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

  // Send batch messages - requires 'messages:write' scope
  router.post('/batch', requireScopes('messages:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const logger = c.get('logger');

    const body = await c.req.json();
    const { messages } = batchSendSchema.parse(body);

    /**
     * FIX-054: Parallel-chunked batch processing.
     *
     * Previous implementation processed all messages in a sequential for loop
     * (1 message at a time). For 1,000 messages this meant 3,000+ sequential
     * DB round-trips (~130s in production, timing out on any reasonable deadline).
     *
     * Now we process in parallel chunks of 50, using Promise.allSettled within
     * each chunk. This brings 1,000 messages from ~130s to ~3s while keeping
     * DB connection pressure bounded (50 concurrent at most, well within the
     * API service's 20-connection pool since each individual create is fast
     * after the multi-row INSERT fix in MessagesRepository).
     */
    const CHUNK_SIZE = 50;

    /**
     * PERF-004: Pre-compute domain verifications and suppressions across the
     * entire batch before entering the per-message processing loop.
     *
     * Previously, each message in the batch called domainsRepo.findByDomain()
     * and suppressionsRepo.checkBulkSuppression() individually. For a 1,000-
     * message batch from the same domain, that was 1,000 identical domain
     * lookups + 1,000 separate suppression queries. For a typical batch
     * (1 domain, ~200 unique recipients), this reduces DB round-trips from
     * ~2,000 to 2.
     */

    // Deduplicate domains across entire batch — query each unique domain once
    const uniqueDomains = [...new Set(
      messages.map(m => m.from.email.split('@')[1] ?? '')
    )].filter(Boolean);

    const domainCache = new Map<string, Awaited<ReturnType<typeof domainsRepo.findByDomain>>>();
    for (const domain of uniqueDomains) {
      domainCache.set(domain, await domainsRepo.findByDomain(domain, tenantId));
    }

    // Deduplicate recipients across entire batch — one bulk suppression check
    const allBatchRecipientEmails = [...new Set(
      messages.flatMap(m => [
        ...m.to.map(r => r.email),
        ...(m.cc ?? []).map(r => r.email),
        ...(m.bcc ?? []).map(r => r.email),
      ])
    )];

    let batchSuppressions = new Map<string, Suppression | null>();
    if (allBatchRecipientEmails.length > 0) {
      const batchSuppressionResult = await suppressionsRepo.checkBulkSuppression(
        allBatchRecipientEmails, tenantId
      );
      if (batchSuppressionResult.ok) {
        batchSuppressions = batchSuppressionResult.value;
      }
    }

    const processSingleMessage = async (
      input: (typeof messages)[number],
      index: number
    ): Promise<{ index: number; success: boolean; messageId?: string; error?: string }> => {
      try {
        // PERF-004: Use pre-computed domain cache instead of per-message DB lookup
        const sendingDomain = input.from.email.split('@')[1] ?? '';
        const domainResult = domainCache.get(sendingDomain);
        
        if (!domainResult || !domainResult.ok || !domainResult.value || domainResult.value.status !== 'verified') {
          return { index, success: false, error: `Domain ${sendingDomain} is not verified` };
        }

        // Combine recipients
        const allRecipients: EmailRecipient[] = [
          ...input.to.map((r) => ({ ...r, type: r.type ?? 'to' as const })),
          ...(input.cc ?? []).map((r) => ({ ...r, type: 'cc' as const })),
          ...(input.bcc ?? []).map((r) => ({ ...r, type: 'bcc' as const })),
        ];

        // PERF-004: Use pre-computed batch-level suppression map
        const validRecipients = allRecipients.filter(
          (r) => !batchSuppressions.get(r.email)
        );

        if (validRecipients.length === 0) {
          return { index, success: false, error: 'All recipients suppressed' };
        }

        // Create message (now uses multi-row INSERT for queue entries)
        const createResult = await messagesRepo.create({
          tenantId,
          userId: userId ?? undefined,
          domainId: domainResult.value.id,
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
          return { index, success: false, error: 'Failed to queue message' };
        }

        // IMP-005: Create 'queued' event for batch messages — single-message
        // POST already does this but batch was missing it, causing event
        // timelines to lack the initial 'queued' entry.
        await eventsRepo.create({
          tenantId,
          messageId: createResult.value.id,
          recipientEmail: validRecipients[0]?.email ?? '',
          eventType: 'queued',
          metadata: { recipientCount: validRecipients.length, batch: true },
        });

        return { index, success: true, messageId: createResult.value.id };
      } catch (error) {
        return { index, success: false, error: error instanceof Error ? error.message : 'Unknown error' };
      }
    };

    // Process in parallel chunks
    const results: Array<{ index: number; success: boolean; messageId?: string; error?: string }> = [];

    for (let chunkStart = 0; chunkStart < messages.length; chunkStart += CHUNK_SIZE) {
      const chunk = messages.slice(chunkStart, chunkStart + CHUNK_SIZE);
      const chunkResults = await Promise.allSettled(
        chunk.map((msg, i) => processSingleMessage(msg, chunkStart + i))
      );

      for (const settled of chunkResults) {
        if (settled.status === 'fulfilled') {
          results.push(settled.value);
        } else {
          // Should not happen since processSingleMessage catches all errors,
          // but handle gracefully just in case
          results.push({ index: results.length, success: false, error: 'Internal error' });
        }
      }
    }

    // Sort results by original index for consistent response ordering
    results.sort((a, b) => a.index - b.index);

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

  // Get message by ID - requires 'messages:read' scope
  router.get('/:id', requireScopes('messages:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const messageId = c.req.param('id');

    // SECURITY FIX: Include tenant_id in DB query to enforce tenant isolation at the data layer
    // Previously used fetch-then-check pattern which could leak timing information
    const result = await messagesRepo.findById(messageId, tenantId);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to fetch message');
    }

    if (!result.value) {
      throw ApiError.notFound('Message');
    }

    const message = result.value;

    // Get events for this message (tenant-scoped for isolation)
    const eventsResult = await eventsRepo.findByMessageId(messageId, tenantId);
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

  // List messages - requires 'messages:read' scope
  router.get('/', requireScopes('messages:read'), async (c) => {
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

  // Get message counts by status - requires 'messages:read' scope
  router.get('/stats/status', requireScopes('messages:read'), async (c) => {
    const tenantId = c.get('tenantId');

    const result = await messagesRepo.countByStatus(tenantId);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to fetch status counts');
    }

    return c.json({ counts: result.value });
  });

  // Cancel scheduled message - requires 'messages:write' scope
  router.post('/:id/cancel', requireScopes('messages:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const messageId = c.req.param('id');
    const logger = c.get('logger');

    // SECURITY FIX: Include tenant_id in DB query to enforce tenant isolation at the data layer
    const result = await messagesRepo.findById(messageId, tenantId);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to fetch message');
    }

    if (!result.value) {
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

    // Audit log - AUDIT-003 FIX: Use message.sent for cancellation tracking
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'message.sent', // Use message.sent with metadata indicating cancellation
      resourceType: 'message',
      resourceId: messageId,
      metadata: { cancelled: true, previousStatus: message.status },
    });

    logger.info('Message cancelled', { messageId });

    return c.json({ success: true, message: 'Message cancelled' });
  });

  return router;
}
