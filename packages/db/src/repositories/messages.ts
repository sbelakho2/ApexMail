/**
 * Messages Repository - Outbox with idempotency and full message lifecycle
 */

import { Result } from '@apexmail/lib';
import { generateUuid, generateMessageId, generateVerpAddress } from '@apexmail/lib/id';
import type { DatabasePool } from '../pool.js';

export interface EmailRecipient {
  email: string;
  name?: string;
  type: 'to' | 'cc' | 'bcc';
}

export interface EmailAttachment {
  filename: string;
  contentType: string;
  size: number;
  storageKey: string;
  contentId?: string; // For inline attachments
  checksum: string;
}

export interface MessageHeaders {
  'Message-ID': string;
  'X-ApexMail-ID': string;
  'X-ApexMail-Tenant': string;
  'X-ApexMail-Campaign'?: string;
  'Return-Path': string;
  'List-Unsubscribe'?: string;
  'List-Unsubscribe-Post'?: string;
  'Feedback-ID'?: string;
  [key: string]: string | undefined;
}

export interface Message {
  id: string;
  tenantId: string;
  userId: string | null;
  idempotencyKey: string | null;
  messageId: string; // RFC 5322 Message-ID
  status: 'pending' | 'queued' | 'sending' | 'sent' | 'delivered' | 'bounced' | 'deferred' | 'failed';
  fromEmail: string;
  fromName: string | null;
  replyTo: string | null;
  recipients: EmailRecipient[];
  subject: string;
  htmlBody: string | null;
  textBody: string | null;
  headers: MessageHeaders;
  attachments: EmailAttachment[];
  templateId: string | null;
  templateData: Record<string, unknown> | null;
  campaignId: string | null;
  tags: string[];
  priority: 'high' | 'normal' | 'low';
  scheduledAt: Date | null;
  sentAt: Date | null;
  deliveredAt: Date | null;
  bouncedAt: Date | null;
  bounceType: 'hard' | 'soft' | null;
  bounceReason: string | null;
  mtaMessageId: string | null;
  ipAddress: string | null;
  sendingDomain: string;
  attempts: number;
  maxAttempts: number;
  lastAttemptAt: Date | null;
  nextAttemptAt: Date | null;
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateMessageInput {
  tenantId: string;
  userId?: string;
  idempotencyKey?: string;
  domainId?: string; // Required for email queue
  fromEmail: string;
  fromName?: string;
  replyTo?: string;
  recipients: EmailRecipient[];
  subject: string;
  htmlBody?: string;
  textBody?: string;
  attachments?: Omit<EmailAttachment, 'checksum'>[];
  templateId?: string;
  templateData?: Record<string, unknown>;
  campaignId?: string;
  tags?: string[];
  priority?: Message['priority'];
  scheduledAt?: Date;
  metadata?: Record<string, unknown>;
}

export interface UpdateMessageInput {
  status?: Message['status'];
  sentAt?: Date;
  deliveredAt?: Date;
  bouncedAt?: Date;
  bounceType?: Message['bounceType'];
  bounceReason?: string;
  mtaMessageId?: string;
  ipAddress?: string;
  attempts?: number;
  lastAttemptAt?: Date;
  nextAttemptAt?: Date | null;
  metadata?: Record<string, unknown>;
}

export class MessagesRepository {
  constructor(private readonly db: DatabasePool) {}

  async create(input: CreateMessageInput): Promise<Result<Message, Error>> {
    // Check idempotency key first
    if (input.idempotencyKey) {
      const existing = await this.findByIdempotencyKey(input.idempotencyKey, input.tenantId);
      if (existing.ok && existing.value) {
        return Result.ok(existing.value);
      }
    }

    const id = generateUuid();
    const sendingDomain = input.fromEmail.split('@')[1] || '';
    const messageIdResult = generateMessageId(sendingDomain);
    const verpAddress = generateVerpAddress(id, sendingDomain);
    const now = new Date();

    const headers: MessageHeaders = {
      'Message-ID': messageIdResult,
      'X-ApexMail-ID': id,
      'X-ApexMail-Tenant': input.tenantId,
      'Return-Path': verpAddress,
    };

    if (input.campaignId) {
      headers['X-ApexMail-Campaign'] = input.campaignId;
      headers['Feedback-ID'] = `${input.campaignId}:${input.tenantId}:apexmail`;
    }

    const attachments: EmailAttachment[] = (input.attachments ?? []).map((att) => ({
      ...att,
      checksum: '', // Will be computed during upload
    }));

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      idempotency_key: string | null;
      message_id: string;
      status: Message['status'];
      from_email: string;
      from_name: string | null;
      reply_to: string | null;
      recipients: string;
      subject: string;
      html_body: string | null;
      text_body: string | null;
      headers: string;
      attachments: string;
      template_id: string | null;
      template_data: string | null;
      campaign_id: string | null;
      tags: string[];
      priority: Message['priority'];
      scheduled_at: Date | null;
      sent_at: Date | null;
      delivered_at: Date | null;
      bounced_at: Date | null;
      bounce_type: Message['bounceType'];
      bounce_reason: string | null;
      mta_message_id: string | null;
      ip_address: string | null;
      sending_domain: string;
      attempts: number;
      max_attempts: number;
      last_attempt_at: Date | null;
      next_attempt_at: Date | null;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `INSERT INTO messages (
        id, tenant_id, user_id, idempotency_key, message_id, status,
        from_email, from_name, reply_to, recipients, subject,
        html_body, text_body, headers, attachments, template_id,
        template_data, campaign_id, tags, priority, scheduled_at,
        sending_domain, max_attempts, next_attempt_at, metadata,
        created_at, updated_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
        $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27
      )
      ON CONFLICT (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL
      DO UPDATE SET updated_at = NOW()
      RETURNING *`,
      [
        id,
        input.tenantId,
        input.userId ?? null,
        input.idempotencyKey ?? null,
        messageIdResult,
        input.scheduledAt ? 'pending' : 'queued',
        input.fromEmail,
        input.fromName ?? null,
        input.replyTo ?? null,
        JSON.stringify(input.recipients),
        input.subject,
        input.htmlBody ?? null,
        input.textBody ?? null,
        JSON.stringify(headers),
        JSON.stringify(attachments),
        input.templateId ?? null,
        input.templateData ? JSON.stringify(input.templateData) : null,
        input.campaignId ?? null,
        input.tags ?? [],
        input.priority ?? 'normal',
        input.scheduledAt ?? null,
        sendingDomain,
        5,
        input.scheduledAt ?? now,
        JSON.stringify(input.metadata ?? {}),
        now,
        now,
      ]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('Failed to create message'));
    }

    const message = this.mapRow(row);

    // Insert into email_queue for each recipient (denormalized for worker performance)
    // Only queue if not scheduled in the future
    const shouldQueue = !input.scheduledAt || input.scheduledAt <= now;
    
    if (shouldQueue && input.domainId) {
      const priorityValue = input.priority === 'high' ? 10 : input.priority === 'low' ? 1 : 5;
      
      /**
       * FIX-054: Multi-row INSERT for email_queue instead of per-recipient loop.
       *
       * Previous implementation ran a separate INSERT per 'to' recipient inside
       * a for loop with await. For a message with 50 'to' recipients, that was
       * 50 sequential DB round-trips. For a /batch of 1,000 such messages,
       * it was 50,000 round-trips (~250s in production).
       *
       * This builds a single multi-row INSERT VALUES (...), (...), (...) and
       * executes it in one round-trip, matching the pattern already used in
       * EventsRepository.writeEvents and AnalyticsRepository.aggregateBatch.
       */
      const fromFormatted = input.fromName ? `${input.fromName} <${input.fromEmail}>` : input.fromEmail;
      const headersJson = JSON.stringify(headers);
      const attachmentsJson = JSON.stringify(attachments);
      const tagsJson = JSON.stringify(input.tags ?? []);
      const metadataJson = JSON.stringify(input.metadata ?? {});

      const toRecipients = input.recipients.filter(r => r.type === 'to');
      
      if (toRecipients.length > 0) {
        const queueValues: unknown[] = [];
        const queuePlaceholders: string[] = [];
        let paramIdx = 1;

        for (const recipient of toRecipients) {
          const queueId = generateUuid();
          const toFormatted = recipient.name ? `${recipient.name} <${recipient.email}>` : recipient.email;

          queuePlaceholders.push(
            `($${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++})`
          );
          queueValues.push(
            queueId,
            message.id,
            input.tenantId,
            input.domainId,
            fromFormatted,
            toFormatted,
            input.subject,
            input.htmlBody ?? null,
            input.textBody ?? null,
            headersJson,
            attachmentsJson,
            input.campaignId ?? null,
            tagsJson,
            metadataJson,
            input.scheduledAt ?? null,
            priorityValue,
            'pending',
            0,
            5,
            now,
            now,
          );
        }

        await this.db.query(
          `INSERT INTO email_queue (
            id, message_id, tenant_id, domain_id, "from", "to", subject,
            html, text, headers, attachments, campaign_id, tags, metadata,
            scheduled_at, priority, status, attempt, max_attempts, created_at, updated_at
          ) VALUES ${queuePlaceholders.join(', ')}`,
          queueValues
        );
      }
    }

    return Result.ok(message);
  }

  async findById(id: string, tenantId?: string): Promise<Result<Message | null, Error>> {
    const sql = tenantId
      ? 'SELECT * FROM messages WHERE id = $1 AND tenant_id = $2'
      : 'SELECT * FROM messages WHERE id = $1';
    const params = tenantId ? [id, tenantId] : [id];
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      idempotency_key: string | null;
      message_id: string;
      status: Message['status'];
      from_email: string;
      from_name: string | null;
      reply_to: string | null;
      recipients: string;
      subject: string;
      html_body: string | null;
      text_body: string | null;
      headers: string;
      attachments: string;
      template_id: string | null;
      template_data: string | null;
      campaign_id: string | null;
      tags: string[];
      priority: Message['priority'];
      scheduled_at: Date | null;
      sent_at: Date | null;
      delivered_at: Date | null;
      bounced_at: Date | null;
      bounce_type: Message['bounceType'];
      bounce_reason: string | null;
      mta_message_id: string | null;
      ip_address: string | null;
      sending_domain: string;
      attempts: number;
      max_attempts: number;
      last_attempt_at: Date | null;
      next_attempt_at: Date | null;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      sql,
      params
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async findByIdempotencyKey(key: string, tenantId: string): Promise<Result<Message | null, Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      idempotency_key: string | null;
      message_id: string;
      status: Message['status'];
      from_email: string;
      from_name: string | null;
      reply_to: string | null;
      recipients: string;
      subject: string;
      html_body: string | null;
      text_body: string | null;
      headers: string;
      attachments: string;
      template_id: string | null;
      template_data: string | null;
      campaign_id: string | null;
      tags: string[];
      priority: Message['priority'];
      scheduled_at: Date | null;
      sent_at: Date | null;
      delivered_at: Date | null;
      bounced_at: Date | null;
      bounce_type: Message['bounceType'];
      bounce_reason: string | null;
      mta_message_id: string | null;
      ip_address: string | null;
      sending_domain: string;
      attempts: number;
      max_attempts: number;
      last_attempt_at: Date | null;
      next_attempt_at: Date | null;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      'SELECT * FROM messages WHERE tenant_id = $1 AND idempotency_key = $2',
      [tenantId, key]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async findByMtaMessageId(mtaId: string): Promise<Result<Message | null, Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      idempotency_key: string | null;
      message_id: string;
      status: Message['status'];
      from_email: string;
      from_name: string | null;
      reply_to: string | null;
      recipients: string;
      subject: string;
      html_body: string | null;
      text_body: string | null;
      headers: string;
      attachments: string;
      template_id: string | null;
      template_data: string | null;
      campaign_id: string | null;
      tags: string[];
      priority: Message['priority'];
      scheduled_at: Date | null;
      sent_at: Date | null;
      delivered_at: Date | null;
      bounced_at: Date | null;
      bounce_type: Message['bounceType'];
      bounce_reason: string | null;
      mta_message_id: string | null;
      ip_address: string | null;
      sending_domain: string;
      attempts: number;
      max_attempts: number;
      last_attempt_at: Date | null;
      next_attempt_at: Date | null;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      'SELECT * FROM messages WHERE mta_message_id = $1',
      [mtaId]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async update(id: string, input: UpdateMessageInput): Promise<Result<Message, Error>> {
    const updates: string[] = [];
    const values: unknown[] = [];
    let paramIndex = 1;

    if (input.status !== undefined) {
      updates.push(`status = $${paramIndex++}`);
      values.push(input.status);
    }
    if (input.sentAt !== undefined) {
      updates.push(`sent_at = $${paramIndex++}`);
      values.push(input.sentAt);
    }
    if (input.deliveredAt !== undefined) {
      updates.push(`delivered_at = $${paramIndex++}`);
      values.push(input.deliveredAt);
    }
    if (input.bouncedAt !== undefined) {
      updates.push(`bounced_at = $${paramIndex++}`);
      values.push(input.bouncedAt);
    }
    if (input.bounceType !== undefined) {
      updates.push(`bounce_type = $${paramIndex++}`);
      values.push(input.bounceType);
    }
    if (input.bounceReason !== undefined) {
      updates.push(`bounce_reason = $${paramIndex++}`);
      values.push(input.bounceReason);
    }
    if (input.mtaMessageId !== undefined) {
      updates.push(`mta_message_id = $${paramIndex++}`);
      values.push(input.mtaMessageId);
    }
    if (input.ipAddress !== undefined) {
      updates.push(`ip_address = $${paramIndex++}`);
      values.push(input.ipAddress);
    }
    if (input.attempts !== undefined) {
      updates.push(`attempts = $${paramIndex++}`);
      values.push(input.attempts);
    }
    if (input.lastAttemptAt !== undefined) {
      updates.push(`last_attempt_at = $${paramIndex++}`);
      values.push(input.lastAttemptAt);
    }
    if (input.nextAttemptAt !== undefined) {
      updates.push(`next_attempt_at = $${paramIndex++}`);
      values.push(input.nextAttemptAt);
    }
    if (input.metadata !== undefined) {
      updates.push(`metadata = metadata || $${paramIndex++}::jsonb`);
      values.push(JSON.stringify(input.metadata));
    }

    updates.push(`updated_at = $${paramIndex++}`);
    values.push(new Date());

    values.push(id);

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      idempotency_key: string | null;
      message_id: string;
      status: Message['status'];
      from_email: string;
      from_name: string | null;
      reply_to: string | null;
      recipients: string;
      subject: string;
      html_body: string | null;
      text_body: string | null;
      headers: string;
      attachments: string;
      template_id: string | null;
      template_data: string | null;
      campaign_id: string | null;
      tags: string[];
      priority: Message['priority'];
      scheduled_at: Date | null;
      sent_at: Date | null;
      delivered_at: Date | null;
      bounced_at: Date | null;
      bounce_type: Message['bounceType'];
      bounce_reason: string | null;
      mta_message_id: string | null;
      ip_address: string | null;
      sending_domain: string;
      attempts: number;
      max_attempts: number;
      last_attempt_at: Date | null;
      next_attempt_at: Date | null;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `UPDATE messages SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
      values
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('Message not found'));
    }

    return Result.ok(this.mapRow(row));
  }

  async markSending(id: string, ipAddress: string): Promise<Result<Message, Error>> {
    return this.update(id, {
      status: 'sending',
      ipAddress,
      attempts: 1,
      lastAttemptAt: new Date(),
    });
  }

  async markSent(id: string, mtaMessageId: string): Promise<Result<Message, Error>> {
    return this.update(id, {
      status: 'sent',
      sentAt: new Date(),
      mtaMessageId,
      nextAttemptAt: null,
    });
  }

  async markDelivered(id: string): Promise<Result<Message, Error>> {
    return this.update(id, {
      status: 'delivered',
      deliveredAt: new Date(),
    });
  }

  async markBounced(id: string, bounceType: 'hard' | 'soft', reason: string): Promise<Result<Message, Error>> {
    return this.update(id, {
      status: 'bounced',
      bouncedAt: new Date(),
      bounceType,
      bounceReason: reason,
      nextAttemptAt: null,
    });
  }

  async markDeferred(id: string, reason: string, nextAttempt: Date): Promise<Result<Message, Error>> {
    const msg = await this.findById(id);
    if (!msg.ok) return msg;
    if (!msg.value) return Result.err(new Error('Message not found'));

    return this.update(id, {
      status: 'deferred',
      attempts: msg.value.attempts + 1,
      lastAttemptAt: new Date(),
      nextAttemptAt: nextAttempt,
      metadata: { lastDeferReason: reason },
    });
  }

  async markFailed(id: string, reason: string): Promise<Result<Message, Error>> {
    return this.update(id, {
      status: 'failed',
      bounceReason: reason,
      nextAttemptAt: null,
    });
  }

  async claimForSending(limit: number, ipAddress: string): Promise<Result<Message[], Error>> {
    const now = new Date();
    
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      idempotency_key: string | null;
      message_id: string;
      status: Message['status'];
      from_email: string;
      from_name: string | null;
      reply_to: string | null;
      recipients: string;
      subject: string;
      html_body: string | null;
      text_body: string | null;
      headers: string;
      attachments: string;
      template_id: string | null;
      template_data: string | null;
      campaign_id: string | null;
      tags: string[];
      priority: Message['priority'];
      scheduled_at: Date | null;
      sent_at: Date | null;
      delivered_at: Date | null;
      bounced_at: Date | null;
      bounce_type: Message['bounceType'];
      bounce_reason: string | null;
      mta_message_id: string | null;
      ip_address: string | null;
      sending_domain: string;
      attempts: number;
      max_attempts: number;
      last_attempt_at: Date | null;
      next_attempt_at: Date | null;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `UPDATE messages
       SET status = 'sending', ip_address = $1, last_attempt_at = $2, attempts = attempts + 1, updated_at = $2
       WHERE id IN (
         SELECT id FROM messages
         WHERE status IN ('queued', 'deferred')
           AND (scheduled_at IS NULL OR scheduled_at <= $2)
           AND (next_attempt_at IS NULL OR next_attempt_at <= $2)
           AND attempts < max_attempts
         ORDER BY 
           CASE priority WHEN 'high' THEN 0 WHEN 'normal' THEN 1 ELSE 2 END,
           created_at
         FOR UPDATE SKIP LOCKED
         LIMIT $3
       )
       RETURNING *`,
      [ipAddress, now, limit]
    );

    if (!result.ok) return result;

    return Result.ok(result.value.rows.map((row) => this.mapRow(row)));
  }

  async countByStatus(tenantId: string): Promise<Result<Record<Message['status'], number>, Error>> {
    const result = await this.db.query<{ status: Message['status']; count: string }>(
      `SELECT status, COUNT(*) as count
       FROM messages
       WHERE tenant_id = $1
       GROUP BY status`,
      [tenantId]
    );

    if (!result.ok) return result;

    const counts: Record<string, number> = {
      pending: 0,
      queued: 0,
      sending: 0,
      sent: 0,
      delivered: 0,
      bounced: 0,
      deferred: 0,
      failed: 0,
    };

    for (const row of result.value.rows) {
      counts[row.status] = parseInt(row.count, 10);
    }

    return Result.ok(counts as Record<Message['status'], number>);
  }

  async listByTenant(
    tenantId: string,
    options: {
      status?: Message['status'];
      campaignId?: string;
      startDate?: Date;
      endDate?: Date;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<Result<{ messages: Message[]; total: number }, Error>> {
    const conditions = ['tenant_id = $1'];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (options.status) {
      conditions.push(`status = $${paramIndex++}`);
      values.push(options.status);
    }
    if (options.campaignId) {
      conditions.push(`campaign_id = $${paramIndex++}`);
      values.push(options.campaignId);
    }
    if (options.startDate) {
      conditions.push(`created_at >= $${paramIndex++}`);
      values.push(options.startDate);
    }
    if (options.endDate) {
      conditions.push(`created_at <= $${paramIndex++}`);
      values.push(options.endDate);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    /**
     * PERF-005: Column projection + window-function pagination.
     *
     * Two changes from the previous implementation:
     *
     * 1. **Column projection**: The old query used `SELECT *`, pulling
     *    html_body (up to 10MB), text_body (1MB), attachments, headers,
     *    template_data — all JSON-parsed per row — even though the list
     *    endpoint only returns id, status, subject, from, sentAt, and
     *    recipientCount. For 100 rows, that could be ~1GB of I/O
     *    discarded immediately. Now we select only the columns needed
     *    for the list view.
     *
     * 2. **Window function pagination**: The old approach ran a separate
     *    `SELECT COUNT(*)` query — a full re-scan of the same rows. Now
     *    `COUNT(*) OVER()` computes the total in the same query pass,
     *    eliminating the second scan entirely.
     */
    const limit = options.limit ?? 50;
    const offset = options.offset ?? 0;
    values.push(limit, offset);

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      idempotency_key: string | null;
      message_id: string;
      status: Message['status'];
      from_email: string;
      from_name: string | null;
      reply_to: string | null;
      recipients: string;
      subject: string;
      campaign_id: string | null;
      tags: string[];
      priority: Message['priority'];
      scheduled_at: Date | null;
      sent_at: Date | null;
      delivered_at: Date | null;
      bounced_at: Date | null;
      bounce_type: Message['bounceType'];
      bounce_reason: string | null;
      mta_message_id: string | null;
      ip_address: string | null;
      sending_domain: string;
      attempts: number;
      max_attempts: number;
      last_attempt_at: Date | null;
      next_attempt_at: Date | null;
      metadata: string;
      created_at: Date;
      updated_at: Date;
      total_count: string;
    }>(
      `SELECT
          id, tenant_id, user_id, idempotency_key, message_id, status,
          from_email, from_name, reply_to, recipients, subject,
          campaign_id, tags, priority, scheduled_at,
          sent_at, delivered_at, bounced_at, bounce_type, bounce_reason,
          mta_message_id, ip_address, sending_domain, attempts, max_attempts,
          last_attempt_at, next_attempt_at, metadata, created_at, updated_at,
          COUNT(*) OVER() AS total_count
       FROM messages ${whereClause}
       ORDER BY created_at DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
      values
    );

    if (!result.ok) return result;

    const total = parseInt(result.value.rows[0]?.total_count ?? '0', 10);

    return Result.ok({
      messages: result.value.rows.map((row) => this.mapListRow(row)),
      total,
    });
  }

  /**
   * PERF-005: Lightweight row mapper for list views.
   *
   * Unlike mapRow() which JSON-parses html_body, text_body, headers,
   * attachments, and template_data, this mapper handles the projected
   * column set returned by listByTenant. The heavy text columns are
   * set to null since they weren't selected.
   */
  private mapListRow(row: {
    id: string;
    tenant_id: string;
    user_id: string | null;
    idempotency_key: string | null;
    message_id: string;
    status: Message['status'];
    from_email: string;
    from_name: string | null;
    reply_to: string | null;
    recipients: string;
    subject: string;
    campaign_id: string | null;
    tags: string[];
    priority: Message['priority'];
    scheduled_at: Date | null;
    sent_at: Date | null;
    delivered_at: Date | null;
    bounced_at: Date | null;
    bounce_type: Message['bounceType'];
    bounce_reason: string | null;
    mta_message_id: string | null;
    ip_address: string | null;
    sending_domain: string;
    attempts: number;
    max_attempts: number;
    last_attempt_at: Date | null;
    next_attempt_at: Date | null;
    metadata: string;
    created_at: Date;
    updated_at: Date;
  }): Message {
    return {
      id: row.id,
      tenantId: row.tenant_id,
      userId: row.user_id,
      idempotencyKey: row.idempotency_key,
      messageId: row.message_id,
      status: row.status,
      fromEmail: row.from_email,
      fromName: row.from_name,
      replyTo: row.reply_to,
      recipients: typeof row.recipients === 'string'
        ? JSON.parse(row.recipients) as EmailRecipient[]
        : row.recipients as unknown as EmailRecipient[],
      subject: row.subject,
      htmlBody: null, // Not selected in list projection
      textBody: null, // Not selected in list projection
      headers: { 'Message-ID': '', 'X-ApexMail-ID': row.id, 'X-ApexMail-Tenant': row.tenant_id, 'Return-Path': '' }, // Minimal placeholder
      attachments: [], // Not selected in list projection
      templateId: null, // Not selected in list projection
      templateData: null, // Not selected in list projection
      campaignId: row.campaign_id,
      tags: row.tags,
      priority: row.priority,
      scheduledAt: row.scheduled_at,
      sentAt: row.sent_at,
      deliveredAt: row.delivered_at,
      bouncedAt: row.bounced_at,
      bounceType: row.bounce_type,
      bounceReason: row.bounce_reason,
      mtaMessageId: row.mta_message_id,
      ipAddress: row.ip_address,
      sendingDomain: row.sending_domain,
      attempts: row.attempts,
      maxAttempts: row.max_attempts,
      lastAttemptAt: row.last_attempt_at,
      nextAttemptAt: row.next_attempt_at,
      metadata: typeof row.metadata === 'string'
        ? JSON.parse(row.metadata) as Record<string, unknown>
        : row.metadata as unknown as Record<string, unknown>,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private mapRow(row: {
    id: string;
    tenant_id: string;
    user_id: string | null;
    idempotency_key: string | null;
    message_id: string;
    status: Message['status'];
    from_email: string;
    from_name: string | null;
    reply_to: string | null;
    recipients: string;
    subject: string;
    html_body: string | null;
    text_body: string | null;
    headers: string;
    attachments: string;
    template_id: string | null;
    template_data: string | null;
    campaign_id: string | null;
    tags: string[];
    priority: Message['priority'];
    scheduled_at: Date | null;
    sent_at: Date | null;
    delivered_at: Date | null;
    bounced_at: Date | null;
    bounce_type: Message['bounceType'];
    bounce_reason: string | null;
    mta_message_id: string | null;
    ip_address: string | null;
    sending_domain: string;
    attempts: number;
    max_attempts: number;
    last_attempt_at: Date | null;
    next_attempt_at: Date | null;
    metadata: string;
    created_at: Date;
    updated_at: Date;
  }): Message {
    return {
      id: row.id,
      tenantId: row.tenant_id,
      userId: row.user_id,
      idempotencyKey: row.idempotency_key,
      messageId: row.message_id,
      status: row.status,
      fromEmail: row.from_email,
      fromName: row.from_name,
      replyTo: row.reply_to,
      recipients: typeof row.recipients === 'string'
        ? JSON.parse(row.recipients) as EmailRecipient[]
        : row.recipients as unknown as EmailRecipient[],
      subject: row.subject,
      htmlBody: row.html_body,
      textBody: row.text_body,
      headers: typeof row.headers === 'string'
        ? JSON.parse(row.headers) as MessageHeaders
        : row.headers as unknown as MessageHeaders,
      attachments: typeof row.attachments === 'string'
        ? JSON.parse(row.attachments) as EmailAttachment[]
        : row.attachments as unknown as EmailAttachment[],
      templateId: row.template_id,
      templateData: row.template_data
        ? (typeof row.template_data === 'string'
          ? JSON.parse(row.template_data)
          : row.template_data) as Record<string, unknown>
        : null,
      campaignId: row.campaign_id,
      tags: row.tags,
      priority: row.priority,
      scheduledAt: row.scheduled_at,
      sentAt: row.sent_at,
      deliveredAt: row.delivered_at,
      bouncedAt: row.bounced_at,
      bounceType: row.bounce_type,
      bounceReason: row.bounce_reason,
      mtaMessageId: row.mta_message_id,
      ipAddress: row.ip_address,
      sendingDomain: row.sending_domain,
      attempts: row.attempts,
      maxAttempts: row.max_attempts,
      lastAttemptAt: row.last_attempt_at,
      nextAttemptAt: row.next_attempt_at,
      metadata: typeof row.metadata === 'string'
        ? JSON.parse(row.metadata) as Record<string, unknown>
        : row.metadata as unknown as Record<string, unknown>,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  /**
   * Get message statistics for a tenant
   */
  async getStats(
    tenantId: string,
    options: { startDate?: Date; endDate?: Date; since?: Date; until?: Date; campaignId?: string } = {}
  ): Promise<Result<{
    total: number;
    queued: number;
    sent: number;
    delivered: number;
    failed: number;
    bounced: number;
  }, Error>> {
    // Support both since/until and startDate/endDate
    const startDate = options.startDate ?? options.since;
    const endDate = options.endDate ?? options.until;

    const conditions = ['tenant_id = $1'];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (startDate) {
      conditions.push(`created_at >= $${paramIndex++}`);
      values.push(startDate);
    }
    if (endDate) {
      conditions.push(`created_at <= $${paramIndex++}`);
      values.push(endDate);
    }
    if (options.campaignId) {
      conditions.push(`campaign_id = $${paramIndex++}`);
      values.push(options.campaignId);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    const result = await this.db.query<{
      status: string;
      count: string;
    }>(
      `SELECT status, COUNT(*) as count
       FROM messages
       ${whereClause}
       GROUP BY status`,
      values
    );

    if (!result.ok) return result;

    const stats = {
      total: 0,
      queued: 0,
      sent: 0,
      delivered: 0,
      failed: 0,
      bounced: 0,
    };

    for (const row of result.value.rows) {
      const count = parseInt(row.count, 10);
      stats.total += count;
      switch (row.status) {
        case 'pending':
        case 'queued':
          stats.queued += count;
          break;
        case 'sent':
        case 'sending':
          stats.sent += count;
          break;
        case 'delivered':
          stats.delivered += count;
          break;
        case 'failed':
        case 'deferred':
          stats.failed += count;
          break;
        case 'bounced':
          stats.bounced += count;
          break;
      }
    }

    return Result.ok(stats);
  }

  /**
   * Get message volume time series data
   */
  async getVolumeTimeSeries(
    tenantId: string,
    options: {
      startDate?: Date;
      endDate?: Date;
      since?: Date;
      until?: Date;
      interval: 'minute' | 'hour' | 'day' | 'week' | 'month';
      domainId?: string;
    }
  ): Promise<Result<{ timestamp: Date; sent: number; delivered: number; bounced: number; failed: number }[], Error>> {
    // Support both since/until and startDate/endDate
    const startDate = options.startDate ?? options.since;
    const endDate = options.endDate ?? options.until;

    const truncFn = options.interval === 'minute' ? 'hour'
      : options.interval === 'hour' ? 'hour'
      : options.interval === 'day' ? 'day'
      : options.interval === 'week' ? 'week'
      : 'month';

    const conditions = ['tenant_id = $1'];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (startDate) {
      conditions.push(`created_at >= $${paramIndex++}`);
      values.push(startDate);
    }
    if (endDate) {
      conditions.push(`created_at <= $${paramIndex++}`);
      values.push(endDate);
    }
    if (options.domainId) {
      conditions.push(`sending_domain = (SELECT domain FROM domains WHERE id = $${paramIndex++})`);
      values.push(options.domainId);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    const result = await this.db.query<{
      bucket: Date;
      status: string;
      count: string;
    }>(
      `SELECT 
        DATE_TRUNC('${truncFn}', created_at) as bucket,
        status,
        COUNT(*) as count
       FROM messages
       ${whereClause}
       GROUP BY bucket, status
       ORDER BY bucket`,
      values
    );

    if (!result.ok) return result;

    // Aggregate by timestamp
    const byTimestamp = new Map<string, { sent: number; delivered: number; bounced: number; failed: number }>();
    
    for (const row of result.value.rows) {
      const key = row.bucket.toISOString();
      const existing = byTimestamp.get(key) ?? { sent: 0, delivered: 0, bounced: 0, failed: 0 };
      const count = parseInt(row.count, 10);
      
      switch (row.status) {
        case 'sent':
        case 'sending':
          existing.sent += count;
          break;
        case 'delivered':
          existing.delivered += count;
          break;
        case 'bounced':
          existing.bounced += count;
          break;
        case 'failed':
        case 'deferred':
          existing.failed += count;
          break;
      }
      
      byTimestamp.set(key, existing);
    }

    return Result.ok(
      Array.from(byTimestamp.entries()).map(([timestamp, data]) => ({
        timestamp: new Date(timestamp),
        ...data,
      }))
    );
  }
}
