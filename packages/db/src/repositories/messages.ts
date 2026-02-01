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

    return Result.ok(this.mapRow(row));
  }

  async findById(id: string): Promise<Result<Message | null, Error>> {
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
      'SELECT * FROM messages WHERE id = $1',
      [id]
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

    const countResult = await this.db.query<{ count: string }>(
      `SELECT COUNT(*) as count FROM messages ${whereClause}`,
      values
    );

    if (!countResult.ok) return countResult;

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
      `SELECT * FROM messages ${whereClause}
       ORDER BY created_at DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
      values
    );

    if (!result.ok) return result;

    return Result.ok({
      messages: result.value.rows.map((row) => this.mapRow(row)),
      total: parseInt(countResult.value.rows[0]?.count ?? '0', 10),
    });
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
}
