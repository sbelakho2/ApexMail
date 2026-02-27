/**
 * Messages Repository - Outbox with idempotency and full message lifecycle
 */

import { Result, parseJsonOrDefault } from '@apexmail/lib';
import { generateUuid, generateMessageId, generateVerpAddress } from '@apexmail/lib/id';
import { createHash } from 'crypto';
import type { DatabasePool } from '../pool.js';
import { withTransaction } from '../transaction.js';

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

type MessageRow = {
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
};

const MESSAGE_COLUMNS =
  'id, tenant_id, user_id, idempotency_key, message_id, status, from_email, from_name, reply_to, recipients, subject, html_body, text_body, headers, attachments, template_id, template_data, campaign_id, tags, priority, scheduled_at, sent_at, delivered_at, bounced_at, bounce_type, bounce_reason, mta_message_id, ip_address, sending_domain, attempts, max_attempts, last_attempt_at, next_attempt_at, metadata, created_at, updated_at';

const MESSAGE_COLUMNS_NO_BODY =
  'id, tenant_id, user_id, idempotency_key, message_id, status, from_email, from_name, reply_to, recipients, subject, headers, attachments, template_id, template_data, campaign_id, tags, priority, scheduled_at, sent_at, delivered_at, bounced_at, bounce_type, bounce_reason, mta_message_id, ip_address, sending_domain, attempts, max_attempts, last_attempt_at, next_attempt_at, metadata, created_at, updated_at';

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

  private deriveSendingDomain(fromEmail: string): string {
    const [, domain = ''] = fromEmail.split('@');
    return domain.trim().toLowerCase();
  }

  private deriveAttachmentChecksum(attachment: EmailAttachment): string {
    return createHash('sha256')
      .update(`${attachment.storageKey}:${attachment.size}:${attachment.filename}`)
      .digest('hex');
  }

  async create(input: CreateMessageInput): Promise<Result<Message, Error>> {
    // Check idempotency key first
    if (input.idempotencyKey) {
      const existing = await this.findByIdempotencyKey(input.idempotencyKey, input.tenantId);
      if (existing.ok && existing.value) {
        return Result.ok(existing.value);
      }
    }

    const id = generateUuid();
    const sendingDomain = this.deriveSendingDomain(input.fromEmail);
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
      checksum: att.checksum || this.deriveAttachmentChecksum(att),
    }));

    /**
     * G-200 / B-046: Wrap message INSERT + email_queue INSERT in a transaction.
     * Previously the two inserts were independent; a crash after the message
     * INSERT but before the queue INSERT would leave an orphaned message that
     * never gets delivered.
     */
    const result = await withTransaction(this.db, async ({ client }) => {
      const insertResult = await client.query(
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

      const row = insertResult.rows[0];
      if (!row) {
        throw new Error('Failed to create message');
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
          const chunkSize = 100;

          for (let i = 0; i < toRecipients.length; i += chunkSize) {
            const chunk = toRecipients.slice(i, i + chunkSize);
            const queueValues: unknown[] = [];
            const queuePlaceholders: string[] = [];
            let paramIdx = 1;

            for (const recipient of chunk) {
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

            await client.query(
              `INSERT INTO email_queue (
                id, message_id, tenant_id, domain_id, "from", "to", subject,
                html, text, headers, attachments, campaign_id, tags, metadata,
                scheduled_at, priority, status, attempt, max_attempts, created_at, updated_at
              ) VALUES ${queuePlaceholders.join(', ')}`,
              queueValues
            );
          }
        }
      }

      return message;
    });

    if (!result.ok) return result;
    return Result.ok(result.value);
  }

  async findById(id: string, tenantId?: string, options?: { includeBody?: boolean }): Promise<Result<Message | null, Error>> {
    // FIX-500-043: Conditionally exclude large body columns when not needed
    const columns = options?.includeBody === false
      ? MESSAGE_COLUMNS_NO_BODY
      : MESSAGE_COLUMNS;
    const sql = tenantId
      ? `SELECT ${columns} FROM messages WHERE id = $1 AND tenant_id = $2`
      : `SELECT ${columns} FROM messages WHERE id = $1`;
    const params = tenantId ? [id, tenantId] : [id];
    const result = await this.db.query<MessageRow>(
      sql,
      params
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async findByIdempotencyKey(key: string, tenantId: string): Promise<Result<Message | null, Error>> {
    const result = await this.db.query<MessageRow>(
      'SELECT * FROM messages WHERE tenant_id = $1 AND idempotency_key = $2',
      [tenantId, key]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  // A-005: Add optional tenantId for database-level tenant isolation
  // FIX-500-048: Partial index idx_messages_mta_message_id added in migration 010_performance_indexes.sql
  async findByMtaMessageId(mtaId: string, tenantId?: string): Promise<Result<Message | null, Error>> {
    const sql = tenantId
      ? 'SELECT * FROM messages WHERE mta_message_id = $1 AND tenant_id = $2'
      : 'SELECT * FROM messages WHERE mta_message_id = $1';
    const params = tenantId ? [mtaId, tenantId] : [mtaId];
    const result = await this.db.query<MessageRow>(sql, params);

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  /**
   * C-105: Valid message status transitions (state machine).
   * Prevents illegal transitions like 'sent' → 'queued' or 'delivered' → 'sending'.
   * Map key = current status, value = set of allowed next statuses.
   */
  private static readonly VALID_TRANSITIONS: Record<Message['status'], Set<Message['status']>> = {
    pending:   new Set(['queued', 'failed']),
    queued:    new Set(['sending', 'failed']),
    sending:   new Set(['sent', 'bounced', 'deferred', 'failed']),
    sent:      new Set(['delivered', 'bounced']),
    delivered: new Set(['bounced']),
    bounced:   new Set(),       // terminal
    deferred:  new Set(['sending', 'failed']),
    failed:    new Set(),       // terminal
  };

  // A-024: Add optional tenantId for database-level tenant isolation
  async update(id: string, input: UpdateMessageInput, tenantId?: string): Promise<Result<Message, Error>> {
    const result = await withTransaction(this.db, async ({ client }) => {
      // C-105: Validate status transition if a new status is being set.
      if (input.status !== undefined) {
        const statusQuery = tenantId
          ? 'SELECT status FROM messages WHERE id = $1 AND tenant_id = $2 FOR UPDATE'
          : 'SELECT status FROM messages WHERE id = $1 FOR UPDATE';
        const statusParams = tenantId ? [id, tenantId] : [id];
        const current = await client.query<{ status: Message['status'] }>(statusQuery, statusParams);
        const currentRow = current.rows[0];
        if (!currentRow) {
          throw new Error('Message not found');
        }
        const allowed = MessagesRepository.VALID_TRANSITIONS[currentRow.status];
        if (allowed && !allowed.has(input.status)) {
          throw new Error(`C-105: Invalid status transition '${currentRow.status}' → '${input.status}'`);
        }
      }

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

      if (updates.length === 0) {
        throw new Error('No updates specified');
      }

      updates.push(`updated_at = $${paramIndex++}`);
      values.push(new Date());

      values.push(id);

      let whereClause = `WHERE id = $${paramIndex}`;
      if (tenantId) {
        paramIndex++;
        whereClause += ` AND tenant_id = $${paramIndex}`;
        values.push(tenantId);
      }

      const updateResult = await client.query<MessageRow>(
        `UPDATE messages SET ${updates.join(', ')} ${whereClause} RETURNING *`,
        values
      );

      const row = updateResult.rows[0];
      if (!row) {
        throw new Error('Message not found');
      }

      return this.mapRow(row);
    });

    return result.ok ? Result.ok(result.value) : result;
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

  /**
   * F-180 / B-038: Atomic markDeferred using SQL increment instead of read-then-update.
   * Avoids TOCTOU race on attempt count.
   */
  async markDeferred(id: string, reason: string, nextAttempt: Date): Promise<Result<Message, Error>> {
    const now = new Date();
    const result = await this.db.query<MessageRow>(
      `UPDATE messages 
       SET status = 'deferred', 
           attempts = attempts + 1, 
           last_attempt_at = $2, 
           next_attempt_at = $3, 
           metadata = metadata || $4::jsonb,
           updated_at = $2
       WHERE id = $1 
       RETURNING *`,
      [id, now, nextAttempt, JSON.stringify({ lastDeferReason: reason })]
    );

    if (!result.ok) return result;
    const row = result.value.rows[0];
    if (!row) return Result.err(new Error('Message not found'));
    return Result.ok(this.mapRow(row));
  }

  async markFailed(id: string, reason: string): Promise<Result<Message, Error>> {
    return this.update(id, {
      status: 'failed',
      bounceReason: reason,
      nextAttemptAt: null,
    });
  }

  /**
   * C-121: Required composite index for email queue claim performance:
   *   CREATE INDEX idx_messages_queue_claim
   *     ON messages (status, priority, created_at)
   *     WHERE status IN ('queued', 'deferred')
   *       AND attempts < max_attempts;
   *
   * The partial index limits its size to only claimable rows (typically <1%
   * of the table). Without this index, every worker poll triggers a
   * sequential scan of the entire messages table — O(n) per claim.
   *
   * Additional index for the scheduled_at / next_attempt_at filters:
   *   CREATE INDEX idx_messages_next_attempt
   *     ON messages (next_attempt_at)
   *     WHERE status IN ('queued', 'deferred');
   *
   * The FOR UPDATE SKIP LOCKED clause requires the rows to be found
   * efficiently first; the index drives the inner SELECT.
   */
  async claimForSending(limit: number, ipAddress: string): Promise<Result<Message[], Error>> {
    const now = new Date();
    
    const result = await this.db.query<MessageRow>(
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

  /**
   * F-218: This method currently uses OFFSET-based pagination which degrades
   * on large tables (Postgres must scan and discard `offset` rows).
   *
   * For tenants with >100K messages, consider adding cursor-based (keyset)
   * pagination using `WHERE created_at < $cursor ORDER BY created_at DESC`.
   * The cursor should be the `created_at` (or `id`) of the last item in the
   * previous page. This gives O(1) seek performance regardless of page depth.
   *
   * Example API: `GET /v1/messages?cursor=<last_created_at>&limit=50`
   * The response should include a `nextCursor` field when more pages exist.
   *
   * C-116: Text search query optimization.
   * The optional `search` parameter uses PostgreSQL full-text search via
   * `to_tsvector / to_tsquery` instead of `LIKE '%term%'`.
   * IMPORTANT: Requires a GIN index on the messages table for performance:
   *   CREATE INDEX idx_messages_search ON messages
   *     USING GIN (to_tsvector('english', subject || ' ' || from_email));
   * Without this index, full-text queries will fall back to a sequential scan.
   */
  async listByTenant(
    tenantId: string,
    options: {
      status?: Message['status'];
      campaignId?: string;
      startDate?: Date;
      endDate?: Date;
      search?: string;
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
    // C-116: Use to_tsvector/plainto_tsquery for efficient full-text search
    // instead of LIKE '%term%' which cannot use indexes.
    if (options.search) {
      conditions.push(
        `to_tsvector('english', coalesce(subject, '') || ' ' || coalesce(from_email, '')) @@ plainto_tsquery('english', $${paramIndex++})`
      );
      values.push(options.search);
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
        ? parseJsonOrDefault<EmailRecipient[]>(row.recipients, [])
        : row.recipients as unknown as EmailRecipient[],
      subject: row.subject,
      htmlBody: null, // Not selected in list projection
      textBody: null, // Not selected in list projection
      headers: {
        'Message-ID': row.message_id || '',
        'X-ApexMail-ID': row.id,
        'X-ApexMail-Tenant': row.tenant_id,
        'Return-Path': row.from_email || '',
      },
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
        ? parseJsonOrDefault<Record<string, unknown>>(row.metadata, {})
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
        ? parseJsonOrDefault<EmailRecipient[]>(row.recipients, [])
        : row.recipients as unknown as EmailRecipient[],
      subject: row.subject,
      htmlBody: row.html_body,
      textBody: row.text_body,
      headers: typeof row.headers === 'string'
        ? parseJsonOrDefault<MessageHeaders>(row.headers, { 'Message-ID': '', 'X-ApexMail-ID': row.id, 'X-ApexMail-Tenant': row.tenant_id, 'Return-Path': '' })
        : row.headers as unknown as MessageHeaders,
      attachments: typeof row.attachments === 'string'
        ? parseJsonOrDefault<EmailAttachment[]>(row.attachments, [])
        : row.attachments as unknown as EmailAttachment[],
      templateId: row.template_id,
      templateData: row.template_data
        ? (typeof row.template_data === 'string'
          ? parseJsonOrDefault<Record<string, unknown>>(row.template_data, {})
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
        ? parseJsonOrDefault<Record<string, unknown>>(row.metadata, {})
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
   * FIX-500-145: Archive old delivered/bounced/failed messages to cold storage.
   *
   * Moves rows from `messages` into `messages_archive` in batches to avoid
   * long lock contention (same CTE pattern as purgeOldQueueEntries).
   * Returns total rows archived.
   */
  async archiveOldMessages(
    olderThanDays: number,
    options: { batchSize?: number; tenantId?: string } = {}
  ): Promise<Result<number, Error>> {
    const batchSize = options.batchSize ?? 1000;
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

    let totalArchived = 0;

    try {
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const conditions = [
          "status IN ('delivered', 'bounced', 'failed')",
          'updated_at < $1',
        ];
        const values: unknown[] = [cutoffDate];
        let paramIndex = 2;

        if (options.tenantId) {
          conditions.push(`tenant_id = $${paramIndex++}`);
          values.push(options.tenantId);
        }

        values.push(batchSize);

        const result = await this.db.query<{ count: string }>(
          `WITH to_archive AS (
            SELECT id FROM messages
            WHERE ${conditions.join(' AND ')}
            LIMIT $${paramIndex}
          ),
          archived AS (
            INSERT INTO messages_archive
            SELECT m.* FROM messages m JOIN to_archive ta ON m.id = ta.id
            ON CONFLICT (id) DO NOTHING
            RETURNING 1
          ),
          deleted AS (
            DELETE FROM messages
            WHERE id IN (SELECT id FROM to_archive)
            RETURNING 1
          )
          SELECT COUNT(*) as count FROM deleted`,
          values
        );

        if (!result.ok) return result;

        const archivedCount = parseInt(result.value.rows[0]?.count ?? '0', 10);
        totalArchived += archivedCount;

        if (archivedCount < batchSize) break;
      }

      return Result.ok(totalArchived);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * C-130: Purge old email_queue entries that have been processed.
   *
   * Completed/failed queue entries are retained for debugging but grow
   * unboundedly.  This method deletes entries in terminal states
   * (delivered, bounced, failed) older than `olderThanDays`, in batches
   * to avoid long lock contention — same pattern as audit-log cleanup
   * (C-081).
   */
  async purgeOldQueueEntries(
    olderThanDays: number,
    options: { batchSize?: number; tenantId?: string } = {}
  ): Promise<Result<number, Error>> {
    const batchSize = options.batchSize ?? 1000;
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

    let totalDeleted = 0;

    try {
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const conditions = [
          "status IN ('delivered', 'bounced', 'failed')",
          'updated_at < $1',
        ];
        const values: unknown[] = [cutoffDate];
        let paramIndex = 2;

        if (options.tenantId) {
          conditions.push(`tenant_id = $${paramIndex++}`);
          values.push(options.tenantId);
        }

        values.push(batchSize);

        const result = await this.db.query<{ count: string }>(
          `WITH deleted AS (
            DELETE FROM email_queue
            WHERE id IN (
              SELECT id FROM email_queue
              WHERE ${conditions.join(' AND ')}
              LIMIT $${paramIndex}
            )
            RETURNING 1
          ) SELECT COUNT(*) as count FROM deleted`,
          values
        );

        if (!result.ok) return result;

        const deletedCount = parseInt(result.value.rows[0]?.count ?? '0', 10);
        totalDeleted += deletedCount;

        // If we deleted fewer rows than the batch size, we're done
        if (deletedCount < batchSize) break;
      }

      return Result.ok(totalDeleted);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
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

    const truncParam = paramIndex++;
    values.push(truncFn);

    const result = await this.db.query<{
      bucket: Date;
      status: string;
      count: string;
    }>(
      `SELECT 
        DATE_TRUNC($${truncParam}, created_at) as bucket,
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

  // ════════════════════════════════════════════════════════════════
  // CAMPAIGN MANAGEMENT
  // ════════════════════════════════════════════════════════════════

  async createCampaign(input: {
    tenantId: string;
    name: string;
    subject?: string;
    listId?: string;
    templateId?: string;
    scheduledAt?: Date;
    status: string;
  }): Promise<{ id: string; name: string; status: string }> {
    const id = generateUuid();
    const result = await this.db.query(
      `INSERT INTO campaigns (id, tenant_id, name, subject, list_id, template_id, scheduled_at, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id, name, status, created_at`,
      [id, input.tenantId, input.name, input.subject, input.listId, input.templateId, input.scheduledAt, input.status]
    );
    if (!result.ok) throw result.error;
    return result.value.rows[0] as { id: string; name: string; status: string };
  }

  async findCampaignByName(name: string, tenantId: string): Promise<{ id: string; name: string; status: string } | null> {
    const result = await this.db.query(
      `SELECT id, name, status, created_at, updated_at FROM campaigns WHERE name = $1 AND tenant_id = $2`,
      [name, tenantId]
    );
    if (!result.ok) throw result.error;
    return (result.value.rows[0] as { id: string; name: string; status: string }) ?? null;
  }

  async updateCampaignStatus(
    campaignId: string,
    tenantId: string,
    status: string
  ): Promise<{ id: string; name: string; status: string }> {
    const result = await this.db.query(
      `UPDATE campaigns SET status = $3, updated_at = NOW() WHERE id = $1 AND tenant_id = $2 RETURNING id, name, status`,
      [campaignId, tenantId, status]
    );
    if (!result.ok) throw result.error;
    return result.value.rows[0] as { id: string; name: string; status: string };
  }

  async getCampaignStats(campaignId: string, tenantId: string): Promise<Record<string, number>> {
    const result = await this.db.query(
      `SELECT status, COUNT(*)::int as count
       FROM messages
       WHERE campaign_id = $1 AND tenant_id = $2
       GROUP BY status`,
      [campaignId, tenantId]
    );
    if (!result.ok) throw result.error;
    const stats: Record<string, number> = { sent: 0, delivered: 0, bounced: 0, failed: 0, queued: 0 };
    for (const row of result.value.rows) {
      stats[row.status as string] = row.count as number;
    }
    return stats;
  }

  async deleteCampaign(campaignId: string, tenantId: string): Promise<void> {
    const result = await this.db.query(
      `DELETE FROM campaigns WHERE id = $1 AND tenant_id = $2`,
      [campaignId, tenantId]
    );
    if (!result.ok) throw result.error;
  }
}
