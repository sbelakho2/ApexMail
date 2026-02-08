/**
 * Bounce Server - Processes bounce messages and DSN reports
 */

import { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';
import { generateId } from '@apexmail/lib';
import { SMTPServer, type SMTPServerSession, type SMTPServerAddress, type SMTPServerDataStream } from 'smtp-server';
import { simpleParser, type ParsedMail } from 'mailparser';

interface BounceServerConfig {
  db: Pool;
  redis: Redis;
  config: {
    host: string;
    port: number;
    hostname: string;
    verpDomain: string;
    maxMessageSize: number;
  };
  logger: Logger;
}

interface BounceInfo {
  originalMessageId: string | null;
  originalRecipient: string | null;
  bounceType: 'hard' | 'soft';
  bounceSubtype: string;
  diagnosticCode: string;
  action: string;
  status: string;
}

export class BounceServer {
  private readonly db: Pool;
  private readonly config: BounceServerConfig['config'];
  private readonly logger: Logger;
  
  private smtpServer: SMTPServer | null = null;

  constructor(options: BounceServerConfig) {
    this.db = options.db;
    this.config = options.config;
    this.logger = options.logger;
  }

  async start(): Promise<void> {
    this.logger.info('Starting bounce SMTP server', {
      host: this.config.host,
      port: this.config.port,
    });

    this.smtpServer = new SMTPServer({
      name: this.config.hostname,
      size: this.config.maxMessageSize,
      disabledCommands: ['AUTH'],
      authOptional: true,
      
      onConnect: (session, callback) => this.onConnect(session, callback),
      onMailFrom: (address, session, callback) => this.onMailFrom(address, session, callback),
      onRcptTo: (address, session, callback) => this.onRcptTo(address, session, callback),
      onData: (stream, session, callback) => this.onData(stream, session, callback),
    });

    await new Promise<void>((resolve, reject) => {
      this.smtpServer!.listen(this.config.port, this.config.host, () => {
        this.logger.info('Bounce SMTP server listening', { port: this.config.port });
        resolve();
      });
      this.smtpServer!.on('error', reject);
    });
  }

  async stop(): Promise<void> {
    this.logger.info('Stopping bounce SMTP server');
    
    if (this.smtpServer) {
      await new Promise<void>((resolve) => {
        this.smtpServer!.close(() => resolve());
      });
    }
    
    this.logger.info('Bounce SMTP server stopped');
  }

  private onConnect(session: SMTPServerSession, callback: (err?: Error) => void): void {
    this.logger.debug('Bounce server connection', { 
      clientIP: session.remoteAddress,
      hostname: session.clientHostname,
    });
    callback();
  }

  private onMailFrom(
    address: SMTPServerAddress,
    _session: SMTPServerSession,
    callback: (err?: Error) => void
  ): void {
    // SECURITY FIX: RFC 5321 requires DSN/bounce notifications to come from the null sender (<>)
    // Accepting bounces from non-null senders allows spoofed bounces (backscatter attacks)
    const sender = address.address?.toLowerCase()?.trim() || '';
    
    if (sender !== '' && sender !== '<>') {
      this.logger.warn('Bounce server rejecting non-null sender', { from: address.address });
      return callback(new Error('550 Bounces must be sent from the null sender (<>)'));
    }
    
    this.logger.debug('Bounce MAIL FROM', { from: '<>' });
    callback();
  }

  private onRcptTo(
    address: SMTPServerAddress,
    _session: SMTPServerSession,
    callback: (err?: Error) => void
  ): void {
    // Accept mail to VERP addresses or bounce addresses
    if (!address.address) {
      callback(new Error('550 Missing recipient address'));
      return;
    }
    const email = address.address.toLowerCase();
    
    // Check if it's a VERP address for our domain
    if (this.isVerpAddress(email) || this.isBounceAddress(email)) {
      this.logger.debug('Accepting bounce recipient', { to: email });
      callback();
    } else {
      callback(new Error('550 Not a valid bounce address'));
    }
  }

  private isVerpAddress(email: string): boolean {
    // VERP format: bounces+tenant_id-message_id-recipient_hash@verp.domain.com
    const verpPattern = new RegExp(`^bounces\\+[^@]+@${this.escapeRegex(this.config.verpDomain)}$`, 'i');
    return verpPattern.test(email);
  }

  private isBounceAddress(email: string): boolean {
    // Standard bounce address format
    const bouncePatterns = [
      /^bounce@/i,
      /^bounces@/i,
      /^return@/i,
      /^mailer-daemon@/i,
    ];
    return bouncePatterns.some(p => p.test(email));
  }

  private escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  private onData(
    stream: SMTPServerDataStream,
    session: SMTPServerSession,
    callback: (err?: Error) => void
  ): void {
    const chunks: Buffer[] = [];

    stream.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
    });

    stream.on('end', async () => {
      try {
        const rawMessage = Buffer.concat(chunks);
        const parsed = await simpleParser(rawMessage);
        
        await this.processBounce(session, parsed, rawMessage);
        callback();
        
      } catch (error) {
        this.logger.error('Bounce processing error', { 
          error: error instanceof Error ? error.message : 'Unknown error',
        });
        callback(new Error('451 Error processing bounce'));
      }
    });

    stream.on('error', (error) => {
      this.logger.error('Bounce stream error', { error });
      callback(error);
    });
  }

  private async processBounce(
    session: SMTPServerSession,
    parsed: ParsedMail,
    rawMessage: Buffer
  ): Promise<void> {
    const bounceId = generateId('bnc');
    const recipient = session.envelope.rcptTo[0]?.address;

    this.logger.info('Processing bounce', {
      bounceId,
      to: recipient,
      from: session.envelope.mailFrom ? session.envelope.mailFrom.address : '<>',
    });

    // Try to extract bounce info from VERP address
    let verpInfo: { tenantId?: string; messageId?: string; recipientHash?: string } | null = null;
    if (recipient && this.isVerpAddress(recipient)) {
      verpInfo = this.parseVerpAddress(recipient);
    }

    // Parse DSN (Delivery Status Notification)
    const bounceInfo = await this.parseBounceMessage(parsed);

    // Try to find original message
    let originalMessage: { id: string; tenant_id: string; to_address: string } | null = null;
    
    if (verpInfo?.messageId) {
      // Use VERP to find message
      const result = await this.db.query<{ id: string; tenant_id: string; to_address: string }>(`
        SELECT id, tenant_id, to_address FROM messages
        WHERE id = $1
      `, [verpInfo.messageId]);
      originalMessage = result.rows[0] ?? null;
    } else if (bounceInfo.originalMessageId) {
      // Use Message-ID header
      const result = await this.db.query<{ id: string; tenant_id: string; to_address: string }>(`
        SELECT id, tenant_id, to_address FROM messages
        WHERE message_id_header = $1
      `, [bounceInfo.originalMessageId]);
      originalMessage = result.rows[0] ?? null;
    }

    if (!originalMessage) {
      this.logger.warn('Could not find original message for bounce', {
        bounceId,
        verpInfo,
        originalMessageId: bounceInfo.originalMessageId,
      });
      // Store as unmatched bounce
      await this.storeUnmatchedBounce(bounceId, session, parsed, rawMessage, bounceInfo);
      return;
    }

    // Record bounce event
    const eventId = generateId('evt');
    await this.db.query(`
      INSERT INTO events (
        id, tenant_id, message_id, event_type, recipient,
        bounce_type, bounce_subtype, diagnostic_code, timestamp, raw_data
      ) VALUES ($1, $2, $3, 'bounced', $4, $5, $6, $7, NOW(), $8)
    `, [
      eventId,
      originalMessage.tenant_id,
      originalMessage.id,
      bounceInfo.originalRecipient || originalMessage.to_address,
      bounceInfo.bounceType,
      bounceInfo.bounceSubtype,
      bounceInfo.diagnosticCode,
      JSON.stringify({
        status: bounceInfo.status,
        action: bounceInfo.action,
        rawHeaders: this.extractHeaders(parsed),
      }),
    ]);

    // Update message status
    await this.db.query(`
      UPDATE messages SET status = 'bounced', updated_at = NOW()
      WHERE id = $1
    `, [originalMessage.id]);

    // Add to suppression list for hard bounces
    if (bounceInfo.bounceType === 'hard') {
      await this.addToSuppressionList(
        originalMessage.tenant_id,
        bounceInfo.originalRecipient || originalMessage.to_address,
        'bounce',
        bounceInfo.bounceSubtype
      );
    }

    // Queue webhook
    await this.queueBounceWebhook(originalMessage.tenant_id, {
      eventId,
      messageId: originalMessage.id,
      recipient: bounceInfo.originalRecipient || originalMessage.to_address,
      bounceType: bounceInfo.bounceType,
      bounceSubtype: bounceInfo.bounceSubtype,
      diagnosticCode: bounceInfo.diagnosticCode,
      timestamp: new Date().toISOString(),
    });

    this.logger.info('Bounce processed', {
      bounceId,
      messageId: originalMessage.id,
      bounceType: bounceInfo.bounceType,
      bounceSubtype: bounceInfo.bounceSubtype,
    });
  }

  private parseVerpAddress(email: string): { tenantId?: string; messageId?: string; recipientHash?: string } {
    // Format: bounces+tenant_id-message_id-recipient_hash@verp.domain.com
    const localPart = email.split('@')[0];
    if (!localPart) return {};
    const parts = localPart.replace('bounces+', '').split('-');
    
    if (parts.length >= 3) {
      return {
        tenantId: parts[0],
        messageId: parts[1],
        recipientHash: parts[2],
      };
    }
    
    return {};
  }

  private async parseBounceMessage(parsed: ParsedMail): Promise<BounceInfo> {
    const result: BounceInfo = {
      originalMessageId: null,
      originalRecipient: null,
      bounceType: 'soft',
      bounceSubtype: 'unknown',
      diagnosticCode: '',
      action: 'failed',
      status: '5.0.0',
    };

    // G-212: Wrap each parsing step in try/catch so a malformed attachment
    // or header doesn't crash the entire bounce processor.
    try {
      // Check for DSN (multipart/report)
      const attachments = parsed.attachments ?? [];
      for (const attachment of attachments) {
        try {
          if (attachment.contentType === 'message/delivery-status') {
            const dsn = attachment.content.toString('utf-8');
            this.parseDSN(dsn, result);
          } else if (attachment.contentType === 'message/rfc822') {
            // Original message headers
            const originalHeaders = attachment.content.toString('utf-8');
            this.extractOriginalMessageId(originalHeaders, result);
          }
        } catch (attachErr) {
          this.logger.warn('G-212: Failed to parse bounce attachment, skipping', {
            contentType: attachment.contentType,
            error: attachErr instanceof Error ? attachErr.message : 'Unknown',
          });
        }
      }
    } catch (err) {
      this.logger.warn('G-212: Failed to iterate bounce attachments', {
        error: err instanceof Error ? err.message : 'Unknown',
      });
    }

    // Fallback: Try to extract from headers
    try {
      if (!result.originalMessageId) {
        // Check In-Reply-To or References headers
        const inReplyTo = parsed.inReplyTo;
        if (inReplyTo) {
          result.originalMessageId = inReplyTo;
        }
      }
    } catch (err) {
      this.logger.warn('G-212: Failed to extract In-Reply-To header', {
        error: err instanceof Error ? err.message : 'Unknown',
      });
    }

    // Analyze bounce type from diagnostic code or text
    try {
      if (!result.diagnosticCode && parsed.text) {
        result.diagnosticCode = this.extractDiagnosticFromText(parsed.text);
      }
    } catch (err) {
      this.logger.warn('G-212: Failed to extract diagnostic from bounce text', {
        error: err instanceof Error ? err.message : 'Unknown',
      });
    }

    // Classify bounce type
    this.classifyBounce(result);

    return result;
  }

  private parseDSN(dsn: string, result: BounceInfo): void {
    const lines = dsn.split(/\r?\n/);

    for (const line of lines) {
      const lowerLine = line.toLowerCase();
      
      if (lowerLine.startsWith('original-recipient:')) {
        result.originalRecipient = this.extractAddress(line);
      } else if (lowerLine.startsWith('final-recipient:')) {
        if (!result.originalRecipient) {
          result.originalRecipient = this.extractAddress(line);
        }
      } else if (lowerLine.startsWith('action:')) {
        result.action = line.split(':')[1]?.trim().toLowerCase() ?? 'failed';
      } else if (lowerLine.startsWith('status:')) {
        result.status = line.split(':')[1]?.trim() ?? '5.0.0';
      } else if (lowerLine.startsWith('diagnostic-code:')) {
        result.diagnosticCode = line.split(':').slice(1).join(':').trim();
      } else if (lowerLine.startsWith('x-original-message-id:')) {
        result.originalMessageId = line.split(':').slice(1).join(':').trim();
      }
    }
  }

  private extractAddress(line: string): string {
    // Format: "Final-Recipient: rfc822;user@example.com"
    const match = line.match(/;?\s*([^\s;]+@[^\s;]+)/);
    return match?.[1] ?? '';
  }

  private extractOriginalMessageId(headers: string, result: BounceInfo): void {
    const match = headers.match(/^message-id:\s*(<[^>]+>|[^\s]+)/im);
    if (match?.[1]) {
      result.originalMessageId = match[1].replace(/[<>]/g, '');
    }
  }

  private extractDiagnosticFromText(text: string): string {
    // Look for SMTP error codes in text
    const smtpMatch = text.match(/(\d{3})[\s-](\d\.\d\.\d)?\s*(.+)/);
    if (smtpMatch) {
      return `smtp;${smtpMatch[1]} ${smtpMatch[2] ?? ''} ${smtpMatch[3]}`.trim();
    }

    // Look for common bounce phrases
    const phrases = [
      /user unknown/i,
      /mailbox not found/i,
      /no such user/i,
      /mailbox full/i,
      /over quota/i,
      /connection refused/i,
      /host not found/i,
      /domain not found/i,
      /blocked/i,
      /rejected/i,
      /spam/i,
    ];

    for (const phrase of phrases) {
      const match = text.match(phrase);
      if (match) {
        return `text;${match[0]}`;
      }
    }

    return '';
  }

  /**
   * E-142: Comprehensive SMTP bounce classification.
   *
   * Maps RFC 3463 enhanced status codes and common diagnostic strings to
   * hard/soft bounce types with granular subtypes.  The ordering is
   * intentional: more specific codes are matched first so they take
   * precedence over the broader class-level fallbacks.
   */
  private classifyBounce(result: BounceInfo): void {
    const status = result.status;
    const diagnostic = result.diagnosticCode.toLowerCase();

    // ------------------------------------------------------------------
    // Step 1 — determine hard vs soft from the status class
    // ------------------------------------------------------------------
    if (status.startsWith('5.')) {
      result.bounceType = 'hard';
    } else if (status.startsWith('4.')) {
      result.bounceType = 'soft';
    }

    // ------------------------------------------------------------------
    // Step 2 — determine subtype from specific status codes + diagnostics
    // ------------------------------------------------------------------

    // --- Hard bounce subtypes ---

    // 5.1.x — Addressing errors
    if (/5\.1\.[1-6]/.test(status) ||
        /user unknown|no such user|mailbox not found|does not exist|address rejected|recipient rejected/i.test(diagnostic)) {
      result.bounceType = 'hard';
      result.bounceSubtype = 'no-mailbox';
    } else if (/5\.1\.0/.test(status) || /invalid address|bad destination/i.test(diagnostic)) {
      result.bounceType = 'hard';
      result.bounceSubtype = 'syntax-error';
    } else if (/5\.1\.[7-9]/.test(status) || /sender.*rejected|null sender/i.test(diagnostic)) {
      result.bounceType = 'hard';
      result.bounceSubtype = 'bad-sender';
    }

    // 5.2.x — Mailbox status
    else if (/5\.2\.1/.test(status) || /disabled|inactive|account.*disabled/i.test(diagnostic)) {
      result.bounceType = 'hard';
      result.bounceSubtype = 'disabled';
    } else if (/5\.2\.2/.test(status) || /over quota|mailbox full|storage exceeded/i.test(diagnostic)) {
      // Permanent quota — treat as hard (RFC 3463 5.2.2)
      result.bounceType = 'hard';
      result.bounceSubtype = 'mailbox-full';
    } else if (/5\.2\.[034]/.test(status) || /message.*too large|size limit/i.test(diagnostic)) {
      result.bounceType = 'hard';
      result.bounceSubtype = 'message-too-large';
    }

    // 5.3.x — System status (destination)
    else if (/5\.3\.[0-5]/.test(status) || /system.*not accepting|not capable/i.test(diagnostic)) {
      result.bounceType = 'hard';
      result.bounceSubtype = 'system-error';
    }

    // 5.5.x — Protocol errors
    else if (/5\.5\.[0-5]/.test(status) || /protocol error|command.*not recognized/i.test(diagnostic)) {
      result.bounceType = 'hard';
      result.bounceSubtype = 'protocol-error';
    }

    // 5.6.x — Media/content errors
    else if (/5\.6\.[0-6]/.test(status) || /content.*rejected|media.*not supported/i.test(diagnostic)) {
      result.bounceType = 'hard';
      result.bounceSubtype = 'content-error';
    }

    // 5.7.x — Policy / security
    else if (/5\.7\.[0-9]/.test(status) ||
             /blocked|rejected|spam|policy|blacklist|dmarc|spf.*fail|dkim.*fail|authentication.*required/i.test(diagnostic)) {
      result.bounceType = 'hard';
      result.bounceSubtype = 'policy';
    }

    // 5.4.x — Network / routing (persistent)
    else if (/5\.4\.[0-7]/.test(status) || /no route|host not found|domain not found|dns.*error/i.test(diagnostic)) {
      result.bounceType = 'hard';
      result.bounceSubtype = 'domain-error';
    }

    // --- Soft bounce subtypes ---

    // 4.2.x — Mailbox issues (temporary)
    else if (/4\.2\.[12]/.test(status) || /over quota|mailbox full|insufficient.*storage/i.test(diagnostic)) {
      result.bounceType = 'soft';
      result.bounceSubtype = 'mailbox-full';
    }

    // 4.4.x — Network / connection issues
    else if (/4\.4\.[1-7]/.test(status) ||
             /connection|network|timeout|timed out|could not connect/i.test(diagnostic)) {
      result.bounceType = 'soft';
      result.bounceSubtype = 'network-error';
    }

    // 4.7.x — Rate limiting / greylisting
    else if (/4\.7\.[0-9]/.test(status) || /rate limit|too many|try.*later|greylisted/i.test(diagnostic)) {
      result.bounceType = 'soft';
      result.bounceSubtype = 'rate-limited';
    }

    // 4.3.x — System issues (temporary)
    else if (/4\.3\.[0-5]/.test(status) || /system|temporary|service.*unavailable/i.test(diagnostic)) {
      result.bounceType = 'soft';
      result.bounceSubtype = 'system-error';
    }

    // 4.1.x — Addressing (temporary — e.g. relay denied temporarily)
    else if (/4\.1\.[0-9]/.test(status)) {
      result.bounceType = 'soft';
      result.bounceSubtype = 'address-temporary';
    }

    // 4.5.x — Protocol issues (temporary)
    else if (/4\.5\.[0-5]/.test(status)) {
      result.bounceType = 'soft';
      result.bounceSubtype = 'protocol-error';
    }

    // --- Default subtypes ---
    else if (result.bounceType === 'hard') {
      result.bounceSubtype = 'other';
    } else {
      result.bounceSubtype = 'unknown';
    }
  }

  private extractHeaders(parsed: ParsedMail): Record<string, string> {
    const headers: Record<string, string> = {};
    for (const [key, value] of parsed.headers) {
      if (typeof value === 'string') {
        headers[key] = value;
      }
    }
    return headers;
  }

  private async storeUnmatchedBounce(
    bounceId: string,
    session: SMTPServerSession,
    _parsed: ParsedMail,
    rawMessage: Buffer,
    bounceInfo: BounceInfo
  ): Promise<void> {
    await this.db.query(`
      INSERT INTO unmatched_bounces (
        id, recipient, from_address, bounce_type, bounce_subtype,
        diagnostic_code, original_message_id, raw_message, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
    `, [
      bounceId,
      session.envelope.rcptTo[0]?.address,
      session.envelope.mailFrom ? session.envelope.mailFrom.address : '<>',
      bounceInfo.bounceType,
      bounceInfo.bounceSubtype,
      bounceInfo.diagnosticCode,
      bounceInfo.originalMessageId,
      rawMessage,
    ]);
  }

  private async addToSuppressionList(
    tenantId: string,
    email: string,
    reason: 'bounce' | 'complaint' | 'unsubscribe',
    subtype: string
  ): Promise<void> {
    const suppressionId = generateId('sup');
    
    await this.db.query(`
      INSERT INTO suppressions (id, tenant_id, email, reason, subtype, created_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
      ON CONFLICT (tenant_id, email) DO UPDATE SET
        reason = EXCLUDED.reason,
        subtype = EXCLUDED.subtype,
        updated_at = NOW()
    `, [suppressionId, tenantId, email.toLowerCase(), reason, subtype]);
  }

  /**
   * FIX-500-366: Cleanup old unmatched bounces in bounded batches
   * Prevents unbounded table growth. Should be called periodically (e.g., daily cron).
   */
  async cleanupUnmatchedBounces(retentionDays = 30, batchSize = 1000): Promise<number> {
    const result = await this.db.query<{ id: string }>(`
      DELETE FROM unmatched_bounces
      WHERE id IN (
        SELECT id FROM unmatched_bounces
        WHERE created_at < NOW() - INTERVAL '1 day' * $1
        LIMIT $2
      )
      RETURNING id
    `, [retentionDays, batchSize]);
    const deleted = result.rowCount ?? 0;
    if (deleted > 0) {
      this.logger.info('Cleaned up unmatched bounces', { deleted, retentionDays });
    }
    return deleted;
  }

  private async queueBounceWebhook(tenantId: string, data: Record<string, unknown>): Promise<void> {
    const result = await this.db.query<{ id: string }>(`
      SELECT id FROM webhooks
      WHERE tenant_id = $1 AND enabled = true
        AND (events @> '"message.bounced"'::jsonb OR events @> '"*"'::jsonb)
    `, [tenantId]);

    for (const webhook of result.rows) {
      await this.db.query(`
        INSERT INTO webhook_queue (
          id, webhook_id, tenant_id, event_type, payload, status, attempt, created_at
        ) VALUES ($1, $2, $3, 'message.bounced', $4, 'pending', 1, NOW())
      `, [
        generateId('whj'),
        webhook.id,
        tenantId,
        JSON.stringify({
          id: generateId('evt'),
          type: 'message.bounced',
          tenantId,
          timestamp: new Date().toISOString(),
          data,
        }),
      ]);
    }
  }
}
