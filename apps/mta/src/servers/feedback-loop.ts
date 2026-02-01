/**
 * Feedback Loop Server - Processes ARF complaint reports
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';
import { generateId } from '@apexmail/lib';
import { SMTPServer, type SMTPServerSession, type SMTPServerAddress, type SMTPServerDataStream } from 'smtp-server';
import { simpleParser, type ParsedMail, type Attachment } from 'mailparser';

interface FeedbackLoopServerConfig {
  db: Pool;
  redis: Redis;
  config: {
    host: string;
    port: number;
    hostname: string;
    maxMessageSize: number;
  };
  logger: Logger;
}

interface ComplaintInfo {
  feedbackType: string;
  userAgent: string;
  version: string;
  originalMessageId: string | null;
  originalRecipient: string | null;
  reportingMTA: string | null;
  sourceIp: string | null;
  arrivalDate: Date | null;
  reportedDomain: string | null;
  reportedUri: string[];
  authenticationResults: string | null;
}

export class FeedbackLoopServer {
  private readonly db: Pool;
  private readonly redis: Redis;
  private readonly config: FeedbackLoopServerConfig['config'];
  private readonly logger: Logger;
  
  private smtpServer: SMTPServer | null = null;

  constructor(options: FeedbackLoopServerConfig) {
    this.db = options.db;
    this.redis = options.redis;
    this.config = options.config;
    this.logger = options.logger;
  }

  async start(): Promise<void> {
    this.logger.info('Starting feedback loop SMTP server', {
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
        this.logger.info('Feedback loop SMTP server listening', { port: this.config.port });
        resolve();
      });
      this.smtpServer!.on('error', reject);
    });
  }

  async stop(): Promise<void> {
    this.logger.info('Stopping feedback loop SMTP server');
    
    if (this.smtpServer) {
      await new Promise<void>((resolve) => {
        this.smtpServer!.close(() => resolve());
      });
    }
    
    this.logger.info('Feedback loop SMTP server stopped');
  }

  private onConnect(session: SMTPServerSession, callback: (err?: Error) => void): void {
    this.logger.debug('FBL server connection', { 
      clientIP: session.remoteAddress,
      hostname: session.clientHostname,
    });
    callback();
  }

  private onMailFrom(
    address: SMTPServerAddress,
    session: SMTPServerSession,
    callback: (err?: Error) => void
  ): void {
    this.logger.debug('FBL MAIL FROM', { from: address.address });
    callback();
  }

  private onRcptTo(
    address: SMTPServerAddress,
    session: SMTPServerSession,
    callback: (err?: Error) => void
  ): void {
    // Accept mail to FBL addresses
    const email = address.address.toLowerCase();
    
    if (this.isFblAddress(email)) {
      this.logger.debug('Accepting FBL recipient', { to: email });
      callback();
    } else {
      callback(new Error('550 Not a valid FBL address'));
    }
  }

  private isFblAddress(email: string): boolean {
    // Accept various FBL address patterns
    const fblPatterns = [
      /^abuse@/i,
      /^complaints@/i,
      /^fbl@/i,
      /^feedback@/i,
      /^postmaster@/i,
    ];
    return fblPatterns.some(p => p.test(email));
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
        
        await this.processComplaint(session, parsed, rawMessage);
        callback();
        
      } catch (error) {
        this.logger.error('FBL processing error', { 
          error: error instanceof Error ? error.message : 'Unknown error',
        });
        callback(new Error('451 Error processing feedback'));
      }
    });

    stream.on('error', (error) => {
      this.logger.error('FBL stream error', { error });
      callback(error);
    });
  }

  private async processComplaint(
    session: SMTPServerSession,
    parsed: ParsedMail,
    rawMessage: Buffer
  ): Promise<void> {
    const complaintId = generateId('cmp');

    this.logger.info('Processing complaint', {
      complaintId,
      from: session.envelope.mailFrom?.address,
      to: session.envelope.rcptTo[0]?.address,
    });

    // Parse ARF report
    const complaintInfo = await this.parseArfReport(parsed);

    // Try to find original message
    let originalMessage: { id: string; tenant_id: string; to_address: string } | null = null;
    
    if (complaintInfo.originalMessageId) {
      const result = await this.db.query<{ id: string; tenant_id: string; to_address: string }>(`
        SELECT id, tenant_id, to_address FROM messages
        WHERE message_id_header = $1
      `, [complaintInfo.originalMessageId]);
      originalMessage = result.rows[0] ?? null;
    }

    // If no match by message-id, try by recipient domain
    if (!originalMessage && complaintInfo.originalRecipient) {
      const result = await this.db.query<{ id: string; tenant_id: string; to_address: string }>(`
        SELECT id, tenant_id, to_address FROM messages
        WHERE to_address = $1
        ORDER BY created_at DESC
        LIMIT 1
      `, [complaintInfo.originalRecipient]);
      originalMessage = result.rows[0] ?? null;
    }

    if (!originalMessage) {
      this.logger.warn('Could not find original message for complaint', {
        complaintId,
        originalMessageId: complaintInfo.originalMessageId,
        originalRecipient: complaintInfo.originalRecipient,
      });
      await this.storeUnmatchedComplaint(complaintId, session, parsed, rawMessage, complaintInfo);
      return;
    }

    // Record complaint event
    const eventId = generateId('evt');
    await this.db.query(`
      INSERT INTO events (
        id, tenant_id, message_id, event_type, recipient,
        complaint_type, complaint_user_agent, timestamp, raw_data
      ) VALUES ($1, $2, $3, 'complained', $4, $5, $6, NOW(), $7)
    `, [
      eventId,
      originalMessage.tenant_id,
      originalMessage.id,
      complaintInfo.originalRecipient || originalMessage.to_address,
      complaintInfo.feedbackType,
      complaintInfo.userAgent,
      JSON.stringify({
        reportingMTA: complaintInfo.reportingMTA,
        sourceIp: complaintInfo.sourceIp,
        arrivalDate: complaintInfo.arrivalDate?.toISOString(),
        reportedDomain: complaintInfo.reportedDomain,
        reportedUri: complaintInfo.reportedUri,
        authResults: complaintInfo.authenticationResults,
      }),
    ]);

    // Update message status
    await this.db.query(`
      UPDATE messages SET status = 'complained', updated_at = NOW()
      WHERE id = $1
    `, [originalMessage.id]);

    // Add to suppression list
    await this.addToSuppressionList(
      originalMessage.tenant_id,
      complaintInfo.originalRecipient || originalMessage.to_address,
      'complaint',
      complaintInfo.feedbackType
    );

    // Queue webhook
    await this.queueComplaintWebhook(originalMessage.tenant_id, {
      eventId,
      messageId: originalMessage.id,
      recipient: complaintInfo.originalRecipient || originalMessage.to_address,
      complaintType: complaintInfo.feedbackType,
      userAgent: complaintInfo.userAgent,
      timestamp: new Date().toISOString(),
    });

    // Update sender reputation
    await this.updateSenderReputation(originalMessage.tenant_id, 'complaint');

    this.logger.info('Complaint processed', {
      complaintId,
      messageId: originalMessage.id,
      feedbackType: complaintInfo.feedbackType,
    });
  }

  private async parseArfReport(parsed: ParsedMail): Promise<ComplaintInfo> {
    const result: ComplaintInfo = {
      feedbackType: 'abuse',
      userAgent: '',
      version: '1',
      originalMessageId: null,
      originalRecipient: null,
      reportingMTA: null,
      sourceIp: null,
      arrivalDate: null,
      reportedDomain: null,
      reportedUri: [],
      authenticationResults: null,
    };

    // Check for ARF format (multipart/report; report-type=feedback-report)
    const attachments = parsed.attachments ?? [];
    
    for (const attachment of attachments) {
      if (attachment.contentType === 'message/feedback-report') {
        this.parseArfFeedback(attachment.content.toString('utf-8'), result);
      } else if (attachment.contentType === 'message/rfc822' || 
                 attachment.contentType === 'text/rfc822-headers') {
        this.extractOriginalMessage(attachment, result);
      }
    }

    // Fallback: Extract from main message headers/body
    if (!result.originalMessageId) {
      // Check X-Original-Message-Id header
      const xOriginalId = parsed.headers.get('x-original-message-id');
      if (typeof xOriginalId === 'string') {
        result.originalMessageId = xOriginalId.replace(/[<>]/g, '');
      }
    }

    // Get feedback type from subject if not set
    if (!result.feedbackType || result.feedbackType === 'abuse') {
      const subject = parsed.subject?.toLowerCase() ?? '';
      if (subject.includes('unsubscribe')) {
        result.feedbackType = 'opt-out';
      } else if (subject.includes('fraud')) {
        result.feedbackType = 'fraud';
      } else if (subject.includes('virus') || subject.includes('malware')) {
        result.feedbackType = 'virus';
      }
    }

    // Get user agent from headers
    if (!result.userAgent) {
      const userAgent = parsed.headers.get('user-agent') || 
                       parsed.headers.get('x-mailer') ||
                       parsed.headers.get('from');
      if (typeof userAgent === 'string') {
        result.userAgent = userAgent;
      } else if (userAgent && typeof userAgent === 'object' && 'text' in userAgent) {
        result.userAgent = String(userAgent.text);
      }
    }

    return result;
  }

  private parseArfFeedback(content: string, result: ComplaintInfo): void {
    const lines = content.split(/\r?\n/);

    for (const line of lines) {
      const colonIndex = line.indexOf(':');
      if (colonIndex === -1) continue;

      const key = line.substring(0, colonIndex).toLowerCase().trim();
      const value = line.substring(colonIndex + 1).trim();

      switch (key) {
        case 'feedback-type':
          result.feedbackType = value.toLowerCase();
          break;
        case 'user-agent':
          result.userAgent = value;
          break;
        case 'version':
          result.version = value;
          break;
        case 'original-mail-from':
          // Sender of original message
          break;
        case 'original-rcpt-to':
          result.originalRecipient = this.extractEmail(value);
          break;
        case 'arrival-date':
          result.arrivalDate = new Date(value);
          break;
        case 'reporting-mta':
          result.reportingMTA = value;
          break;
        case 'source-ip':
          result.sourceIp = value;
          break;
        case 'reported-domain':
          result.reportedDomain = value;
          break;
        case 'reported-uri':
          result.reportedUri.push(value);
          break;
        case 'authentication-results':
          result.authenticationResults = value;
          break;
      }
    }
  }

  private extractOriginalMessage(attachment: Attachment, result: ComplaintInfo): void {
    const content = attachment.content.toString('utf-8');
    
    // Extract Message-ID
    const messageIdMatch = content.match(/^message-id:\s*(<[^>]+>|[^\r\n]+)/im);
    if (messageIdMatch) {
      result.originalMessageId = messageIdMatch[1].replace(/[<>]/g, '').trim();
    }

    // Extract To address if not already set
    if (!result.originalRecipient) {
      const toMatch = content.match(/^to:\s*([^\r\n]+)/im);
      if (toMatch) {
        result.originalRecipient = this.extractEmail(toMatch[1]);
      }
    }
  }

  private extractEmail(text: string): string {
    // Extract email from formats like "Name <email@example.com>" or just "email@example.com"
    const match = text.match(/<([^>]+)>/) || text.match(/([^\s,;]+@[^\s,;]+)/);
    return match?.[1]?.trim().toLowerCase() ?? '';
  }

  private async storeUnmatchedComplaint(
    complaintId: string,
    session: SMTPServerSession,
    parsed: ParsedMail,
    rawMessage: Buffer,
    complaintInfo: ComplaintInfo
  ): Promise<void> {
    await this.db.query(`
      INSERT INTO unmatched_complaints (
        id, recipient, from_address, feedback_type, user_agent,
        original_message_id, original_recipient, raw_message, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
    `, [
      complaintId,
      session.envelope.rcptTo[0]?.address,
      session.envelope.mailFrom?.address,
      complaintInfo.feedbackType,
      complaintInfo.userAgent,
      complaintInfo.originalMessageId,
      complaintInfo.originalRecipient,
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

  private async queueComplaintWebhook(tenantId: string, data: Record<string, unknown>): Promise<void> {
    const result = await this.db.query<{ id: string }>(`
      SELECT id FROM webhooks
      WHERE tenant_id = $1 AND enabled = true
        AND (events @> '"message.complained"'::jsonb OR events @> '"*"'::jsonb)
    `, [tenantId]);

    for (const webhook of result.rows) {
      await this.db.query(`
        INSERT INTO webhook_queue (
          id, webhook_id, tenant_id, event_type, payload, status, attempt, created_at
        ) VALUES ($1, $2, $3, 'message.complained', $4, 'pending', 1, NOW())
      `, [
        generateId('whj'),
        webhook.id,
        tenantId,
        JSON.stringify({
          id: generateId('evt'),
          type: 'message.complained',
          tenantId,
          timestamp: new Date().toISOString(),
          data,
        }),
      ]);
    }
  }

  private async updateSenderReputation(tenantId: string, eventType: 'complaint' | 'bounce'): Promise<void> {
    // Update daily reputation stats
    const date = new Date().toISOString().split('T')[0];
    const field = eventType === 'complaint' ? 'complaints' : 'bounces';

    await this.db.query(`
      INSERT INTO reputation_stats (tenant_id, date, ${field})
      VALUES ($1, $2, 1)
      ON CONFLICT (tenant_id, date) DO UPDATE SET
        ${field} = reputation_stats.${field} + 1
    `, [tenantId, date]);

    // Update Redis real-time counter
    const key = `reputation:${tenantId}:${eventType}:${date}`;
    await this.redis.incr(key);
    await this.redis.expire(key, 86400 * 7); // 7 days TTL

    // Check if reputation is degrading (for alerting)
    const recentComplaints = await this.redis.get(`reputation:${tenantId}:complaint:${date}`);
    const recentSent = await this.redis.get(`sent:${tenantId}:${date}`);

    if (recentComplaints && recentSent) {
      const complaintRate = parseInt(recentComplaints) / parseInt(recentSent);
      
      // Alert if complaint rate exceeds threshold (0.1%)
      if (complaintRate > 0.001) {
        this.logger.warn('High complaint rate detected', {
          tenantId,
          complaintRate: (complaintRate * 100).toFixed(4) + '%',
          complaints: recentComplaints,
          sent: recentSent,
        });

        // Store alert
        await this.db.query(`
          INSERT INTO reputation_alerts (id, tenant_id, alert_type, value, threshold, created_at)
          VALUES ($1, $2, 'high_complaint_rate', $3, 0.001, NOW())
        `, [generateId('alt'), tenantId, complaintRate]);
      }
    }
  }
}
