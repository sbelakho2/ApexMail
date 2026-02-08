/**
 * Inbound SMTP Server - Receives and processes incoming email
 * 
 * SECURITY: Uses timing-safe comparisons for password verification
 */

import { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';
import { generateId } from '@apexmail/lib';
import { verifyPassword } from '@apexmail/lib/crypto';
import { SMTPServer, type SMTPServerSession, type SMTPServerAddress, type SMTPServerDataStream } from 'smtp-server';
import { simpleParser, type ParsedMail, type AddressObject, type Headers } from 'mailparser';
import { EmailAuthenticator, type AuthenticationResults } from '../auth/email-authentication.js';
import { readFileSync } from 'fs';

interface InboundServerConfig {
  db: Pool;
  redis: Redis;
  config: {
    host: string;
    port: number;
    securePort: number;
    hostname: string;
    maxMessageSize: number;
    maxRecipients: number;
    authRequired: boolean;
    tls: {
      enabled: boolean;
      keyPath?: string;
      certPath?: string;
    };
  };
  rateLimit: {
    enabled: boolean;
    maxConnectionsPerIP: number;
    maxMessagesPerConnection: number;
    maxRecipientsPerMessage: number;
  };
  emailAuth: {
    requireSPF: boolean;
    requireDKIM: boolean;
    enforceDMARC: boolean;
    allowSoftFail: boolean;
    trustedRelays: string[];
  };
  logger: Logger;
}

interface SessionContext {
  id: string;
  clientIP: string;
  authenticated: boolean;
  tenantId?: string;
  messageCount: number;
  startTime: Date;
  heloHostname: string;
  mailFrom?: string;
}

export class InboundServer {
  private readonly db: Pool;
  private readonly config: InboundServerConfig['config'];
  private readonly rateLimit: InboundServerConfig['rateLimit'];
  private readonly emailAuth: InboundServerConfig['emailAuth'];
  private readonly logger: Logger;
  private readonly authenticator: EmailAuthenticator;
  private readonly redis: Redis;
  
  private smtpServer: SMTPServer | null = null;
  private secureSmtpServer: SMTPServer | null = null;
  private readonly sessions = new Map<string, SessionContext>();
  private readonly connectionCounts = new Map<string, number>();
  // SECURITY FIX: Track auth attempts for rate limiting
  private readonly authAttemptCounts = new Map<string, { count: number; firstAttempt: number }>();
  private readonly AUTH_RATE_LIMIT = 5; // Max auth attempts
  private readonly AUTH_RATE_WINDOW = 60 * 1000; // 1 minute window
  // Memory management: Periodic cleanup timer
  private cleanupTimer: NodeJS.Timeout | null = null;

  constructor(options: InboundServerConfig) {
    this.db = options.db;
    this.redis = options.redis;
    this.config = options.config;
    this.rateLimit = options.rateLimit;
    this.emailAuth = options.emailAuth;
    this.logger = options.logger;
    
    // Initialize email authenticator
    this.authenticator = new EmailAuthenticator({
      requireSPF: this.emailAuth.requireSPF,
      requireDKIM: this.emailAuth.requireDKIM,
      enforceDMARC: this.emailAuth.enforceDMARC,
      allowSoftFail: this.emailAuth.allowSoftFail,
      trustedRelays: this.emailAuth.trustedRelays,
      logger: this.logger,
    });
    
    // Start periodic cleanup of stale auth attempts to prevent memory leak
    this.cleanupTimer = setInterval(() => this.cleanupStaleEntries(), 60000);
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /**
   * Clean up stale entries from tracking maps to prevent memory leaks
   */
  private cleanupStaleEntries(): void {
    const now = Date.now();
    let cleanedAuthAttempts = 0;
    
    // Clean up expired auth attempt records
    for (const [ip, attempts] of this.authAttemptCounts) {
      if (now - attempts.firstAttempt > this.AUTH_RATE_WINDOW) {
        this.authAttemptCounts.delete(ip);
        cleanedAuthAttempts++;
      }
    }
    
    if (cleanedAuthAttempts > 0) {
      this.logger.debug('Cleaned up stale auth attempt records', {
        cleaned: cleanedAuthAttempts,
        remaining: this.authAttemptCounts.size,
      });
    }
  }

  async start(): Promise<void> {
    this.logger.info('Starting inbound SMTP server', {
      host: this.config.host,
      port: this.config.port,
    });

    // Determine if we're in production mode
    const isProduction = process.env.NODE_ENV === 'production';

    // Load TLS certificates if enabled
    let tlsOptions: { key?: Buffer; cert?: Buffer } = {};
    if (this.config.tls.enabled && this.config.tls.keyPath && this.config.tls.certPath) {
      try {
        tlsOptions = {
          key: readFileSync(this.config.tls.keyPath),
          cert: readFileSync(this.config.tls.certPath),
        };
        this.logger.info('TLS certificates loaded successfully', {
          keyPath: this.config.tls.keyPath,
          certPath: this.config.tls.certPath,
        });
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        
        // In production, TLS certificate failure is fatal
        if (isProduction) {
          this.logger.error('FATAL: Failed to load TLS certificates in production mode', { 
            error: errorMessage,
            keyPath: this.config.tls.keyPath,
            certPath: this.config.tls.certPath,
          });
          throw new Error(`Failed to load TLS certificates: ${errorMessage}. TLS is required in production.`);
        }
        
        // In development, warn but continue
        this.logger.warn('Failed to load TLS certificates, starting without TLS (development mode only)', { 
          error: errorMessage 
        });
      }
    } else if (isProduction && this.config.tls.enabled) {
      // TLS is enabled but paths are missing in production
      throw new Error('TLS is enabled but certificate paths are not configured. TLS is required in production.');
    }

    // Security: Only allow insecure auth in development mode AND when explicitly not in production
    // This prevents accidental exposure if NODE_ENV is unset
    const allowInsecureAuth = !isProduction && process.env.ALLOW_INSECURE_AUTH === 'true';
    
    if (allowInsecureAuth) {
      this.logger.warn('SECURITY WARNING: Insecure authentication is enabled. Do not use in production!');
    }

    // Create SMTP server (port 25)
    this.smtpServer = new SMTPServer({
      name: this.config.hostname,
      size: this.config.maxMessageSize,
      authOptional: !this.config.authRequired,
      allowInsecureAuth,
      disabledCommands: this.config.authRequired ? [] : ['AUTH'],
      
      onConnect: (session, callback) => this.onConnect(session, callback),
      onAuth: (auth, session, callback) => this.onAuth(auth, session, callback),
      onMailFrom: (address, session, callback) => this.onMailFrom(address, session, callback),
      onRcptTo: (address, session, callback) => this.onRcptTo(address, session, callback),
      onData: (stream, session, callback) => this.onData(stream, session, callback),
      onClose: (session) => this.onClose(session),
      
      ...(this.config.tls.enabled && tlsOptions.key && {
        secure: false, // STARTTLS
        key: tlsOptions.key,
        cert: tlsOptions.cert,
      }),
    });

    await new Promise<void>((resolve, reject) => {
      this.smtpServer!.listen(this.config.port, this.config.host, () => {
        this.logger.info('SMTP server listening', { port: this.config.port });
        resolve();
      });
      this.smtpServer!.on('error', reject);
    });

    // Create secure SMTP server (port 465) if TLS is enabled
    if (this.config.tls.enabled && tlsOptions.key && tlsOptions.cert) {
      this.secureSmtpServer = new SMTPServer({
        name: this.config.hostname,
        size: this.config.maxMessageSize,
        authOptional: !this.config.authRequired,
        secure: true,
        key: tlsOptions.key,
        cert: tlsOptions.cert,
        
        onConnect: (session, callback) => this.onConnect(session, callback),
        onAuth: (auth, session, callback) => this.onAuth(auth, session, callback),
        onMailFrom: (address, session, callback) => this.onMailFrom(address, session, callback),
        onRcptTo: (address, session, callback) => this.onRcptTo(address, session, callback),
        onData: (stream, session, callback) => this.onData(stream, session, callback),
        onClose: (session) => this.onClose(session),
      });

      await new Promise<void>((resolve, reject) => {
        this.secureSmtpServer!.listen(this.config.securePort, this.config.host, () => {
          this.logger.info('Secure SMTP server listening', { port: this.config.securePort });
          resolve();
        });
        this.secureSmtpServer!.on('error', reject);
      });
    }
  }

  async stop(): Promise<void> {
    this.logger.info('Stopping inbound SMTP server');

    // Clear cleanup timer
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }

    // Shutdown email authenticator
    this.authenticator.shutdown();

    const promises: Promise<void>[] = [];

    if (this.smtpServer) {
      promises.push(new Promise((resolve) => {
        this.smtpServer!.close(() => resolve());
      }));
    }

    if (this.secureSmtpServer) {
      promises.push(new Promise((resolve) => {
        this.secureSmtpServer!.close(() => resolve());
      }));
    }

    await Promise.all(promises);
    
    // Clear all tracking maps
    this.sessions.clear();
    this.connectionCounts.clear();
    this.authAttemptCounts.clear();
    
    this.logger.info('Inbound SMTP server stopped');
  }

  private onConnect(session: SMTPServerSession, callback: (err?: Error) => void): void {
    const clientIP = session.remoteAddress;
    const sessionId = generateId('ses');

    this.logger.debug('SMTP connection', { sessionId, clientIP });

    // Rate limit: Check connections per IP
    if (this.rateLimit.enabled) {
      const currentConnections = this.connectionCounts.get(clientIP) ?? 0;
      if (currentConnections >= this.rateLimit.maxConnectionsPerIP) {
        this.logger.warn('Connection rate limit exceeded', { clientIP, currentConnections });
        return callback(new Error('421 Too many connections from your IP'));
      }
      this.connectionCounts.set(clientIP, currentConnections + 1);
    }

    // Create session context
    this.sessions.set(session.id, {
      id: sessionId,
      clientIP,
      authenticated: false,
      messageCount: 0,
      startTime: new Date(),
      heloHostname: session.hostNameAppearsAs ?? '',
    });

    callback();
  }

  private onAuth(
    auth: { method: string; username?: string; password?: string },
    session: SMTPServerSession,
    callback: (err?: Error | null, response?: { user: string }) => void
  ): void {
    const ctx = this.sessions.get(session.id);
    if (!ctx) {
      return callback(new Error('Session not found'));
    }

    // SECURITY FIX: Rate limit authentication attempts to prevent brute force attacks
    const clientIP = ctx.clientIP;
    const now = Date.now();
    let attempts = this.authAttemptCounts.get(clientIP);
    
    // Clean up expired attempt records
    if (attempts && (now - attempts.firstAttempt) > this.AUTH_RATE_WINDOW) {
      this.authAttemptCounts.delete(clientIP);
      attempts = undefined;
    }
    
    if (attempts) {
      if (attempts.count >= this.AUTH_RATE_LIMIT) {
        this.logger.warn('Auth rate limit exceeded', { 
          clientIP, 
          attempts: attempts.count,
          username: auth.username,
        });
        // Use Redis to track persistent blocks
        this.redis.setex(`smtp:auth_blocked:${clientIP}`, 300, '1').catch(() => {});
        return callback(new Error('421 Too many authentication attempts. Try again later.'));
      }
      attempts.count++;
    } else {
      this.authAttemptCounts.set(clientIP, { count: 1, firstAttempt: now });
    }

    // Check if IP is persistently blocked
    this.redis.get(`smtp:auth_blocked:${clientIP}`).then((blocked) => {
      if (blocked) {
        this.logger.warn('Auth attempt from blocked IP', { clientIP, username: auth.username });
        return callback(new Error('421 Your IP is temporarily blocked. Try again later.'));
      }
      
      this.logger.debug('SMTP auth attempt', { 
        sessionId: ctx.id, 
        username: auth.username,
        method: auth.method,
      });

      // Validate credentials against database
      this.validateCredentials(auth.username ?? '', auth.password ?? '')
        .then((result) => {
          if (result.valid) {
            // Clear auth attempts on successful login
            this.authAttemptCounts.delete(clientIP);
            ctx.authenticated = true;
            ctx.tenantId = result.tenantId;
            callback(null, { user: auth.username ?? '' });
          } else {
            callback(new Error('535 Authentication failed'));
          }
        })
        .catch((error) => {
          this.logger.error('Auth error', { error });
          callback(new Error('451 Temporary authentication failure'));
        });
    }).catch((error) => {
      this.logger.error('Redis error checking auth block', { error });
      // Fall through to attempt auth if Redis fails
      this.validateCredentials(auth.username ?? '', auth.password ?? '')
        .then((result) => {
          if (result.valid) {
            ctx.authenticated = true;
            ctx.tenantId = result.tenantId;
            callback(null, { user: auth.username ?? '' });
          } else {
            callback(new Error('535 Authentication failed'));
          }
        })
        .catch((err) => {
          this.logger.error('Auth error', { error: err });
          callback(new Error('451 Temporary authentication failure'));
        });
    });
  }

  private async validateCredentials(
    username: string,
    password: string
  ): Promise<{ valid: boolean; tenantId?: string }> {
    // Look up SMTP credentials in database
    const result = await this.db.query<{ tenant_id: string; password_hash: string }>(`
      SELECT tenant_id, password_hash
      FROM smtp_credentials
      WHERE username = $1 AND is_active = true
    `, [username]);

    const row = result.rows[0];
    if (!row) {
      return { valid: false };
    }

    const { tenant_id, password_hash } = row;

    // SECURITY: Use scrypt-based password verification (replaces weak SHA-256 hashing)
    // scrypt is a memory-hard KDF resistant to GPU/ASIC brute-force attacks
    const isValid = await verifyPassword(password, password_hash);
    if (!isValid) {
      return { valid: false };
    }

    return { valid: true, tenantId: tenant_id };
  }

  private onMailFrom(
    address: SMTPServerAddress,
    session: SMTPServerSession,
    callback: (err?: Error) => void
  ): void {
    const ctx = this.sessions.get(session.id);
    if (!ctx) {
      return callback(new Error('Session not found'));
    }

    this.logger.debug('MAIL FROM', { sessionId: ctx.id, from: address.address });

    // Store MAIL FROM for authentication
    ctx.mailFrom = address.address;

    // Check message count rate limit
    if (this.rateLimit.enabled && ctx.messageCount >= this.rateLimit.maxMessagesPerConnection) {
      return callback(new Error('452 Too many messages'));
    }

    // Validate sender domain if authenticated
    if (ctx.authenticated && ctx.tenantId) {
      this.validateSenderDomain(address.address, ctx.tenantId)
        .then((valid) => {
          if (valid) {
            callback();
          } else {
            callback(new Error('550 Sender domain not authorized'));
          }
        })
        .catch((error) => {
          this.logger.error('Sender validation error', { error });
          callback(new Error('451 Temporary error'));
        });
    } else {
      callback();
    }
  }

  private async validateSenderDomain(email: string, tenantId: string): Promise<boolean> {
    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return false;

    const result = await this.db.query(`
      SELECT 1 FROM domains
      WHERE tenant_id = $1 AND name = $2 AND is_verified = true
    `, [tenantId, domain]);

    return result.rows.length > 0;
  }

  private onRcptTo(
    address: SMTPServerAddress,
    session: SMTPServerSession,
    callback: (err?: Error) => void
  ): void {
    const ctx = this.sessions.get(session.id);
    if (!ctx) {
      return callback(new Error('Session not found'));
    }

    this.logger.debug('RCPT TO', { sessionId: ctx.id, to: address.address });

    // Check recipient count
    const recipientCount = (session.envelope.rcptTo?.length ?? 0) + 1;
    if (recipientCount > this.config.maxRecipients) {
      return callback(new Error('452 Too many recipients'));
    }

    // Validate recipient domain
    this.validateRecipient(address.address)
      .then((result) => {
        if (result.accepted) {
          callback();
        } else {
          callback(new Error(result.error ?? '550 User unknown'));
        }
      })
      .catch((error) => {
        this.logger.error('Recipient validation error', { error });
        callback(new Error('451 Temporary error'));
      });
  }

  private async validateRecipient(email: string): Promise<{ accepted: boolean; error?: string }> {
    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) {
      return { accepted: false, error: '550 Invalid address' };
    }

    // Check if we accept mail for this domain
    const result = await this.db.query(`
      SELECT id, tenant_id FROM domains
      WHERE name = $1 AND is_verified = true AND accepts_inbound = true
    `, [domain]);

    if (result.rows.length === 0) {
      return { accepted: false, error: '550 We do not accept mail for this domain' };
    }

    return { accepted: true };
  }

  private onData(
    stream: SMTPServerDataStream,
    session: SMTPServerSession,
    callback: (err?: Error) => void
  ): void {
    const ctx = this.sessions.get(session.id);
    if (!ctx) {
      return callback(new Error('Session not found'));
    }

    const chunks: Buffer[] = [];
    let size = 0;

    stream.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
      size += chunk.length;

      // Check size limit
      if (size > this.config.maxMessageSize) {
        stream.destroy(new Error('552 Message too large'));
      }
    });

    stream.on('end', async () => {
      try {
        const rawMessage = Buffer.concat(chunks);
        
        // Parse the email
        const parsed = await simpleParser(rawMessage);

        // Process the message
        await this.processInboundMessage(session, parsed, rawMessage, ctx);

        ctx.messageCount++;
        callback();

      } catch (error) {
        this.logger.error('Message processing error', { 
          sessionId: ctx.id, 
          error: error instanceof Error ? error.message : 'Unknown error',
        });
        callback(new Error('451 Error processing message'));
      }
    });

    stream.on('error', (error) => {
      this.logger.error('Stream error', { sessionId: ctx.id, error });
      callback(error);
    });
  }

  private async processInboundMessage(
    session: SMTPServerSession,
    parsed: ParsedMail,
    rawMessage: Buffer,
    ctx: SessionContext
  ): Promise<void> {
    const messageId = generateId('inb');
    const envelope = session.envelope;

    this.logger.info('Processing inbound message', {
      sessionId: ctx.id,
      messageId,
      from: envelope.mailFrom,
      to: envelope.rcptTo.map(r => r.address),
      subject: parsed.subject,
      size: rawMessage.length,
    });

    // Perform email authentication (SPF, DKIM, DMARC)
    let authResults: AuthenticationResults | null = null;
    let authAction: 'accept' | 'quarantine' | 'reject' = 'accept';
    
    try {
      authResults = await this.authenticator.authenticate(
        parsed,
        rawMessage,
        ctx.clientIP,
        ctx.heloHostname,
        ctx.mailFrom ?? (envelope.mailFrom ? (typeof envelope.mailFrom === 'string' ? envelope.mailFrom : envelope.mailFrom.address ?? '') : '')
      );

      const authDecision = this.authenticator.shouldAccept(authResults);
      authAction = authDecision.action;

      this.logger.info('Email authentication results', {
        sessionId: ctx.id,
        messageId,
        spf: authResults.spf.result,
        dkim: authResults.dkim.result,
        dmarc: authResults.dmarc.result,
        dmarcPolicy: authResults.dmarc.policy,
        action: authAction,
        reason: authDecision.reason,
      });

      // Reject if authentication fails and policy says reject
      if (!authDecision.accept) {
        throw new Error(`550 Email rejected: ${authDecision.reason}`);
      }
    } catch (error) {
      // If it's a rejection error, rethrow
      if (error instanceof Error && error.message.startsWith('550')) {
        throw error;
      }
      // Log other auth errors but continue processing
      this.logger.warn('Email authentication error', {
        sessionId: ctx.id,
        messageId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }

    // Check for VERP-style reply addresses to link replies to original messages
    // Format: reply+{original_message_id}@inbound.domain.com
    const replyTracking = await this.checkVerpReplyAddress(envelope.rcptTo);

    // Extract recipient domains to find tenants
    const recipientDomains = new Set<string>();
    for (const rcpt of envelope.rcptTo) {
      const domain = rcpt.address.split('@')[1]?.toLowerCase();
      if (domain) recipientDomains.add(domain);
    }

    // Look up domains
    const domainResult = await this.db.query<{ id: string; tenant_id: string; name: string }>(`
      SELECT id, tenant_id, name FROM domains
      WHERE name = ANY($1) AND is_verified = true
    `, [Array.from(recipientDomains)]);

    const domainMap = new Map<string, { id: string; tenant_id: string; name: string }>(domainResult.rows.map((d: { id: string; tenant_id: string; name: string }) => [d.name, d]));

    // Store message for each recipient
    for (const rcpt of envelope.rcptTo) {
      const recipientEmail = rcpt.address;
      const recipientDomain = recipientEmail.split('@')[1]?.toLowerCase();
      if (!recipientDomain) continue;
      const domain = domainMap.get(recipientDomain);

      if (!domain) continue;

      // Check if this is a reply to an original message via VERP
      const linkedMessageId = replyTracking.get(recipientEmail);

      // Store inbound message
      // FIX-500-365: ON CONFLICT prevents duplicate inbound messages if same message delivered twice
      await this.db.query(`
        INSERT INTO inbound_messages (
          id, tenant_id, domain_id, message_id_header, from_address, to_address,
          subject, text_body, html_body, raw_message, headers, attachments,
          received_at, client_ip, session_id, in_reply_to_message_id,
          spf_result, dkim_result, dmarc_result, dmarc_policy, auth_action
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), $13, $14, $15, $16, $17, $18, $19, $20)
        ON CONFLICT (tenant_id, message_id_header) DO NOTHING
      `, [
        messageId,
        domain.tenant_id,
        domain.id,
        parsed.messageId,
        this.extractAddress(parsed.from),
        recipientEmail,
        parsed.subject,
        parsed.text,
        parsed.html,
        rawMessage,
        JSON.stringify(this.headersToObject(parsed.headers)),
        JSON.stringify(this.extractAttachments(parsed)),
        ctx.clientIP,
        ctx.id,
        linkedMessageId ?? parsed.inReplyTo ?? null,
        authResults?.spf.result ?? 'none',
        authResults?.dkim.result ?? 'none',
        authResults?.dmarc.result ?? 'none',
        authResults?.dmarc.policy ?? 'none',
        authAction,
      ]);

      // If this is a reply, update the original message's reply count
      if (linkedMessageId) {
        await this.recordReplyToOriginalMessage(domain.tenant_id, linkedMessageId, messageId);
      }

      // Queue for webhook delivery if configured
      await this.queueInboundWebhook(domain.tenant_id, messageId, {
        from: this.extractAddress(parsed.from),
        to: recipientEmail,
        subject: parsed.subject,
        textBody: parsed.text,
        htmlBody: parsed.html !== false ? parsed.html : undefined,
        headers: this.headersToObject(parsed.headers),
        inReplyTo: linkedMessageId ?? parsed.inReplyTo ?? undefined,
        isReply: !!linkedMessageId,
        authentication: authResults ? {
          spf: authResults.spf.result,
          dkim: authResults.dkim.result,
          dmarc: authResults.dmarc.result,
          dmarcPolicy: authResults.dmarc.policy,
          action: authAction,
        } : undefined,
      });
    }
  }

  /**
   * Check for VERP-style reply addresses in recipients
   * Format: reply+{message_id}@domain.com or bounce+{message_id}@domain.com
   * Returns a map of recipient address -> original message ID
   */
  private async checkVerpReplyAddress(
    recipients: readonly SMTPServerAddress[]
  ): Promise<Map<string, string>> {
    const result = new Map<string, string>();
    
    for (const rcpt of recipients) {
      const address = rcpt.address.toLowerCase();
      // Match VERP patterns: reply+xxx@, bounce+xxx@, r+xxx@
      const verpMatch = address.match(/^(?:reply|bounce|r)\+([a-z0-9_-]+)@/i);
      
      if (verpMatch?.[1]) {
        const originalMessageId = verpMatch[1];
        result.set(rcpt.address, originalMessageId);
        
        this.logger.debug('Detected VERP reply address', {
          recipient: rcpt.address,
          originalMessageId,
        });
      }
    }
    
    return result;
  }

  /**
   * Record that a reply was received for an original message
   */
  private async recordReplyToOriginalMessage(
    tenantId: string,
    originalMessageId: string,
    replyMessageId: string
  ): Promise<void> {
    try {
      // Update reply count on original message
      await this.db.query(`
        UPDATE messages 
        SET reply_count = COALESCE(reply_count, 0) + 1,
            last_reply_at = NOW()
        WHERE id = $1 OR message_id = $1
      `, [originalMessageId]);

      // Create a reply event
      await this.db.query(`
        INSERT INTO events (
          id, tenant_id, message_id, event_type, timestamp,
          metadata, deduplication_key
        ) VALUES (
          $1, $2, $3, 'reply_received', NOW(),
          $4, $5
        )
        ON CONFLICT (deduplication_key) DO NOTHING
      `, [
        generateId('evt'),
        tenantId,
        originalMessageId,
        JSON.stringify({ replyMessageId }),
        `reply:${originalMessageId}:${replyMessageId}`,
      ]);

      this.logger.info('Recorded reply to original message', {
        tenantId,
        originalMessageId,
        replyMessageId,
      });
    } catch (error) {
      this.logger.error('Failed to record reply', {
        originalMessageId,
        replyMessageId,
        error: error instanceof Error ? error.message : 'Unknown',
      });
    }
  }

  private extractAddress(from: AddressObject | undefined): string {
    if (!from) return '';
    const address = from.value?.[0];
    return address?.address ?? '';
  }

  private headersToObject(headers: Headers): Record<string, string> {
    const obj: Record<string, string> = {};
    for (const [key, value] of headers) {
      if (typeof value === 'string') {
        obj[key] = value;
      } else if (value && typeof value === 'object' && 'value' in value) {
        obj[key] = String(value.value);
      }
    }
    return obj;
  }

  private extractAttachments(parsed: ParsedMail): Array<{
    filename: string;
    contentType: string;
    size: number;
    contentId?: string;
  }> {
    return (parsed.attachments ?? []).map(att => ({
      filename: att.filename ?? 'attachment',
      contentType: att.contentType,
      size: att.size,
      contentId: att.contentId,
    }));
  }

  private async queueInboundWebhook(
    tenantId: string,
    messageId: string,
    data: Record<string, unknown>
  ): Promise<void> {
    // Find webhooks for inbound events
    const result = await this.db.query<{ id: string }>(`
      SELECT id FROM webhooks
      WHERE tenant_id = $1 AND enabled = true
        AND (events @> '"message.inbound"'::jsonb OR events @> '"*"'::jsonb)
    `, [tenantId]);

    for (const webhook of result.rows) {
      await this.db.query(`
        INSERT INTO webhook_queue (
          id, webhook_id, tenant_id, event_type, payload, status, attempt, created_at
        ) VALUES ($1, $2, $3, 'message.inbound', $4, 'pending', 1, NOW())
      `, [
        generateId('whj'),
        webhook.id,
        tenantId,
        JSON.stringify({
          id: generateId('evt'),
          type: 'message.inbound',
          tenantId,
          timestamp: new Date().toISOString(),
          data: {
            messageId,
            ...data,
          },
        }),
      ]);
    }
  }

  private onClose(session: SMTPServerSession): void {
    const ctx = this.sessions.get(session.id);
    if (!ctx) return;

    // Decrement connection count
    if (this.rateLimit.enabled) {
      const count = this.connectionCounts.get(ctx.clientIP) ?? 1;
      if (count <= 1) {
        this.connectionCounts.delete(ctx.clientIP);
      } else {
        this.connectionCounts.set(ctx.clientIP, count - 1);
      }
    }

    const duration = Date.now() - ctx.startTime.getTime();
    this.logger.debug('SMTP connection closed', {
      sessionId: ctx.id,
      clientIP: ctx.clientIP,
      messageCount: ctx.messageCount,
      duration,
    });

    this.sessions.delete(session.id);
  }
}
