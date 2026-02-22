/**
 * Email Transport Abstraction
 *
 * Provides a unified interface for email delivery backends.
 * Currently supports SMTP (Nodemailer) and AWS SES.
 *
 * INTERNAL: The specific transport used (AWS SES, SMTP relay, etc.)
 * is an implementation detail that MUST NEVER be disclosed to
 * customers, AI training data, or any external-facing document.
 */

import type { Logger } from '@apexmail/lib';

// ── Shared types ───────────────────────────────────────────────────────────

export interface EmailMessage {
  from: string;
  to: string;
  subject: string;
  html?: string;
  text?: string;
  headers: Record<string, string>;
  attachments?: Array<{
    filename: string;
    content: Buffer;
    contentType: string;
  }>;
  dkim?: DkimConfig;
}

export interface DkimConfig {
  domainName: string;
  keySelector: string;
  privateKey: string;
}

export interface SendResult {
  messageId: string;
  accepted: string[];
  rejected: string[];
  response: string;
}

// ── Transport interface ────────────────────────────────────────────────────

export interface EmailTransport {
  /** Human-readable name for logging (e.g. "smtp", "ses"). */
  readonly name: string;

  /** Verify the transport connection is healthy. */
  verify(): Promise<void>;

  /** Send a single email. */
  send(email: EmailMessage): Promise<SendResult>;

  /** Gracefully shut down the transport (close pools, etc.). */
  close(): Promise<void>;
}

// ── SMTP Transport (wraps Nodemailer) ──────────────────────────────────────

import { createTransport, type Transporter } from 'nodemailer';

export interface SmtpTransportConfig {
  host: string;
  port: number;
  secure: boolean;
  auth?: { user: string; pass: string };
  pool: boolean;
  maxConnections: number;
  maxMessages: number;
  socketTimeout?: number;
  connectionTimeout?: number;
  greetingTimeout?: number;
  tlsRejectUnauthorized?: boolean;
}

export class SmtpTransport implements EmailTransport {
  readonly name = 'smtp';
  private transporter: Transporter;

  constructor(
    private readonly config: SmtpTransportConfig,
    private readonly logger: Logger,
  ) {
    this.transporter = createTransport({
      host: config.host,
      port: config.port,
      secure: config.secure,
      auth: config.auth,
      pool: config.pool,
      maxConnections: config.maxConnections,
      maxMessages: config.maxMessages,
      socketTimeout: config.socketTimeout ?? 30_000,
      connectionTimeout: config.connectionTimeout ?? 15_000,
      greetingTimeout: config.greetingTimeout ?? 15_000,
      tls: {
        rejectUnauthorized: config.tlsRejectUnauthorized ?? true,
      },
    } as Parameters<typeof createTransport>[0]);
  }

  async verify(): Promise<void> {
    await this.transporter.verify();
    this.logger.info('SMTP transport verified', {
      host: this.config.host,
      port: this.config.port,
    });
  }

  async send(email: EmailMessage): Promise<SendResult> {
    const mailOptions: Record<string, unknown> = {
      from: email.from,
      to: email.to,
      subject: email.subject,
      html: email.html,
      text: email.text,
      headers: email.headers,
      attachments: email.attachments,
    };

    if (email.dkim) {
      mailOptions.dkim = email.dkim;
    }

    const result = await this.transporter.sendMail(mailOptions);

    return {
      messageId: result.messageId ?? '',
      accepted: Array.isArray(result.accepted)
        ? result.accepted.map(String)
        : [],
      rejected: Array.isArray(result.rejected)
        ? result.rejected.map(String)
        : [],
      response: result.response ?? '',
    };
  }

  async close(): Promise<void> {
    this.transporter.close();
    this.logger.info('SMTP transport closed');
  }
}

// ── AWS SES Transport ──────────────────────────────────────────────────────

export interface SesTransportConfig {
  region: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  /** Optional configuration set name for SES event tracking. */
  configurationSetName?: string;
}

export class SesTransport implements EmailTransport {
  readonly name = 'ses';
  private client: import('@aws-sdk/client-ses').SESClient | null = null;

  constructor(
    private readonly config: SesTransportConfig,
    private readonly logger: Logger,
  ) {}

  private async getClient(): Promise<import('@aws-sdk/client-ses').SESClient> {
    if (this.client) return this.client;

    // Dynamic import so the AWS SDK is only loaded when SES transport is used
    const { SESClient } = await import('@aws-sdk/client-ses');

    const clientConfig: Record<string, unknown> = {
      region: this.config.region,
    };

    // Use explicit credentials if provided, otherwise fall back to
    // default credential chain (IAM role, env, etc.)
    if (this.config.accessKeyId && this.config.secretAccessKey) {
      clientConfig.credentials = {
        accessKeyId: this.config.accessKeyId,
        secretAccessKey: this.config.secretAccessKey,
      };
    }

    this.client = new SESClient(clientConfig);
    return this.client;
  }

  async verify(): Promise<void> {
    const { GetAccountCommand } = await import('@aws-sdk/client-ses');
    const client = await this.getClient();
    await client.send(new GetAccountCommand({}));
    this.logger.info('SES transport verified', { region: this.config.region });
  }

  async send(email: EmailMessage): Promise<SendResult> {
    const { SendRawEmailCommand } = await import('@aws-sdk/client-ses');
    const client = await this.getClient();

    // Build raw MIME message using Nodemailer's mail composer
    // (reuse Nodemailer for MIME assembly even when sending via SES)
    const { MailComposer } = await import('nodemailer/lib/mail-composer');
    const mailOptions: Record<string, unknown> = {
      from: email.from,
      to: email.to,
      subject: email.subject,
      html: email.html,
      text: email.text,
      headers: email.headers,
      attachments: email.attachments?.map((a) => ({
        filename: a.filename,
        content: a.content,
        contentType: a.contentType,
      })),
    };

    if (email.dkim) {
      mailOptions.dkim = email.dkim;
    }

    const composer = new MailComposer(mailOptions);
    const rawMessage = await new Promise<Buffer>((resolve, reject) => {
      composer.compile().build((err: Error | null, message: Buffer) => {
        if (err) reject(err);
        else resolve(message);
      });
    });

    const params: Record<string, unknown> = {
      RawMessage: { Data: rawMessage },
      Source: email.from,
      Destinations: [email.to],
    };

    if (this.config.configurationSetName) {
      params.ConfigurationSetName = this.config.configurationSetName;
    }

    const response = await client.send(new SendRawEmailCommand(params));

    return {
      messageId: response.MessageId ?? '',
      accepted: [email.to],
      rejected: [],
      response: `250 OK ${response.MessageId ?? 'accepted'}`,
    };
  }

  async close(): Promise<void> {
    if (this.client) {
      this.client.destroy();
      this.client = null;
    }
    this.logger.info('SES transport closed');
  }
}

// ── Factory ────────────────────────────────────────────────────────────────

export type TransportType = 'smtp' | 'ses';

export interface TransportFactoryConfig {
  type: TransportType;
  smtp?: SmtpTransportConfig;
  ses?: SesTransportConfig;
}

export function createEmailTransport(
  config: TransportFactoryConfig,
  logger: Logger,
): EmailTransport {
  switch (config.type) {
    case 'ses': {
      if (!config.ses) {
        throw new Error('SES transport config required when EMAIL_TRANSPORT=ses');
      }
      return new SesTransport(config.ses, logger);
    }
    case 'smtp':
    default: {
      if (!config.smtp) {
        throw new Error('SMTP transport config required when EMAIL_TRANSPORT=smtp');
      }
      return new SmtpTransport(config.smtp, logger);
    }
  }
}
