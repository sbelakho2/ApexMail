/**
 * ApexMail Server Client
 * 
 * TypeScript client for the Rust-based ApexMail server.
 * Connects via gRPC to send emails through the purpose-built mail infrastructure.
 * 
 * All emails are sent directly via SMTP with DKIM signing
 * through the purpose-built Rust mail server.
 * 
 * Uses @grpc/grpc-js for native gRPC communication with the Rust tonic services
 * defined in mail.proto (OutboundService + MailstoreService).
 */

import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { createLogger } from '@apexmail/lib';

const logger = createLogger({ name: 'mail-server-client', level: 'info' });

// Resolve proto path relative to workspace root
const PROTO_PATH = path.resolve(
    import.meta.dirname ?? __dirname,
    '../../../services/mail-server/crates/mail-proto/proto/mail.proto',
);

// FIX-500-375: Proto definition is loaded lazily and cached at module level (singleton pattern).
// getGrpcObject() only calls loadSync on the first invocation; subsequent calls return the cached object.
let _packageDef: protoLoader.PackageDefinition | null = null;
let _grpcObject: grpc.GrpcObject | null = null;

function getGrpcObject(): grpc.GrpcObject {
    if (!_grpcObject) {
        _packageDef = protoLoader.loadSync(PROTO_PATH, {
            keepCase: false,
            longs: String,
            enums: String,
            defaults: true,
            oneofs: true,
        });
        _grpcObject = grpc.loadPackageDefinition(_packageDef);
    }
    return _grpcObject;
}

function ensureProtoPath(): void {
    if (!fs.existsSync(PROTO_PATH)) {
        throw new Error(`mail.proto not found at ${PROTO_PATH}`);
    }
}

/* eslint-disable @typescript-eslint/no-explicit-any */
type GrpcServiceClient = grpc.Client & Record<string, any>;
/* eslint-enable @typescript-eslint/no-explicit-any */

// Configuration
export interface MailServerConfig {
    /** gRPC endpoint for the outbound queue service (host:port) */
    outboundGrpcUrl: string;
    /** gRPC endpoint for the mailstore service (host:port) */
    mailstoreGrpcUrl?: string;
    /** Tenant ID for multi-tenant setups */
    tenantId?: string;
    /** Default from domain */
    defaultFromDomain?: string;
    /** Connection timeout in ms */
    timeout?: number;
    /** Use TLS for gRPC connections */
    useTls?: boolean;
}

// Email types
export interface EmailRecipient {
    email: string;
    name?: string;
}

export interface EmailAttachment {
    filename: string;
    contentType: string;
    content: Buffer;
    contentId?: string;
}

export interface SendEmailOptions {
    from: string | EmailRecipient;
    to: string | string[] | EmailRecipient[];
    cc?: string | string[] | EmailRecipient[];
    bcc?: string | string[] | EmailRecipient[];
    replyTo?: string;
    subject: string;
    text?: string;
    html?: string;
    attachments?: EmailAttachment[];
    headers?: Record<string, string>;
    campaignId?: string;
    tags?: string[];
    metadata?: Record<string, string>;
    scheduledAt?: Date;
}

export interface QueueEmailOptions extends SendEmailOptions {
    priority?: number;
}

export interface SendResult {
    success: boolean;
    emailId: string;
    messageId?: string;
    error?: string;
    recipients?: Array<{
        email: string;
        accepted: boolean;
        error?: string;
    }>;
}

export interface QueueResult {
    success: boolean;
    emailId: string;
    status: string;
    error?: string;
}

export interface MailServerQueueStats {
    pendingCount: number;
    sendingCount: number;
    sentToday: number;
    failedToday: number;
    bouncedToday: number;
    averageDeliveryTimeMs: number;
    error?: string;
}

export interface DeliveryStatus {
    emailId: string;
    status: 'queued' | 'sending' | 'sent' | 'delivered' | 'bounced' | 'failed' | 'cancelled';
    queuedAt?: Date;
    sentAt?: Date;
    deliveredAt?: Date;
    bouncedAt?: Date;
    attempts: number;
    lastError?: string;
}

/**
 * Wrap a gRPC unary call in a Promise with deadline support.
 */
function grpcUnary<TReq, TRes>(
    client: GrpcServiceClient,
    method: string,
    request: TReq,
    timeoutMs: number,
): Promise<TRes> {
    return new Promise((resolve, reject) => {
        const deadline = new Date(Date.now() + timeoutMs);
        const fn = client[method]?.bind(client);
        if (!fn) {
            return reject(new Error(`gRPC method '${method}' not found on client`));
        }
        fn(request, { deadline }, (err: grpc.ServiceError | null, res: TRes) => {
            if (err) return reject(err);
            resolve(res);
        });
    });
}

/**
 * Parse a gRPC URL (grpc://host:port or host:port) into a bare host:port target.
 */
function parseGrpcTarget(url: string): string {
    return url.replace(/^grpc:\/\//, '').replace(/^https?:\/\//, '');
}

/**
 * Mail Server Client
 * 
 * Provides a high-level interface to the Rust mail server via gRPC.
 * Communicates with OutboundService (QueueEmail, SendEmailNow, GetDeliveryStatus,
 * CancelEmail, QueueBulkEmails, GetQueueStats) and optionally MailstoreService.
 */
export class MailServerClient {
    private config: Required<MailServerConfig>;
    private _connected = false;
    private outboundClient: GrpcServiceClient | null = null;
    private mailstoreClient: GrpcServiceClient | null = null;
    
    constructor(config: MailServerConfig) {
        ensureProtoPath();
        this.config = {
            outboundGrpcUrl: config.outboundGrpcUrl,
            mailstoreGrpcUrl: config.mailstoreGrpcUrl || '',
            tenantId: config.tenantId || 'default',
            defaultFromDomain: config.defaultFromDomain || 'apexmail.ee',
            timeout: config.timeout || 30000,
            useTls: config.useTls ?? false,
        };
        
        logger.info('MailServerClient initialized', {
            outboundUrl: this.config.outboundGrpcUrl,
            tenantId: this.config.tenantId,
        });
    }
    
    /**
     * Connect to the mail server via gRPC
     */
    async connect(): Promise<void> {
        logger.info('Connecting to mail server via gRPC...');
        
        const grpcObj = getGrpcObject();
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const mailProto = (grpcObj as any).apexmail;
        if (!mailProto) {
            throw new Error('Failed to load apexmail gRPC package from proto definition');
        }
        
        const creds = this.config.useTls
            ? grpc.credentials.createSsl()
            : grpc.credentials.createInsecure();
        
        // Connect to OutboundService
        const outboundTarget = parseGrpcTarget(this.config.outboundGrpcUrl);
        this.outboundClient = new mailProto.OutboundService(outboundTarget, creds) as GrpcServiceClient;
        
        // Optionally connect to MailstoreService
        if (this.config.mailstoreGrpcUrl) {
            const mailstoreTarget = parseGrpcTarget(this.config.mailstoreGrpcUrl);
            this.mailstoreClient = new mailProto.MailstoreService(mailstoreTarget, creds) as GrpcServiceClient;
        }
        
        // Wait for the outbound channel to be ready
        await new Promise<void>((resolve, reject) => {
            const deadline = new Date(Date.now() + this.config.timeout);
            this.outboundClient!.waitForReady(deadline, (err: Error | undefined) => {
                if (err) reject(new Error(`gRPC connect timeout: ${err.message}`));
                else resolve();
            });
        });
        
        this._connected = true;
        logger.info('Connected to mail server via gRPC');
    }
    
    /**
     * Disconnect from the mail server
     */
    async disconnect(): Promise<void> {
        if (this.outboundClient) {
            this.outboundClient.close();
            this.outboundClient = null;
        }
        if (this.mailstoreClient) {
            this.mailstoreClient.close();
            this.mailstoreClient = null;
        }
        this._connected = false;
        logger.info('Disconnected from mail server');
    }
    
    /**
     * Check if connected
     */
    get isConnected(): boolean {
        return this._connected;
    }
    
    /**
     * Send an email immediately via OutboundService.SendEmailNow
     */
    async send(options: SendEmailOptions): Promise<SendResult> {
        this.ensureConnected();
        const request = this.buildSendRequest(options);
        
        logger.debug('Sending email via gRPC SendEmailNow', {
            from: request.from,
            to: request.to,
            subject: options.subject,
        });
        
        try {
            const response = await grpcUnary<typeof request, {
                success: boolean;
                emailId: string;
                messageId: string;
                error: string;
                recipients: Array<{ email: string; accepted: boolean; error: string }>;
            }>(this.outboundClient!, 'sendEmailNow', request, this.config.timeout);
            
            const result: SendResult = {
                success: response.success,
                emailId: response.emailId,
                messageId: response.messageId || undefined,
                error: response.error || undefined,
                recipients: response.recipients,
            };
            
            if (result.success) {
                logger.info('Email sent successfully', {
                    emailId: result.emailId,
                    messageId: result.messageId,
                });
            } else {
                logger.error('Failed to send email', { error: result.error });
            }
            
            return result;
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            logger.error('Email send error', { error: errorMessage });
            
            return {
                success: false,
                emailId: '',
                error: errorMessage,
            };
        }
    }
    
    /**
     * Queue an email for later delivery via OutboundService.QueueEmail
     */
    async queue(options: QueueEmailOptions): Promise<QueueResult> {
        this.ensureConnected();
        const request = this.buildQueueRequest(options);
        
        logger.debug('Queueing email via gRPC QueueEmail', {
            from: request.from,
            to: request.to,
            subject: options.subject,
            scheduledAt: options.scheduledAt,
        });
        
        try {
            const response = await grpcUnary<typeof request, {
                success: boolean;
                emailId: string;
                status: string;
                error: string;
            }>(this.outboundClient!, 'queueEmail', request, this.config.timeout);
            
            const result: QueueResult = {
                success: response.success,
                emailId: response.emailId,
                status: response.status,
                error: response.error || undefined,
            };
            
            if (result.success) {
                logger.info('Email queued', {
                    emailId: result.emailId,
                    status: result.status,
                });
            } else {
                logger.error('Failed to queue email', { error: result.error });
            }
            
            return result;
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            logger.error('Email queue error', { error: errorMessage });
            
            return {
                success: false,
                emailId: '',
                status: 'failed',
                error: errorMessage,
            };
        }
    }
    
    /**
     * Queue multiple emails in bulk via OutboundService.QueueBulkEmails
     */
    async queueBulk(emails: QueueEmailOptions[]): Promise<{
        results: QueueResult[];
        queuedCount: number;
        failedCount: number;
    }> {
        this.ensureConnected();
        const requests = emails.map((e) => this.buildQueueRequest(e));
        
        logger.debug('Queueing bulk emails via gRPC QueueBulkEmails', { count: emails.length });
        
        try {
            const response = await grpcUnary<
                { emails: typeof requests },
                {
                    results: Array<{ success: boolean; emailId: string; status: string; error: string }>;
                    queuedCount: number;
                    failedCount: number;
                }
            >(this.outboundClient!, 'queueBulkEmails', { emails: requests }, this.config.timeout);
            
            logger.info('Bulk emails queued', {
                queued: response.queuedCount,
                failed: response.failedCount,
            });
            
            return {
                results: response.results.map((r) => ({
                    success: r.success,
                    emailId: r.emailId,
                    status: r.status,
                    error: r.error || undefined,
                })),
                queuedCount: response.queuedCount,
                failedCount: response.failedCount,
            };
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            logger.error('Bulk queue error', { error: errorMessage });
            
            return {
                results: [],
                queuedCount: 0,
                failedCount: emails.length,
            };
        }
    }
    
    /**
     * Get delivery status via OutboundService.GetDeliveryStatus
     */
    async getDeliveryStatus(emailId: string): Promise<DeliveryStatus | null> {
        this.ensureConnected();
        try {
            const response = await grpcUnary<
                { emailId: string },
                {
                    emailId: string;
                    status: string;
                    queuedAt: string;
                    sentAt: string;
                    deliveredAt: string;
                    bouncedAt: string;
                    attempts: number;
                    lastError: string;
                }
            >(this.outboundClient!, 'getDeliveryStatus', { emailId }, this.config.timeout);
            
            return {
                emailId: response.emailId,
                status: response.status as DeliveryStatus['status'],
                queuedAt: response.queuedAt ? new Date(response.queuedAt) : undefined,
                sentAt: response.sentAt ? new Date(response.sentAt) : undefined,
                deliveredAt: response.deliveredAt ? new Date(response.deliveredAt) : undefined,
                bouncedAt: response.bouncedAt ? new Date(response.bouncedAt) : undefined,
                attempts: response.attempts,
                lastError: response.lastError || undefined,
            };
        } catch (error) {
            logger.error('Failed to get delivery status', { emailId, error });
            return null;
        }
    }
    
    /**
     * Cancel a queued email via OutboundService.CancelEmail
     */
    async cancel(emailId: string): Promise<{ success: boolean; error?: string }> {
        this.ensureConnected();
        try {
            const response = await grpcUnary<
                { emailId: string },
                { success: boolean; error: string }
            >(this.outboundClient!, 'cancelEmail', { emailId }, this.config.timeout);
            
            if (response.success) {
                logger.info('Email cancelled', { emailId });
            }
            
            return { success: response.success, error: response.error || undefined };
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            return { success: false, error: errorMessage };
        }
    }
    
    /**
     * Get queue statistics via OutboundService.GetQueueStats
     */
    async getQueueStats(): Promise<MailServerQueueStats> {
        this.ensureConnected();
        try {
            const response = await grpcUnary<
                Record<string, never>,
                {
                    pendingCount: number;
                    sendingCount: number;
                    sentToday: number;
                    failedToday: number;
                    bouncedToday: number;
                    averageDeliveryTimeMs: number;
                }
            >(this.outboundClient!, 'getQueueStats', {}, this.config.timeout);
            
            return {
                pendingCount: response.pendingCount,
                sendingCount: response.sendingCount,
                sentToday: response.sentToday,
                failedToday: response.failedToday,
                bouncedToday: response.bouncedToday,
                averageDeliveryTimeMs: response.averageDeliveryTimeMs,
            };
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            logger.error('Failed to get queue stats', { error: errorMessage });
            return {
                pendingCount: 0,
                sendingCount: 0,
                sentToday: 0,
                failedToday: 0,
                bouncedToday: 0,
                averageDeliveryTimeMs: 0,
                error: errorMessage,
            };
        }
    }
    
    // ========== Private Methods ==========
    
    private ensureConnected(): void {
        if (!this._connected || !this.outboundClient) {
            throw new Error('MailServerClient is not connected. Call connect() first.');
        }
    }
    
    private normalizeRecipient(recipient: string | EmailRecipient): string {
        if (typeof recipient === 'string') {
            return recipient;
        }
        if (!recipient.name) {
            return recipient.email;
        }

        const escapedName = recipient.name.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        const needsQuotes = /[()<>@,;:\\".\[\]]|\s/.test(escapedName);
        const displayName = needsQuotes ? `"${escapedName}"` : escapedName;
        return `${displayName} <${recipient.email}>`;
    }
    
    private normalizeRecipients(recipients: string | string[] | EmailRecipient[] | undefined): string[] {
        if (!recipients) return [];
        if (typeof recipients === 'string') return [recipients];
        return recipients.map((r) => this.normalizeRecipient(r));
    }
    
    private buildSendRequest(options: SendEmailOptions) {
        return {
            tenantId: this.config.tenantId,
            from: this.normalizeRecipient(options.from),
            to: this.normalizeRecipients(options.to),
            cc: this.normalizeRecipients(options.cc),
            bcc: this.normalizeRecipients(options.bcc),
            replyTo: options.replyTo || '',
            subject: options.subject,
            textBody: options.text || '',
            htmlBody: options.html || '',
            attachments: options.attachments?.map((a) => ({
                filename: a.filename,
                contentType: a.contentType,
                content: a.content.toString('base64'),
                contentId: a.contentId || '',
            })) || [],
            headers: options.headers || {},
        };
    }
    
    private buildQueueRequest(options: QueueEmailOptions) {
        return {
            ...this.buildSendRequest(options),
            scheduledAt: options.scheduledAt ? Math.floor(options.scheduledAt.getTime() / 1000) : 0,
            campaignId: options.campaignId || '',
            tags: options.tags || [],
            metadata: options.metadata || {},
            priority: options.priority || 0,
        };
    }
}

/**
 * Create a mail server client with the given configuration
 */
export function createMailServerClient(config: MailServerConfig): MailServerClient {
    return new MailServerClient(config);
}

/**
 * Create a sendEmail function compatible with the drip engine
 */
export function createDripEmailSender(client: MailServerClient, defaultFrom: string) {
    return async (params: {
        to: string;
        subject: string;
        htmlBody: string;
        textBody: string;
    }): Promise<{ messageId: string }> => {
        const result = await client.send({
            from: defaultFrom,
            to: params.to,
            subject: params.subject,
            html: params.htmlBody,
            text: params.textBody,
        });
        
        if (!result.success) {
            throw new Error(result.error || 'Failed to send email');
        }
        
        return { messageId: result.messageId || result.emailId };
    };
}

// Export default instance factory
export default createMailServerClient;
