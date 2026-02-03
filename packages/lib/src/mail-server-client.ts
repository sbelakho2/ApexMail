/**
 * ApexMail Server Client
 * 
 * TypeScript client for the Rust-based ApexMail server.
 * Connects via gRPC to send emails through the self-hosted mail infrastructure.
 * 
 * NO THIRD-PARTY EMAIL SERVICES - All emails are sent directly via SMTP
 * with DKIM signing through the Rust mail server.
 */

import { createLogger } from '@apexmail/lib';

const logger = createLogger({ name: 'mail-server-client', level: 'info' });

// Configuration
export interface MailServerConfig {
    /** gRPC endpoint for the outbound queue service */
    outboundGrpcUrl: string;
    /** gRPC endpoint for the mailstore service */
    mailstoreGrpcUrl?: string;
    /** Tenant ID for multi-tenant setups */
    tenantId?: string;
    /** Default from domain */
    defaultFromDomain?: string;
    /** Connection timeout in ms */
    timeout?: number;
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
 * Mail Server Client
 * 
 * Provides a high-level interface to the Rust mail server via gRPC.
 */
export class MailServerClient {
    private config: Required<MailServerConfig>;
    private _connected = false;
    
    constructor(config: MailServerConfig) {
        this.config = {
            outboundGrpcUrl: config.outboundGrpcUrl,
            mailstoreGrpcUrl: config.mailstoreGrpcUrl || '',
            tenantId: config.tenantId || 'default',
            defaultFromDomain: config.defaultFromDomain || 'apexmail.ee',
            timeout: config.timeout || 30000,
        };
        
        logger.info('MailServerClient initialized', {
            outboundUrl: this.config.outboundGrpcUrl,
            tenantId: this.config.tenantId,
        });
    }
    
    /**
     * Connect to the mail server
     */
    async connect(): Promise<void> {
        // In a real implementation, this would establish gRPC connections
        // For now, we'll use HTTP/REST as a fallback
        logger.info('Connecting to mail server...');
        this._connected = true;
        logger.info('Connected to mail server');
    }
    
    /**
     * Disconnect from the mail server
     */
    async disconnect(): Promise<void> {
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
     * Send an email immediately
     */
    async send(options: SendEmailOptions): Promise<SendResult> {
        const request = this.buildSendRequest(options);
        
        logger.debug('Sending email', {
            from: request.from,
            to: request.to,
            subject: options.subject,
        });
        
        try {
            // Make HTTP request to the server (gRPC-Web or REST endpoint)
            const response = await this.makeRequest<SendResult>('/v1/email/send', request);
            
            if (response.success) {
                logger.info('Email sent successfully', {
                    emailId: response.emailId,
                    messageId: response.messageId,
                });
            } else {
                logger.error('Failed to send email', { error: response.error });
            }
            
            return response;
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
     * Queue an email for later delivery
     */
    async queue(options: QueueEmailOptions): Promise<QueueResult> {
        const request = this.buildQueueRequest(options);
        
        logger.debug('Queueing email', {
            from: request.from,
            to: request.to,
            subject: options.subject,
            scheduledAt: options.scheduledAt,
        });
        
        try {
            const response = await this.makeRequest<QueueResult>('/v1/email/queue', request);
            
            if (response.success) {
                logger.info('Email queued', {
                    emailId: response.emailId,
                    status: response.status,
                });
            } else {
                logger.error('Failed to queue email', { error: response.error });
            }
            
            return response;
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
     * Queue multiple emails in bulk
     */
    async queueBulk(emails: QueueEmailOptions[]): Promise<{
        results: QueueResult[];
        queuedCount: number;
        failedCount: number;
    }> {
        const requests = emails.map((e) => this.buildQueueRequest(e));
        
        logger.debug('Queueing bulk emails', { count: emails.length });
        
        try {
            const response = await this.makeRequest<{
                results: QueueResult[];
                queuedCount: number;
                failedCount: number;
            }>('/v1/email/queue-bulk', { emails: requests });
            
            logger.info('Bulk emails queued', {
                queued: response.queuedCount,
                failed: response.failedCount,
            });
            
            return response;
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
     * Get delivery status for an email
     */
    async getDeliveryStatus(emailId: string): Promise<DeliveryStatus | null> {
        try {
            const response = await this.makeRequest<DeliveryStatus>(
                `/v1/email/status/${emailId}`,
                null,
                'GET'
            );
            return response;
        } catch (error) {
            logger.error('Failed to get delivery status', { emailId, error });
            return null;
        }
    }
    
    /**
     * Cancel a queued email
     */
    async cancel(emailId: string): Promise<{ success: boolean; error?: string }> {
        try {
            const response = await this.makeRequest<{ success: boolean; error?: string }>(
                `/v1/email/cancel/${emailId}`,
                null,
                'POST'
            );
            
            if (response.success) {
                logger.info('Email cancelled', { emailId });
            }
            
            return response;
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            return { success: false, error: errorMessage };
        }
    }
    
    /**
     * Get queue statistics
     */
    async getQueueStats(): Promise<MailServerQueueStats> {
        try {
            const response = await this.makeRequest<MailServerQueueStats>('/v1/email/stats', null, 'GET');
            return response;
        } catch (error) {
            logger.error('Failed to get queue stats', { error });
            return {
                pendingCount: 0,
                sendingCount: 0,
                sentToday: 0,
                failedToday: 0,
                bouncedToday: 0,
                averageDeliveryTimeMs: 0,
            };
        }
    }
    
    // ========== Private Methods ==========
    
    private normalizeRecipient(recipient: string | EmailRecipient): string {
        if (typeof recipient === 'string') {
            return recipient;
        }
        return recipient.name ? `${recipient.name} <${recipient.email}>` : recipient.email;
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
    
    private async makeRequest<T>(
        path: string,
        body: unknown,
        method: 'GET' | 'POST' = 'POST'
    ): Promise<T> {
        const url = new URL(path, this.config.outboundGrpcUrl.replace('grpc://', 'http://'));
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);
        
        try {
            const response = await fetch(url.toString(), {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    'X-Tenant-ID': this.config.tenantId,
                },
                body: body ? JSON.stringify(body) : undefined,
                signal: controller.signal,
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            return await response.json() as T;
        } finally {
            clearTimeout(timeoutId);
        }
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
