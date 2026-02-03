/**
 * @apexmail/node - Official Node.js SDK for ApexMail
 * 
 * A simple, type-safe client for the ApexMail transactional email API.
 * 
 * @example
 * ```typescript
 * import { ApexMail } from '@apexmail/node';
 * 
 * const apexmail = new ApexMail('am_live_xxxx');
 * 
 * await apexmail.emails.send({
 *   from: 'hello@example.com',
 *   to: 'user@example.com',
 *   subject: 'Welcome!',
 *   html: '<h1>Hello World</h1>'
 * });
 * ```
 */

// ============================================================================
// Types
// ============================================================================

export interface ApexMailConfig {
    /** API Key (starts with am_live_ or am_test_) */
    apiKey: string;
    /** Base URL for API (default: https://api.apexmail.ee) */
    baseUrl?: string;
    /** Request timeout in milliseconds (default: 30000) */
    timeout?: number;
    /** Custom fetch implementation */
    fetch?: typeof fetch;
}

export interface EmailAddress {
    email: string;
    name?: string;
}

export type EmailRecipient = string | EmailAddress;

export interface Attachment {
    /** Filename to display */
    filename: string;
    /** Base64-encoded content or Buffer */
    content: string | Buffer;
    /** MIME type (e.g., 'application/pdf') */
    contentType?: string;
}

export interface SendEmailOptions {
    /** Sender email address */
    from: EmailRecipient;
    /** Recipient email address(es) */
    to: EmailRecipient | EmailRecipient[];
    /** CC recipients */
    cc?: EmailRecipient | EmailRecipient[];
    /** BCC recipients */
    bcc?: EmailRecipient | EmailRecipient[];
    /** Reply-to address */
    replyTo?: EmailRecipient;
    /** Email subject */
    subject: string;
    /** HTML body */
    html?: string;
    /** Plain text body */
    text?: string;
    /** File attachments */
    attachments?: Attachment[];
    /** Custom headers */
    headers?: Record<string, string>;
    /** Tags for categorization */
    tags?: Array<{ name: string; value: string }>;
    /** Schedule send time (ISO 8601) */
    scheduledAt?: string | Date;
}

export interface SendEmailResponse {
    id: string;
    status: 'queued' | 'sending' | 'sent' | 'delivered' | 'failed';
}

export interface BatchSendOptions {
    /** Array of emails to send (max 1000) */
    emails: SendEmailOptions[];
}

export interface BatchSendResponse {
    ids: string[];
    successCount: number;
    failureCount: number;
    errors?: Array<{ index: number; error: string }>;
}

export interface Email {
    id: string;
    from: EmailAddress;
    to: EmailAddress[];
    subject: string;
    status: 'queued' | 'sending' | 'sent' | 'delivered' | 'bounced' | 'complained' | 'failed';
    createdAt: string;
    sentAt?: string;
    deliveredAt?: string;
    openedAt?: string;
    clickedAt?: string;
}

export interface ListEmailsOptions {
    /** Filter by status */
    status?: Email['status'];
    /** Number of results (default: 20, max: 100) */
    limit?: number;
    /** Pagination cursor */
    cursor?: string;
    /** Filter by tag */
    tag?: string;
}

export interface ListEmailsResponse {
    data: Email[];
    hasMore: boolean;
    cursor?: string;
}

export interface Domain {
    id: string;
    domain: string;
    status: 'pending' | 'verified' | 'failed';
    dnsRecords: DnsRecord[];
    createdAt: string;
    verifiedAt?: string;
}

export interface DnsRecord {
    type: 'TXT' | 'CNAME' | 'MX';
    name: string;
    value: string;
    priority?: number;
    verified: boolean;
}

export interface CreateDomainOptions {
    domain: string;
}

export interface ApiKey {
    id: string;
    name: string;
    prefix: string;
    scopes: string[];
    createdAt: string;
    lastUsedAt?: string;
    expiresAt?: string;
}

export interface CreateApiKeyOptions {
    name: string;
    scopes?: string[];
    expiresAt?: string | Date;
}

export interface CreateApiKeyResponse {
    id: string;
    key: string;
    name: string;
    scopes: string[];
}

export interface Webhook {
    id: string;
    url: string;
    events: WebhookEvent[];
    active: boolean;
    secret: string;
    createdAt: string;
}

export type WebhookEvent = 
    | 'email.sent'
    | 'email.delivered'
    | 'email.opened'
    | 'email.clicked'
    | 'email.bounced'
    | 'email.complained'
    | 'email.failed';

export interface CreateWebhookOptions {
    url: string;
    events: WebhookEvent[];
}

export interface Analytics {
    sent: number;
    delivered: number;
    opened: number;
    clicked: number;
    bounced: number;
    complained: number;
    deliveryRate: number;
    openRate: number;
    clickRate: number;
    bounceRate: number;
}

export interface GetAnalyticsOptions {
    /** Start date (ISO 8601) */
    from?: string | Date;
    /** End date (ISO 8601) */
    to?: string | Date;
    /** Group by period */
    groupBy?: 'hour' | 'day' | 'week' | 'month';
    /** Filter by tag */
    tag?: string;
}

// ============================================================================
// Errors
// ============================================================================

export class ApexMailError extends Error {
    public readonly statusCode: number;
    public readonly code: string;
    public readonly details?: Record<string, unknown>;

    constructor(message: string, statusCode: number, code: string, details?: Record<string, unknown>) {
        super(message);
        this.name = 'ApexMailError';
        this.statusCode = statusCode;
        this.code = code;
        this.details = details;
    }
}

export class ValidationError extends ApexMailError {
    constructor(message: string, details?: Record<string, unknown>) {
        super(message, 400, 'VALIDATION_ERROR', details);
        this.name = 'ValidationError';
    }
}

export class AuthenticationError extends ApexMailError {
    constructor(message = 'Invalid API key') {
        super(message, 401, 'AUTHENTICATION_ERROR');
        this.name = 'AuthenticationError';
    }
}

export class RateLimitError extends ApexMailError {
    public readonly retryAfter: number;

    constructor(retryAfter: number) {
        super(`Rate limit exceeded. Retry after ${retryAfter} seconds`, 429, 'RATE_LIMIT_ERROR');
        this.name = 'RateLimitError';
        this.retryAfter = retryAfter;
    }
}

// ============================================================================
// HTTP Client
// ============================================================================

class HttpClient {
    private baseUrl: string;
    private apiKey: string;
    private timeout: number;
    private fetchFn: typeof fetch;

    constructor(config: ApexMailConfig) {
        this.baseUrl = config.baseUrl || 'https://api.apexmail.ee';
        this.apiKey = config.apiKey;
        this.timeout = config.timeout || 30000;
        this.fetchFn = config.fetch || fetch;
    }

    async request<T>(
        method: string,
        path: string,
        body?: unknown
    ): Promise<T> {
        const url = `${this.baseUrl}${path}`;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
            const response = await this.fetchFn(url, {
                method,
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json',
                    'User-Agent': '@apexmail/node/1.0.0',
                },
                body: body ? JSON.stringify(body) : undefined,
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            const data = await response.json().catch(() => ({})) as Record<string, unknown>;

            if (!response.ok) {
                this.handleError(response, data);
            }

            return data as T;
        } catch (error) {
            clearTimeout(timeoutId);
            
            if (error instanceof ApexMailError) {
                throw error;
            }
            
            if (error instanceof Error && error.name === 'AbortError') {
                throw new ApexMailError('Request timeout', 408, 'TIMEOUT_ERROR');
            }

            throw new ApexMailError(
                error instanceof Error ? error.message : 'Unknown error',
                500,
                'NETWORK_ERROR'
            );
        }
    }

    private handleError(response: Response, data: Record<string, unknown>): never {
        const message = (data.message as string) || 'Request failed';
        const code = (data.code as string) || 'UNKNOWN_ERROR';

        switch (response.status) {
            case 400:
                throw new ValidationError(message, data.details as Record<string, unknown>);
            case 401:
                throw new AuthenticationError(message);
            case 429:
                const retryAfter = parseInt(response.headers.get('Retry-After') || '60', 10);
                throw new RateLimitError(retryAfter);
            default:
                throw new ApexMailError(message, response.status, code, data.details as Record<string, unknown>);
        }
    }

    get<T>(path: string): Promise<T> {
        return this.request<T>('GET', path);
    }

    post<T>(path: string, body?: unknown): Promise<T> {
        return this.request<T>('POST', path, body);
    }

    patch<T>(path: string, body?: unknown): Promise<T> {
        return this.request<T>('PATCH', path, body);
    }

    delete<T>(path: string): Promise<T> {
        return this.request<T>('DELETE', path);
    }
}

// ============================================================================
// Resource Classes
// ============================================================================

/**
 * Emails API - Send and manage transactional emails
 */
class EmailsApi {
    constructor(private client: HttpClient) {}

    /**
     * Send a single email
     * 
     * @example
     * ```typescript
     * const { id } = await apexmail.emails.send({
     *   from: 'hello@example.com',
     *   to: 'user@example.com',
     *   subject: 'Welcome!',
     *   html: '<h1>Hello World</h1>'
     * });
     * ```
     */
    async send(options: SendEmailOptions): Promise<SendEmailResponse> {
        return this.client.post<SendEmailResponse>('/v1/emails', this.normalizeEmail(options));
    }

    /**
     * Send multiple emails in a single request (max 1000)
     * 
     * @example
     * ```typescript
     * const result = await apexmail.emails.batch({
     *   emails: [
     *     { from: 'hello@example.com', to: 'user1@example.com', subject: 'Hello', html: '<p>Hi</p>' },
     *     { from: 'hello@example.com', to: 'user2@example.com', subject: 'Hello', html: '<p>Hi</p>' }
     *   ]
     * });
     * ```
     */
    async batch(options: BatchSendOptions): Promise<BatchSendResponse> {
        if (options.emails.length > 1000) {
            throw new ValidationError('Maximum 1000 emails per batch');
        }
        return this.client.post<BatchSendResponse>('/v1/emails/batch', {
            emails: options.emails.map(e => this.normalizeEmail(e))
        });
    }

    /**
     * Get email by ID
     */
    async get(id: string): Promise<Email> {
        return this.client.get<Email>(`/v1/emails/${id}`);
    }

    /**
     * List emails with pagination
     */
    async list(options?: ListEmailsOptions): Promise<ListEmailsResponse> {
        const params = new URLSearchParams();
        if (options?.status) params.set('status', options.status);
        if (options?.limit) params.set('limit', options.limit.toString());
        if (options?.cursor) params.set('cursor', options.cursor);
        if (options?.tag) params.set('tag', options.tag);
        
        const query = params.toString();
        return this.client.get<ListEmailsResponse>(`/v1/emails${query ? `?${query}` : ''}`);
    }

    /**
     * Cancel a scheduled email
     */
    async cancel(id: string): Promise<void> {
        await this.client.post(`/v1/emails/${id}/cancel`);
    }

    private normalizeEmail(options: SendEmailOptions): Record<string, unknown> {
        return {
            from: this.normalizeRecipient(options.from),
            to: this.normalizeRecipients(options.to),
            cc: options.cc ? this.normalizeRecipients(options.cc) : undefined,
            bcc: options.bcc ? this.normalizeRecipients(options.bcc) : undefined,
            replyTo: options.replyTo ? this.normalizeRecipient(options.replyTo) : undefined,
            subject: options.subject,
            html: options.html,
            text: options.text,
            attachments: options.attachments?.map(a => ({
                filename: a.filename,
                content: Buffer.isBuffer(a.content) ? a.content.toString('base64') : a.content,
                contentType: a.contentType,
            })),
            headers: options.headers,
            tags: options.tags,
            scheduledAt: options.scheduledAt instanceof Date 
                ? options.scheduledAt.toISOString() 
                : options.scheduledAt,
        };
    }

    private normalizeRecipient(recipient: EmailRecipient): EmailAddress {
        if (typeof recipient === 'string') {
            return { email: recipient };
        }
        return recipient;
    }

    private normalizeRecipients(recipients: EmailRecipient | EmailRecipient[]): EmailAddress[] {
        const arr = Array.isArray(recipients) ? recipients : [recipients];
        return arr.map(r => this.normalizeRecipient(r));
    }
}

/**
 * Domains API - Manage sending domains
 */
class DomainsApi {
    constructor(private client: HttpClient) {}

    /**
     * Add a new domain for sending
     */
    async create(options: CreateDomainOptions): Promise<Domain> {
        return this.client.post<Domain>('/v1/domains', options);
    }

    /**
     * Get domain by ID
     */
    async get(id: string): Promise<Domain> {
        return this.client.get<Domain>(`/v1/domains/${id}`);
    }

    /**
     * List all domains
     */
    async list(): Promise<{ data: Domain[] }> {
        return this.client.get<{ data: Domain[] }>('/v1/domains');
    }

    /**
     * Verify domain DNS records
     */
    async verify(id: string): Promise<Domain> {
        return this.client.post<Domain>(`/v1/domains/${id}/verify`);
    }

    /**
     * Delete a domain
     */
    async delete(id: string): Promise<void> {
        await this.client.delete(`/v1/domains/${id}`);
    }
}

/**
 * API Keys API - Manage API keys
 */
class ApiKeysApi {
    constructor(private client: HttpClient) {}

    /**
     * Create a new API key
     */
    async create(options: CreateApiKeyOptions): Promise<CreateApiKeyResponse> {
        return this.client.post<CreateApiKeyResponse>('/v1/api-keys', {
            ...options,
            expiresAt: options.expiresAt instanceof Date 
                ? options.expiresAt.toISOString() 
                : options.expiresAt,
        });
    }

    /**
     * List all API keys
     */
    async list(): Promise<{ data: ApiKey[] }> {
        return this.client.get<{ data: ApiKey[] }>('/v1/api-keys');
    }

    /**
     * Revoke an API key
     */
    async revoke(id: string): Promise<void> {
        await this.client.delete(`/v1/api-keys/${id}`);
    }
}

/**
 * Webhooks API - Manage webhook endpoints
 */
class WebhooksApi {
    constructor(private client: HttpClient) {}

    /**
     * Create a new webhook endpoint
     */
    async create(options: CreateWebhookOptions): Promise<Webhook> {
        return this.client.post<Webhook>('/v1/webhooks', options);
    }

    /**
     * Get webhook by ID
     */
    async get(id: string): Promise<Webhook> {
        return this.client.get<Webhook>(`/v1/webhooks/${id}`);
    }

    /**
     * List all webhooks
     */
    async list(): Promise<{ data: Webhook[] }> {
        return this.client.get<{ data: Webhook[] }>('/v1/webhooks');
    }

    /**
     * Update webhook
     */
    async update(id: string, options: Partial<CreateWebhookOptions>): Promise<Webhook> {
        return this.client.patch<Webhook>(`/v1/webhooks/${id}`, options);
    }

    /**
     * Delete webhook
     */
    async delete(id: string): Promise<void> {
        await this.client.delete(`/v1/webhooks/${id}`);
    }
}

/**
 * Analytics API - Access email analytics
 */
class AnalyticsApi {
    constructor(private client: HttpClient) {}

    /**
     * Get email analytics
     */
    async get(options?: GetAnalyticsOptions): Promise<Analytics> {
        const params = new URLSearchParams();
        if (options?.from) {
            params.set('from', options.from instanceof Date ? options.from.toISOString() : options.from);
        }
        if (options?.to) {
            params.set('to', options.to instanceof Date ? options.to.toISOString() : options.to);
        }
        if (options?.groupBy) params.set('groupBy', options.groupBy);
        if (options?.tag) params.set('tag', options.tag);
        
        const query = params.toString();
        return this.client.get<Analytics>(`/v1/analytics${query ? `?${query}` : ''}`);
    }
}

// ============================================================================
// Main Client
// ============================================================================

/**
 * ApexMail SDK Client
 * 
 * @example
 * ```typescript
 * import { ApexMail } from '@apexmail/node';
 * 
 * const apexmail = new ApexMail('am_live_xxxx');
 * 
 * // Send an email
 * const { id } = await apexmail.emails.send({
 *   from: 'hello@example.com',
 *   to: 'user@example.com',
 *   subject: 'Welcome!',
 *   html: '<h1>Hello World</h1>'
 * });
 * 
 * // Check status
 * const email = await apexmail.emails.get(id);
 * console.log(email.status); // 'delivered'
 * ```
 */
export class ApexMail {
    public readonly emails: EmailsApi;
    public readonly domains: DomainsApi;
    public readonly apiKeys: ApiKeysApi;
    public readonly webhooks: WebhooksApi;
    public readonly analytics: AnalyticsApi;

    constructor(apiKey: string);
    constructor(config: ApexMailConfig);
    constructor(apiKeyOrConfig: string | ApexMailConfig) {
        const config: ApexMailConfig = typeof apiKeyOrConfig === 'string' 
            ? { apiKey: apiKeyOrConfig }
            : apiKeyOrConfig;

        if (!config.apiKey) {
            throw new ValidationError('API key is required');
        }

        if (!config.apiKey.startsWith('am_')) {
            throw new ValidationError('Invalid API key format. Keys should start with "am_live_" or "am_test_"');
        }

        const client = new HttpClient(config);

        this.emails = new EmailsApi(client);
        this.domains = new DomainsApi(client);
        this.apiKeys = new ApiKeysApi(client);
        this.webhooks = new WebhooksApi(client);
        this.analytics = new AnalyticsApi(client);
    }
}

// Default export
export default ApexMail;
