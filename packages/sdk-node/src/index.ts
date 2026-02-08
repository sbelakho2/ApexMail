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
    /** FIX-500-276: Enable debug logging */
    debug?: boolean;
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
    /** FIX-500-274: Idempotency key to prevent duplicate sends */
    idempotencyKey?: string;
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

// FIX-500-295: Aligned event names across Node and Python SDKs
// FIX-500-459: Uses message.* prefix to match API server event types
export type WebhookEvent = 
    | 'message.accepted'
    | 'message.queued'
    | 'message.sending'
    | 'message.sent'
    | 'message.delivered'
    | 'message.opened'
    | 'message.clicked'
    | 'message.bounced'
    | 'message.complained'
    | 'message.failed'
    | 'message.deferred'
    | 'message.dropped'
    | 'message.unsubscribed'
    | 'domain.verified'
    | 'domain.failed'
    | 'suppression.added'
    | '*';

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

export class NotFoundError extends ApexMailError {
    constructor(message = 'Resource not found', details?: Record<string, unknown>) {
        super(message, 404, 'NOT_FOUND', details);
        this.name = 'NotFoundError';
    }
}

export class ForbiddenError extends ApexMailError {
    constructor(message = 'Forbidden', details?: Record<string, unknown>) {
        super(message, 403, 'FORBIDDEN', details);
        this.name = 'ForbiddenError';
    }
}

export class ConflictError extends ApexMailError {
    constructor(message = 'Conflict', details?: Record<string, unknown>) {
        super(message, 409, 'CONFLICT', details);
        this.name = 'ConflictError';
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
// Helpers
// ============================================================================

// FIX-500-275: ID format validation
const ID_REGEX = /^[a-zA-Z0-9_-]{1,128}$/;
function validateId(id: string, resourceName: string): void {
    if (!id || !ID_REGEX.test(id)) {
        throw new ValidationError(`Invalid ${resourceName} ID format: "${id}". IDs must be 1-128 alphanumeric characters, hyphens, or underscores.`);
    }
}

// ============================================================================
// HTTP Client with Retry Logic
// ============================================================================

interface RetryConfig {
    maxRetries: number;
    initialDelayMs: number;
    maxDelayMs: number;
    retryableStatuses: Set<number>;
}

const DEFAULT_RETRY_CONFIG: RetryConfig = {
    maxRetries: 3,
    initialDelayMs: 1000,
    maxDelayMs: 30000,
    // Retry on network errors, rate limits, and server errors
    retryableStatuses: new Set([408, 429, 500, 502, 503, 504]),
};

class HttpClient {
    private baseUrl: string;
    private apiKey: string;
    private timeout: number;
    private fetchFn: typeof fetch;
    private retryConfig: RetryConfig;
    private debug: boolean; // FIX-500-276

    constructor(config: ApexMailConfig) {
        // FIX-500-283: Validate baseUrl
        const baseUrl = (config.baseUrl || 'https://api.apexmail.ee').replace(/\/+$/, '');
        if (!/^https?:\/\/.+/.test(baseUrl)) {
            throw new ValidationError(`Invalid baseUrl: "${config.baseUrl}". Must start with https:// or http://`);
        }
        this.baseUrl = baseUrl;
        this.apiKey = config.apiKey;
        this.timeout = config.timeout || 30000;
        this.debug = config.debug || false;
        // C-135: Node.js 18+ global fetch (undici) uses HTTP keep-alive by
        // default, so connections are reused across requests automatically.
        // Custom fetch implementations should enable keep-alive similarly.
        this.fetchFn = config.fetch || fetch;
        this.retryConfig = DEFAULT_RETRY_CONFIG;
    }

    // FIX-500-274: Support idempotency key header
    async request<T>(
        method: string,
        path: string,
        body?: unknown,
        options?: { idempotencyKey?: string }
    ): Promise<T> {
        return this.requestWithRetry<T>(method, path, body, 0, options);
    }

    /**
     * SECURITY FIX: Implement retry logic with exponential backoff
     * Handles transient network errors and rate limits properly
     *
     * C-134: Request body cloning is inherently safe here — `body` is the
     * original JS object and `JSON.stringify(body)` is called fresh on each
     * attempt, so the body is never "consumed" across retries.
     */
    private async requestWithRetry<T>(
        method: string,
        path: string,
        body: unknown,
        attempt: number,
        options?: { idempotencyKey?: string }
    ): Promise<T> {
        const url = `${this.baseUrl}${path}`;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        // FIX-500-276: Debug logging
        if (this.debug) {
            console.debug(`[ApexMail] ${method} ${path}${attempt > 0 ? ` (retry ${attempt})` : ''}`);
        }

        try {
            // FIX-500-274: Include Idempotency-Key header when provided
            const headers: Record<string, string> = {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json',
                    'User-Agent': '@apexmail/node/1.0.0',
            };
            if (options?.idempotencyKey) {
                headers['Idempotency-Key'] = options.idempotencyKey;
            }

            const response = await this.fetchFn(url, {
                method,
                headers,
                body: body ? JSON.stringify(body) : undefined,
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            // Handle rate limiting with Retry-After header
            if (response.status === 429) {
                const retryAfter = parseInt(response.headers.get('Retry-After') || '60', 10);
                
                if (attempt < this.retryConfig.maxRetries) {
                    const delay = Math.min(retryAfter * 1000, this.retryConfig.maxDelayMs);
                    await this.sleep(delay);
                    return this.requestWithRetry<T>(method, path, body, attempt + 1, options);
                }
                
                throw new RateLimitError(retryAfter);
            }

            // Retry on server errors, respecting Retry-After header if present
            if (this.retryConfig.retryableStatuses.has(response.status) && attempt < this.retryConfig.maxRetries) {
                const retryAfterHeader = response.headers.get('Retry-After');
                let delay: number;
                if (retryAfterHeader) {
                    // Retry-After can be seconds (integer) or an HTTP-date
                    const parsed = parseInt(retryAfterHeader, 10);
                    if (!isNaN(parsed)) {
                        delay = Math.min(parsed * 1000, this.retryConfig.maxDelayMs);
                    } else {
                        // Try parsing as HTTP-date
                        const date = new Date(retryAfterHeader).getTime();
                        delay = !isNaN(date)
                            ? Math.min(Math.max(0, date - Date.now()), this.retryConfig.maxDelayMs)
                            : this.calculateBackoff(attempt);
                    }
                } else {
                    delay = this.calculateBackoff(attempt);
                }
                await this.sleep(delay);
                return this.requestWithRetry<T>(method, path, body, attempt + 1, options);
            }

            // FIX-500-276: Debug logging for response
            if (this.debug) {
                console.debug(`[ApexMail] ${method} ${path} → ${response.status}`);
            }

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
            
            // Retry on timeout
            if (error instanceof Error && error.name === 'AbortError') {
                if (attempt < this.retryConfig.maxRetries) {
                    const delay = this.calculateBackoff(attempt);
                    await this.sleep(delay);
                    return this.requestWithRetry<T>(method, path, body, attempt + 1, options);
                }
                throw new ApexMailError('Request timeout', 408, 'TIMEOUT_ERROR');
            }

            // Retry on network errors
            if (error instanceof Error && (
                error.message.includes('ECONNREFUSED') ||
                error.message.includes('ECONNRESET') ||
                error.message.includes('ETIMEDOUT') ||
                error.message.includes('network')
            )) {
                if (attempt < this.retryConfig.maxRetries) {
                    const delay = this.calculateBackoff(attempt);
                    await this.sleep(delay);
                    return this.requestWithRetry<T>(method, path, body, attempt + 1, options);
                }
            }

            throw new ApexMailError(
                error instanceof Error ? error.message : 'Unknown error',
                500,
                'NETWORK_ERROR'
            );
        }
    }

    /**
     * Calculate exponential backoff with jitter
     */
    private calculateBackoff(attempt: number): number {
        const baseDelay = this.retryConfig.initialDelayMs * Math.pow(2, attempt);
        const jitter = Math.random() * 0.3 * baseDelay; // Add up to 30% jitter
        return Math.min(baseDelay + jitter, this.retryConfig.maxDelayMs);
    }

    private sleep(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * E-188: Build actionable error messages that include:
     *   1. What went wrong (human-readable message)
     *   2. HTTP status code
     *   3. Truncated response body for debugging
     *   4. Suggestion for how to fix
     */
    private handleError(response: Response, data: Record<string, unknown>): never {
        const serverMessage = (data.message as string) || 'Request failed';
        const code = (data.code as string) || 'UNKNOWN_ERROR';
        const bodyPreview = JSON.stringify(data).slice(0, 200);

        switch (response.status) {
            case 400:
                throw new ValidationError(
                    `Validation failed (400): ${serverMessage}. Check your request parameters. Response: ${bodyPreview}`,
                    data.details as Record<string, unknown>,
                );
            case 401:
                throw new AuthenticationError(
                    `Authentication failed (401): ${serverMessage}. Verify your API key is correct and not expired.`,
                );
            case 403:
                throw new ForbiddenError(
                    `Forbidden (403): ${serverMessage}. Your API key may lack the required scopes for this operation.`,
                    data.details as Record<string, unknown>,
                );
            case 404:
                throw new NotFoundError(
                    `Not found (404): ${serverMessage}. Verify the resource ID exists and belongs to your account.`,
                    data.details as Record<string, unknown>,
                );
            case 409:
                throw new ConflictError(
                    `Conflict (409): ${serverMessage}. The resource may already exist or was modified concurrently.`,
                    data.details as Record<string, unknown>,
                );
            case 429: {
                const retryAfter = parseInt(response.headers.get('Retry-After') || '60', 10);
                throw new RateLimitError(retryAfter);
            }
            default:
                throw new ApexMailError(
                    `Request failed (${response.status}): ${serverMessage}. Response: ${bodyPreview}`,
                    response.status,
                    code,
                    data.details as Record<string, unknown>,
                );
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
     * F-246: Basic email format validation.
     * Checks that a string looks like a valid email address before making
     * the API call, saving a round-trip for obviously malformed input.
     */
    private static readonly EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    /**
     * F-246: Validate send options before making the API call.
     * Catches common mistakes client-side for faster feedback.
     */
    private validateSendOptions(options: SendEmailOptions): void {
        // Required fields
        if (!options.from) {
            throw new ValidationError('"from" is required');
        }
        if (!options.to) {
            throw new ValidationError('"to" is required');
        }
        if (!options.subject) {
            throw new ValidationError('"subject" is required');
        }
        if (!options.html && !options.text) {
            throw new ValidationError('Either "html" or "text" body is required');
        }

        // FIX-500-281: Reject whitespace-only bodies
        if (options.html && !options.html.trim()) {
            throw new ValidationError('"html" body must not be empty or whitespace-only');
        }
        if (options.text && !options.text.trim()) {
            throw new ValidationError('"text" body must not be empty or whitespace-only');
        }

        // Email format: from
        const fromEmail = typeof options.from === 'string' ? options.from : options.from.email;
        if (!EmailsApi.EMAIL_REGEX.test(fromEmail)) {
            throw new ValidationError(`Invalid "from" email format: ${fromEmail}`);
        }

        // Email format: to (validate each recipient)
        const toList = Array.isArray(options.to) ? options.to : [options.to];
        if (toList.length === 0) {
            throw new ValidationError('"to" must contain at least one recipient');
        }
        for (const recipient of toList) {
            const email = typeof recipient === 'string' ? recipient : recipient.email;
            if (!EmailsApi.EMAIL_REGEX.test(email)) {
                throw new ValidationError(`Invalid "to" email format: ${email}`);
            }
        }

        // String length limits
        if (options.subject.length > 998) {
            throw new ValidationError('"subject" exceeds maximum length of 998 characters (RFC 2822)');
        }
        if (options.html && options.html.length > 10 * 1024 * 1024) {
            throw new ValidationError('"html" body exceeds maximum size of 10MB');
        }
        if (options.text && options.text.length > 10 * 1024 * 1024) {
            throw new ValidationError('"text" body exceeds maximum size of 10MB');
        }
    }

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
        // F-246: Validate inputs before making the API call
        this.validateSendOptions(options);
        // FIX-500-274: Thread idempotencyKey as a header
        return this.client.request<SendEmailResponse>('POST', '/v1/emails', this.normalizeEmail(options), 
            options.idempotencyKey ? { idempotencyKey: options.idempotencyKey } : undefined
        );
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
        if (!options.emails || options.emails.length === 0) {
            throw new ValidationError('"emails" array must not be empty');
        }
        if (options.emails.length > 1000) {
            throw new ValidationError('Maximum 1000 emails per batch');
        }
        // F-246: Validate each email in the batch
        for (let i = 0; i < options.emails.length; i++) {
            try {
                this.validateSendOptions(options.emails[i]!);
            } catch (err) {
                if (err instanceof ValidationError) {
                    throw new ValidationError(`Email at index ${i}: ${err.message}`);
                }
                throw err;
            }
        }
        return this.client.post<BatchSendResponse>('/v1/emails/batch', {
            emails: options.emails.map(e => this.normalizeEmail(e))
        });
    }

    /**
     * Get email by ID
     */
    async get(id: string): Promise<Email> {
        validateId(id, 'email');
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
        validateId(id, 'email');
        await this.client.post(`/v1/emails/${id}/cancel`);
    }

    private normalizeEmail(options: SendEmailOptions): Record<string, unknown> {
        const result: Record<string, unknown> = {
            from: this.normalizeRecipient(options.from),
            to: this.normalizeRecipients(options.to),
            subject: options.subject,
        };
        // FIX-500-282: Only include defined fields to avoid sending nulls
        if (options.cc) result.cc = this.normalizeRecipients(options.cc);
        if (options.bcc) result.bcc = this.normalizeRecipients(options.bcc);
        if (options.replyTo) result.replyTo = this.normalizeRecipient(options.replyTo);
        if (options.html) result.html = options.html;
        if (options.text) result.text = options.text;
        if (options.attachments) {
            result.attachments = options.attachments.map(a => ({
                filename: a.filename,
                content: Buffer.isBuffer(a.content) ? a.content.toString('base64') : a.content,
                contentType: a.contentType,
            }));
        }
        if (options.headers) result.headers = options.headers;
        if (options.tags) result.tags = options.tags;
        if (options.scheduledAt) {
            result.scheduledAt = options.scheduledAt instanceof Date
                ? options.scheduledAt.toISOString()
                : options.scheduledAt;
        }
        return result;
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
        validateId(id, 'domain');
        return this.client.get<Domain>(`/v1/domains/${id}`);
    }

    /**
     * List all domains
     * FIX-500-278: Support pagination
     */
    async list(options?: { limit?: number; offset?: number }): Promise<{ data: Domain[] }> {
        const params = new URLSearchParams();
        if (options?.limit) params.set('limit', options.limit.toString());
        if (options?.offset) params.set('offset', options.offset.toString());
        const query = params.toString();
        return this.client.get<{ data: Domain[] }>(`/v1/domains${query ? `?${query}` : ''}`);
    }

    /**
     * Verify domain DNS records
     */
    async verify(id: string): Promise<Domain> {
        validateId(id, 'domain');
        return this.client.post<Domain>(`/v1/domains/${id}/verify`);
    }

    /**
     * Delete a domain
     */
    async delete(id: string): Promise<void> {
        validateId(id, 'domain');
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
     * FIX-500-279: Support pagination
     */
    async list(options?: { limit?: number; offset?: number }): Promise<{ data: ApiKey[] }> {
        const params = new URLSearchParams();
        if (options?.limit) params.set('limit', options.limit.toString());
        if (options?.offset) params.set('offset', options.offset.toString());
        const query = params.toString();
        return this.client.get<{ data: ApiKey[] }>(`/v1/api-keys${query ? `?${query}` : ''}`);
    }

    /**
     * Revoke an API key
     */
    async revoke(id: string): Promise<void> {
        validateId(id, 'API key');
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
        validateId(id, 'webhook');
        return this.client.get<Webhook>(`/v1/webhooks/${id}`);
    }

    /**
     * List all webhooks
     * FIX-500-280: Support pagination
     */
    async list(options?: { limit?: number; offset?: number }): Promise<{ data: Webhook[] }> {
        const params = new URLSearchParams();
        if (options?.limit) params.set('limit', options.limit.toString());
        if (options?.offset) params.set('offset', options.offset.toString());
        const query = params.toString();
        return this.client.get<{ data: Webhook[] }>(`/v1/webhooks${query ? `?${query}` : ''}`);
    }

    /**
     * Update webhook
     */
    async update(id: string, options: Partial<CreateWebhookOptions>): Promise<Webhook> {
        validateId(id, 'webhook');
        return this.client.patch<Webhook>(`/v1/webhooks/${id}`, options);
    }

    /**
     * Delete webhook
     */
    async delete(id: string): Promise<void> {
        validateId(id, 'webhook');
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
        // FIX-500-284: Validate date range
        if (options?.from && options?.to) {
            const fromMs = options.from instanceof Date ? options.from.getTime() : new Date(options.from).getTime();
            const toMs = options.to instanceof Date ? options.to.getTime() : new Date(options.to).getTime();
            if (isNaN(fromMs) || isNaN(toMs)) {
                throw new ValidationError('Invalid date format in analytics "from" or "to"');
            }
            if (fromMs >= toMs) {
                throw new ValidationError('Analytics "from" date must be before "to" date');
            }
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

        // SECURITY FIX: Stronger API key validation
        // Valid formats: am_live_<32 chars> or am_test_<32 chars>
        const apiKeyPattern = /^am_(live|test)_[a-zA-Z0-9]{32,}$/;
        if (!apiKeyPattern.test(config.apiKey)) {
            throw new ValidationError(
                'Invalid API key format. Keys should match "am_live_<key>" or "am_test_<key>" where <key> is at least 32 alphanumeric characters'
            );
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
