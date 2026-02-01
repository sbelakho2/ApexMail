/**
 * SDK Generator Service
 * 
 * Generates client SDKs in multiple languages:
 * - TypeScript/JavaScript
 * - Python
 * - Ruby
 * - Go
 * - PHP
 * - Java
 * - C#
 */

import type { Pool } from 'pg';
import { config } from '../config.js';

export interface SdkConfig {
  language: SdkLanguage;
  version: string;
  apiVersion: string;
  packageName?: string;
  namespace?: string;
}

export type SdkLanguage = 'typescript' | 'python' | 'ruby' | 'go' | 'php' | 'java' | 'csharp';

export interface GeneratedSdk {
  language: SdkLanguage;
  version: string;
  files: SdkFile[];
  readme: string;
  installInstructions: string;
}

export interface SdkFile {
  path: string;
  content: string;
}

type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export class SdkGeneratorService {
  private db: Pool;
  private apiVersion: string;

  constructor(db: Pool) {
    this.db = db;
    this.apiVersion = config.currentApiVersion;
  }

  /**
   * Generate SDK for a specific language
   */
  async generateSdk(sdkConfig: SdkConfig): Promise<Result<GeneratedSdk>> {
    try {
      switch (sdkConfig.language) {
        case 'typescript':
          return this.generateTypeScriptSdk(sdkConfig);
        case 'python':
          return this.generatePythonSdk(sdkConfig);
        case 'ruby':
          return this.generateRubySdk(sdkConfig);
        case 'go':
          return this.generateGoSdk(sdkConfig);
        case 'php':
          return this.generatePhpSdk(sdkConfig);
        case 'java':
          return this.generateJavaSdk(sdkConfig);
        case 'csharp':
          return this.generateCSharpSdk(sdkConfig);
        default:
          return { ok: false, error: new Error(`Unsupported language: ${sdkConfig.language}`) };
      }
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Generate TypeScript SDK
   */
  private async generateTypeScriptSdk(sdkConfig: SdkConfig): Promise<Result<GeneratedSdk>> {
    const packageName = sdkConfig.packageName ?? '@apexmail/sdk';
    const files: SdkFile[] = [];

    // package.json
    files.push({
      path: 'package.json',
      content: JSON.stringify({
        name: packageName,
        version: sdkConfig.version,
        description: 'ApexMail TypeScript SDK',
        main: 'dist/index.js',
        types: 'dist/index.d.ts',
        type: 'module',
        scripts: {
          build: 'tsc',
          test: 'vitest',
        },
        dependencies: {},
        devDependencies: {
          typescript: '^5.3.3',
          vitest: '^1.2.0',
        },
        engines: { node: '>=18.0.0' },
        license: 'MIT',
      }, null, 2),
    });

    // tsconfig.json
    files.push({
      path: 'tsconfig.json',
      content: JSON.stringify({
        compilerOptions: {
          target: 'ES2022',
          module: 'NodeNext',
          moduleResolution: 'NodeNext',
          strict: true,
          esModuleInterop: true,
          skipLibCheck: true,
          forceConsistentCasingInFileNames: true,
          declaration: true,
          declarationMap: true,
          outDir: './dist',
          rootDir: './src',
        },
        include: ['src/**/*'],
        exclude: ['node_modules', 'dist'],
      }, null, 2),
    });

    // Main client
    files.push({
      path: 'src/index.ts',
      content: `/**
 * ApexMail TypeScript SDK
 * Version: ${sdkConfig.version}
 * API Version: ${sdkConfig.apiVersion}
 */

export { ApexMailClient } from './client.js';
export { EmailsResource } from './resources/emails.js';
export { DomainsResource } from './resources/domains.js';
export { WebhooksResource } from './resources/webhooks.js';
export { TemplatesResource } from './resources/templates.js';
export { AnalyticsResource } from './resources/analytics.js';
export * from './types.js';
export * from './errors.js';
`,
    });

    // Types
    files.push({
      path: 'src/types.ts',
      content: `/**
 * ApexMail SDK Types
 */

export interface ApexMailConfig {
  apiKey: string;
  baseUrl?: string;
  apiVersion?: string;
  timeout?: number;
  maxRetries?: number;
}

export interface Email {
  id: string;
  from: EmailAddress;
  to: EmailAddress[];
  cc?: EmailAddress[];
  bcc?: EmailAddress[];
  subject: string;
  text?: string;
  html?: string;
  templateId?: string;
  templateData?: Record<string, unknown>;
  attachments?: Attachment[];
  headers?: Record<string, string>;
  tags?: string[];
  metadata?: Record<string, unknown>;
  scheduledAt?: Date;
  createdAt: Date;
  status: EmailStatus;
}

export interface EmailAddress {
  email: string;
  name?: string;
}

export interface Attachment {
  filename: string;
  content: string | Buffer;
  contentType?: string;
  contentId?: string;
  disposition?: 'attachment' | 'inline';
}

export type EmailStatus = 
  | 'queued'
  | 'sending'
  | 'sent'
  | 'delivered'
  | 'bounced'
  | 'deferred'
  | 'dropped'
  | 'complained';

export interface SendEmailRequest {
  from: EmailAddress | string;
  to: (EmailAddress | string)[];
  cc?: (EmailAddress | string)[];
  bcc?: (EmailAddress | string)[];
  subject: string;
  text?: string;
  html?: string;
  templateId?: string;
  templateData?: Record<string, unknown>;
  attachments?: Attachment[];
  headers?: Record<string, string>;
  tags?: string[];
  metadata?: Record<string, unknown>;
  scheduledAt?: Date | string;
}

export interface SendEmailResponse {
  id: string;
  status: EmailStatus;
  message: string;
}

export interface BatchSendRequest {
  messages: SendEmailRequest[];
  sendAt?: Date | string;
}

export interface BatchSendResponse {
  batchId: string;
  accepted: number;
  rejected: number;
  messages: Array<{
    index: number;
    id?: string;
    status: 'accepted' | 'rejected';
    error?: string;
  }>;
}

export interface Domain {
  id: string;
  domain: string;
  status: DomainStatus;
  dkimSelector: string;
  dkimPublicKey: string;
  records: DnsRecord[];
  createdAt: Date;
  verifiedAt?: Date;
}

export type DomainStatus = 'pending' | 'verified' | 'failed';

export interface DnsRecord {
  type: 'TXT' | 'CNAME' | 'MX';
  name: string;
  value: string;
  priority?: number;
  verified: boolean;
}

export interface Template {
  id: string;
  name: string;
  subject: string;
  html?: string;
  text?: string;
  variables: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface WebhookEndpoint {
  id: string;
  url: string;
  events: string[];
  enabled: boolean;
  secret: string;
  description?: string;
  createdAt: Date;
}

export interface AnalyticsQuery {
  startDate: Date | string;
  endDate: Date | string;
  groupBy?: 'hour' | 'day' | 'week' | 'month';
  filters?: {
    domain?: string;
    tag?: string;
    status?: EmailStatus;
  };
}

export interface AnalyticsResponse {
  sent: number;
  delivered: number;
  bounced: number;
  opened: number;
  clicked: number;
  complained: number;
  unsubscribed: number;
  series?: AnalyticsDataPoint[];
}

export interface AnalyticsDataPoint {
  timestamp: Date;
  sent: number;
  delivered: number;
  bounced: number;
  opened: number;
  clicked: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  hasMore: boolean;
  nextCursor?: string;
  total?: number;
}

export interface ListOptions {
  limit?: number;
  cursor?: string;
  startingAfter?: string;
  endingBefore?: string;
}
`,
    });

    // Errors
    files.push({
      path: 'src/errors.ts',
      content: `/**
 * ApexMail SDK Errors
 */

export class ApexMailError extends Error {
  public readonly code: string;
  public readonly statusCode?: number;
  public readonly requestId?: string;

  constructor(message: string, code: string, statusCode?: number, requestId?: string) {
    super(message);
    this.name = 'ApexMailError';
    this.code = code;
    this.statusCode = statusCode;
    this.requestId = requestId;
    Error.captureStackTrace(this, this.constructor);
  }
}

export class AuthenticationError extends ApexMailError {
  constructor(message: string = 'Invalid API key', requestId?: string) {
    super(message, 'authentication_error', 401, requestId);
    this.name = 'AuthenticationError';
  }
}

export class RateLimitError extends ApexMailError {
  public readonly retryAfter?: number;

  constructor(message: string = 'Rate limit exceeded', retryAfter?: number, requestId?: string) {
    super(message, 'rate_limit_error', 429, requestId);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

export class ValidationError extends ApexMailError {
  public readonly errors?: Record<string, string[]>;

  constructor(message: string, errors?: Record<string, string[]>, requestId?: string) {
    super(message, 'validation_error', 400, requestId);
    this.name = 'ValidationError';
    this.errors = errors;
  }
}

export class NotFoundError extends ApexMailError {
  constructor(resource: string, id: string, requestId?: string) {
    super(\`\${resource} not found: \${id}\`, 'not_found', 404, requestId);
    this.name = 'NotFoundError';
  }
}

export class ServerError extends ApexMailError {
  constructor(message: string = 'Internal server error', requestId?: string) {
    super(message, 'server_error', 500, requestId);
    this.name = 'ServerError';
  }
}
`,
    });

    // Client
    files.push({
      path: 'src/client.ts',
      content: `/**
 * ApexMail Client
 */

import type { ApexMailConfig } from './types.js';
import { EmailsResource } from './resources/emails.js';
import { DomainsResource } from './resources/domains.js';
import { WebhooksResource } from './resources/webhooks.js';
import { TemplatesResource } from './resources/templates.js';
import { AnalyticsResource } from './resources/analytics.js';
import { HttpClient } from './http.js';

export class ApexMailClient {
  private readonly httpClient: HttpClient;

  public readonly emails: EmailsResource;
  public readonly domains: DomainsResource;
  public readonly webhooks: WebhooksResource;
  public readonly templates: TemplatesResource;
  public readonly analytics: AnalyticsResource;

  constructor(config: ApexMailConfig | string) {
    const fullConfig: ApexMailConfig = typeof config === 'string'
      ? { apiKey: config }
      : config;

    this.httpClient = new HttpClient({
      apiKey: fullConfig.apiKey,
      baseUrl: fullConfig.baseUrl ?? '${config.apiBaseUrl}',
      apiVersion: fullConfig.apiVersion ?? '${sdkConfig.apiVersion}',
      timeout: fullConfig.timeout ?? 30000,
      maxRetries: fullConfig.maxRetries ?? 3,
    });

    this.emails = new EmailsResource(this.httpClient);
    this.domains = new DomainsResource(this.httpClient);
    this.webhooks = new WebhooksResource(this.httpClient);
    this.templates = new TemplatesResource(this.httpClient);
    this.analytics = new AnalyticsResource(this.httpClient);
  }

  /**
   * Get the HTTP client for custom requests
   */
  getHttpClient(): HttpClient {
    return this.httpClient;
  }
}
`,
    });

    // HTTP Client
    files.push({
      path: 'src/http.ts',
      content: `/**
 * HTTP Client
 */

import {
  ApexMailError,
  AuthenticationError,
  RateLimitError,
  ValidationError,
  NotFoundError,
  ServerError,
} from './errors.js';

export interface HttpClientConfig {
  apiKey: string;
  baseUrl: string;
  apiVersion: string;
  timeout: number;
  maxRetries: number;
}

export class HttpClient {
  private readonly config: HttpClientConfig;

  constructor(config: HttpClientConfig) {
    this.config = config;
  }

  async request<T>(
    method: string,
    path: string,
    options: {
      body?: unknown;
      query?: Record<string, string | number | boolean | undefined>;
      headers?: Record<string, string>;
      idempotencyKey?: string;
    } = {}
  ): Promise<T> {
    let url = \`\${this.config.baseUrl}\${path}\`;

    if (options.query) {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(options.query)) {
        if (value !== undefined) {
          params.set(key, String(value));
        }
      }
      const queryString = params.toString();
      if (queryString) {
        url += \`?\${queryString}\`;
      }
    }

    const headers: Record<string, string> = {
      'Authorization': \`Bearer \${this.config.apiKey}\`,
      'Content-Type': 'application/json',
      'X-API-Version': this.config.apiVersion,
      'User-Agent': 'apexmail-node/${sdkConfig.version}',
      ...options.headers,
    };

    if (options.idempotencyKey) {
      headers['Idempotency-Key'] = options.idempotencyKey;
    }

    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.config.timeout);

        const response = await fetch(url, {
          method,
          headers,
          body: options.body ? JSON.stringify(options.body) : undefined,
          signal: controller.signal,
        });

        clearTimeout(timeout);

        const requestId = response.headers.get('X-Request-ID') ?? undefined;

        if (response.ok) {
          const data = await response.json();
          return data as T;
        }

        const errorBody = await response.json().catch(() => ({}));

        switch (response.status) {
          case 401:
            throw new AuthenticationError(errorBody.message, requestId);
          case 404:
            throw new NotFoundError(errorBody.resource ?? 'Resource', errorBody.id ?? 'unknown', requestId);
          case 422:
            throw new ValidationError(errorBody.message, errorBody.errors, requestId);
          case 429: {
            const retryAfter = parseInt(response.headers.get('Retry-After') ?? '60', 10);
            if (attempt < this.config.maxRetries) {
              await this.sleep(retryAfter * 1000);
              continue;
            }
            throw new RateLimitError(errorBody.message, retryAfter, requestId);
          }
          case 500:
          case 502:
          case 503:
          case 504:
            if (attempt < this.config.maxRetries) {
              await this.sleep(Math.pow(2, attempt) * 1000);
              continue;
            }
            throw new ServerError(errorBody.message, requestId);
          default:
            throw new ApexMailError(
              errorBody.message ?? 'Unknown error',
              errorBody.code ?? 'unknown_error',
              response.status,
              requestId
            );
        }
      } catch (error) {
        if (error instanceof ApexMailError) {
          throw error;
        }
        lastError = error as Error;
        if (attempt < this.config.maxRetries) {
          await this.sleep(Math.pow(2, attempt) * 1000);
          continue;
        }
      }
    }

    throw lastError ?? new Error('Request failed');
  }

  async get<T>(path: string, query?: Record<string, string | number | boolean | undefined>): Promise<T> {
    return this.request<T>('GET', path, { query });
  }

  async post<T>(path: string, body?: unknown, idempotencyKey?: string): Promise<T> {
    return this.request<T>('POST', path, { body, idempotencyKey });
  }

  async put<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('PUT', path, { body });
  }

  async patch<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('PATCH', path, { body });
  }

  async delete<T>(path: string): Promise<T> {
    return this.request<T>('DELETE', path);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
`,
    });

    // Emails Resource
    files.push({
      path: 'src/resources/emails.ts',
      content: `/**
 * Emails Resource
 */

import type { HttpClient } from '../http.js';
import type {
  Email,
  SendEmailRequest,
  SendEmailResponse,
  BatchSendRequest,
  BatchSendResponse,
  ListOptions,
  PaginatedResponse,
} from '../types.js';

export class EmailsResource {
  private readonly http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  /**
   * Send a single email
   */
  async send(request: SendEmailRequest, idempotencyKey?: string): Promise<SendEmailResponse> {
    return this.http.post<SendEmailResponse>('/v1/emails', request, idempotencyKey);
  }

  /**
   * Send batch emails
   */
  async sendBatch(request: BatchSendRequest, idempotencyKey?: string): Promise<BatchSendResponse> {
    return this.http.post<BatchSendResponse>('/v1/emails/batch', request, idempotencyKey);
  }

  /**
   * Get email by ID
   */
  async get(emailId: string): Promise<Email> {
    return this.http.get<Email>(\`/v1/emails/\${emailId}\`);
  }

  /**
   * List emails
   */
  async list(options?: ListOptions): Promise<PaginatedResponse<Email>> {
    return this.http.get<PaginatedResponse<Email>>('/v1/emails', options);
  }

  /**
   * Cancel scheduled email
   */
  async cancel(emailId: string): Promise<{ success: boolean }> {
    return this.http.post<{ success: boolean }>(\`/v1/emails/\${emailId}/cancel\`);
  }

  /**
   * Get email events
   */
  async getEvents(emailId: string): Promise<EmailEvent[]> {
    return this.http.get<EmailEvent[]>(\`/v1/emails/\${emailId}/events\`);
  }
}

interface EmailEvent {
  type: string;
  timestamp: Date;
  data: Record<string, unknown>;
}
`,
    });

    // Domains Resource
    files.push({
      path: 'src/resources/domains.ts',
      content: `/**
 * Domains Resource
 */

import type { HttpClient } from '../http.js';
import type { Domain, ListOptions, PaginatedResponse } from '../types.js';

export class DomainsResource {
  private readonly http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  /**
   * Add a domain
   */
  async create(domain: string): Promise<Domain> {
    return this.http.post<Domain>('/v1/domains', { domain });
  }

  /**
   * Get domain by ID
   */
  async get(domainId: string): Promise<Domain> {
    return this.http.get<Domain>(\`/v1/domains/\${domainId}\`);
  }

  /**
   * List domains
   */
  async list(options?: ListOptions): Promise<PaginatedResponse<Domain>> {
    return this.http.get<PaginatedResponse<Domain>>('/v1/domains', options);
  }

  /**
   * Verify domain
   */
  async verify(domainId: string): Promise<Domain> {
    return this.http.post<Domain>(\`/v1/domains/\${domainId}/verify\`);
  }

  /**
   * Delete domain
   */
  async delete(domainId: string): Promise<{ success: boolean }> {
    return this.http.delete<{ success: boolean }>(\`/v1/domains/\${domainId}\`);
  }

  /**
   * Get DNS records for domain
   */
  async getDnsRecords(domainId: string): Promise<Domain['records']> {
    const domain = await this.get(domainId);
    return domain.records;
  }
}
`,
    });

    // Webhooks Resource
    files.push({
      path: 'src/resources/webhooks.ts',
      content: `/**
 * Webhooks Resource
 */

import type { HttpClient } from '../http.js';
import type { WebhookEndpoint, ListOptions, PaginatedResponse } from '../types.js';

export class WebhooksResource {
  private readonly http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  /**
   * Create webhook endpoint
   */
  async create(data: {
    url: string;
    events: string[];
    description?: string;
  }): Promise<WebhookEndpoint> {
    return this.http.post<WebhookEndpoint>('/v1/webhooks', data);
  }

  /**
   * Get webhook by ID
   */
  async get(webhookId: string): Promise<WebhookEndpoint> {
    return this.http.get<WebhookEndpoint>(\`/v1/webhooks/\${webhookId}\`);
  }

  /**
   * List webhooks
   */
  async list(options?: ListOptions): Promise<PaginatedResponse<WebhookEndpoint>> {
    return this.http.get<PaginatedResponse<WebhookEndpoint>>('/v1/webhooks', options);
  }

  /**
   * Update webhook
   */
  async update(webhookId: string, data: {
    url?: string;
    events?: string[];
    description?: string;
    enabled?: boolean;
  }): Promise<WebhookEndpoint> {
    return this.http.patch<WebhookEndpoint>(\`/v1/webhooks/\${webhookId}\`, data);
  }

  /**
   * Delete webhook
   */
  async delete(webhookId: string): Promise<{ success: boolean }> {
    return this.http.delete<{ success: boolean }>(\`/v1/webhooks/\${webhookId}\`);
  }

  /**
   * Rotate webhook secret
   */
  async rotateSecret(webhookId: string): Promise<{ secret: string }> {
    return this.http.post<{ secret: string }>(\`/v1/webhooks/\${webhookId}/rotate-secret\`);
  }

  /**
   * Test webhook
   */
  async test(webhookId: string): Promise<{ success: boolean; statusCode?: number; error?: string }> {
    return this.http.post<{ success: boolean; statusCode?: number; error?: string }>(
      \`/v1/webhooks/\${webhookId}/test\`
    );
  }
}
`,
    });

    // Templates Resource
    files.push({
      path: 'src/resources/templates.ts',
      content: `/**
 * Templates Resource
 */

import type { HttpClient } from '../http.js';
import type { Template, ListOptions, PaginatedResponse } from '../types.js';

export class TemplatesResource {
  private readonly http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  /**
   * Create template
   */
  async create(data: {
    name: string;
    subject: string;
    html?: string;
    text?: string;
  }): Promise<Template> {
    return this.http.post<Template>('/v1/templates', data);
  }

  /**
   * Get template by ID
   */
  async get(templateId: string): Promise<Template> {
    return this.http.get<Template>(\`/v1/templates/\${templateId}\`);
  }

  /**
   * List templates
   */
  async list(options?: ListOptions): Promise<PaginatedResponse<Template>> {
    return this.http.get<PaginatedResponse<Template>>('/v1/templates', options);
  }

  /**
   * Update template
   */
  async update(templateId: string, data: {
    name?: string;
    subject?: string;
    html?: string;
    text?: string;
  }): Promise<Template> {
    return this.http.patch<Template>(\`/v1/templates/\${templateId}\`, data);
  }

  /**
   * Delete template
   */
  async delete(templateId: string): Promise<{ success: boolean }> {
    return this.http.delete<{ success: boolean }>(\`/v1/templates/\${templateId}\`);
  }

  /**
   * Render template preview
   */
  async preview(templateId: string, data: Record<string, unknown>): Promise<{ html?: string; text?: string }> {
    return this.http.post<{ html?: string; text?: string }>(\`/v1/templates/\${templateId}/preview\`, { data });
  }
}
`,
    });

    // Analytics Resource
    files.push({
      path: 'src/resources/analytics.ts',
      content: `/**
 * Analytics Resource
 */

import type { HttpClient } from '../http.js';
import type { AnalyticsQuery, AnalyticsResponse } from '../types.js';

export class AnalyticsResource {
  private readonly http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  /**
   * Get email analytics
   */
  async getStats(query: AnalyticsQuery): Promise<AnalyticsResponse> {
    return this.http.get<AnalyticsResponse>('/v1/analytics/stats', {
      start_date: query.startDate instanceof Date ? query.startDate.toISOString() : query.startDate,
      end_date: query.endDate instanceof Date ? query.endDate.toISOString() : query.endDate,
      group_by: query.groupBy,
      domain: query.filters?.domain,
      tag: query.filters?.tag,
      status: query.filters?.status,
    });
  }

  /**
   * Get bounce rate
   */
  async getBounceRate(query: AnalyticsQuery): Promise<{ bounceRate: number; hardBounces: number; softBounces: number }> {
    return this.http.get<{ bounceRate: number; hardBounces: number; softBounces: number }>(
      '/v1/analytics/bounces',
      {
        start_date: query.startDate instanceof Date ? query.startDate.toISOString() : query.startDate,
        end_date: query.endDate instanceof Date ? query.endDate.toISOString() : query.endDate,
      }
    );
  }

  /**
   * Get engagement metrics
   */
  async getEngagement(query: AnalyticsQuery): Promise<{ openRate: number; clickRate: number; unsubscribeRate: number }> {
    return this.http.get<{ openRate: number; clickRate: number; unsubscribeRate: number }>(
      '/v1/analytics/engagement',
      {
        start_date: query.startDate instanceof Date ? query.startDate.toISOString() : query.startDate,
        end_date: query.endDate instanceof Date ? query.endDate.toISOString() : query.endDate,
      }
    );
  }

  /**
   * Get deliverability report
   */
  async getDeliverability(query: AnalyticsQuery): Promise<DeliverabilityReport> {
    return this.http.get<DeliverabilityReport>('/v1/analytics/deliverability', {
      start_date: query.startDate instanceof Date ? query.startDate.toISOString() : query.startDate,
      end_date: query.endDate instanceof Date ? query.endDate.toISOString() : query.endDate,
    });
  }
}

interface DeliverabilityReport {
  deliveryRate: number;
  inboxRate: number;
  spamRate: number;
  byProvider: Array<{
    provider: string;
    deliveryRate: number;
    inboxRate: number;
  }>;
}
`,
    });

    const readme = `# ApexMail TypeScript SDK

Official TypeScript/JavaScript SDK for the ApexMail API.

## Installation

\`\`\`bash
npm install ${packageName}
# or
yarn add ${packageName}
# or
pnpm add ${packageName}
\`\`\`

## Quick Start

\`\`\`typescript
import { ApexMailClient } from '${packageName}';

const client = new ApexMailClient('your-api-key');

// Send an email
const response = await client.emails.send({
  from: 'sender@yourdomain.com',
  to: ['recipient@example.com'],
  subject: 'Hello from ApexMail!',
  html: '<h1>Welcome!</h1><p>This is your first email.</p>',
});

console.log(\`Email sent: \${response.id}\`);
\`\`\`

## API Version

This SDK uses API version \`${sdkConfig.apiVersion}\`.

## Resources

- **emails** - Send and manage emails
- **domains** - Domain verification and management
- **webhooks** - Webhook endpoint management
- **templates** - Email templates
- **analytics** - Email analytics and reporting

## Documentation

Full documentation: ${config.docsBaseUrl}/sdk/typescript
`;

    const installInstructions = `npm install ${packageName}
# or
yarn add ${packageName}
# or
pnpm add ${packageName}`;

    return {
      ok: true,
      value: {
        language: 'typescript',
        version: sdkConfig.version,
        files,
        readme,
        installInstructions,
      },
    };
  }

  /**
   * Generate Python SDK
   */
  private async generatePythonSdk(sdkConfig: SdkConfig): Promise<Result<GeneratedSdk>> {
    const packageName = sdkConfig.packageName ?? 'apexmail';
    const files: SdkFile[] = [];

    // setup.py
    files.push({
      path: 'setup.py',
      content: `from setuptools import setup, find_packages

setup(
    name="${packageName}",
    version="${sdkConfig.version}",
    description="ApexMail Python SDK",
    author="ApexMail",
    author_email="support@apexmail.io",
    url="https://github.com/apexmail/apexmail-python",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "httpx>=0.25.0",
        "pydantic>=2.0.0",
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
`,
    });

    // pyproject.toml
    files.push({
      path: 'pyproject.toml',
      content: `[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "${packageName}"
version = "${sdkConfig.version}"
description = "ApexMail Python SDK"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.8"
dependencies = [
    "httpx>=0.25.0",
    "pydantic>=2.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-asyncio>=0.21.0",
    "mypy>=1.0.0",
]
`,
    });

    // Main package
    files.push({
      path: 'apexmail/__init__.py',
      content: `"""
ApexMail Python SDK
Version: ${sdkConfig.version}
API Version: ${sdkConfig.apiVersion}
"""

from .client import ApexMailClient
from .resources.emails import EmailsResource
from .resources.domains import DomainsResource
from .resources.webhooks import WebhooksResource
from .resources.templates import TemplatesResource
from .resources.analytics import AnalyticsResource
from .models import *
from .exceptions import *

__version__ = "${sdkConfig.version}"
__api_version__ = "${sdkConfig.apiVersion}"

__all__ = [
    "ApexMailClient",
    "EmailsResource",
    "DomainsResource",
    "WebhooksResource",
    "TemplatesResource",
    "AnalyticsResource",
]
`,
    });

    // Client
    files.push({
      path: 'apexmail/client.py',
      content: `"""
ApexMail Client
"""

from typing import Optional
import httpx

from .http import HttpClient
from .resources.emails import EmailsResource
from .resources.domains import DomainsResource
from .resources.webhooks import WebhooksResource
from .resources.templates import TemplatesResource
from .resources.analytics import AnalyticsResource


class ApexMailClient:
    """
    ApexMail API client.
    
    Usage:
        client = ApexMailClient("your-api-key")
        response = client.emails.send(
            from_email="sender@yourdomain.com",
            to=["recipient@example.com"],
            subject="Hello!",
            html="<h1>Welcome!</h1>"
        )
    """
    
    def __init__(
        self,
        api_key: str,
        base_url: str = "${config.apiBaseUrl}",
        api_version: str = "${sdkConfig.apiVersion}",
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        self._http = HttpClient(
            api_key=api_key,
            base_url=base_url,
            api_version=api_version,
            timeout=timeout,
            max_retries=max_retries,
        )
        
        self.emails = EmailsResource(self._http)
        self.domains = DomainsResource(self._http)
        self.webhooks = WebhooksResource(self._http)
        self.templates = TemplatesResource(self._http)
        self.analytics = AnalyticsResource(self._http)
    
    def close(self) -> None:
        """Close the HTTP client."""
        self._http.close()
    
    def __enter__(self) -> "ApexMailClient":
        return self
    
    def __exit__(self, *args) -> None:
        self.close()


class AsyncApexMailClient:
    """
    Async ApexMail API client.
    
    Usage:
        async with AsyncApexMailClient("your-api-key") as client:
            response = await client.emails.send(
                from_email="sender@yourdomain.com",
                to=["recipient@example.com"],
                subject="Hello!",
                html="<h1>Welcome!</h1>"
            )
    """
    
    def __init__(
        self,
        api_key: str,
        base_url: str = "${config.apiBaseUrl}",
        api_version: str = "${sdkConfig.apiVersion}",
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        self._http = HttpClient(
            api_key=api_key,
            base_url=base_url,
            api_version=api_version,
            timeout=timeout,
            max_retries=max_retries,
            async_mode=True,
        )
        
        self.emails = EmailsResource(self._http, async_mode=True)
        self.domains = DomainsResource(self._http, async_mode=True)
        self.webhooks = WebhooksResource(self._http, async_mode=True)
        self.templates = TemplatesResource(self._http, async_mode=True)
        self.analytics = AnalyticsResource(self._http, async_mode=True)
    
    async def close(self) -> None:
        """Close the HTTP client."""
        await self._http.aclose()
    
    async def __aenter__(self) -> "AsyncApexMailClient":
        return self
    
    async def __aexit__(self, *args) -> None:
        await self.close()
`,
    });

    // HTTP Client
    files.push({
      path: 'apexmail/http.py',
      content: `"""
HTTP Client
"""

from typing import Any, Dict, Optional, Union
import time

import httpx

from .exceptions import (
    ApexMailError,
    AuthenticationError,
    RateLimitError,
    ValidationError,
    NotFoundError,
    ServerError,
)


class HttpClient:
    """HTTP client for ApexMail API requests."""
    
    def __init__(
        self,
        api_key: str,
        base_url: str,
        api_version: str,
        timeout: float = 30.0,
        max_retries: int = 3,
        async_mode: bool = False,
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.api_version = api_version
        self.timeout = timeout
        self.max_retries = max_retries
        self.async_mode = async_mode
        
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "X-API-Version": api_version,
            "User-Agent": f"apexmail-python/${sdkConfig.version}",
        }
        
        if async_mode:
            self._async_client = httpx.AsyncClient(
                base_url=base_url,
                headers=self._headers,
                timeout=timeout,
            )
        else:
            self._sync_client = httpx.Client(
                base_url=base_url,
                headers=self._headers,
                timeout=timeout,
            )
    
    def request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Any:
        """Make a synchronous HTTP request."""
        headers = {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        
        last_error = None
        
        for attempt in range(self.max_retries + 1):
            try:
                response = self._sync_client.request(
                    method=method,
                    url=path,
                    json=body,
                    params=params,
                    headers=headers,
                )
                
                return self._handle_response(response, attempt)
            
            except (httpx.TimeoutException, httpx.NetworkError) as e:
                last_error = e
                if attempt < self.max_retries:
                    time.sleep(2 ** attempt)
                    continue
                raise ServerError(f"Request failed: {str(e)}")
        
        raise last_error or ServerError("Request failed")
    
    async def arequest(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Any:
        """Make an asynchronous HTTP request."""
        import asyncio
        
        headers = {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        
        last_error = None
        
        for attempt in range(self.max_retries + 1):
            try:
                response = await self._async_client.request(
                    method=method,
                    url=path,
                    json=body,
                    params=params,
                    headers=headers,
                )
                
                return self._handle_response(response, attempt)
            
            except (httpx.TimeoutException, httpx.NetworkError) as e:
                last_error = e
                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise ServerError(f"Request failed: {str(e)}")
        
        raise last_error or ServerError("Request failed")
    
    def _handle_response(self, response: httpx.Response, attempt: int) -> Any:
        """Handle HTTP response."""
        request_id = response.headers.get("X-Request-ID")
        
        if response.is_success:
            return response.json()
        
        try:
            error_body = response.json()
        except Exception:
            error_body = {}
        
        message = error_body.get("message", "Unknown error")
        
        if response.status_code == 401:
            raise AuthenticationError(message, request_id)
        elif response.status_code == 404:
            raise NotFoundError(
                error_body.get("resource", "Resource"),
                error_body.get("id", "unknown"),
                request_id,
            )
        elif response.status_code == 422:
            raise ValidationError(message, error_body.get("errors"), request_id)
        elif response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 60))
            raise RateLimitError(message, retry_after, request_id)
        elif response.status_code >= 500:
            raise ServerError(message, request_id)
        else:
            raise ApexMailError(
                message,
                error_body.get("code", "unknown_error"),
                response.status_code,
                request_id,
            )
    
    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        return self.request("GET", path, params=params)
    
    def post(
        self,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Any:
        return self.request("POST", path, body=body, idempotency_key=idempotency_key)
    
    def patch(self, path: str, body: Optional[Dict[str, Any]] = None) -> Any:
        return self.request("PATCH", path, body=body)
    
    def delete(self, path: str) -> Any:
        return self.request("DELETE", path)
    
    async def aget(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        return await self.arequest("GET", path, params=params)
    
    async def apost(
        self,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Any:
        return await self.arequest("POST", path, body=body, idempotency_key=idempotency_key)
    
    async def apatch(self, path: str, body: Optional[Dict[str, Any]] = None) -> Any:
        return await self.arequest("PATCH", path, body=body)
    
    async def adelete(self, path: str) -> Any:
        return await self.arequest("DELETE", path)
    
    def close(self) -> None:
        if hasattr(self, "_sync_client"):
            self._sync_client.close()
    
    async def aclose(self) -> None:
        if hasattr(self, "_async_client"):
            await self._async_client.aclose()
`,
    });

    // Exceptions
    files.push({
      path: 'apexmail/exceptions.py',
      content: `"""
ApexMail SDK Exceptions
"""

from typing import Optional, Dict, List


class ApexMailError(Exception):
    """Base exception for ApexMail SDK."""
    
    def __init__(
        self,
        message: str,
        code: str = "unknown_error",
        status_code: Optional[int] = None,
        request_id: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.request_id = request_id
    
    def __str__(self) -> str:
        parts = [self.message]
        if self.code:
            parts.append(f"(code: {self.code})")
        if self.request_id:
            parts.append(f"[request_id: {self.request_id}]")
        return " ".join(parts)


class AuthenticationError(ApexMailError):
    """Raised when authentication fails."""
    
    def __init__(
        self,
        message: str = "Invalid API key",
        request_id: Optional[str] = None,
    ):
        super().__init__(message, "authentication_error", 401, request_id)


class RateLimitError(ApexMailError):
    """Raised when rate limit is exceeded."""
    
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: int = 60,
        request_id: Optional[str] = None,
    ):
        super().__init__(message, "rate_limit_error", 429, request_id)
        self.retry_after = retry_after


class ValidationError(ApexMailError):
    """Raised when request validation fails."""
    
    def __init__(
        self,
        message: str,
        errors: Optional[Dict[str, List[str]]] = None,
        request_id: Optional[str] = None,
    ):
        super().__init__(message, "validation_error", 400, request_id)
        self.errors = errors or {}


class NotFoundError(ApexMailError):
    """Raised when a resource is not found."""
    
    def __init__(
        self,
        resource: str,
        resource_id: str,
        request_id: Optional[str] = None,
    ):
        message = f"{resource} not found: {resource_id}"
        super().__init__(message, "not_found", 404, request_id)
        self.resource = resource
        self.resource_id = resource_id


class ServerError(ApexMailError):
    """Raised when a server error occurs."""
    
    def __init__(
        self,
        message: str = "Internal server error",
        request_id: Optional[str] = None,
    ):
        super().__init__(message, "server_error", 500, request_id)
`,
    });

    // Models
    files.push({
      path: 'apexmail/models.py',
      content: `"""
ApexMail SDK Models
"""

from datetime import datetime
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, EmailStr, Field


class EmailAddress(BaseModel):
    """Email address with optional name."""
    email: EmailStr
    name: Optional[str] = None


class Attachment(BaseModel):
    """Email attachment."""
    filename: str
    content: Union[str, bytes]
    content_type: Optional[str] = None
    content_id: Optional[str] = None
    disposition: str = "attachment"


class Email(BaseModel):
    """Email message."""
    id: str
    from_: EmailAddress = Field(alias="from")
    to: List[EmailAddress]
    cc: Optional[List[EmailAddress]] = None
    bcc: Optional[List[EmailAddress]] = None
    subject: str
    text: Optional[str] = None
    html: Optional[str] = None
    template_id: Optional[str] = None
    template_data: Optional[Dict[str, Any]] = None
    attachments: Optional[List[Attachment]] = None
    headers: Optional[Dict[str, str]] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    scheduled_at: Optional[datetime] = None
    created_at: datetime
    status: str


class SendEmailRequest(BaseModel):
    """Request to send an email."""
    from_: Union[EmailAddress, str] = Field(alias="from")
    to: List[Union[EmailAddress, str]]
    cc: Optional[List[Union[EmailAddress, str]]] = None
    bcc: Optional[List[Union[EmailAddress, str]]] = None
    subject: str
    text: Optional[str] = None
    html: Optional[str] = None
    template_id: Optional[str] = None
    template_data: Optional[Dict[str, Any]] = None
    attachments: Optional[List[Attachment]] = None
    headers: Optional[Dict[str, str]] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    scheduled_at: Optional[Union[datetime, str]] = None


class SendEmailResponse(BaseModel):
    """Response from sending an email."""
    id: str
    status: str
    message: str


class Domain(BaseModel):
    """Email domain."""
    id: str
    domain: str
    status: str
    dkim_selector: str
    dkim_public_key: str
    records: List["DnsRecord"]
    created_at: datetime
    verified_at: Optional[datetime] = None


class DnsRecord(BaseModel):
    """DNS record for domain verification."""
    type: str
    name: str
    value: str
    priority: Optional[int] = None
    verified: bool


class WebhookEndpoint(BaseModel):
    """Webhook endpoint."""
    id: str
    url: str
    events: List[str]
    enabled: bool
    secret: str
    description: Optional[str] = None
    created_at: datetime


class Template(BaseModel):
    """Email template."""
    id: str
    name: str
    subject: str
    html: Optional[str] = None
    text: Optional[str] = None
    variables: List[str]
    created_at: datetime
    updated_at: datetime


class PaginatedResponse(BaseModel):
    """Paginated API response."""
    data: List[Any]
    has_more: bool
    next_cursor: Optional[str] = None
    total: Optional[int] = None
`,
    });

    // Resources init
    files.push({
      path: 'apexmail/resources/__init__.py',
      content: `"""
ApexMail Resources
"""

from .emails import EmailsResource
from .domains import DomainsResource
from .webhooks import WebhooksResource
from .templates import TemplatesResource
from .analytics import AnalyticsResource

__all__ = [
    "EmailsResource",
    "DomainsResource",
    "WebhooksResource",
    "TemplatesResource",
    "AnalyticsResource",
]
`,
    });

    // Emails resource
    files.push({
      path: 'apexmail/resources/emails.py',
      content: `"""
Emails Resource
"""

from typing import Optional, List, Dict, Any, Union
from datetime import datetime

from ..http import HttpClient


class EmailsResource:
    """Resource for managing emails."""
    
    def __init__(self, http: HttpClient, async_mode: bool = False):
        self._http = http
        self._async_mode = async_mode
    
    def send(
        self,
        from_email: Union[str, Dict[str, str]],
        to: List[Union[str, Dict[str, str]]],
        subject: str,
        text: Optional[str] = None,
        html: Optional[str] = None,
        cc: Optional[List[Union[str, Dict[str, str]]]] = None,
        bcc: Optional[List[Union[str, Dict[str, str]]]] = None,
        template_id: Optional[str] = None,
        template_data: Optional[Dict[str, Any]] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
        headers: Optional[Dict[str, str]] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        scheduled_at: Optional[Union[datetime, str]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send an email."""
        body = {
            "from": from_email,
            "to": to,
            "subject": subject,
        }
        
        if text:
            body["text"] = text
        if html:
            body["html"] = html
        if cc:
            body["cc"] = cc
        if bcc:
            body["bcc"] = bcc
        if template_id:
            body["template_id"] = template_id
        if template_data:
            body["template_data"] = template_data
        if attachments:
            body["attachments"] = attachments
        if headers:
            body["headers"] = headers
        if tags:
            body["tags"] = tags
        if metadata:
            body["metadata"] = metadata
        if scheduled_at:
            body["scheduled_at"] = (
                scheduled_at.isoformat()
                if isinstance(scheduled_at, datetime)
                else scheduled_at
            )
        
        return self._http.post("/v1/emails", body, idempotency_key)
    
    def get(self, email_id: str) -> Dict[str, Any]:
        """Get email by ID."""
        return self._http.get(f"/v1/emails/{email_id}")
    
    def list(
        self,
        limit: int = 50,
        cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List emails."""
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        return self._http.get("/v1/emails", params)
    
    def cancel(self, email_id: str) -> Dict[str, Any]:
        """Cancel a scheduled email."""
        return self._http.post(f"/v1/emails/{email_id}/cancel")
    
    def get_events(self, email_id: str) -> List[Dict[str, Any]]:
        """Get email events."""
        return self._http.get(f"/v1/emails/{email_id}/events")


class AsyncEmailsResource(EmailsResource):
    """Async resource for managing emails."""
    
    async def send(self, *args, **kwargs) -> Dict[str, Any]:
        body = self._build_send_body(*args, **kwargs)
        idempotency_key = kwargs.get("idempotency_key")
        return await self._http.apost("/v1/emails", body, idempotency_key)
    
    async def get(self, email_id: str) -> Dict[str, Any]:
        return await self._http.aget(f"/v1/emails/{email_id}")
    
    async def list(self, limit: int = 50, cursor: Optional[str] = None) -> Dict[str, Any]:
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        return await self._http.aget("/v1/emails", params)
    
    async def cancel(self, email_id: str) -> Dict[str, Any]:
        return await self._http.apost(f"/v1/emails/{email_id}/cancel")
    
    async def get_events(self, email_id: str) -> List[Dict[str, Any]]:
        return await self._http.aget(f"/v1/emails/{email_id}/events")
`,
    });

    // Domains resource
    files.push({
      path: 'apexmail/resources/domains.py',
      content: `"""
Domains Resource
"""

from typing import Optional, Dict, Any

from ..http import HttpClient


class DomainsResource:
    """Resource for managing domains."""
    
    def __init__(self, http: HttpClient, async_mode: bool = False):
        self._http = http
        self._async_mode = async_mode
    
    def create(self, domain: str) -> Dict[str, Any]:
        """Add a domain."""
        return self._http.post("/v1/domains", {"domain": domain})
    
    def get(self, domain_id: str) -> Dict[str, Any]:
        """Get domain by ID."""
        return self._http.get(f"/v1/domains/{domain_id}")
    
    def list(self, limit: int = 50, cursor: Optional[str] = None) -> Dict[str, Any]:
        """List domains."""
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        return self._http.get("/v1/domains", params)
    
    def verify(self, domain_id: str) -> Dict[str, Any]:
        """Verify domain."""
        return self._http.post(f"/v1/domains/{domain_id}/verify")
    
    def delete(self, domain_id: str) -> Dict[str, Any]:
        """Delete domain."""
        return self._http.delete(f"/v1/domains/{domain_id}")
`,
    });

    // Webhooks resource
    files.push({
      path: 'apexmail/resources/webhooks.py',
      content: `"""
Webhooks Resource
"""

from typing import Optional, List, Dict, Any

from ..http import HttpClient


class WebhooksResource:
    """Resource for managing webhooks."""
    
    def __init__(self, http: HttpClient, async_mode: bool = False):
        self._http = http
        self._async_mode = async_mode
    
    def create(
        self,
        url: str,
        events: List[str],
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create webhook endpoint."""
        body = {"url": url, "events": events}
        if description:
            body["description"] = description
        return self._http.post("/v1/webhooks", body)
    
    def get(self, webhook_id: str) -> Dict[str, Any]:
        """Get webhook by ID."""
        return self._http.get(f"/v1/webhooks/{webhook_id}")
    
    def list(self, limit: int = 50, cursor: Optional[str] = None) -> Dict[str, Any]:
        """List webhooks."""
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        return self._http.get("/v1/webhooks", params)
    
    def update(
        self,
        webhook_id: str,
        url: Optional[str] = None,
        events: Optional[List[str]] = None,
        description: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Update webhook."""
        body = {}
        if url is not None:
            body["url"] = url
        if events is not None:
            body["events"] = events
        if description is not None:
            body["description"] = description
        if enabled is not None:
            body["enabled"] = enabled
        return self._http.patch(f"/v1/webhooks/{webhook_id}", body)
    
    def delete(self, webhook_id: str) -> Dict[str, Any]:
        """Delete webhook."""
        return self._http.delete(f"/v1/webhooks/{webhook_id}")
    
    def rotate_secret(self, webhook_id: str) -> Dict[str, Any]:
        """Rotate webhook secret."""
        return self._http.post(f"/v1/webhooks/{webhook_id}/rotate-secret")
    
    def test(self, webhook_id: str) -> Dict[str, Any]:
        """Test webhook."""
        return self._http.post(f"/v1/webhooks/{webhook_id}/test")
`,
    });

    // Templates resource
    files.push({
      path: 'apexmail/resources/templates.py',
      content: `"""
Templates Resource
"""

from typing import Optional, Dict, Any

from ..http import HttpClient


class TemplatesResource:
    """Resource for managing templates."""
    
    def __init__(self, http: HttpClient, async_mode: bool = False):
        self._http = http
        self._async_mode = async_mode
    
    def create(
        self,
        name: str,
        subject: str,
        html: Optional[str] = None,
        text: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create template."""
        body = {"name": name, "subject": subject}
        if html:
            body["html"] = html
        if text:
            body["text"] = text
        return self._http.post("/v1/templates", body)
    
    def get(self, template_id: str) -> Dict[str, Any]:
        """Get template by ID."""
        return self._http.get(f"/v1/templates/{template_id}")
    
    def list(self, limit: int = 50, cursor: Optional[str] = None) -> Dict[str, Any]:
        """List templates."""
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        return self._http.get("/v1/templates", params)
    
    def update(
        self,
        template_id: str,
        name: Optional[str] = None,
        subject: Optional[str] = None,
        html: Optional[str] = None,
        text: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update template."""
        body = {}
        if name is not None:
            body["name"] = name
        if subject is not None:
            body["subject"] = subject
        if html is not None:
            body["html"] = html
        if text is not None:
            body["text"] = text
        return self._http.patch(f"/v1/templates/{template_id}", body)
    
    def delete(self, template_id: str) -> Dict[str, Any]:
        """Delete template."""
        return self._http.delete(f"/v1/templates/{template_id}")
    
    def preview(self, template_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Preview template with data."""
        return self._http.post(f"/v1/templates/{template_id}/preview", {"data": data})
`,
    });

    // Analytics resource
    files.push({
      path: 'apexmail/resources/analytics.py',
      content: `"""
Analytics Resource
"""

from typing import Optional, Dict, Any
from datetime import datetime

from ..http import HttpClient


class AnalyticsResource:
    """Resource for analytics."""
    
    def __init__(self, http: HttpClient, async_mode: bool = False):
        self._http = http
        self._async_mode = async_mode
    
    def get_stats(
        self,
        start_date: datetime,
        end_date: datetime,
        group_by: Optional[str] = None,
        domain: Optional[str] = None,
        tag: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get email statistics."""
        params = {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
        }
        if group_by:
            params["group_by"] = group_by
        if domain:
            params["domain"] = domain
        if tag:
            params["tag"] = tag
        if status:
            params["status"] = status
        
        return self._http.get("/v1/analytics/stats", params)
    
    def get_bounce_rate(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> Dict[str, Any]:
        """Get bounce rate."""
        params = {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
        }
        return self._http.get("/v1/analytics/bounces", params)
    
    def get_engagement(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> Dict[str, Any]:
        """Get engagement metrics."""
        params = {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
        }
        return self._http.get("/v1/analytics/engagement", params)
    
    def get_deliverability(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> Dict[str, Any]:
        """Get deliverability report."""
        params = {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
        }
        return self._http.get("/v1/analytics/deliverability", params)
`,
    });

    const readme = `# ApexMail Python SDK

Official Python SDK for the ApexMail API.

## Installation

\`\`\`bash
pip install ${packageName}
\`\`\`

## Quick Start

\`\`\`python
from apexmail import ApexMailClient

client = ApexMailClient("your-api-key")

# Send an email
response = client.emails.send(
    from_email="sender@yourdomain.com",
    to=["recipient@example.com"],
    subject="Hello from ApexMail!",
    html="<h1>Welcome!</h1><p>This is your first email.</p>",
)

print(f"Email sent: {response['id']}")
\`\`\`

## Async Support

\`\`\`python
from apexmail import AsyncApexMailClient

async with AsyncApexMailClient("your-api-key") as client:
    response = await client.emails.send(
        from_email="sender@yourdomain.com",
        to=["recipient@example.com"],
        subject="Hello!",
        html="<h1>Welcome!</h1>",
    )
\`\`\`

## API Version

This SDK uses API version \`${sdkConfig.apiVersion}\`.

## Documentation

Full documentation: ${config.docsBaseUrl}/sdk/python
`;

    const installInstructions = `pip install ${packageName}`;

    return {
      ok: true,
      value: {
        language: 'python',
        version: sdkConfig.version,
        files,
        readme,
        installInstructions,
      },
    };
  }

  // Stub implementations for other languages
  private async generateRubySdk(sdkConfig: SdkConfig): Promise<Result<GeneratedSdk>> {
    const files: SdkFile[] = [];
    const gemName = sdkConfig.packageName ?? 'apexmail';

    files.push({
      path: `${gemName}.gemspec`,
      content: `Gem::Specification.new do |spec|
  spec.name          = "${gemName}"
  spec.version       = "${sdkConfig.version}"
  spec.authors       = ["ApexMail"]
  spec.email         = ["support@apexmail.io"]
  spec.summary       = "ApexMail Ruby SDK"
  spec.description   = "Official Ruby SDK for the ApexMail API"
  spec.homepage      = "https://github.com/apexmail/apexmail-ruby"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 2.7.0"

  spec.files         = Dir["lib/**/*", "LICENSE", "README.md"]
  spec.require_paths = ["lib"]

  spec.add_dependency "faraday", "~> 2.0"
  spec.add_dependency "faraday-retry", "~> 2.0"

  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "webmock", "~> 3.0"
end
`,
    });

    files.push({
      path: 'lib/apexmail.rb',
      content: `# frozen_string_literal: true

require_relative "apexmail/version"
require_relative "apexmail/client"
require_relative "apexmail/resources/emails"
require_relative "apexmail/resources/domains"
require_relative "apexmail/resources/webhooks"
require_relative "apexmail/resources/templates"
require_relative "apexmail/resources/analytics"
require_relative "apexmail/errors"

module ApexMail
  class << self
    attr_accessor :api_key, :api_version

    def configure
      yield self
    end
  end

  @api_version = "${sdkConfig.apiVersion}"
end
`,
    });

    files.push({
      path: 'lib/apexmail/version.rb',
      content: `# frozen_string_literal: true

module ApexMail
  VERSION = "${sdkConfig.version}"
end
`,
    });

    files.push({
      path: 'lib/apexmail/client.rb',
      content: `# frozen_string_literal: true

require "faraday"
require "faraday/retry"
require "json"

module ApexMail
  class Client
    BASE_URL = "${config.apiBaseUrl}"

    attr_reader :emails, :domains, :webhooks, :templates, :analytics

    def initialize(api_key: nil, api_version: nil)
      @api_key = api_key || ApexMail.api_key
      @api_version = api_version || ApexMail.api_version || "${sdkConfig.apiVersion}"

      raise ArgumentError, "API key is required" unless @api_key

      @connection = build_connection

      @emails = Resources::Emails.new(self)
      @domains = Resources::Domains.new(self)
      @webhooks = Resources::Webhooks.new(self)
      @templates = Resources::Templates.new(self)
      @analytics = Resources::Analytics.new(self)
    end

    def request(method, path, params = {}, body = nil)
      response = @connection.public_send(method, path) do |req|
        req.params = params if params.any?
        req.body = body.to_json if body
      end

      parse_response(response)
    end

    private

    def build_connection
      Faraday.new(url: BASE_URL) do |conn|
        conn.request :retry, max: 3, interval: 0.5, backoff_factor: 2
        conn.headers["Authorization"] = "Bearer #{@api_key}"
        conn.headers["Content-Type"] = "application/json"
        conn.headers["X-API-Version"] = @api_version
        conn.headers["User-Agent"] = "apexmail-ruby/#{VERSION}"
        conn.adapter Faraday.default_adapter
      end
    end

    def parse_response(response)
      body = JSON.parse(response.body) rescue {}

      case response.status
      when 200..299
        body
      when 401
        raise AuthenticationError.new(body["message"])
      when 404
        raise NotFoundError.new(body["resource"], body["id"])
      when 422
        raise ValidationError.new(body["message"], body["errors"])
      when 429
        raise RateLimitError.new(body["message"], response.headers["Retry-After"]&.to_i)
      when 500..599
        raise ServerError.new(body["message"])
      else
        raise ApexMailError.new(body["message"], body["code"], response.status)
      end
    end
  end
end
`,
    });

    const readme = `# ApexMail Ruby SDK

Official Ruby SDK for the ApexMail API.

## Installation

\`\`\`ruby
gem '${gemName}'
\`\`\`

Or install directly:

\`\`\`bash
gem install ${gemName}
\`\`\`

## Quick Start

\`\`\`ruby
require 'apexmail'

client = ApexMail::Client.new(api_key: 'your-api-key')

response = client.emails.send(
  from: 'sender@yourdomain.com',
  to: ['recipient@example.com'],
  subject: 'Hello from ApexMail!',
  html: '<h1>Welcome!</h1>'
)

puts "Email sent: #{response['id']}"
\`\`\`
`;

    return {
      ok: true,
      value: {
        language: 'ruby',
        version: sdkConfig.version,
        files,
        readme,
        installInstructions: `gem install ${gemName}`,
      },
    };
  }

  private async generateGoSdk(sdkConfig: SdkConfig): Promise<Result<GeneratedSdk>> {
    const moduleName = sdkConfig.packageName ?? 'github.com/apexmail/apexmail-go';
    const files: SdkFile[] = [];

    files.push({
      path: 'go.mod',
      content: `module ${moduleName}

go 1.21

require (
	github.com/google/uuid v1.5.0
)
`,
    });

    files.push({
      path: 'apexmail.go',
      content: `// Package apexmail provides a client for the ApexMail API.
package apexmail

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultBaseURL   = "${config.apiBaseUrl}"
	defaultAPIVersion = "${sdkConfig.apiVersion}"
	defaultTimeout   = 30 * time.Second
)

// Client is the ApexMail API client.
type Client struct {
	apiKey     string
	baseURL    string
	apiVersion string
	httpClient *http.Client

	Emails    *EmailsService
	Domains   *DomainsService
	Webhooks  *WebhooksService
	Templates *TemplatesService
	Analytics *AnalyticsService
}

// ClientOption is a function that configures the client.
type ClientOption func(*Client)

// WithBaseURL sets the base URL for the client.
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = url
	}
}

// WithAPIVersion sets the API version for the client.
func WithAPIVersion(version string) ClientOption {
	return func(c *Client) {
		c.apiVersion = version
	}
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// NewClient creates a new ApexMail API client.
func NewClient(apiKey string, opts ...ClientOption) *Client {
	c := &Client{
		apiKey:     apiKey,
		baseURL:    defaultBaseURL,
		apiVersion: defaultAPIVersion,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}

	for _, opt := range opts {
		opt(c)
	}

	c.Emails = &EmailsService{client: c}
	c.Domains = &DomainsService{client: c}
	c.Webhooks = &WebhooksService{client: c}
	c.Templates = &TemplatesService{client: c}
	c.Analytics = &AnalyticsService{client: c}

	return c
}

func (c *Client) request(method, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Version", c.apiVersion)
	req.Header.Set("User-Agent", "apexmail-go/${sdkConfig.version}")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiErr APIError
		if err := json.Unmarshal(respBody, &apiErr); err != nil {
			return fmt.Errorf("API error: %d", resp.StatusCode)
		}
		apiErr.StatusCode = resp.StatusCode
		return &apiErr
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}

	return nil
}
`,
    });

    files.push({
      path: 'emails.go',
      content: `package apexmail

import "time"

// EmailsService handles email operations.
type EmailsService struct {
	client *Client
}

// Email represents an email message.
type Email struct {
	ID          string            \`json:"id"\`
	From        EmailAddress      \`json:"from"\`
	To          []EmailAddress    \`json:"to"\`
	CC          []EmailAddress    \`json:"cc,omitempty"\`
	BCC         []EmailAddress    \`json:"bcc,omitempty"\`
	Subject     string            \`json:"subject"\`
	Text        string            \`json:"text,omitempty"\`
	HTML        string            \`json:"html,omitempty"\`
	TemplateID  string            \`json:"template_id,omitempty"\`
	TemplateData map[string]interface{} \`json:"template_data,omitempty"\`
	Tags        []string          \`json:"tags,omitempty"\`
	Metadata    map[string]interface{} \`json:"metadata,omitempty"\`
	ScheduledAt *time.Time        \`json:"scheduled_at,omitempty"\`
	CreatedAt   time.Time         \`json:"created_at"\`
	Status      string            \`json:"status"\`
}

// EmailAddress represents an email address with optional name.
type EmailAddress struct {
	Email string \`json:"email"\`
	Name  string \`json:"name,omitempty"\`
}

// SendEmailRequest represents a request to send an email.
type SendEmailRequest struct {
	From        interface{}       \`json:"from"\`
	To          []interface{}     \`json:"to"\`
	CC          []interface{}     \`json:"cc,omitempty"\`
	BCC         []interface{}     \`json:"bcc,omitempty"\`
	Subject     string            \`json:"subject"\`
	Text        string            \`json:"text,omitempty"\`
	HTML        string            \`json:"html,omitempty"\`
	TemplateID  string            \`json:"template_id,omitempty"\`
	TemplateData map[string]interface{} \`json:"template_data,omitempty"\`
	Tags        []string          \`json:"tags,omitempty"\`
	Metadata    map[string]interface{} \`json:"metadata,omitempty"\`
	ScheduledAt *time.Time        \`json:"scheduled_at,omitempty"\`
}

// SendEmailResponse represents a response from sending an email.
type SendEmailResponse struct {
	ID      string \`json:"id"\`
	Status  string \`json:"status"\`
	Message string \`json:"message"\`
}

// Send sends an email.
func (s *EmailsService) Send(req *SendEmailRequest) (*SendEmailResponse, error) {
	var resp SendEmailResponse
	err := s.client.request("POST", "/v1/emails", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Get retrieves an email by ID.
func (s *EmailsService) Get(emailID string) (*Email, error) {
	var email Email
	err := s.client.request("GET", "/v1/emails/"+emailID, nil, &email)
	if err != nil {
		return nil, err
	}
	return &email, nil
}

// Cancel cancels a scheduled email.
func (s *EmailsService) Cancel(emailID string) error {
	return s.client.request("POST", "/v1/emails/"+emailID+"/cancel", nil, nil)
}
`,
    });

    const readme = `# ApexMail Go SDK

Official Go SDK for the ApexMail API.

## Installation

\`\`\`bash
go get ${moduleName}
\`\`\`

## Quick Start

\`\`\`go
package main

import (
	"fmt"
	"log"

	"${moduleName}"
)

func main() {
	client := apexmail.NewClient("your-api-key")

	resp, err := client.Emails.Send(&apexmail.SendEmailRequest{
		From:    "sender@yourdomain.com",
		To:      []interface{}{"recipient@example.com"},
		Subject: "Hello from ApexMail!",
		HTML:    "<h1>Welcome!</h1>",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Email sent: %s\\n", resp.ID)
}
\`\`\`
`;

    return {
      ok: true,
      value: {
        language: 'go',
        version: sdkConfig.version,
        files,
        readme,
        installInstructions: `go get ${moduleName}`,
      },
    };
  }

  private async generatePhpSdk(sdkConfig: SdkConfig): Promise<Result<GeneratedSdk>> {
    const packageName = sdkConfig.packageName ?? 'apexmail/apexmail-php';
    const files: SdkFile[] = [];

    files.push({
      path: 'composer.json',
      content: JSON.stringify({
        name: packageName,
        description: 'ApexMail PHP SDK',
        type: 'library',
        license: 'MIT',
        autoload: {
          'psr-4': {
            'ApexMail\\\\': 'src/',
          },
        },
        require: {
          php: '>=8.1',
          'guzzlehttp/guzzle': '^7.0',
        },
        'require-dev': {
          phpunit: '^10.0',
        },
      }, null, 2),
    });

    files.push({
      path: 'src/ApexMailClient.php',
      content: `<?php

namespace ApexMail;

use GuzzleHttp\\Client;
use GuzzleHttp\\Exception\\RequestException;

class ApexMailClient
{
    private const BASE_URL = '${config.apiBaseUrl}';
    private const API_VERSION = '${sdkConfig.apiVersion}';

    private Client $http;
    private string $apiKey;
    private string $apiVersion;

    public Emails $emails;
    public Domains $domains;
    public Webhooks $webhooks;
    public Templates $templates;
    public Analytics $analytics;

    public function __construct(string $apiKey, array $options = [])
    {
        $this->apiKey = $apiKey;
        $this->apiVersion = $options['api_version'] ?? self::API_VERSION;

        $this->http = new Client([
            'base_uri' => $options['base_url'] ?? self::BASE_URL,
            'timeout' => $options['timeout'] ?? 30,
            'headers' => [
                'Authorization' => 'Bearer ' . $this->apiKey,
                'Content-Type' => 'application/json',
                'X-API-Version' => $this->apiVersion,
                'User-Agent' => 'apexmail-php/${sdkConfig.version}',
            ],
        ]);

        $this->emails = new Emails($this);
        $this->domains = new Domains($this);
        $this->webhooks = new Webhooks($this);
        $this->templates = new Templates($this);
        $this->analytics = new Analytics($this);
    }

    public function request(string $method, string $path, array $body = []): array
    {
        try {
            $options = [];
            if (!empty($body)) {
                $options['json'] = $body;
            }

            $response = $this->http->request($method, $path, $options);
            return json_decode($response->getBody()->getContents(), true);
        } catch (RequestException $e) {
            $response = $e->getResponse();
            $body = json_decode($response?->getBody()->getContents() ?? '{}', true);
            
            throw match($response?->getStatusCode()) {
                401 => new AuthenticationException($body['message'] ?? 'Authentication failed'),
                404 => new NotFoundException($body['resource'] ?? 'Resource', $body['id'] ?? 'unknown'),
                422 => new ValidationException($body['message'] ?? 'Validation failed', $body['errors'] ?? []),
                429 => new RateLimitException($body['message'] ?? 'Rate limit exceeded'),
                default => new ApexMailException($body['message'] ?? 'Unknown error', $response?->getStatusCode() ?? 500),
            };
        }
    }
}
`,
    });

    const readme = `# ApexMail PHP SDK

Official PHP SDK for the ApexMail API.

## Installation

\`\`\`bash
composer require ${packageName}
\`\`\`

## Quick Start

\`\`\`php
<?php

require_once 'vendor/autoload.php';

use ApexMail\\ApexMailClient;

$client = new ApexMailClient('your-api-key');

$response = $client->emails->send([
    'from' => 'sender@yourdomain.com',
    'to' => ['recipient@example.com'],
    'subject' => 'Hello from ApexMail!',
    'html' => '<h1>Welcome!</h1>',
]);

echo "Email sent: " . $response['id'];
\`\`\`
`;

    return {
      ok: true,
      value: {
        language: 'php',
        version: sdkConfig.version,
        files,
        readme,
        installInstructions: `composer require ${packageName}`,
      },
    };
  }

  private async generateJavaSdk(sdkConfig: SdkConfig): Promise<Result<GeneratedSdk>> {
    const files: SdkFile[] = [];
    const groupId = 'io.apexmail';
    const artifactId = sdkConfig.packageName ?? 'apexmail-java';

    files.push({
      path: 'pom.xml',
      content: `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>${groupId}</groupId>
    <artifactId>${artifactId}</artifactId>
    <version>${sdkConfig.version}</version>
    <packaging>jar</packaging>

    <name>ApexMail Java SDK</name>
    <description>Official Java SDK for the ApexMail API</description>

    <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <dependency>
            <groupId>com.google.code.gson</groupId>
            <artifactId>gson</artifactId>
            <version>2.10.1</version>
        </dependency>
        <dependency>
            <groupId>com.squareup.okhttp3</groupId>
            <artifactId>okhttp</artifactId>
            <version>4.12.0</version>
        </dependency>
    </dependencies>
</project>
`,
    });

    files.push({
      path: 'src/main/java/io/apexmail/ApexMailClient.java',
      content: `package io.apexmail;

import io.apexmail.resources.*;
import okhttp3.*;
import com.google.gson.Gson;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

public class ApexMailClient {
    private static final String DEFAULT_BASE_URL = "${config.apiBaseUrl}";
    private static final String DEFAULT_API_VERSION = "${sdkConfig.apiVersion}";

    private final OkHttpClient httpClient;
    private final String baseUrl;
    private final String apiKey;
    private final String apiVersion;
    private final Gson gson;

    public final Emails emails;
    public final Domains domains;
    public final Webhooks webhooks;
    public final Templates templates;
    public final Analytics analytics;

    public ApexMailClient(String apiKey) {
        this(apiKey, DEFAULT_BASE_URL, DEFAULT_API_VERSION);
    }

    public ApexMailClient(String apiKey, String baseUrl, String apiVersion) {
        this.apiKey = apiKey;
        this.baseUrl = baseUrl;
        this.apiVersion = apiVersion;
        this.gson = new Gson();

        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .addInterceptor(chain -> {
                Request original = chain.request();
                Request request = original.newBuilder()
                    .header("Authorization", "Bearer " + apiKey)
                    .header("Content-Type", "application/json")
                    .header("X-API-Version", apiVersion)
                    .header("User-Agent", "apexmail-java/${sdkConfig.version}")
                    .method(original.method(), original.body())
                    .build();
                return chain.proceed(request);
            })
            .build();

        this.emails = new Emails(this);
        this.domains = new Domains(this);
        this.webhooks = new Webhooks(this);
        this.templates = new Templates(this);
        this.analytics = new Analytics(this);
    }

    public <T> T request(String method, String path, Object body, Class<T> responseType) throws ApexMailException {
        Request.Builder requestBuilder = new Request.Builder()
            .url(baseUrl + path);

        if (body != null) {
            RequestBody requestBody = RequestBody.create(
                gson.toJson(body),
                MediaType.parse("application/json")
            );
            requestBuilder.method(method, requestBody);
        } else if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
            requestBuilder.method(method, RequestBody.create("", null));
        } else {
            requestBuilder.method(method, null);
        }

        try (Response response = httpClient.newCall(requestBuilder.build()).execute()) {
            String responseBody = response.body() != null ? response.body().string() : "";

            if (!response.isSuccessful()) {
                throw new ApexMailException("API error: " + response.code(), response.code());
            }

            return gson.fromJson(responseBody, responseType);
        } catch (IOException e) {
            throw new ApexMailException("Request failed: " + e.getMessage(), 0);
        }
    }
}
`,
    });

    const readme = `# ApexMail Java SDK

Official Java SDK for the ApexMail API.

## Installation

### Maven

\`\`\`xml
<dependency>
    <groupId>${groupId}</groupId>
    <artifactId>${artifactId}</artifactId>
    <version>${sdkConfig.version}</version>
</dependency>
\`\`\`

### Gradle

\`\`\`groovy
implementation '${groupId}:${artifactId}:${sdkConfig.version}'
\`\`\`

## Quick Start

\`\`\`java
import io.apexmail.ApexMailClient;
import io.apexmail.models.SendEmailRequest;
import io.apexmail.models.SendEmailResponse;
import java.util.List;

public class Example {
    public static void main(String[] args) {
        ApexMailClient client = new ApexMailClient("your-api-key");

        SendEmailRequest request = new SendEmailRequest()
            .from("sender@yourdomain.com")
            .to(List.of("recipient@example.com"))
            .subject("Hello from ApexMail!")
            .html("<h1>Welcome!</h1>");

        SendEmailResponse response = client.emails.send(request);
        System.out.println("Email sent: " + response.getId());
    }
}
\`\`\`
`;

    return {
      ok: true,
      value: {
        language: 'java',
        version: sdkConfig.version,
        files,
        readme,
        installInstructions: `<!-- Maven -->
<dependency>
    <groupId>${groupId}</groupId>
    <artifactId>${artifactId}</artifactId>
    <version>${sdkConfig.version}</version>
</dependency>`,
      },
    };
  }

  private async generateCSharpSdk(sdkConfig: SdkConfig): Promise<Result<GeneratedSdk>> {
    const packageName = sdkConfig.packageName ?? 'ApexMail';
    const files: SdkFile[] = [];

    files.push({
      path: `${packageName}/${packageName}.csproj`,
      content: `<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <Version>${sdkConfig.version}</Version>
    <PackageId>${packageName}</PackageId>
    <Authors>ApexMail</Authors>
    <Company>ApexMail</Company>
    <Description>Official .NET SDK for the ApexMail API</Description>
    <PackageLicenseExpression>MIT</PackageLicenseExpression>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="System.Text.Json" Version="8.0.0" />
  </ItemGroup>

</Project>
`,
    });

    files.push({
      path: `${packageName}/ApexMailClient.cs`,
      content: `using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace ${packageName};

public class ApexMailClient : IDisposable
{
    private const string DefaultBaseUrl = "${config.apiBaseUrl}";
    private const string DefaultApiVersion = "${sdkConfig.apiVersion}";

    private readonly HttpClient _httpClient;
    private readonly JsonSerializerOptions _jsonOptions;

    public EmailsService Emails { get; }
    public DomainsService Domains { get; }
    public WebhooksService Webhooks { get; }
    public TemplatesService Templates { get; }
    public AnalyticsService Analytics { get; }

    public ApexMailClient(string apiKey, string? baseUrl = null, string? apiVersion = null)
    {
        _httpClient = new HttpClient
        {
            BaseAddress = new Uri(baseUrl ?? DefaultBaseUrl),
            Timeout = TimeSpan.FromSeconds(30)
        };

        _httpClient.DefaultRequestHeaders.Authorization = 
            new AuthenticationHeaderValue("Bearer", apiKey);
        _httpClient.DefaultRequestHeaders.Add("X-API-Version", apiVersion ?? DefaultApiVersion);
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("apexmail-dotnet/${sdkConfig.version}");

        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            WriteIndented = false
        };

        Emails = new EmailsService(this);
        Domains = new DomainsService(this);
        Webhooks = new WebhooksService(this);
        Templates = new TemplatesService(this);
        Analytics = new AnalyticsService(this);
    }

    public async Task<T> RequestAsync<T>(
        HttpMethod method,
        string path,
        object? body = null,
        CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(method, path);

        if (body != null)
        {
            var json = JsonSerializer.Serialize(body, _jsonOptions);
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
        }

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new ApexMailException(
                $"API error: {response.StatusCode}",
                (int)response.StatusCode);
        }

        return JsonSerializer.Deserialize<T>(responseBody, _jsonOptions)!;
    }

    public void Dispose()
    {
        _httpClient.Dispose();
        GC.SuppressFinalize(this);
    }
}
`,
    });

    const readme = `# ApexMail .NET SDK

Official .NET SDK for the ApexMail API.

## Installation

\`\`\`bash
dotnet add package ${packageName}
\`\`\`

Or via NuGet Package Manager:

\`\`\`
Install-Package ${packageName}
\`\`\`

## Quick Start

\`\`\`csharp
using ${packageName};

var client = new ApexMailClient("your-api-key");

var response = await client.Emails.SendAsync(new SendEmailRequest
{
    From = "sender@yourdomain.com",
    To = new[] { "recipient@example.com" },
    Subject = "Hello from ApexMail!",
    Html = "<h1>Welcome!</h1>"
});

Console.WriteLine($"Email sent: {response.Id}");
\`\`\`
`;

    return {
      ok: true,
      value: {
        language: 'csharp',
        version: sdkConfig.version,
        files,
        readme,
        installInstructions: `dotnet add package ${packageName}`,
      },
    };
  }

  /**
   * Get all available SDK languages
   */
  getAvailableLanguages(): SdkLanguage[] {
    return ['typescript', 'python', 'ruby', 'go', 'php', 'java', 'csharp'];
  }
}
