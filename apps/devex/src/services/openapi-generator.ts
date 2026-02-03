/**
 * OpenAPI Specification Generator
 * 
 * Generates OpenAPI 3.1 specification for the ApexMail API
 */

import type { Pool } from 'pg';
import { config } from '../config.js';

export interface OpenApiSpec {
  openapi: string;
  info: OpenApiInfo;
  servers: OpenApiServer[];
  security: OpenApiSecurityRequirement[];
  paths: Record<string, OpenApiPathItem>;
  components: OpenApiComponents;
  tags: OpenApiTag[];
  externalDocs?: OpenApiExternalDocs;
}

export interface OpenApiInfo {
  title: string;
  version: string;
  description: string;
  termsOfService?: string;
  contact?: {
    name?: string;
    url?: string;
    email?: string;
  };
  license?: {
    name: string;
    url?: string;
  };
}

export interface OpenApiServer {
  url: string;
  description: string;
  variables?: Record<string, OpenApiServerVariable>;
}

export interface OpenApiServerVariable {
  default: string;
  description?: string;
  enum?: string[];
}

export interface OpenApiSecurityRequirement {
  [name: string]: string[];
}

export interface OpenApiPathItem {
  summary?: string;
  description?: string;
  get?: OpenApiOperation;
  post?: OpenApiOperation;
  put?: OpenApiOperation;
  patch?: OpenApiOperation;
  delete?: OpenApiOperation;
  parameters?: OpenApiParameter[];
}

export interface OpenApiOperation {
  operationId: string;
  summary: string;
  description: string;
  tags: string[];
  security?: OpenApiSecurityRequirement[];
  parameters?: OpenApiParameter[];
  requestBody?: OpenApiRequestBody;
  responses: Record<string, OpenApiResponse>;
  deprecated?: boolean;
}

export interface OpenApiParameter {
  name?: string;
  in?: 'path' | 'query' | 'header' | 'cookie';
  description?: string;
  required?: boolean;
  schema?: OpenApiSchema;
  example?: unknown;
  $ref?: string;
}

export interface OpenApiRequestBody {
  description?: string;
  required: boolean;
  content: Record<string, OpenApiMediaType>;
}

export interface OpenApiMediaType {
  schema: OpenApiSchema;
  example?: unknown;
  examples?: Record<string, OpenApiExample>;
}

export interface OpenApiResponse {
  description?: string;
  headers?: Record<string, OpenApiHeader>;
  content?: Record<string, OpenApiMediaType>;
  $ref?: string;
}

export interface OpenApiHeader {
  description: string;
  schema: OpenApiSchema;
}

export interface OpenApiSchema {
  type?: string;
  format?: string;
  description?: string;
  enum?: unknown[];
  items?: OpenApiSchema;
  properties?: Record<string, OpenApiSchema>;
  required?: string[];
  additionalProperties?: boolean | OpenApiSchema;
  $ref?: string;
  allOf?: OpenApiSchema[];
  anyOf?: OpenApiSchema[];
  oneOf?: OpenApiSchema[];
  nullable?: boolean;
  default?: unknown;
  example?: unknown;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  minItems?: number;
  maxItems?: number;
  pattern?: string;
}

export interface OpenApiExample {
  summary?: string;
  description?: string;
  value: unknown;
}

export interface OpenApiComponents {
  schemas: Record<string, OpenApiSchema>;
  securitySchemes: Record<string, OpenApiSecurityScheme>;
  parameters?: Record<string, OpenApiParameter>;
  responses?: Record<string, OpenApiResponse>;
  requestBodies?: Record<string, OpenApiRequestBody>;
  headers?: Record<string, OpenApiHeader>;
  examples?: Record<string, OpenApiExample>;
}

export interface OpenApiSecurityScheme {
  type: 'apiKey' | 'http' | 'oauth2' | 'openIdConnect';
  description?: string;
  name?: string;
  in?: 'header' | 'query' | 'cookie';
  scheme?: string;
  bearerFormat?: string;
  flows?: OpenApiOAuthFlows;
  openIdConnectUrl?: string;
}

export interface OpenApiOAuthFlows {
  implicit?: OpenApiOAuthFlow;
  password?: OpenApiOAuthFlow;
  clientCredentials?: OpenApiOAuthFlow;
  authorizationCode?: OpenApiOAuthFlow;
}

export interface OpenApiOAuthFlow {
  authorizationUrl?: string;
  tokenUrl?: string;
  refreshUrl?: string;
  scopes: Record<string, string>;
}

export interface OpenApiTag {
  name: string;
  description: string;
  externalDocs?: OpenApiExternalDocs;
}

export interface OpenApiExternalDocs {
  description?: string;
  url: string;
}

type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export class OpenApiGenerator {
  protected db: Pool;
  private version: string;

  constructor(db: Pool, version: string = config.currentApiVersion) {
    this.db = db;
    this.version = version;
  }

  /**
   * Generate complete OpenAPI specification
   */
  async generateSpec(): Promise<Result<OpenApiSpec>> {
    try {
      const spec: OpenApiSpec = {
        openapi: '3.1.0',
        info: this.generateInfo(),
        servers: this.generateServers(),
        security: [{ BearerAuth: [] }, { ApiKeyAuth: [] }],
        paths: this.generatePaths(),
        components: this.generateComponents(),
        tags: this.generateTags(),
        externalDocs: {
          description: 'Full API Documentation',
          url: 'https://docs.apexmail.ee',
        },
      };

      return { ok: true, value: spec };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  private generateInfo(): OpenApiInfo {
    return {
      title: 'ApexMail API',
      version: this.version,
      description: `
# ApexMail API

ApexMail provides a powerful email API for sending transactional emails at scale.

## Authentication

All API requests require authentication using either:
- **Bearer Token**: Include in the Authorization header as \`Bearer <api_key>\`
- **API Key Header**: Include in the \`X-API-Key\` header

## Rate Limiting

API requests are rate limited based on your plan:
- **Free**: 100 requests/minute
- **Starter**: 1,000 requests/minute
- **Growth**: 5,000 requests/minute
- **Scale**: 10,000 requests/minute
- **Enterprise**: Unlimited

Rate limit headers are included in all responses:
- \`X-RateLimit-Limit\`: Maximum requests per window
- \`X-RateLimit-Remaining\`: Remaining requests in current window
- \`X-RateLimit-Reset\`: Unix timestamp when the window resets

## Versioning

The API version is specified in the URL path (e.g., \`/v1/\`). You can also use the \`X-API-Version\` header for date-based versioning.

Current version: ${this.version}

## Idempotency

For POST requests, you can include an \`Idempotency-Key\` header to ensure idempotent operations. The same key will return the same response for 24 hours.
      `.trim(),
      termsOfService: 'https://apexmail.ee/terms',
      contact: {
        name: 'ApexMail Support',
        url: 'https://apexmail.ee/support',
        email: 'contact@apexmail.ee',
      },
      license: {
        name: 'Proprietary',
        url: 'https://apexmail.ee/license',
      },
    };
  }

  private generateServers(): OpenApiServer[] {
    return [
      {
        url: 'https://api.apexmail.ee/v1',
        description: 'Production API',
      },
      {
        url: 'https://sandbox.apexmail.ee/v1',
        description: 'Sandbox API (for testing)',
      },
      {
        url: '{protocol}://{host}/v1',
        description: 'Custom server',
        variables: {
          protocol: { default: 'https', enum: ['https', 'http'] },
          host: { default: 'api.apexmail.ee' },
        },
      },
    ];
  }

  private generatePaths(): Record<string, OpenApiPathItem> {
    return {
      // Email endpoints
      '/emails': {
        post: {
          operationId: 'sendEmail',
          summary: 'Send an email',
          description: 'Send a transactional email to one or more recipients.',
          tags: ['Emails'],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SendEmailRequest' },
                examples: {
                  simple: {
                    summary: 'Simple email',
                    value: {
                      from: { email: 'sender@example.com', name: 'Sender Name' },
                      to: [{ email: 'recipient@example.com', name: 'Recipient' }],
                      subject: 'Hello World',
                      text: 'This is a test email.',
                    },
                  },
                  html: {
                    summary: 'HTML email with template',
                    value: {
                      from: { email: 'sender@example.com', name: 'Sender Name' },
                      to: [{ email: 'recipient@example.com' }],
                      subject: 'Welcome to ApexMail',
                      html: '<h1>Welcome!</h1><p>Thanks for signing up.</p>',
                      tags: ['welcome', 'onboarding'],
                    },
                  },
                  template: {
                    summary: 'Template-based email',
                    value: {
                      from: { email: 'sender@example.com' },
                      to: [{ email: 'recipient@example.com' }],
                      templateId: 'tpl_welcome_email',
                      templateData: { name: 'John', company: 'Acme Inc' },
                    },
                  },
                },
              },
            },
          },
          responses: {
            '200': {
              description: 'Email queued successfully',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/SendEmailResponse' },
                },
              },
            },
            '400': { $ref: '#/components/responses/BadRequest' },
            '401': { $ref: '#/components/responses/Unauthorized' },
            '429': { $ref: '#/components/responses/RateLimited' },
          },
        },
        get: {
          operationId: 'listEmails',
          summary: 'List emails',
          description: 'Retrieve a list of sent emails with optional filters.',
          tags: ['Emails'],
          parameters: [
            { $ref: '#/components/parameters/PageSize' },
            { $ref: '#/components/parameters/PageCursor' },
            {
              name: 'status',
              in: 'query',
              description: 'Filter by email status',
              required: false,
              schema: { type: 'string', enum: ['queued', 'sent', 'delivered', 'bounced', 'failed'] },
            },
            {
              name: 'from',
              in: 'query',
              description: 'Filter by sender email',
              required: false,
              schema: { type: 'string', format: 'email' },
            },
            {
              name: 'to',
              in: 'query',
              description: 'Filter by recipient email',
              required: false,
              schema: { type: 'string', format: 'email' },
            },
            {
              name: 'startDate',
              in: 'query',
              description: 'Filter emails sent after this date',
              required: false,
              schema: { type: 'string', format: 'date-time' },
            },
            {
              name: 'endDate',
              in: 'query',
              description: 'Filter emails sent before this date',
              required: false,
              schema: { type: 'string', format: 'date-time' },
            },
          ],
          responses: {
            '200': {
              description: 'List of emails',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/EmailList' },
                },
              },
            },
            '401': { $ref: '#/components/responses/Unauthorized' },
          },
        },
      },
      '/emails/{emailId}': {
        parameters: [
          {
            name: 'emailId',
            in: 'path',
            description: 'The email ID',
            required: true,
            schema: { type: 'string', pattern: '^msg_[a-zA-Z0-9]+$' },
          },
        ],
        get: {
          operationId: 'getEmail',
          summary: 'Get email details',
          description: 'Retrieve detailed information about a specific email.',
          tags: ['Emails'],
          responses: {
            '200': {
              description: 'Email details',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Email' },
                },
              },
            },
            '404': { $ref: '#/components/responses/NotFound' },
          },
        },
      },
      '/emails/{emailId}/events': {
        parameters: [
          {
            name: 'emailId',
            in: 'path',
            description: 'The email ID',
            required: true,
            schema: { type: 'string' },
          },
        ],
        get: {
          operationId: 'getEmailEvents',
          summary: 'Get email events',
          description: 'Retrieve delivery events for a specific email.',
          tags: ['Emails'],
          responses: {
            '200': {
              description: 'Email events',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/EmailEventList' },
                },
              },
            },
          },
        },
      },
      '/emails/{emailId}/cancel': {
        parameters: [
          {
            name: 'emailId',
            in: 'path',
            description: 'The email ID',
            required: true,
            schema: { type: 'string' },
          },
        ],
        post: {
          operationId: 'cancelEmail',
          summary: 'Cancel scheduled email',
          description: 'Cancel a scheduled email that has not yet been sent.',
          tags: ['Emails'],
          responses: {
            '200': {
              description: 'Email cancelled',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Email' },
                },
              },
            },
            '400': {
              description: 'Email cannot be cancelled',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Error' },
                },
              },
            },
          },
        },
      },

      // Batch endpoints
      '/batch': {
        post: {
          operationId: 'sendBatch',
          summary: 'Send batch emails',
          description: 'Send multiple emails in a single request (up to 1000).',
          tags: ['Batch'],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/BatchSendRequest' },
              },
            },
          },
          responses: {
            '200': {
              description: 'Batch queued',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/BatchSendResponse' },
                },
              },
            },
          },
        },
      },
      '/batch/{batchId}': {
        parameters: [
          {
            name: 'batchId',
            in: 'path',
            description: 'The batch ID',
            required: true,
            schema: { type: 'string' },
          },
        ],
        get: {
          operationId: 'getBatch',
          summary: 'Get batch status',
          description: 'Retrieve the status of a batch send operation.',
          tags: ['Batch'],
          responses: {
            '200': {
              description: 'Batch status',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Batch' },
                },
              },
            },
          },
        },
      },

      // Domain endpoints
      '/domains': {
        post: {
          operationId: 'addDomain',
          summary: 'Add a domain',
          description: 'Add a new sending domain to your account.',
          tags: ['Domains'],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AddDomainRequest' },
              },
            },
          },
          responses: {
            '201': {
              description: 'Domain added',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Domain' },
                },
              },
            },
          },
        },
        get: {
          operationId: 'listDomains',
          summary: 'List domains',
          description: 'Retrieve all sending domains for your account.',
          tags: ['Domains'],
          responses: {
            '200': {
              description: 'List of domains',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/DomainList' },
                },
              },
            },
          },
        },
      },
      '/domains/{domainId}': {
        parameters: [
          {
            name: 'domainId',
            in: 'path',
            description: 'The domain ID',
            required: true,
            schema: { type: 'string' },
          },
        ],
        get: {
          operationId: 'getDomain',
          summary: 'Get domain',
          description: 'Retrieve details of a specific domain.',
          tags: ['Domains'],
          responses: {
            '200': {
              description: 'Domain details',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Domain' },
                },
              },
            },
          },
        },
        delete: {
          operationId: 'deleteDomain',
          summary: 'Delete domain',
          description: 'Remove a domain from your account.',
          tags: ['Domains'],
          responses: {
            '204': { description: 'Domain deleted' },
          },
        },
      },
      '/domains/{domainId}/verify': {
        parameters: [
          {
            name: 'domainId',
            in: 'path',
            description: 'The domain ID',
            required: true,
            schema: { type: 'string' },
          },
        ],
        post: {
          operationId: 'verifyDomain',
          summary: 'Verify domain',
          description: 'Trigger DNS verification for a domain.',
          tags: ['Domains'],
          responses: {
            '200': {
              description: 'Verification status',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/DomainVerification' },
                },
              },
            },
          },
        },
      },

      // Template endpoints
      '/templates': {
        post: {
          operationId: 'createTemplate',
          summary: 'Create template',
          description: 'Create a new email template.',
          tags: ['Templates'],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/CreateTemplateRequest' },
              },
            },
          },
          responses: {
            '201': {
              description: 'Template created',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Template' },
                },
              },
            },
          },
        },
        get: {
          operationId: 'listTemplates',
          summary: 'List templates',
          description: 'Retrieve all email templates.',
          tags: ['Templates'],
          responses: {
            '200': {
              description: 'List of templates',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/TemplateList' },
                },
              },
            },
          },
        },
      },
      '/templates/{templateId}': {
        parameters: [
          {
            name: 'templateId',
            in: 'path',
            description: 'The template ID',
            required: true,
            schema: { type: 'string' },
          },
        ],
        get: {
          operationId: 'getTemplate',
          summary: 'Get template',
          description: 'Retrieve a specific template.',
          tags: ['Templates'],
          responses: {
            '200': {
              description: 'Template details',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Template' },
                },
              },
            },
          },
        },
        patch: {
          operationId: 'updateTemplate',
          summary: 'Update template',
          description: 'Update an existing template.',
          tags: ['Templates'],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/UpdateTemplateRequest' },
              },
            },
          },
          responses: {
            '200': {
              description: 'Template updated',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Template' },
                },
              },
            },
          },
        },
        delete: {
          operationId: 'deleteTemplate',
          summary: 'Delete template',
          description: 'Delete a template.',
          tags: ['Templates'],
          responses: {
            '204': { description: 'Template deleted' },
          },
        },
      },
      '/templates/{templateId}/render': {
        parameters: [
          {
            name: 'templateId',
            in: 'path',
            description: 'The template ID',
            required: true,
            schema: { type: 'string' },
          },
        ],
        post: {
          operationId: 'renderTemplate',
          summary: 'Render template',
          description: 'Render a template with sample data.',
          tags: ['Templates'],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    data: {
                      type: 'object',
                      additionalProperties: true,
                      description: 'Template variables',
                    },
                  },
                  required: ['data'],
                },
              },
            },
          },
          responses: {
            '200': {
              description: 'Rendered template',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/RenderedTemplate' },
                },
              },
            },
          },
        },
      },

      // Webhook endpoints
      '/webhooks': {
        post: {
          operationId: 'createWebhook',
          summary: 'Create webhook',
          description: 'Create a new webhook endpoint.',
          tags: ['Webhooks'],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/CreateWebhookRequest' },
              },
            },
          },
          responses: {
            '201': {
              description: 'Webhook created',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Webhook' },
                },
              },
            },
          },
        },
        get: {
          operationId: 'listWebhooks',
          summary: 'List webhooks',
          description: 'Retrieve all webhook endpoints.',
          tags: ['Webhooks'],
          responses: {
            '200': {
              description: 'List of webhooks',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/WebhookList' },
                },
              },
            },
          },
        },
      },
      '/webhooks/{webhookId}': {
        parameters: [
          {
            name: 'webhookId',
            in: 'path',
            description: 'The webhook ID',
            required: true,
            schema: { type: 'string' },
          },
        ],
        get: {
          operationId: 'getWebhook',
          summary: 'Get webhook',
          description: 'Retrieve a specific webhook.',
          tags: ['Webhooks'],
          responses: {
            '200': {
              description: 'Webhook details',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Webhook' },
                },
              },
            },
          },
        },
        patch: {
          operationId: 'updateWebhook',
          summary: 'Update webhook',
          description: 'Update a webhook endpoint.',
          tags: ['Webhooks'],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/UpdateWebhookRequest' },
              },
            },
          },
          responses: {
            '200': {
              description: 'Webhook updated',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Webhook' },
                },
              },
            },
          },
        },
        delete: {
          operationId: 'deleteWebhook',
          summary: 'Delete webhook',
          description: 'Delete a webhook endpoint.',
          tags: ['Webhooks'],
          responses: {
            '204': { description: 'Webhook deleted' },
          },
        },
      },
      '/webhooks/{webhookId}/test': {
        parameters: [
          {
            name: 'webhookId',
            in: 'path',
            description: 'The webhook ID',
            required: true,
            schema: { type: 'string' },
          },
        ],
        post: {
          operationId: 'testWebhook',
          summary: 'Test webhook',
          description: 'Send a test event to a webhook endpoint.',
          tags: ['Webhooks'],
          requestBody: {
            required: false,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    eventType: {
                      type: 'string',
                      description: 'Event type to simulate',
                      example: 'email.delivered',
                    },
                  },
                },
              },
            },
          },
          responses: {
            '200': {
              description: 'Test result',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/WebhookTestResult' },
                },
              },
            },
          },
        },
      },

      // API Key endpoints
      '/api-keys': {
        post: {
          operationId: 'createApiKey',
          summary: 'Create API key',
          description: 'Create a new API key.',
          tags: ['API Keys'],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/CreateApiKeyRequest' },
              },
            },
          },
          responses: {
            '201': {
              description: 'API key created',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/ApiKeyCreated' },
                },
              },
            },
          },
        },
        get: {
          operationId: 'listApiKeys',
          summary: 'List API keys',
          description: 'Retrieve all API keys.',
          tags: ['API Keys'],
          responses: {
            '200': {
              description: 'List of API keys',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/ApiKeyList' },
                },
              },
            },
          },
        },
      },
      '/api-keys/{keyId}': {
        parameters: [
          {
            name: 'keyId',
            in: 'path',
            description: 'The API key ID',
            required: true,
            schema: { type: 'string' },
          },
        ],
        delete: {
          operationId: 'revokeApiKey',
          summary: 'Revoke API key',
          description: 'Revoke an API key.',
          tags: ['API Keys'],
          responses: {
            '204': { description: 'API key revoked' },
          },
        },
      },

      // Analytics endpoints
      '/analytics/overview': {
        get: {
          operationId: 'getAnalyticsOverview',
          summary: 'Get analytics overview',
          description: 'Get an overview of email analytics.',
          tags: ['Analytics'],
          parameters: [
            {
              name: 'startDate',
              in: 'query',
              required: true,
              schema: { type: 'string', format: 'date' },
            },
            {
              name: 'endDate',
              in: 'query',
              required: true,
              schema: { type: 'string', format: 'date' },
            },
          ],
          responses: {
            '200': {
              description: 'Analytics overview',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AnalyticsOverview' },
                },
              },
            },
          },
        },
      },
      '/analytics/time-series': {
        get: {
          operationId: 'getAnalyticsTimeSeries',
          summary: 'Get time series analytics',
          description: 'Get time series data for email metrics.',
          tags: ['Analytics'],
          parameters: [
            {
              name: 'startDate',
              in: 'query',
              required: true,
              schema: { type: 'string', format: 'date' },
            },
            {
              name: 'endDate',
              in: 'query',
              required: true,
              schema: { type: 'string', format: 'date' },
            },
            {
              name: 'granularity',
              in: 'query',
              required: false,
              schema: { type: 'string', enum: ['hour', 'day', 'week', 'month'], default: 'day' },
            },
            {
              name: 'metrics',
              in: 'query',
              required: false,
              schema: { type: 'array', items: { type: 'string' } },
            },
          ],
          responses: {
            '200': {
              description: 'Time series data',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AnalyticsTimeSeries' },
                },
              },
            },
          },
        },
      },

      // Suppression list endpoints
      '/suppressions': {
        post: {
          operationId: 'addSuppression',
          summary: 'Add suppression',
          description: 'Add an email address to the suppression list.',
          tags: ['Suppressions'],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AddSuppressionRequest' },
              },
            },
          },
          responses: {
            '201': {
              description: 'Suppression added',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Suppression' },
                },
              },
            },
          },
        },
        get: {
          operationId: 'listSuppressions',
          summary: 'List suppressions',
          description: 'Retrieve the suppression list.',
          tags: ['Suppressions'],
          parameters: [
            {
              name: 'type',
              in: 'query',
              required: false,
              schema: { type: 'string', enum: ['bounce', 'complaint', 'unsubscribe', 'manual'] },
            },
          ],
          responses: {
            '200': {
              description: 'Suppression list',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/SuppressionList' },
                },
              },
            },
          },
        },
      },
      '/suppressions/{email}': {
        parameters: [
          {
            name: 'email',
            in: 'path',
            description: 'The email address',
            required: true,
            schema: { type: 'string', format: 'email' },
          },
        ],
        get: {
          operationId: 'getSuppression',
          summary: 'Check suppression',
          description: 'Check if an email is suppressed.',
          tags: ['Suppressions'],
          responses: {
            '200': {
              description: 'Suppression status',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Suppression' },
                },
              },
            },
            '404': {
              description: 'Not suppressed',
            },
          },
        },
        delete: {
          operationId: 'removeSuppression',
          summary: 'Remove suppression',
          description: 'Remove an email from the suppression list.',
          tags: ['Suppressions'],
          responses: {
            '204': { description: 'Suppression removed' },
          },
        },
      },

      // Account endpoints
      '/account': {
        get: {
          operationId: 'getAccount',
          summary: 'Get account',
          description: 'Retrieve account details.',
          tags: ['Account'],
          responses: {
            '200': {
              description: 'Account details',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Account' },
                },
              },
            },
          },
        },
      },
      '/account/usage': {
        get: {
          operationId: 'getUsage',
          summary: 'Get usage',
          description: 'Retrieve current billing period usage.',
          tags: ['Account'],
          responses: {
            '200': {
              description: 'Usage details',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Usage' },
                },
              },
            },
          },
        },
      },
    };
  }

  private generateComponents(): OpenApiComponents {
    return {
      schemas: {
        // Email schemas
        SendEmailRequest: {
          type: 'object',
          required: ['from', 'to'],
          properties: {
            from: { $ref: '#/components/schemas/EmailAddress' },
            to: {
              type: 'array',
              items: { $ref: '#/components/schemas/EmailAddress' },
              minItems: 1,
              maxItems: 50,
            },
            cc: {
              type: 'array',
              items: { $ref: '#/components/schemas/EmailAddress' },
            },
            bcc: {
              type: 'array',
              items: { $ref: '#/components/schemas/EmailAddress' },
            },
            replyTo: { $ref: '#/components/schemas/EmailAddress' },
            subject: { type: 'string', maxLength: 998 },
            text: { type: 'string' },
            html: { type: 'string' },
            templateId: { type: 'string' },
            templateData: { type: 'object', additionalProperties: true },
            attachments: {
              type: 'array',
              items: { $ref: '#/components/schemas/Attachment' },
            },
            headers: { type: 'object', additionalProperties: { type: 'string' } },
            tags: {
              type: 'array',
              items: { type: 'string' },
              maxItems: 10,
            },
            metadata: { type: 'object', additionalProperties: true },
            scheduledAt: { type: 'string', format: 'date-time' },
          },
        },
        SendEmailResponse: {
          type: 'object',
          properties: {
            id: { type: 'string', example: 'msg_abc123' },
            status: { type: 'string', enum: ['queued', 'scheduled'] },
            scheduledAt: { type: 'string', format: 'date-time', nullable: true },
          },
        },
        Email: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            from: { $ref: '#/components/schemas/EmailAddress' },
            to: { type: 'array', items: { $ref: '#/components/schemas/EmailAddress' } },
            subject: { type: 'string' },
            status: { type: 'string', enum: ['queued', 'sent', 'delivered', 'bounced', 'failed'] },
            createdAt: { type: 'string', format: 'date-time' },
            sentAt: { type: 'string', format: 'date-time', nullable: true },
            deliveredAt: { type: 'string', format: 'date-time', nullable: true },
            tags: { type: 'array', items: { type: 'string' } },
            metadata: { type: 'object', additionalProperties: true },
          },
        },
        EmailList: {
          type: 'object',
          properties: {
            data: { type: 'array', items: { $ref: '#/components/schemas/Email' } },
            hasMore: { type: 'boolean' },
            nextCursor: { type: 'string', nullable: true },
          },
        },
        EmailEventList: {
          type: 'object',
          properties: {
            data: {
              type: 'array',
              items: { $ref: '#/components/schemas/EmailEvent' },
            },
          },
        },
        EmailEvent: {
          type: 'object',
          properties: {
            type: { type: 'string' },
            timestamp: { type: 'string', format: 'date-time' },
            recipient: { type: 'string', format: 'email' },
            data: { type: 'object', additionalProperties: true },
          },
        },
        EmailAddress: {
          type: 'object',
          required: ['email'],
          properties: {
            email: { type: 'string', format: 'email' },
            name: { type: 'string' },
          },
        },
        Attachment: {
          type: 'object',
          required: ['filename', 'content'],
          properties: {
            filename: { type: 'string' },
            content: { type: 'string', description: 'Base64-encoded content' },
            contentType: { type: 'string' },
            contentId: { type: 'string', description: 'For inline attachments' },
          },
        },

        // Batch schemas
        BatchSendRequest: {
          type: 'object',
          required: ['emails'],
          properties: {
            emails: {
              type: 'array',
              items: { $ref: '#/components/schemas/SendEmailRequest' },
              maxItems: 1000,
            },
          },
        },
        BatchSendResponse: {
          type: 'object',
          properties: {
            batchId: { type: 'string' },
            total: { type: 'integer' },
            accepted: { type: 'integer' },
            rejected: { type: 'integer' },
            errors: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  index: { type: 'integer' },
                  error: { type: 'string' },
                },
              },
            },
          },
        },
        Batch: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            status: { type: 'string', enum: ['processing', 'completed', 'partial', 'failed'] },
            total: { type: 'integer' },
            sent: { type: 'integer' },
            failed: { type: 'integer' },
            createdAt: { type: 'string', format: 'date-time' },
            completedAt: { type: 'string', format: 'date-time', nullable: true },
          },
        },

        // Domain schemas
        AddDomainRequest: {
          type: 'object',
          required: ['domain'],
          properties: {
            domain: { type: 'string', format: 'hostname' },
          },
        },
        Domain: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            domain: { type: 'string' },
            status: { type: 'string', enum: ['pending', 'verified', 'failed'] },
            dnsRecords: {
              type: 'array',
              items: { $ref: '#/components/schemas/DnsRecord' },
            },
            createdAt: { type: 'string', format: 'date-time' },
            verifiedAt: { type: 'string', format: 'date-time', nullable: true },
          },
        },
        DomainList: {
          type: 'object',
          properties: {
            data: { type: 'array', items: { $ref: '#/components/schemas/Domain' } },
          },
        },
        DomainVerification: {
          type: 'object',
          properties: {
            domain: { type: 'string' },
            status: { type: 'string', enum: ['verified', 'pending', 'failed'] },
            records: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  type: { type: 'string' },
                  name: { type: 'string' },
                  expected: { type: 'string' },
                  actual: { type: 'string', nullable: true },
                  verified: { type: 'boolean' },
                },
              },
            },
          },
        },
        DnsRecord: {
          type: 'object',
          properties: {
            type: { type: 'string', enum: ['TXT', 'CNAME', 'MX'] },
            name: { type: 'string' },
            value: { type: 'string' },
            priority: { type: 'integer', nullable: true },
          },
        },

        // Template schemas
        CreateTemplateRequest: {
          type: 'object',
          required: ['name', 'subject'],
          properties: {
            name: { type: 'string' },
            subject: { type: 'string' },
            html: { type: 'string' },
            text: { type: 'string' },
            description: { type: 'string' },
          },
        },
        UpdateTemplateRequest: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            subject: { type: 'string' },
            html: { type: 'string' },
            text: { type: 'string' },
            description: { type: 'string' },
          },
        },
        Template: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            subject: { type: 'string' },
            html: { type: 'string' },
            text: { type: 'string' },
            description: { type: 'string' },
            createdAt: { type: 'string', format: 'date-time' },
            updatedAt: { type: 'string', format: 'date-time' },
          },
        },
        TemplateList: {
          type: 'object',
          properties: {
            data: { type: 'array', items: { $ref: '#/components/schemas/Template' } },
          },
        },
        RenderedTemplate: {
          type: 'object',
          properties: {
            subject: { type: 'string' },
            html: { type: 'string' },
            text: { type: 'string' },
          },
        },

        // Webhook schemas
        CreateWebhookRequest: {
          type: 'object',
          required: ['url', 'events'],
          properties: {
            url: { type: 'string', format: 'uri' },
            events: {
              type: 'array',
              items: { type: 'string' },
              description: 'Events to subscribe to',
            },
            description: { type: 'string' },
            enabled: { type: 'boolean', default: true },
          },
        },
        UpdateWebhookRequest: {
          type: 'object',
          properties: {
            url: { type: 'string', format: 'uri' },
            events: { type: 'array', items: { type: 'string' } },
            description: { type: 'string' },
            enabled: { type: 'boolean' },
          },
        },
        Webhook: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            url: { type: 'string' },
            events: { type: 'array', items: { type: 'string' } },
            description: { type: 'string' },
            enabled: { type: 'boolean' },
            secret: { type: 'string', description: 'Shown only on creation' },
            createdAt: { type: 'string', format: 'date-time' },
          },
        },
        WebhookList: {
          type: 'object',
          properties: {
            data: { type: 'array', items: { $ref: '#/components/schemas/Webhook' } },
          },
        },
        WebhookTestResult: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            statusCode: { type: 'integer' },
            responseTime: { type: 'integer', description: 'Response time in ms' },
            error: { type: 'string', nullable: true },
          },
        },

        // API Key schemas
        CreateApiKeyRequest: {
          type: 'object',
          required: ['name'],
          properties: {
            name: { type: 'string' },
            scopes: {
              type: 'array',
              items: { type: 'string' },
              description: 'Permission scopes',
            },
            expiresAt: { type: 'string', format: 'date-time', nullable: true },
          },
        },
        ApiKeyCreated: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            key: { type: 'string', description: 'Full API key - shown only once' },
            name: { type: 'string' },
            prefix: { type: 'string', description: 'Key prefix for identification' },
            scopes: { type: 'array', items: { type: 'string' } },
            createdAt: { type: 'string', format: 'date-time' },
            expiresAt: { type: 'string', format: 'date-time', nullable: true },
          },
        },
        ApiKey: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            prefix: { type: 'string' },
            scopes: { type: 'array', items: { type: 'string' } },
            lastUsedAt: { type: 'string', format: 'date-time', nullable: true },
            createdAt: { type: 'string', format: 'date-time' },
            expiresAt: { type: 'string', format: 'date-time', nullable: true },
          },
        },
        ApiKeyList: {
          type: 'object',
          properties: {
            data: { type: 'array', items: { $ref: '#/components/schemas/ApiKey' } },
          },
        },

        // Analytics schemas
        AnalyticsOverview: {
          type: 'object',
          properties: {
            sent: { type: 'integer' },
            delivered: { type: 'integer' },
            opened: { type: 'integer' },
            clicked: { type: 'integer' },
            bounced: { type: 'integer' },
            complained: { type: 'integer' },
            unsubscribed: { type: 'integer' },
            deliveryRate: { type: 'number' },
            openRate: { type: 'number' },
            clickRate: { type: 'number' },
            bounceRate: { type: 'number' },
          },
        },
        AnalyticsTimeSeries: {
          type: 'object',
          properties: {
            granularity: { type: 'string' },
            data: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  timestamp: { type: 'string', format: 'date-time' },
                  sent: { type: 'integer' },
                  delivered: { type: 'integer' },
                  opened: { type: 'integer' },
                  clicked: { type: 'integer' },
                  bounced: { type: 'integer' },
                },
              },
            },
          },
        },

        // Suppression schemas
        AddSuppressionRequest: {
          type: 'object',
          required: ['email'],
          properties: {
            email: { type: 'string', format: 'email' },
            reason: { type: 'string' },
          },
        },
        Suppression: {
          type: 'object',
          properties: {
            email: { type: 'string', format: 'email' },
            type: { type: 'string', enum: ['bounce', 'complaint', 'unsubscribe', 'manual'] },
            reason: { type: 'string' },
            createdAt: { type: 'string', format: 'date-time' },
          },
        },
        SuppressionList: {
          type: 'object',
          properties: {
            data: { type: 'array', items: { $ref: '#/components/schemas/Suppression' } },
            hasMore: { type: 'boolean' },
            nextCursor: { type: 'string', nullable: true },
          },
        },

        // Account schemas
        Account: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            email: { type: 'string', format: 'email' },
            plan: { type: 'string' },
            status: { type: 'string' },
            createdAt: { type: 'string', format: 'date-time' },
          },
        },
        Usage: {
          type: 'object',
          properties: {
            period: {
              type: 'object',
              properties: {
                start: { type: 'string', format: 'date' },
                end: { type: 'string', format: 'date' },
              },
            },
            emails: {
              type: 'object',
              properties: {
                sent: { type: 'integer' },
                limit: { type: 'integer', nullable: true },
              },
            },
            apiCalls: {
              type: 'object',
              properties: {
                count: { type: 'integer' },
                limit: { type: 'integer', nullable: true },
              },
            },
          },
        },

        // Error schemas
        Error: {
          type: 'object',
          required: ['error'],
          properties: {
            error: {
              type: 'object',
              properties: {
                code: { type: 'string' },
                message: { type: 'string' },
                details: { type: 'object', additionalProperties: true },
              },
            },
          },
        },
      },
      securitySchemes: {
        BearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'API Key',
          description: 'Use your API key as a Bearer token',
        },
        ApiKeyAuth: {
          type: 'apiKey',
          in: 'header',
          name: 'X-API-Key',
          description: 'Use your API key in the X-API-Key header',
        },
      },
      parameters: {
        PageSize: {
          name: 'limit',
          in: 'query',
          description: 'Number of items to return (max 100)',
          required: false,
          schema: { type: 'integer', minimum: 1, maximum: 100, default: 20 },
        },
        PageCursor: {
          name: 'cursor',
          in: 'query',
          description: 'Cursor for pagination',
          required: false,
          schema: { type: 'string' },
        },
      },
      responses: {
        BadRequest: {
          description: 'Bad request',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/Error' },
              example: {
                error: {
                  code: 'validation_error',
                  message: 'Invalid request body',
                  details: { field: 'from.email', error: 'Invalid email format' },
                },
              },
            },
          },
        },
        Unauthorized: {
          description: 'Unauthorized',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/Error' },
              example: {
                error: {
                  code: 'unauthorized',
                  message: 'Invalid or missing API key',
                },
              },
            },
          },
        },
        NotFound: {
          description: 'Resource not found',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/Error' },
              example: {
                error: {
                  code: 'not_found',
                  message: 'The requested resource was not found',
                },
              },
            },
          },
        },
        RateLimited: {
          description: 'Rate limit exceeded',
          headers: {
            'X-RateLimit-Limit': {
              description: 'The maximum number of requests allowed',
              schema: { type: 'integer' },
            },
            'X-RateLimit-Remaining': {
              description: 'The number of requests remaining',
              schema: { type: 'integer' },
            },
            'X-RateLimit-Reset': {
              description: 'Unix timestamp when the rate limit resets',
              schema: { type: 'integer' },
            },
            'Retry-After': {
              description: 'Seconds to wait before retrying',
              schema: { type: 'integer' },
            },
          },
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/Error' },
              example: {
                error: {
                  code: 'rate_limited',
                  message: 'Rate limit exceeded. Please retry after 60 seconds.',
                },
              },
            },
          },
        },
      },
    };
  }

  private generateTags(): OpenApiTag[] {
    return [
      {
        name: 'Emails',
        description: 'Send and manage transactional emails',
        externalDocs: { url: 'https://docs.apexmail.ee/api/emails' },
      },
      {
        name: 'Batch',
        description: 'Send multiple emails in a single request',
        externalDocs: { url: 'https://docs.apexmail.ee/api/batch' },
      },
      {
        name: 'Domains',
        description: 'Manage sending domains',
        externalDocs: { url: 'https://docs.apexmail.ee/api/domains' },
      },
      {
        name: 'Templates',
        description: 'Manage email templates',
        externalDocs: { url: 'https://docs.apexmail.ee/api/templates' },
      },
      {
        name: 'Webhooks',
        description: 'Manage webhook endpoints for event notifications',
        externalDocs: { url: 'https://docs.apexmail.ee/api/webhooks' },
      },
      {
        name: 'API Keys',
        description: 'Manage API keys',
        externalDocs: { url: 'https://docs.apexmail.ee/api/api-keys' },
      },
      {
        name: 'Analytics',
        description: 'View email analytics and metrics',
        externalDocs: { url: 'https://docs.apexmail.ee/api/analytics' },
      },
      {
        name: 'Suppressions',
        description: 'Manage suppression list',
        externalDocs: { url: 'https://docs.apexmail.ee/api/suppressions' },
      },
      {
        name: 'Account',
        description: 'Account information and usage',
        externalDocs: { url: 'https://docs.apexmail.ee/api/account' },
      },
    ];
  }

  /**
   * Export spec in different formats
   */
  async exportSpec(format: 'json' | 'yaml' = 'json'): Promise<Result<string>> {
    const specResult = await this.generateSpec();
    if (!specResult.ok) return specResult;

    try {
      if (format === 'yaml') {
        // Convert to YAML
        const yaml = this.toYaml(specResult.value);
        return { ok: true, value: yaml };
      }

      return { ok: true, value: JSON.stringify(specResult.value, null, 2) };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  private toYaml(obj: unknown, indent: number = 0): string {
    const spaces = '  '.repeat(indent);
    
    if (obj === null || obj === undefined) {
      return 'null';
    }
    
    if (typeof obj === 'boolean' || typeof obj === 'number') {
      return String(obj);
    }
    
    if (typeof obj === 'string') {
      if (obj.includes('\n') || obj.includes(':') || obj.includes('#')) {
        return `|\n${obj.split('\n').map(line => spaces + '  ' + line).join('\n')}`;
      }
      if (obj.match(/^[\d.]+$/) || obj === 'true' || obj === 'false' || obj === '') {
        return `"${obj}"`;
      }
      return obj;
    }
    
    if (Array.isArray(obj)) {
      if (obj.length === 0) return '[]';
      return '\n' + obj.map(item => {
        const value = this.toYaml(item, indent + 1);
        if (typeof item === 'object' && item !== null) {
          return `${spaces}- ${value.trim()}`;
        }
        return `${spaces}- ${value}`;
      }).join('\n');
    }
    
    if (typeof obj === 'object') {
      const entries = Object.entries(obj);
      if (entries.length === 0) return '{}';
      return entries.map(([key, value]) => {
        const yamlValue = this.toYaml(value, indent + 1);
        if (typeof value === 'object' && value !== null && !Array.isArray(value) && Object.keys(value).length > 0) {
          return `${spaces}${key}:\n${yamlValue.split('\n').map(l => '  ' + l).join('\n')}`;
        }
        if (Array.isArray(value) && value.length > 0) {
          return `${spaces}${key}:${yamlValue}`;
        }
        return `${spaces}${key}: ${yamlValue}`;
      }).join('\n');
    }
    
    return String(obj);
  }
}
