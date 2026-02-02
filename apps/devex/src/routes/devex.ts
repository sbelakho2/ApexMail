/**
 * DevEx Routes
 * 
 * API routes for developer experience features:
 * - API versioning
 * - Webhooks
 * - SDK generation
 * - Sandbox mode
 * - OpenAPI spec
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { z } from 'zod';
import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import { ApiVersioningService, VersionStatus } from '../services/api-versioning.js';
import { WebhookService, WebhookEventType } from '../services/webhooks.js';
import { SdkGenerator, SDK_LANGUAGES, type SdkLanguage } from '../services/sdk-generator.js';
import { SandboxService, SandboxMode } from '../services/sandbox.js';
import { OpenApiGenerator } from '../services/openapi-generator.js';
import { CliToolService } from '../services/cli-tool.js';
import { config } from '../config.js';

type Variables = {
  tenantId: string;
  apiVersion: string;
};

export function createDevExRoutes(db: Pool, redis?: Redis): Hono<{ Variables: Variables }> {
  const app = new Hono<{ Variables: Variables }>();

  // Initialize services
  const versioningService = new ApiVersioningService(db);
  const webhookService = redis ? new WebhookService(db, redis) : null;
  const sdkGenerator = new SdkGenerator(db);
  const sandboxService = new SandboxService(db);
  const openApiGenerator = new OpenApiGenerator(db);
  const cliToolService = new CliToolService(db);

  // CORS
  app.use('/*', cors());

  // Version middleware
  app.use('/*', async (c, next) => {
    const headerVersion = c.req.header('X-API-Version');
    const version = headerVersion ?? config.currentApiVersion;
    c.set('apiVersion', version);
    await next();
  });

  // ============================================
  // API Versioning Routes
  // ============================================

  /**
   * Get current API version info
   */
  app.get('/versions', async (c) => {
    const result = await versioningService.getVersions();
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({
      current: config.currentApiVersion,
      versions: result.value,
    });
  });

  /**
   * Get specific version info
   */
  app.get('/versions/:version', async (c) => {
    const version = c.req.param('version');
    const result = await versioningService.getVersion(version);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }
    if (!result.value) {
      return c.json({ error: 'Version not found' }, 404);
    }

    return c.json(result.value);
  });

  /**
   * Get version changelog
   */
  app.get('/versions/:version/changelog', async (c) => {
    const version = c.req.param('version');
    const result = await versioningService.getChangelog(version);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ changelog: result.value });
  });

  /**
   * Get deprecation notices
   */
  app.get('/deprecations', async (c) => {
    const result = await versioningService.getVersions();
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    const deprecations = result.value.filter(
      v => v.status === VersionStatus.DEPRECATED || v.status === VersionStatus.SUNSET
    );

    return c.json({ deprecations });
  });

  // ============================================
  // Webhook Routes
  // ============================================

  const webhookCreateSchema = z.object({
    url: z.string().url(),
    events: z.array(z.nativeEnum(WebhookEventType)),
    description: z.string().optional(),
    headers: z.record(z.string()).optional(),
    enabled: z.boolean().optional().default(true),
  });

  /**
   * List webhooks
   */
  app.get('/webhooks', async (c) => {
    if (!webhookService) {
      return c.json({ error: 'Webhook service unavailable' }, 503);
    }
    const tenantId = c.get('tenantId');
    const result = await webhookService.listEndpoints(tenantId);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ data: result.value });
  });

  /**
   * Create webhook
   */
  app.post('/webhooks', async (c) => {
    if (!webhookService) {
      return c.json({ error: 'Webhook service unavailable' }, 503);
    }
    const tenantId = c.get('tenantId');
    const body = await c.req.json();
    
    const parsed = webhookCreateSchema.safeParse(body);
    if (!parsed.success) {
      return c.json({ error: 'Validation failed', details: parsed.error.issues }, 400);
    }

    const result = await webhookService.createEndpoint(
      tenantId,
      {
        url: parsed.data.url,
        events: parsed.data.events,
        description: parsed.data.description,
        metadata: parsed.data.headers ? { headers: parsed.data.headers } : undefined,
      }
    );
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  /**
   * Get webhook
   */
  app.get('/webhooks/:id', async (c) => {
    if (!webhookService) {
      return c.json({ error: 'Webhook service unavailable' }, 503);
    }
    const tenantId = c.get('tenantId');
    const id = c.req.param('id');
    const result = await webhookService.getEndpoint(tenantId, id);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }
    if (!result.value) {
      return c.json({ error: 'Webhook not found' }, 404);
    }

    return c.json(result.value);
  });

  /**
   * Update webhook
   */
  app.patch('/webhooks/:id', async (c) => {
    if (!webhookService) {
      return c.json({ error: 'Webhook service unavailable' }, 503);
    }
    const tenantId = c.get('tenantId');
    const id = c.req.param('id');
    const body = await c.req.json();

    const result = await webhookService.updateEndpoint(tenantId, id, body);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Delete webhook
   */
  app.delete('/webhooks/:id', async (c) => {
    if (!webhookService) {
      return c.json({ error: 'Webhook service unavailable' }, 503);
    }
    const tenantId = c.get('tenantId');
    const id = c.req.param('id');
    const result = await webhookService.deleteEndpoint(tenantId, id);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.body(null, 204);
  });

  /**
   * Test webhook
   */
  app.post('/webhooks/:id/test', async (c) => {
    if (!webhookService) {
      return c.json({ error: 'Webhook service unavailable' }, 503);
    }
    const tenantId = c.get('tenantId');
    const id = c.req.param('id');

    const result = await webhookService.testEndpoint(tenantId, id);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Get webhook delivery logs
   */
  app.get('/webhooks/:id/logs', async (c) => {
    if (!webhookService) {
      return c.json({ error: 'Webhook service unavailable' }, 503);
    }
    const tenantId = c.get('tenantId');
    const id = c.req.param('id');
    const limit = parseInt(c.req.query('limit') ?? '50');
    const offset = parseInt(c.req.query('offset') ?? '0');

    const result = await webhookService.getDeliveries(tenantId, { endpointId: id, limit, offset });
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ data: result.value });
  });

  /**
   * Get webhook event types
   */
  app.get('/webhook-events', async (c) => {
    return c.json({
      events: Object.values(WebhookEventType).map(type => ({
        type,
        description: getEventDescription(type),
      })),
    });
  });

  /**
   * Rotate webhook secret
   */
  app.post('/webhooks/:id/rotate-secret', async (c) => {
    if (!webhookService) {
      return c.json({ error: 'Webhook service unavailable' }, 503);
    }
    const tenantId = c.get('tenantId');
    const id = c.req.param('id');
    const result = await webhookService.rotateSecret(tenantId, id);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ secret: result.value });
  });

  // ============================================
  // SDK Routes
  // ============================================

  /**
   * Get available SDK languages
   */
  app.get('/sdks', async (c) => {
    const availableLanguages = sdkGenerator.getAvailableLanguages();
    return c.json({
      languages: availableLanguages.map(lang => ({
        id: lang,
        name: getLanguageName(lang),
        packageManager: getPackageManager(lang),
      })),
    });
  });

  /**
   * Generate SDK
   */
  app.post('/sdks/:language', async (c) => {
    const language = c.req.param('language') as SdkLanguage;
    if (!Object.values(SDK_LANGUAGES).includes(language)) {
      return c.json({ error: 'Unsupported language' }, 400);
    }

    const body = await c.req.json().catch(() => ({}));
    const version = body.version ?? config.currentApiVersion;

    const result = await sdkGenerator.generateSdk({ language, version, apiVersion: config.currentApiVersion });
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Download SDK as archive
   */
  app.get('/sdks/:language/download', async (c) => {
    const language = c.req.param('language') as SdkLanguage;
    if (!Object.values(SDK_LANGUAGES).includes(language)) {
      return c.json({ error: 'Unsupported language' }, 400);
    }

    const version = c.req.query('version') ?? config.currentApiVersion;

    // Generate SDK
    const result = await sdkGenerator.generateSdk({ language, version, apiVersion: config.currentApiVersion });
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    // For now, return the files as JSON since createArchive doesn't exist
    // In production, this would create a zip archive
    const filename = `apexmail-${language}-sdk-${version}.zip`;
    const archiveContent = JSON.stringify(result.value.files, null, 2);
    return new Response(archiveContent, {
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="${filename.replace('.zip', '.json')}"`,
      },
    });
  });

  // ============================================
  // Sandbox Routes
  // ============================================

  const sandboxCreateSchema = z.object({
    name: z.string().min(1).max(100),
    mode: z.nativeEnum(SandboxMode).optional().default(SandboxMode.CAPTURE),
    settings: z.object({
      captureEmails: z.boolean().optional(),
      simulateDelivery: z.boolean().optional(),
      simulateBounces: z.boolean().optional(),
      bounceRate: z.number().min(0).max(1).optional(),
      simulateComplaints: z.boolean().optional(),
      complaintRate: z.number().min(0).max(1).optional(),
      simulateDelays: z.boolean().optional(),
      delayMinMs: z.number().min(0).optional(),
      delayMaxMs: z.number().min(0).optional(),
      forwardTo: z.string().email().nullable().optional(),
      allowedRecipientPatterns: z.array(z.string()).optional(),
      blockedRecipientPatterns: z.array(z.string()).optional(),
      webhookUrl: z.string().url().nullable().optional(),
      maxEmailsPerDay: z.number().min(0).optional(),
      retainEmailsDays: z.number().min(1).max(90).optional(),
    }).optional(),
    expiresInHours: z.number().min(1).max(720).optional(),  // Max 30 days
  });

  /**
   * List sandbox environments
   */
  app.get('/sandboxes', async (c) => {
    const tenantId = c.get('tenantId');
    const result = await sandboxService.listEnvironments(tenantId);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ data: result.value });
  });

  /**
   * Create sandbox environment
   */
  app.post('/sandboxes', async (c) => {
    const tenantId = c.get('tenantId');
    const body = await c.req.json();

    const parsed = sandboxCreateSchema.safeParse(body);
    if (!parsed.success) {
      return c.json({ error: 'Validation failed', details: parsed.error.issues }, 400);
    }

    const result = await sandboxService.createEnvironment(
      tenantId,
      parsed.data.name,
      parsed.data.mode,
      parsed.data.settings,
      undefined,
      parsed.data.expiresInHours
    );
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  /**
   * Get sandbox environment
   */
  app.get('/sandboxes/:id', async (c) => {
    const id = c.req.param('id');
    const result = await sandboxService.getEnvironment(id);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }
    if (!result.value) {
      return c.json({ error: 'Sandbox not found' }, 404);
    }

    return c.json(result.value);
  });

  /**
   * Update sandbox settings
   */
  app.patch('/sandboxes/:id', async (c) => {
    const id = c.req.param('id');
    const body = await c.req.json();

    const result = await sandboxService.updateSettings(id, body);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Delete sandbox environment
   */
  app.delete('/sandboxes/:id', async (c) => {
    const id = c.req.param('id');
    const result = await sandboxService.deleteEnvironment(id);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.body(null, 204);
  });

  /**
   * Get captured emails
   */
  app.get('/sandboxes/:id/emails', async (c) => {
    const id = c.req.param('id');
    const limit = parseInt(c.req.query('limit') ?? '50');
    const offset = parseInt(c.req.query('offset') ?? '0');
    const from = c.req.query('from');
    const to = c.req.query('to');
    const subject = c.req.query('subject');

    const result = await sandboxService.getCapturedEmails(id, {
      limit,
      offset,
      from: from ?? undefined,
      to: to ?? undefined,
      subject: subject ?? undefined,
    });
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Get a specific captured email
   */
  app.get('/sandboxes/:id/emails/:emailId', async (c) => {
    const emailId = c.req.param('emailId');
    const result = await sandboxService.getCapturedEmail(emailId);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }
    if (!result.value) {
      return c.json({ error: 'Email not found' }, 404);
    }

    return c.json(result.value);
  });

  /**
   * Delete a captured email
   */
  app.delete('/sandboxes/:id/emails/:emailId', async (c) => {
    const emailId = c.req.param('emailId');
    const result = await sandboxService.deleteCapturedEmail(emailId);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.body(null, 204);
  });

  /**
   * Clear all captured emails
   */
  app.delete('/sandboxes/:id/emails', async (c) => {
    const id = c.req.param('id');
    const result = await sandboxService.clearCapturedEmails(id);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ message: 'All emails cleared' });
  });

  /**
   * Get sandbox statistics
   */
  app.get('/sandboxes/:id/stats', async (c) => {
    const id = c.req.param('id');
    const result = await sandboxService.getStats(id);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Generate sandbox API key
   */
  app.post('/sandboxes/:id/api-keys', async (c) => {
    const tenantId = c.get('tenantId');
    const id = c.req.param('id');
    const result = await sandboxService.generateSandboxApiKey(tenantId, id);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  /**
   * Create test inbox
   */
  app.post('/sandboxes/:id/inboxes', async (c) => {
    const id = c.req.param('id');
    const result = await sandboxService.createTestInbox(id);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  /**
   * Get test inbox emails
   */
  app.get('/sandboxes/:sandboxId/inboxes/:inboxId/emails', async (c) => {
    const inboxId = c.req.param('inboxId');
    const result = await sandboxService.getTestInboxEmails(inboxId);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ data: result.value });
  });

  // ============================================
  // OpenAPI Routes
  // ============================================

  /**
   * Get OpenAPI specification (JSON)
   */
  app.get('/openapi.json', async (c) => {
    const result = await openApiGenerator.exportSpec('json');
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return new Response(result.value, {
      headers: {
        'Content-Type': 'application/json',
      },
    });
  });

  /**
   * Get OpenAPI specification (YAML)
   */
  app.get('/openapi.yaml', async (c) => {
    const result = await openApiGenerator.exportSpec('yaml');
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return new Response(result.value, {
      headers: {
        'Content-Type': 'application/x-yaml',
      },
    });
  });

  // ============================================
  // CLI Routes
  // ============================================

  /**
   * Get CLI commands
   */
  app.get('/cli/commands', async (c) => {
    const result = await cliToolService.getCommands();
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ commands: result.value });
  });

  /**
   * Get specific CLI command
   */
  app.get('/cli/commands/:name', async (c) => {
    const name = c.req.param('name');
    const result = await cliToolService.getCommand(name);
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }
    if (!result.value) {
      return c.json({ error: 'Command not found' }, 404);
    }

    return c.json(result.value);
  });

  /**
   * Download CLI source
   */
  app.get('/cli/download', async (c) => {
    const result = await cliToolService.generateCli();
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Get CLI installation instructions
   */
  app.get('/cli/install', async (c) => {
    return c.json({
      instructions: cliToolService.getInstallInstructions(),
      npm: 'npm install -g @apexmail/cli',
      yarn: 'yarn global add @apexmail/cli',
      pnpm: 'pnpm add -g @apexmail/cli',
    });
  });

  // ============================================
  // Health Check
  // ============================================

  app.get('/health', async (c) => {
    return c.json({
      status: 'healthy',
      service: 'devex',
      timestamp: new Date().toISOString(),
    });
  });

  return app;
}

// Helper functions

function getEventDescription(type: WebhookEventType): string {
  const descriptions: Record<string, string> = {
    [WebhookEventType.EMAIL_SENT]: 'Email has been sent to the recipient server',
    [WebhookEventType.EMAIL_DELIVERED]: 'Email was successfully delivered',
    [WebhookEventType.EMAIL_BOUNCED]: 'Email bounced (hard or soft)',
    [WebhookEventType.EMAIL_DEFERRED]: 'Email delivery was deferred',
    [WebhookEventType.EMAIL_OPENED]: 'Recipient opened the email',
    [WebhookEventType.EMAIL_CLICKED]: 'Recipient clicked a link in the email',
    [WebhookEventType.EMAIL_UNSUBSCRIBED]: 'Recipient unsubscribed',
    [WebhookEventType.EMAIL_COMPLAINED]: 'Recipient marked as spam',
    [WebhookEventType.CONTACT_CREATED]: 'Contact was created',
    [WebhookEventType.CONTACT_UPDATED]: 'Contact was updated',
    [WebhookEventType.CONTACT_DELETED]: 'Contact was deleted',
    [WebhookEventType.LIST_SUBSCRIBED]: 'Subscribed to list',
    [WebhookEventType.LIST_UNSUBSCRIBED]: 'Unsubscribed from list',
  };
  return descriptions[type] ?? 'Unknown event';
}

function getLanguageName(lang: SdkLanguage): string {
  const names: Record<SdkLanguage, string> = {
    [SDK_LANGUAGES.typescript]: 'TypeScript/JavaScript',
    [SDK_LANGUAGES.python]: 'Python',
    [SDK_LANGUAGES.ruby]: 'Ruby',
    [SDK_LANGUAGES.go]: 'Go',
    [SDK_LANGUAGES.php]: 'PHP',
    [SDK_LANGUAGES.java]: 'Java',
    [SDK_LANGUAGES.csharp]: 'C#/.NET',
  };
  return names[lang] ?? lang;
}

function getPackageManager(lang: SdkLanguage): string {
  const managers: Record<SdkLanguage, string> = {
    [SDK_LANGUAGES.typescript]: 'npm',
    [SDK_LANGUAGES.python]: 'pip',
    [SDK_LANGUAGES.ruby]: 'gem',
    [SDK_LANGUAGES.go]: 'go mod',
    [SDK_LANGUAGES.php]: 'composer',
    [SDK_LANGUAGES.java]: 'maven',
    [SDK_LANGUAGES.csharp]: 'nuget',
  };
  return managers[lang] ?? 'unknown';
}
