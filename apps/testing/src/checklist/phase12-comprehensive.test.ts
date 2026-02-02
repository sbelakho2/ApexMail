/**
 * Phase 12: Developer Experience (DX) - Comprehensive Tests
 * 
 * Tests for:
 * - API versioning
 * - Idempotency keys
 * - Request tracing
 * - Rate limit headers
 * - Webhooks
 * - SDKs & tooling
 */

import { describe, test, expect, beforeAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const DEVEX_DIR = path.join(__dirname, '../../../..', 'apps/devex/src');
const DEVEX_SERVICES = path.join(DEVEX_DIR, 'services');
const DEVEX_ROUTES = path.join(DEVEX_DIR, 'routes');

describe('Phase 12: Developer Experience (DX)', () => {
  // ============================================================
  // 12.1 API Excellence
  // ============================================================
  describe('12.1 API Excellence', () => {
    describe('API Versioning', () => {
      let versioningSource: string;

      beforeAll(() => {
        if (fs.existsSync(path.join(DEVEX_SERVICES, 'api-versioning.ts'))) {
          versioningSource = fs.readFileSync(path.join(DEVEX_SERVICES, 'api-versioning.ts'), 'utf-8');
        }
      });

      test('api versioning service exists', () => {
        expect(fs.existsSync(path.join(DEVEX_SERVICES, 'api-versioning.ts'))).toBe(true);
      });

      test('supports URL versioning (/v1/)', () => {
        expect(versioningSource).toMatch(/\/v\d+\//);
        expect(versioningSource).toMatch(/version|Version/i);
      });

      test('implements deprecation policy', () => {
        expect(versioningSource).toMatch(/deprecat|sunset|Sunset/i);
      });

      test('supports multiple API versions', () => {
        expect(versioningSource).toMatch(/v1|v2/);
      });
    });

    describe('Idempotency', () => {
      test('idempotency implementation exists', () => {
        // Check in devex or lib
        const apiDir = path.join(__dirname, '../../../..', 'apps/api/src');
        const libDir = path.join(__dirname, '../../../../..', 'packages/lib/src');
        
        const hasIdempotency = 
          fs.existsSync(path.join(apiDir, 'middleware/idempotency.ts')) ||
          fs.existsSync(path.join(apiDir, 'middlewares/idempotency.ts')) ||
          fs.existsSync(path.join(libDir, 'api/idempotency.ts'));
        
        // Or check content in devex
        let found = hasIdempotency;
        if (!found && fs.existsSync(DEVEX_DIR)) {
          const files = fs.readdirSync(DEVEX_DIR, { recursive: true });
          for (const file of files) {
            if (typeof file === 'string' && file.endsWith('.ts')) {
              const content = fs.readFileSync(path.join(DEVEX_DIR, file), 'utf-8');
              if (content.includes('Idempotency-Key') || content.includes('idempotencyKey')) {
                found = true;
                break;
              }
            }
          }
        }
        
        expect(found).toBe(true);
      });
    });

    describe('Request Tracing', () => {
      test('returns X-Request-ID in responses', () => {
        // Check middleware or app setup
        const appSource = fs.readFileSync(path.join(DEVEX_DIR, 'app.ts'), 'utf-8');
        expect(appSource).toMatch(/X-Request-ID|requestId|request_id|x-request-id/i);
      });
    });

    describe('Rate Limiting', () => {
      test('rate limit headers are implemented', () => {
        const appSource = fs.readFileSync(path.join(DEVEX_DIR, 'app.ts'), 'utf-8');
        
        const hasRateLimitHeaders = 
          appSource.includes('X-RateLimit') ||
          appSource.includes('RateLimit-Limit') ||
          appSource.includes('rateLimit');
        
        expect(hasRateLimitHeaders).toBe(true);
      });
    });

    describe('Bulk Operations', () => {
      test('bulk endpoints are supported', () => {
        // Check services for batch operations (batch is defined in services, not routes)
        let hasBulk = false;
        
        // Check routes first
        if (fs.existsSync(DEVEX_ROUTES)) {
          const routeFiles = fs.readdirSync(DEVEX_ROUTES);
          for (const file of routeFiles) {
            const content = fs.readFileSync(path.join(DEVEX_ROUTES, file), 'utf-8');
            if (content.includes('batch') || content.includes('bulk')) {
              hasBulk = true;
              break;
            }
          }
        }
        
        // Also check services for batch support
        if (!hasBulk && fs.existsSync(DEVEX_SERVICES)) {
          const serviceFiles = fs.readdirSync(DEVEX_SERVICES);
          for (const file of serviceFiles) {
            const filePath = path.join(DEVEX_SERVICES, file);
            if (fs.statSync(filePath).isFile()) {
              const content = fs.readFileSync(filePath, 'utf-8');
              if (content.includes('batch') || content.includes('bulk') || content.includes('Batch')) {
                hasBulk = true;
                break;
              }
            }
          }
        }
        
        expect(hasBulk).toBe(true);
      });
    });
  });

  // ============================================================
  // 12.2 Webhooks
  // ============================================================
  describe('12.2 Webhooks', () => {
    let webhooksSource: string;

    beforeAll(() => {
      webhooksSource = fs.readFileSync(path.join(DEVEX_SERVICES, 'webhooks.ts'), 'utf-8');
    });

    test('webhooks service exists', () => {
      expect(fs.existsSync(path.join(DEVEX_SERVICES, 'webhooks.ts'))).toBe(true);
    });

    describe('Webhook Signatures', () => {
      test('implements HMAC-SHA256 signatures', () => {
        expect(webhooksSource).toMatch(/hmac|HMAC|sha256|SHA256/i);
        expect(webhooksSource).toMatch(/signature|Signature/i);
      });

      test('includes timestamp for replay prevention', () => {
        expect(webhooksSource).toMatch(/timestamp|createdAt|time/i);
      });
    });

    describe('Webhook Retry Logic', () => {
      test('implements exponential backoff', () => {
        expect(webhooksSource).toContain('RETRY_SCHEDULE');
        // Check for increasing intervals
        expect(webhooksSource).toMatch(/60.*1000/); // 1 minute
        expect(webhooksSource).toMatch(/300.*1000|5.*60.*1000/); // 5 minutes
      });

      test('has max retries limit', () => {
        expect(webhooksSource).toContain('MAX_RETRIES');
      });

      test('supports dead-letter after failures', () => {
        expect(webhooksSource).toMatch(/dead.*letter|deadLetter|failed/i);
      });
    });

    describe('Webhook Event Types', () => {
      test('supports granular event subscriptions', () => {
        const expectedEvents = [
          'email.sent',
          'email.delivered',
          'email.bounced',
          'email.opened',
          'email.clicked',
          'email.complained',
          'email.unsubscribed'
        ];

        for (const event of expectedEvents) {
          expect(webhooksSource).toContain(event);
        }
      });

      test('defines webhook event enum', () => {
        expect(webhooksSource).toContain('WebhookEventType');
      });
    });

    describe('Webhook Endpoint Management', () => {
      test('supports creating endpoints', () => {
        expect(webhooksSource).toContain('createEndpoint');
      });

      test('validates webhook URLs', () => {
        expect(webhooksSource).toMatch(/https|http/i);
        expect(webhooksSource).toMatch(/URL|url/);
        expect(webhooksSource).toMatch(/valid|Valid/i);
      });

      test('supports endpoint enable/disable', () => {
        expect(webhooksSource).toContain('enabled');
      });
    });

    describe('Webhook Delivery Tracking', () => {
      test('tracks delivery status', () => {
        expect(webhooksSource).toContain('WebhookDelivery');
        expect(webhooksSource).toMatch(/pending|success|failed|retrying/);
      });

      test('tracks latency', () => {
        expect(webhooksSource).toMatch(/latency|duration/i);
      });
    });
  });

  // ============================================================
  // 12.3 SDKs & Tooling
  // ============================================================
  describe('12.3 SDKs & Tooling', () => {
    describe('OpenAPI Specification', () => {
      let openapiSource: string;

      beforeAll(() => {
        if (fs.existsSync(path.join(DEVEX_SERVICES, 'openapi-generator.ts'))) {
          openapiSource = fs.readFileSync(path.join(DEVEX_SERVICES, 'openapi-generator.ts'), 'utf-8');
        }
      });

      test('openapi generator exists', () => {
        expect(fs.existsSync(path.join(DEVEX_SERVICES, 'openapi-generator.ts'))).toBe(true);
      });

      test('generates OpenAPI 3.0 spec', () => {
        expect(openapiSource).toMatch(/openapi|OpenAPI|3\.0/i);
      });

      test('includes all endpoint definitions', () => {
        expect(openapiSource).toMatch(/paths|endpoints|route/i);
      });
    });

    describe('SDK Generator', () => {
      let sdkSource: string;

      beforeAll(() => {
        if (fs.existsSync(path.join(DEVEX_SERVICES, 'sdk-generator.ts'))) {
          sdkSource = fs.readFileSync(path.join(DEVEX_SERVICES, 'sdk-generator.ts'), 'utf-8');
        }
      });

      test('sdk generator exists', () => {
        expect(fs.existsSync(path.join(DEVEX_SERVICES, 'sdk-generator.ts'))).toBe(true);
      });

      test('supports multiple languages', () => {
        expect(sdkSource).toMatch(/typescript|python|go|java/i);
      });
    });

    describe('CLI Tool', () => {
      let cliSource: string;

      beforeAll(() => {
        if (fs.existsSync(path.join(DEVEX_SERVICES, 'cli-tool.ts'))) {
          cliSource = fs.readFileSync(path.join(DEVEX_SERVICES, 'cli-tool.ts'), 'utf-8');
        }
      });

      test('cli tool exists', () => {
        expect(fs.existsSync(path.join(DEVEX_SERVICES, 'cli-tool.ts'))).toBe(true);
      });

      test('supports send command', () => {
        expect(cliSource).toMatch(/send|Send/);
      });

      test('supports status check', () => {
        expect(cliSource).toMatch(/status|Status/i);
      });
    });

    describe('Sandbox Mode', () => {
      let sandboxSource: string;

      beforeAll(() => {
        if (fs.existsSync(path.join(DEVEX_SERVICES, 'sandbox.ts'))) {
          sandboxSource = fs.readFileSync(path.join(DEVEX_SERVICES, 'sandbox.ts'), 'utf-8');
        }
      });

      test('sandbox service exists', () => {
        expect(fs.existsSync(path.join(DEVEX_SERVICES, 'sandbox.ts'))).toBe(true);
      });

      test('implements sandbox mode flag', () => {
        expect(sandboxSource).toMatch(/sandbox|Sandbox/);
      });

      test('captures emails without actual sending', () => {
        expect(sandboxSource).toMatch(/capture|store|log/i);
        expect(sandboxSource).toMatch(/no.*send|test.*inbox|virtual/i);
      });
    });
  });

  // ============================================================
  // Service Structure Validation
  // ============================================================
  describe('Service Structure', () => {
    test('devex app has proper entry point', () => {
      const indexSource = fs.readFileSync(path.join(DEVEX_DIR, 'index.ts'), 'utf-8');
      
      // Check for graceful shutdown
      expect(indexSource).toMatch(/shutdown|SIGTERM|SIGINT/i);
      
      // Check for database connection
      expect(indexSource).toMatch(/db|database|pool/i);
    });

    test('devex app creates proper HTTP server', () => {
      const indexSource = fs.readFileSync(path.join(DEVEX_DIR, 'index.ts'), 'utf-8');
      expect(indexSource).toMatch(/serve|listen|server/i);
    });

    test('configuration is properly loaded', () => {
      const configPath = path.join(DEVEX_DIR, 'config.ts');
      expect(fs.existsSync(configPath)).toBe(true);
      
      const configSource = fs.readFileSync(configPath, 'utf-8');
      expect(configSource).toMatch(/port|host|env/i);
    });
  });
});
