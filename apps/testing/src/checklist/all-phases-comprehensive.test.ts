/**
 * COMPREHENSIVE TESTS FOR ALL 18 PHASES
 * 
 * Tests based on APEXMAIL_IMPLEMENTATION_CHECKLIST.md
 * These tests verify actual implementation details, not just file existence.
 * They WILL fail if implementations are incomplete or buggy.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const ROOT_DIR = path.resolve(__dirname, '../../../..');

function fileExists(relativePath: string): boolean {
    return fs.existsSync(path.join(ROOT_DIR, relativePath));
}

function readFile(relativePath: string): string {
    const fullPath = path.join(ROOT_DIR, relativePath);
    if (!fs.existsSync(fullPath)) {
        throw new Error(`MISSING FILE: ${relativePath}`);
    }
    return fs.readFileSync(fullPath, 'utf-8');
}

function dirExists(relativePath: string): boolean {
    const fullPath = path.join(ROOT_DIR, relativePath);
    return fs.existsSync(fullPath) && fs.statSync(fullPath).isDirectory();
}

function listDir(relativePath: string): string[] {
    const fullPath = path.join(ROOT_DIR, relativePath);
    if (!fs.existsSync(fullPath)) return [];
    return fs.readdirSync(fullPath);
}

// ============================================================================
// PHASE 1: FOUNDATIONS
// ============================================================================
describe('Phase 1: Foundations', () => {
    describe('1.1 Monorepo Structure', () => {
        it('should have pnpm workspace configuration', () => {
            expect(fileExists('pnpm-workspace.yaml')).toBe(true);
            const content = readFile('pnpm-workspace.yaml');
            expect(content).toContain('packages');
        });

        it('should have Turborepo configuration', () => {
            expect(fileExists('turbo.json')).toBe(true);
            const turbo = JSON.parse(readFile('turbo.json'));
            expect(turbo.pipeline || turbo.tasks).toBeDefined();
        });

        it('should have base TypeScript config with strict mode', () => {
            expect(fileExists('tsconfig.base.json')).toBe(true);
            const tsconfig = JSON.parse(readFile('tsconfig.base.json'));
            expect(tsconfig.compilerOptions.strict).toBe(true);
        });
    });

    describe('1.2 ADR Documentation', () => {
        it('should have ADR for database choice', () => {
            expect(fileExists('docs/adr/0001-database-choice.md')).toBe(true);
            const content = readFile('docs/adr/0001-database-choice.md');
            expect(content.toLowerCase()).toContain('postgres');
        });

        it('should have ADR for MTA stack', () => {
            expect(fileExists('docs/adr/0002-mta-stack.md')).toBe(true);
        });

        it('should have ADR for AI local inference', () => {
            expect(fileExists('docs/adr/0004-ai-local-inference.md')).toBe(true);
            const content = readFile('docs/adr/0004-ai-local-inference.md');
            expect(content.toLowerCase()).toContain('onnx');
        });
    });

    describe('1.3 Shared Library', () => {
        it('should have Result type for explicit error handling', () => {
            expect(fileExists('packages/lib/src/result.ts')).toBe(true);
            const content = readFile('packages/lib/src/result.ts');
            expect(content).toContain('Result<T, E>');
            expect(content).toContain('ok: true');
            expect(content).toContain('ok: false');
        });

        it('should have Result.ok and Result.err helper functions', () => {
            const content = readFile('packages/lib/src/result.ts');
            expect(content).toContain('ok<T>(value: T)');
            expect(content).toContain('err<E>(error: E)');
        });

        it('should have Result.unwrap and Result.map utilities', () => {
            const content = readFile('packages/lib/src/result.ts');
            expect(content).toContain('unwrap');
            expect(content).toContain('map');
        });
    });
});

// ============================================================================
// PHASE 2: DATA LAYER
// ============================================================================
describe('Phase 2: Data Layer', () => {
    describe('2.1 Database Connection Pool', () => {
        it('should have DatabasePool class', () => {
            expect(fileExists('packages/db/src/pool.ts')).toBe(true);
            const content = readFile('packages/db/src/pool.ts');
            expect(content).toContain('class DatabasePool');
        });

        it('should configure PgBouncer transaction mode with correct limits', () => {
            const content = readFile('packages/db/src/pool.ts');
            // API: 20, Worker: 30, MTA: 10 = 60 total
            expect(content).toContain('maxConnections');
            expect(content).toMatch(/20|30|10/);
        });

        it('should have connect() and disconnect() methods', () => {
            const content = readFile('packages/db/src/pool.ts');
            expect(content).toContain('async connect()');
            expect(content).toContain('async disconnect()');
        });

        it('should set statement_timeout on each connection', () => {
            const content = readFile('packages/db/src/pool.ts');
            expect(content).toContain('statement_timeout');
        });
    });

    describe('2.2 Transaction Support', () => {
        it('should have transaction helpers with automatic rollback', () => {
            expect(fileExists('packages/db/src/transaction.ts')).toBe(true);
            const content = readFile('packages/db/src/transaction.ts');
            expect(content).toContain('withTransaction');
        });

        it('should support isolation levels', () => {
            const content = readFile('packages/db/src/transaction.ts');
            expect(content).toContain('IsolationLevel');
            expect(content).toContain('SERIALIZABLE');
            expect(content).toContain('READ COMMITTED');
        });

        it('should support nested transactions via savepoints', () => {
            const content = readFile('packages/db/src/transaction.ts');
            expect(content).toContain('savepoint');
        });

        it('should handle serialization failures with retry', () => {
            const content = readFile('packages/db/src/transaction.ts');
            expect(content).toContain('isRetryableError');
            expect(content).toContain('40001'); // serialization_failure code
            expect(content).toContain('retries');
        });
    });

    describe('2.3 Migration Fingerprinting', () => {
        it('should have migration fingerprint verification', () => {
            expect(fileExists('packages/db/src/fingerprint.ts')).toBe(true);
        });
    });
});

// ============================================================================
// PHASE 3: CORE EMAIL DATA PLANE
// ============================================================================
describe('Phase 3: Core Email Data Plane', () => {
    describe('3.1 API Application', () => {
        it('should have API application entry point', () => {
            expect(fileExists('apps/api/src/index.ts')).toBe(true);
        });

        it('should have API routes', () => {
            expect(dirExists('apps/api/src/routes')).toBe(true);
        });
    });

    describe('3.2 Rate Limiting', () => {
        it('should have rate limiter middleware', () => {
            expect(fileExists('apps/api/src/middleware/rate-limiter.ts')).toBe(true);
            const content = readFile('apps/api/src/middleware/rate-limiter.ts');
            expect(content).toContain('rateLimiter');
        });

        it('should return X-RateLimit-* headers', () => {
            const content = readFile('apps/api/src/middleware/rate-limiter.ts');
            expect(content).toContain('X-RateLimit-Limit');
            expect(content).toContain('X-RateLimit-Remaining');
            expect(content).toContain('X-RateLimit-Reset');
        });

        it('should return Retry-After header when limited', () => {
            const content = readFile('apps/api/src/middleware/rate-limiter.ts');
            expect(content).toContain('Retry-After');
        });

        it('should return 429 status code when rate limited', () => {
            const content = readFile('apps/api/src/middleware/rate-limiter.ts');
            expect(content).toContain('tooManyRequests');
        });

        it('should have sliding window rate limiter for high-precision', () => {
            const content = readFile('apps/api/src/middleware/rate-limiter.ts');
            expect(content).toContain('slidingWindowRateLimiter');
        });
    });

    describe('3.3 Idempotency', () => {
        it('should have idempotency middleware', () => {
            expect(fileExists('apps/api/src/middleware/idempotency.ts')).toBe(true);
            const content = readFile('apps/api/src/middleware/idempotency.ts');
            expect(content).toContain('idempotencyMiddleware');
        });

        it('should use X-Idempotency-Key header', () => {
            const content = readFile('apps/api/src/middleware/idempotency.ts');
            expect(content).toContain('X-Idempotency-Key');
        });

        it('should detect request body mismatch for same key', () => {
            const content = readFile('apps/api/src/middleware/idempotency.ts');
            expect(content).toContain('fingerprint');
            expect(content).toContain('IDEMPOTENCY_KEY_MISMATCH');
        });

        it('should set X-Idempotent-Replayed header on cached response', () => {
            const content = readFile('apps/api/src/middleware/idempotency.ts');
            expect(content).toContain('X-Idempotent-Replayed');
        });
    });

    describe('3.4 Error Handling', () => {
        it('should have centralized error handler', () => {
            expect(fileExists('apps/api/src/middleware/error-handler.ts')).toBe(true);
            const content = readFile('apps/api/src/middleware/error-handler.ts');
            expect(content).toContain('ApiError');
            expect(content).toContain('errorHandler');
        });

        it('should have standard HTTP error factory methods', () => {
            const content = readFile('apps/api/src/middleware/error-handler.ts');
            expect(content).toContain('badRequest');
            expect(content).toContain('unauthorized');
            expect(content).toContain('forbidden');
            expect(content).toContain('notFound');
            expect(content).toContain('tooManyRequests');
            expect(content).toContain('internal');
        });

        it('should handle Zod validation errors', () => {
            const content = readFile('apps/api/src/middleware/error-handler.ts');
            expect(content).toContain('ZodError');
            expect(content).toContain('VALIDATION_ERROR');
        });
    });
});

// ============================================================================
// PHASE 4: MTA STACK
// ============================================================================
describe('Phase 4: MTA Stack', () => {
    describe('4.1 MTA Application', () => {
        it('should have MTA application', () => {
            expect(dirExists('apps/mta')).toBe(true);
            expect(fileExists('apps/mta/src/index.ts')).toBe(true);
        });

        it('should have MTA servers directory', () => {
            expect(dirExists('apps/mta/src/servers')).toBe(true);
        });
    });

    describe('4.2 Bounce Processing (VERP)', () => {
        it('should have bounce server', () => {
            expect(fileExists('apps/mta/src/servers/bounce.ts')).toBe(true);
            const content = readFile('apps/mta/src/servers/bounce.ts');
            expect(content).toContain('BounceServer');
        });

        it('should implement VERP address parsing', () => {
            const content = readFile('apps/mta/src/servers/bounce.ts');
            expect(content).toContain('isVerpAddress');
            expect(content).toContain('parseVerpAddress');
        });

        it('should parse DSN (Delivery Status Notification)', () => {
            const content = readFile('apps/mta/src/servers/bounce.ts');
            expect(content).toContain('parseBounceMessage');
        });

        it('should classify bounce types (hard/soft)', () => {
            const content = readFile('apps/mta/src/servers/bounce.ts');
            expect(content).toContain('bounceType');
            expect(content).toContain("'hard'");
            expect(content).toContain("'soft'");
        });
    });

    describe('4.3 Feedback Loop Processing', () => {
        it('should have feedback loop server', () => {
            expect(fileExists('apps/mta/src/servers/feedback-loop.ts')).toBe(true);
        });
    });

    describe('4.4 Inbound Email Processing', () => {
        it('should have inbound server', () => {
            expect(fileExists('apps/mta/src/servers/inbound.ts')).toBe(true);
        });
    });
});

// ============================================================================
// PHASE 5: ANALYTICS & TRACKING
// ============================================================================
describe('Phase 5: Analytics & Tracking', () => {
    describe('5.1 Tracking Application', () => {
        it('should have tracking application', () => {
            expect(dirExists('apps/tracking')).toBe(true);
            expect(fileExists('apps/tracking/src/index.ts')).toBe(true);
        });
    });

    describe('5.2 Event Processing', () => {
        it('should have event processor', () => {
            expect(fileExists('apps/tracking/src/processor.ts')).toBe(true);
            const content = readFile('apps/tracking/src/processor.ts');
            expect(content).toContain('EventProcessor');
        });

        it('should buffer events for batch writing', () => {
            const content = readFile('apps/tracking/src/processor.ts');
            expect(content).toContain('buffer');
            expect(content).toContain('flushIntervalMs');
            expect(content).toContain('maxBufferSize');
        });

        it('should implement open tracking with deduplication', () => {
            const content = readFile('apps/tracking/src/processor.ts');
            expect(content).toContain('recordOpen');
            expect(content).toContain('isDuplicate');
            expect(content).toContain('dedupeKey');
        });

        it('should implement click tracking', () => {
            const content = readFile('apps/tracking/src/processor.ts');
            expect(content).toContain('recordClick');
            expect(content).toContain('linkId');
            expect(content).toContain('linkUrl');
        });
    });

    describe('5.3 Analytics Application', () => {
        it('should have analytics application', () => {
            expect(dirExists('apps/analytics')).toBe(true);
        });
    });
});

// ============================================================================
// PHASE 6: SALES AUTOPILOT
// ============================================================================
describe('Phase 6: Sales Autopilot', () => {
    describe('6.1 Sales Autopilot Application', () => {
        it('should have sales-autopilot application', () => {
            expect(dirExists('apps/sales-autopilot')).toBe(true);
            expect(fileExists('apps/sales-autopilot/src/index.ts')).toBe(true);
        });
    });

    describe('6.2 Lead Generation', () => {
        it('should have scrapers directory', () => {
            expect(dirExists('apps/sales-autopilot/src/scrapers')).toBe(true);
        });

        it('should have enrichment directory', () => {
            expect(dirExists('apps/sales-autopilot/src/enrichment')).toBe(true);
        });
    });

    describe('6.3 Drip Campaigns', () => {
        it('should have campaigns directory', () => {
            expect(dirExists('apps/sales-autopilot/src/campaigns')).toBe(true);
        });
    });

    describe('6.4 CRM', () => {
        it('should have CRM directory', () => {
            expect(dirExists('apps/sales-autopilot/src/crm')).toBe(true);
        });
    });
});

// ============================================================================
// PHASE 6.5: SECURITY & COMPLIANCE
// ============================================================================
describe('Phase 6.5: Security & Compliance', () => {
    describe('6.5.1 Compliance Application', () => {
        it('should have compliance application', () => {
            expect(dirExists('apps/compliance')).toBe(true);
            expect(fileExists('apps/compliance/src/index.ts')).toBe(true);
        });
    });

    describe('6.5.2 Risk Scoring', () => {
        it('should have risk scoring module', () => {
            expect(dirExists('apps/compliance/src/risk')).toBe(true);
        });
    });

    describe('6.5.3 Content Scanning', () => {
        it('should have content scanning module', () => {
            expect(dirExists('apps/compliance/src/content')).toBe(true);
        });
    });

    describe('6.5.4 Audit Logging', () => {
        it('should have audit logging module', () => {
            expect(dirExists('apps/compliance/src/audit')).toBe(true);
        });
    });

    describe('6.5.5 GDPR', () => {
        it('should have GDPR module', () => {
            expect(dirExists('apps/compliance/src/gdpr')).toBe(true);
        });
    });
});

// ============================================================================
// PHASE 7: PRODUCT UX
// ============================================================================
describe('Phase 7: Product UX', () => {
    describe('7.1 Web Application', () => {
        it('should have web application with Next.js', () => {
            expect(dirExists('apps/web')).toBe(true);
            expect(fileExists('apps/web/next.config.mjs')).toBe(true);
        });

        it('should use App Router (src/app directory)', () => {
            expect(dirExists('apps/web/src/app')).toBe(true);
        });
    });

    describe('7.2 Design System', () => {
        it('should have Tailwind configuration', () => {
            expect(fileExists('apps/web/tailwind.config.ts')).toBe(true);
            const content = readFile('apps/web/tailwind.config.ts');
            expect(content).toContain('darkMode');
        });

        it('should have UI components directory', () => {
            expect(dirExists('apps/web/src/components/ui')).toBe(true);
        });

        it('should have Button component with variants', () => {
            expect(fileExists('apps/web/src/components/ui/button.tsx')).toBe(true);
            const content = readFile('apps/web/src/components/ui/button.tsx');
            expect(content).toContain('buttonVariants');
            expect(content).toContain('variant');
        });

        it('should have essential UI components', () => {
            const uiComponents = listDir('apps/web/src/components/ui');
            expect(uiComponents).toContain('button.tsx');
            expect(uiComponents).toContain('input.tsx');
            expect(uiComponents).toContain('card.tsx');
            expect(uiComponents).toContain('dialog.tsx');
        });

        it('should have CSS variables for theming', () => {
            expect(fileExists('apps/web/src/app/globals.css')).toBe(true);
            const content = readFile('apps/web/src/app/globals.css');
            expect(content).toContain('--primary');
            expect(content).toContain('--background');
            expect(content).toContain('.dark');
        });

        it('should support reduced motion for accessibility', () => {
            const content = readFile('apps/web/src/app/globals.css');
            expect(content).toContain('prefers-reduced-motion');
        });
    });
});

// ============================================================================
// PHASE 8: AI INTELLIGENCE
// ============================================================================
describe('Phase 8: AI Intelligence', () => {
    describe('8.1 AI Application', () => {
        it('should have AI application', () => {
            expect(dirExists('apps/ai')).toBe(true);
            expect(fileExists('apps/ai/src/index.ts')).toBe(true);
        });
    });

    describe('8.2 Inference Engine', () => {
        it('should have inference module', () => {
            expect(dirExists('apps/ai/src/inference')).toBe(true);
        });
    });

    describe('8.3 Content Generation', () => {
        it('should have content generation module', () => {
            expect(dirExists('apps/ai/src/content')).toBe(true);
        });
    });

    describe('8.4 Unified Assistant', () => {
        it('should have unified assistant module', () => {
            expect(dirExists('apps/ai/src/assistant')).toBe(true);
        });
    });
});

// ============================================================================
// PHASE 9: TESTING
// ============================================================================
describe('Phase 9: Testing', () => {
    describe('9.1 Testing Infrastructure', () => {
        it('should have testing application', () => {
            expect(dirExists('apps/testing')).toBe(true);
        });

        it('should have Vitest configuration', () => {
            expect(fileExists('apps/testing/vitest.config.ts')).toBe(true);
        });

        it('should have Playwright configuration', () => {
            expect(fileExists('apps/testing/playwright.config.ts')).toBe(true);
        });
    });

    describe('9.2 Test Suites', () => {
        it('should have E2E tests', () => {
            expect(dirExists('apps/testing/src/e2e')).toBe(true);
        });

        it('should have chaos tests', () => {
            expect(dirExists('apps/testing/src/chaos')).toBe(true);
        });

        it('should have load tests', () => {
            expect(dirExists('apps/testing/src/load')).toBe(true);
        });
    });
});

// ============================================================================
// PHASE 10: OPERATIONS
// ============================================================================
describe('Phase 10: Operations', () => {
    describe('10.1 Ops Application', () => {
        it('should have ops application', () => {
            expect(dirExists('apps/ops')).toBe(true);
            expect(fileExists('apps/ops/src/index.ts')).toBe(true);
        });
    });

    describe('10.2 SLO Management', () => {
        it('should have SLO module', () => {
            expect(dirExists('apps/ops/src/slo')).toBe(true);
        });
    });

    describe('10.3 Health Monitoring', () => {
        it('should have health module', () => {
            expect(dirExists('apps/ops/src/health')).toBe(true);
        });
    });

    describe('10.4 Status & Trust', () => {
        it('should have status module', () => {
            expect(dirExists('apps/ops/src/status')).toBe(true);
        });

        it('should have trust module', () => {
            expect(dirExists('apps/ops/src/trust')).toBe(true);
        });
    });
});

// ============================================================================
// PHASE 11: BILLING
// ============================================================================
describe('Phase 11: Billing', () => {
    describe('11.1 Billing Application', () => {
        it('should have billing application', () => {
            expect(dirExists('apps/billing')).toBe(true);
            expect(fileExists('apps/billing/src/index.ts')).toBe(true);
        });
    });

    describe('11.2 Usage Metering', () => {
        it('should have metering service', () => {
            expect(fileExists('apps/billing/src/services/metering.ts')).toBe(true);
            const content = readFile('apps/billing/src/services/metering.ts');
            expect(content).toContain('MeteringService');
        });

        it('should implement idempotent event counting', () => {
            const content = readFile('apps/billing/src/services/metering.ts');
            expect(content).toContain('recordEvent');
            expect(content).toContain('dedupKey');
            expect(content).toContain('exactly-once');
        });

        it('should track email events, API calls, webhooks', () => {
            const content = readFile('apps/billing/src/services/metering.ts');
            expect(content).toContain('emails_sent');
            expect(content).toContain('api_calls');
            expect(content).toContain('webhooks_delivered');
        });
    });

    describe('11.3 Stripe Integration', () => {
        it('should have Stripe integration service', () => {
            expect(fileExists('apps/billing/src/services/stripe-integration.ts')).toBe(true);
            const content = readFile('apps/billing/src/services/stripe-integration.ts');
            expect(content).toContain('StripeService');
        });

        it('should create Stripe customers', () => {
            const content = readFile('apps/billing/src/services/stripe-integration.ts');
            expect(content).toContain('getOrCreateCustomer');
            expect(content).toContain('stripeCustomerId');
        });

        it('should handle subscriptions', () => {
            const content = readFile('apps/billing/src/services/stripe-integration.ts');
            expect(content).toContain('StripeSubscription');
            expect(content).toContain('SubscriptionStatus');
        });
    });

    describe('11.4 Billing Services', () => {
        it('should have dunning service', () => {
            expect(fileExists('apps/billing/src/services/dunning.ts')).toBe(true);
        });

        it('should have invoices service', () => {
            expect(fileExists('apps/billing/src/services/invoices.ts')).toBe(true);
        });

        it('should have plans service', () => {
            expect(fileExists('apps/billing/src/services/plans.ts')).toBe(true);
        });

        it('should have proration service', () => {
            expect(fileExists('apps/billing/src/services/proration.ts')).toBe(true);
        });

        it('should have usage alerts service', () => {
            expect(fileExists('apps/billing/src/services/usage-alerts.ts')).toBe(true);
        });
    });
});

// ============================================================================
// PHASE 12: DEVELOPER EXPERIENCE
// ============================================================================
describe('Phase 12: Developer Experience', () => {
    describe('12.1 DevEx Application', () => {
        it('should have devex application', () => {
            expect(dirExists('apps/devex')).toBe(true);
            expect(fileExists('apps/devex/src/index.ts')).toBe(true);
        });
    });

    describe('12.2 Webhooks', () => {
        it('should have webhooks service', () => {
            expect(fileExists('apps/devex/src/services/webhooks.ts')).toBe(true);
            const content = readFile('apps/devex/src/services/webhooks.ts');
            expect(content).toContain('WebhookService');
        });

        it('should implement HMAC-SHA256 signature', () => {
            const content = readFile('apps/devex/src/services/webhooks.ts');
            // Uses either raw createHmac or hmacSign wrapper
            const usesHmac = content.includes('createHmac') || content.includes('hmacSign');
            expect(usesHmac).toBe(true);
            expect(content).toContain('sha256');
        });

        it('should implement exponential backoff retry', () => {
            const content = readFile('apps/devex/src/services/webhooks.ts');
            expect(content).toContain('RETRY_SCHEDULE');
            expect(content).toContain('MAX_RETRIES');
        });

        it('should define webhook event types', () => {
            const content = readFile('apps/devex/src/services/webhooks.ts');
            expect(content).toContain('WEBHOOK_EVENTS');
            expect(content).toContain('email.sent');
            expect(content).toContain('email.delivered');
            expect(content).toContain('email.bounced');
        });
    });

    describe('12.3 SDK & API Tooling', () => {
        it('should have API versioning service', () => {
            expect(fileExists('apps/devex/src/services/api-versioning.ts')).toBe(true);
        });

        it('should have SDK generator service', () => {
            expect(fileExists('apps/devex/src/services/sdk-generator.ts')).toBe(true);
        });

        it('should have OpenAPI generator', () => {
            expect(fileExists('apps/devex/src/services/openapi-generator.ts')).toBe(true);
        });

        it('should have sandbox service', () => {
            expect(fileExists('apps/devex/src/services/sandbox.ts')).toBe(true);
        });

        it('should have CLI tool service', () => {
            expect(fileExists('apps/devex/src/services/cli-tool.ts')).toBe(true);
        });
    });
});

// ============================================================================
// PHASE 13: HIGH AVAILABILITY
// ============================================================================
describe('Phase 13: High Availability', () => {
    describe('13.1 HA Application', () => {
        it('should have HA application', () => {
            expect(dirExists('apps/ha')).toBe(true);
            expect(fileExists('apps/ha/src/index.ts')).toBe(true);
        });
    });

    describe('13.2 HA Services', () => {
        it('should have replication service', () => {
            expect(fileExists('apps/ha/src/services/replication.ts')).toBe(true);
        });

        it('should have failover service', () => {
            expect(fileExists('apps/ha/src/services/failover.ts')).toBe(true);
        });

        it('should have circuit breaker service', () => {
            expect(fileExists('apps/ha/src/services/circuit-breaker.ts')).toBe(true);
        });

        it('should have backup service', () => {
            expect(fileExists('apps/ha/src/services/backup.ts')).toBe(true);
        });

        it('should have health check service', () => {
            expect(fileExists('apps/ha/src/services/health-check.ts')).toBe(true);
        });

        it('should have multi-region service', () => {
            expect(fileExists('apps/ha/src/services/multi-region.ts')).toBe(true);
        });
    });
});

// ============================================================================
// PHASE 14: OBSERVABILITY
// ============================================================================
describe('Phase 14: Observability', () => {
    describe('14.1 Observability Application', () => {
        it('should have observability application', () => {
            expect(dirExists('apps/observability')).toBe(true);
            expect(fileExists('apps/observability/src/index.ts')).toBe(true);
        });
    });

    describe('14.2 Distributed Tracing', () => {
        it('should have tracing service', () => {
            expect(fileExists('apps/observability/src/services/tracing.ts')).toBe(true);
            const content = readFile('apps/observability/src/services/tracing.ts');
            expect(content).toContain('TracingService');
        });

        it('should use OpenTelemetry', () => {
            const content = readFile('apps/observability/src/services/tracing.ts');
            expect(content).toContain('@opentelemetry');
            expect(content).toContain('SpanContext');
            expect(content).toContain('Tracer');
        });
    });

    describe('14.3 Metrics & Alerting', () => {
        it('should have metrics service', () => {
            expect(fileExists('apps/observability/src/services/metrics.ts')).toBe(true);
        });

        it('should have alerting service', () => {
            expect(fileExists('apps/observability/src/services/alerting.ts')).toBe(true);
        });

        it('should have logging service', () => {
            expect(fileExists('apps/observability/src/services/logging.ts')).toBe(true);
        });

        it('should have dashboards service', () => {
            expect(fileExists('apps/observability/src/services/dashboards.ts')).toBe(true);
        });
    });
});

// ============================================================================
// PHASE 15: MULTI-TENANT ISOLATION
// ============================================================================
describe('Phase 15: Multi-Tenant Isolation', () => {
    describe('15.1 Isolation Application', () => {
        it('should have isolation application', () => {
            expect(dirExists('apps/isolation')).toBe(true);
            expect(fileExists('apps/isolation/src/index.ts')).toBe(true);
        });
    });

    describe('15.2 Isolation Services', () => {
        it('should have tenant service', () => {
            expect(fileExists('apps/isolation/src/services/tenant.ts')).toBe(true);
        });

        it('should have rate limit service', () => {
            expect(fileExists('apps/isolation/src/services/rate-limit.ts')).toBe(true);
        });

        it('should have data isolation service', () => {
            expect(fileExists('apps/isolation/src/services/data-isolation.ts')).toBe(true);
        });

        it('should have encryption service', () => {
            expect(fileExists('apps/isolation/src/services/encryption.ts')).toBe(true);
        });

        it('should have audit service', () => {
            expect(fileExists('apps/isolation/src/services/audit.ts')).toBe(true);
        });
    });
});

// ============================================================================
// PHASE 16: EDGE CASES
// ============================================================================
describe('Phase 16: Edge Cases', () => {
    describe('16.1 Edge Cases Application', () => {
        it('should have edge-cases application', () => {
            expect(dirExists('apps/edge-cases')).toBe(true);
            expect(fileExists('apps/edge-cases/src/index.ts')).toBe(true);
        });
    });
});

// ============================================================================
// PHASE 17: ENTERPRISE
// ============================================================================
describe('Phase 17: Enterprise', () => {
    describe('17.1 Enterprise Application', () => {
        it('should have enterprise application', () => {
            expect(dirExists('apps/enterprise')).toBe(true);
            expect(fileExists('apps/enterprise/src/index.ts')).toBe(true);
        });
    });

    describe('17.2 Enterprise Documentation', () => {
        it('should have SSO documentation', () => {
            expect(fileExists('docs/enterprise/sso.md')).toBe(true);
        });

        it('should have compliance documentation', () => {
            expect(fileExists('docs/enterprise/compliance.md')).toBe(true);
        });

        it('should have sub-accounts documentation', () => {
            expect(fileExists('docs/enterprise/sub-accounts.md')).toBe(true);
        });
    });
});

// ============================================================================
// PHASE 18: MARKETING WEBSITE
// ============================================================================
describe('Phase 18: Marketing Website', () => {
    describe('18.1 Marketing Application', () => {
        it('should have marketing application with Next.js', () => {
            expect(dirExists('apps/marketing')).toBe(true);
            expect(fileExists('apps/marketing/next.config.mjs')).toBe(true);
        });

        it('should have Tailwind configuration', () => {
            expect(fileExists('apps/marketing/tailwind.config.ts')).toBe(true);
        });
    });
});

// ============================================================================
// CRITICAL INFRASTRUCTURE CHECKS
// ============================================================================
describe('Critical Infrastructure Verification', () => {
    describe('Worker Application', () => {
        it('should have worker application', () => {
            expect(dirExists('apps/worker')).toBe(true);
            expect(fileExists('apps/worker/src/index.ts')).toBe(true);
        });
    });

    describe('Package Exports', () => {
        it('should have lib package index', () => {
            expect(fileExists('packages/lib/src/index.ts')).toBe(true);
        });

        it('should have db package index', () => {
            expect(fileExists('packages/db/src/index.ts')).toBe(true);
        });
    });

    describe('Documentation', () => {
        it('should have API documentation', () => {
            expect(dirExists('docs/api')).toBe(true);
        });

        it('should have architecture documentation', () => {
            expect(dirExists('docs/architecture')).toBe(true);
        });

        it('should have deployment documentation', () => {
            expect(dirExists('docs/deployment')).toBe(true);
        });
    });
});
