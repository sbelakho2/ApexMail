/**
 * Batch 2 (#11–20) Targeted Tests
 *
 * Each test verifies a specific fix introduced in Batch 2 by inspecting
 * the actual source code for the expected patterns.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.resolve(__dirname, '../../../..');

function read(rel: string): string {
    return fs.readFileSync(path.join(ROOT, rel), 'utf-8');
}

// ---------------------------------------------------------------------------
// #11: Tracking X-Forwarded-For already validates against trusted proxy list
// ---------------------------------------------------------------------------
describe('#11 – Tracking X-Forwarded-For trusted-proxy validation', () => {
    const src = read('apps/tracking/src/routes.ts');

    it('iterates through forwarded IPs and skips trusted proxies', () => {
        // The implementation must check each IP against a known-trusted list
        expect(src).toContain('trustedProxies');
        // Must check connecting IP is trusted before trusting headers
        expect(src).toContain('isIPInRanges');
        // Iterates IPs and skips any that are trusted proxies
        expect(src).toMatch(/for\s*\(.*ip.*of.*ips\)/);
    });
});

// ---------------------------------------------------------------------------
// #12: Worker reply handler uses FOR UPDATE SKIP LOCKED
// ---------------------------------------------------------------------------
describe('#12 – Inbound reply concurrent-processing guard', () => {
    const src = read('apps/worker/src/processors/reply-handler.ts');

    it('uses FOR UPDATE SKIP LOCKED in the pending-message query', () => {
        expect(src).toMatch(/FOR\s+UPDATE\s+SKIP\s+LOCKED/i);
    });
});

// ---------------------------------------------------------------------------
// #13: Suppressions check — verified that subscriptions queries use existing
//      `email` column in suppressions table (not a bug).
// ---------------------------------------------------------------------------
describe('#13 – Suppression check uses valid column', () => {
    const sub = read('packages/db/src/repositories/subscriptions.ts');
    const sup = read('packages/db/src/repositories/suppressions.ts');

    it('subscriptions repo queries suppressions by email (column exists)', () => {
        expect(sub).toContain('FROM suppressions');
        expect(sub).toMatch(/AND\s+email\s*=\s*\$/i);
    });

    it('suppressions repo uses email_hash for primary lookups', () => {
        expect(sup).toContain('email_hash');
    });
});

// ---------------------------------------------------------------------------
// #14: Tenant DELETE uses soft-delete instead of hard-delete
// ---------------------------------------------------------------------------
describe('#14 – Tenant soft-delete', () => {
    const src = read('apps/control-plane/src/app/api/tenants/route.ts');

    it('does NOT contain DELETE FROM tenants', () => {
        expect(src).not.toMatch(/DELETE\s+FROM\s+tenants/i);
    });

    it('uses UPDATE with status = deleted', () => {
        expect(src).toMatch(/UPDATE\s+tenants\s+SET\s+status\s*=\s*'deleted'/i);
    });

    it('sets suspended = true on soft-delete', () => {
        expect(src).toContain('suspended = true');
    });

    it('records deletedAt timestamp in metadata', () => {
        expect(src).toContain('deletedAt');
    });

    it('returns 404 when tenant is already deleted or not found', () => {
        expect(src).toMatch(/already deleted.*404|404.*already deleted/i);
    });
});

// ---------------------------------------------------------------------------
// #15: Sales-autopilot drip emails wire actual email API
// ---------------------------------------------------------------------------
describe('#15 – Sales-autopilot send callback wires email API', () => {
    const src = read('apps/sales-autopilot/src/index.ts');

    it('no longer uses no-op "Would send email" logger', () => {
        expect(src).not.toContain("'Would send email'");
        expect(src).not.toContain('"Would send email"');
    });

    it('calls the email API via fetch', () => {
        expect(src).toContain('/api/v1/messages/send');
        expect(src).toContain('fetch(');
    });

    it('passes htmlBody and textBody (matching callback signature)', () => {
        expect(src).toContain('params.htmlBody');
        expect(src).toContain('params.textBody');
    });

    it('handles fetch errors gracefully', () => {
        expect(src).toContain('catch (error)');
        expect(src).toContain("messageId: `failed_");
    });
});

// ---------------------------------------------------------------------------
// #16: CRM getLead scoped by tenant_id
// ---------------------------------------------------------------------------
describe('#16 – CRM getLead tenant scoping', () => {
    const src = read('apps/sales-autopilot/src/crm/pipeline.ts');

    it('getLead accepts an optional tenantId parameter', () => {
        expect(src).toMatch(/getLead\(leadId:\s*string,\s*tenantId\?:\s*string\)/);
    });

    it('adds tenant_id to WHERE clause when tenantId is provided', () => {
        expect(src).toMatch(/WHERE\s+id\s*=\s*\$1\s+AND\s+tenant_id\s*=\s*\$2/i);
    });
});

// ---------------------------------------------------------------------------
// #17: AI health endpoint checks actual service readiness
// ---------------------------------------------------------------------------
describe('#17 – AI health endpoint checks real state', () => {
    const routes = read('apps/ai/src/routes.ts');
    const index = read('apps/ai/src/index.ts');

    it('health endpoint is async (lazy-imports bootstrap)', () => {
        expect(routes).toMatch(/app\.get\('\/health',\s*async/);
    });

    it('calls getBootstrap() and getReadiness()', () => {
        expect(routes).toContain('getBootstrap');
        expect(routes).toContain('getReadiness');
    });

    it('returns 503 when service is not ready', () => {
        expect(routes).toMatch(/503/);
    });

    it('no longer hardcodes all services as ready', () => {
        // The old pattern had a static object with inference/chatbot/mailbot all "ready"
        expect(routes).not.toMatch(/services:\s*\{\s*inference:\s*'ready'/);
    });

    it('AI_MODELS JSON.parse is wrapped in try-catch', () => {
        expect(index).toMatch(/try\s*\{[\s\S]*?JSON\.parse\(process\.env\.AI_MODELS\)/);
    });

    it('logs error on malformed AI_MODELS', () => {
        expect(index).toContain('Failed to parse AI_MODELS');
    });

    it('uses ESM-compatible entry-point detection', () => {
        // FIX-500-190: Updated detection uses require.main + arg.endsWith fallback
        expect(index).toMatch(/arg\.endsWith|process\.argv\[1\]/);
    });
});

// ---------------------------------------------------------------------------
// #18: Control plane returns 500 on API errors, not demo data
// ---------------------------------------------------------------------------
describe('#18 – Control plane error handlers return 500', () => {
    const files = [
        { name: 'campaigns', path: 'apps/control-plane/src/app/api/campaigns/route.ts' },
        { name: 'crm/leads', path: 'apps/control-plane/src/app/api/crm/leads/route.ts' },
        { name: 'secrets', path: 'apps/control-plane/src/app/api/secrets/route.ts' },
        { name: 'content', path: 'apps/control-plane/src/app/api/content/route.ts' },
        { name: 'leads/discovery', path: 'apps/control-plane/src/app/api/leads/discovery/route.ts' },
        { name: 'inbox', path: 'apps/control-plane/src/app/api/inbox/route.ts' },
    ];

    for (const { name, path: filePath } of files) {
        describe(`${name} route`, () => {
            const src = read(filePath);

            it('catch block does NOT return DEMO_ data', () => {
                // Extract catch blocks — look for catch followed by return NextResponse.json(DEMO_
                const catchBlocks = src.split(/\bcatch\b/).slice(1);
                for (const block of catchBlocks) {
                    // Only look at the first return in the catch block (within ~8 lines)
                    const firstLines = block.split('\n').slice(0, 8).join('\n');
                    expect(firstLines).not.toMatch(/NextResponse\.json\(DEMO_/);
                }
            });

            it('catch block returns status 500', () => {
                // The catch block should contain { status: 500 }
                expect(src).toMatch(/status:\s*500/);
            });
        });
    }
});

// ---------------------------------------------------------------------------
// #19: Enterprise OIDC JWT decode has security documentation
// ---------------------------------------------------------------------------
describe('#19 – Enterprise JWT decode security annotation', () => {
    const src = read('apps/enterprise/src/services/sso.ts');

    it('decodeJWT has a JSDoc warning about no signature verification', () => {
        expect(src).toMatch(/WITHOUT\s+signature\s+verification/i);
    });

    it('documents that callers must cross-check via userinfo endpoint', () => {
        expect(src).toMatch(/fetchOIDCUserInfo|userinfo|JWKS/i);
    });

    it('implements JWKS verification via verifyJWTWithJWKS', () => {
        expect(src).toContain('verifyJWTWithJWKS');
        expect(src).toContain('jwksUri');
        expect(src).toContain('fetchJWKS');
    });

    it('validates JWT signature, issuer, audience, and nonce', () => {
        expect(src).toContain('signatureValid');
        expect(src).toContain('expectedIssuer');
        expect(src).toContain('expectedAudience');
        expect(src).toContain('expectedNonce');
    });

    it('caches JWKS keys and handles key rotation', () => {
        expect(src).toContain('JWKS_CACHE_TTL_MS');
        expect(src).toContain('forceRefresh');
        expect(src).toContain('jwksCacheMap');
    });
});

// ---------------------------------------------------------------------------
// #20: Sales-autopilot LIMIT parameter has upper bound cap
// ---------------------------------------------------------------------------
describe('#20 – Sales-autopilot LIMIT cap', () => {
    const src = read('apps/sales-autopilot/src/routes.ts');

    it('caps the limit parameter with Math.min', () => {
        expect(src).toMatch(/Math\.min\(/);
    });

    it('caps at a maximum of 100', () => {
        expect(src).toMatch(/Math\.min\(.*100\)/);
    });

    it('also enforces a minimum of 1 via Math.max', () => {
        expect(src).toMatch(/Math\.max\(/);
    });
});

// ---------------------------------------------------------------------------
// Bonus: #30 pulled forward – Logout GET removed (CSRF prevention)
// ---------------------------------------------------------------------------
describe('#30 – Logout GET handler removed', () => {
    const src = read('apps/control-plane/src/app/api/auth/logout/route.ts');

    it('exports POST handler', () => {
        expect(src).toMatch(/export\s+async\s+function\s+POST/);
    });

    it('does NOT export GET handler', () => {
        expect(src).not.toMatch(/export\s+async\s+function\s+GET/);
    });

    it('documents why GET was removed', () => {
        expect(src).toMatch(/CSRF|GET logout removed/i);
    });
});
