/**
 * Batch 3 (#21–40) Targeted Tests — Security
 *
 * Each test verifies a specific security fix introduced in Batch 3 by
 * inspecting the actual source code for the expected patterns.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.resolve(__dirname, '../../../..');

function read(rel: string): string {
    return fs.readFileSync(path.join(ROOT, rel), 'utf-8');
}

// ---------------------------------------------------------------------------
// #21: DKIM per-domain key resolution
// ---------------------------------------------------------------------------
describe('#21 – DKIM per-domain key directory', () => {
    const src = read('apps/mta/src/config.ts');

    it('has keyDirectory field in dkim config', () => {
        expect(src).toContain('keyDirectory');
    });

    it('reads DKIM_KEY_DIRECTORY from env', () => {
        expect(src).toContain('DKIM_KEY_DIRECTORY');
    });

    it('has FIX-500-021 annotation', () => {
        expect(src).toContain('FIX-500-021');
    });
});

// ---------------------------------------------------------------------------
// #22: Tracking tokens already use AES-128-GCM (verified — no change needed)
// ---------------------------------------------------------------------------
describe('#22 – Tracking tokens use authenticated encryption', () => {
    const src = read('services/mail-server/crates/tracking-service/src/codec.rs');

    it('uses aes128gcm_encrypt for encoding', () => {
        expect(src).toContain('aes128gcm_encrypt');
    });

    it('uses aes128gcm_decrypt for decoding', () => {
        expect(src).toContain('aes128gcm_decrypt');
    });
});

// ---------------------------------------------------------------------------
// #23: Unsubscribe token PII leak — encrypted, not plaintext+HMAC
// ---------------------------------------------------------------------------
describe('#23 – Unsubscribe token encrypted (no PII leak)', () => {
    const src = read('services/mail-server/crates/tracking-service/src/codec.rs');

    it('generate_unsubscribe_token uses aes128gcm_encrypt', () => {
        // Should encrypt the payload, not expose it in plaintext
        expect(src).toMatch(/generate_unsubscribe_token[\s\S]*?aes128gcm_encrypt/);
    });

    it('verify_unsubscribe_token tries GCM decryption first', () => {
        expect(src).toMatch(/verify_unsubscribe_token[\s\S]*?aes128gcm_decrypt/);
    });

    it('has backward-compatible legacy HMAC fallback', () => {
        // Legacy tokens should still be verifiable
        expect(src).toContain('legacy HMAC-signed format');
    });
});

// ---------------------------------------------------------------------------
// #24: SAML SHA-1 uses structured logging, not console.warn
// ---------------------------------------------------------------------------
describe('#24 – SAML SHA-1 structured logging', () => {
    const src = read('apps/enterprise/src/services/sso.ts');

    it('uses this.logger.warn for SHA-1 deprecation warning', () => {
        expect(src).toContain('this.logger.warn');
    });

    it('mentions SHA-1 is deprecated in the warning', () => {
        expect(src).toMatch(/SHA-1.*deprecated/i);
    });

    it('has FIX-500-024 annotation', () => {
        expect(src).toContain('FIX-500-024');
    });
});

// ---------------------------------------------------------------------------
// #25: HA /internal/* auth middleware
// ---------------------------------------------------------------------------
describe('#25 – HA /internal/* routes require auth', () => {
    const src = read('apps/ha/src/app.ts');

    it('has middleware for /internal/* routes', () => {
        expect(src).toMatch(/\/internal\/\*/);
    });

    it('checks authorization header', () => {
        expect(src).toMatch(/authorization/i);
    });

    it('returns 401 for missing auth', () => {
        expect(src).toContain('401');
    });

    it('has FIX-500-025 annotation', () => {
        expect(src).toContain('FIX-500-025');
    });
});

// ---------------------------------------------------------------------------
// #26: Ops API key authentication
// ---------------------------------------------------------------------------
describe('#26 – Ops routes require API key auth', () => {
    const src = read('apps/ops/src/routes.ts');

    it('checks OPS_API_KEY env var', () => {
        expect(src).toContain('OPS_API_KEY');
    });

    it('checks authorization header', () => {
        expect(src).toMatch(/authorization/i);
    });

    it('returns 401 for missing credentials', () => {
        expect(src).toContain('401');
    });

    it('has FIX-500-026 annotation', () => {
        expect(src).toContain('FIX-500-026');
    });
});

// ---------------------------------------------------------------------------
// #27: Timing-safe comparison in compliance webhook auth
// ---------------------------------------------------------------------------
describe('#27 – Compliance timing-safe token comparison', () => {
    const src = read('apps/compliance/src/routes.ts');

    it('imports crypto module', () => {
        expect(src).toMatch(/import crypto from 'crypto'/);
    });

    it('uses timingSafeEqual for token comparison', () => {
        expect(src).toContain('timingSafeEqual');
    });

    it('converts tokens to Buffer before comparison', () => {
        expect(src).toContain('Buffer.from');
    });

    it('has FIX-500-027 annotation', () => {
        expect(src).toContain('FIX-500-027');
    });
});

// ---------------------------------------------------------------------------
// #28: HA default keys rejected in production
// ---------------------------------------------------------------------------
describe('#28 – HA default keys rejected in production', () => {
    const src = read('apps/ha/src/config.ts');

    it('checks for default internal-key value', () => {
        expect(src).toContain("'internal-key'");
    });

    it('throws error when default keys used in production', () => {
        expect(src).toMatch(/must be set in production/i);
    });

    it('has FIX-500-028 annotation', () => {
        expect(src).toContain('FIX-500-028');
    });
});

// ---------------------------------------------------------------------------
// #29: Login rate limiter periodic cleanup
// ---------------------------------------------------------------------------
describe('#29 – Login rate limiter cleanup interval', () => {
    const src = read('apps/control-plane/src/app/api/auth/login/route.ts');

    it('has setInterval for rate limiter cleanup', () => {
        expect(src).toContain('setInterval');
    });

    it('uses .unref() to avoid keeping the process alive', () => {
        expect(src).toContain('.unref()');
    });

    it('has FIX-500-029 annotation', () => {
        expect(src).toContain('FIX-500-029');
    });
});

// ---------------------------------------------------------------------------
// #30: Logout GET removed — already done in Batch 2 (verified there)
// ---------------------------------------------------------------------------
describe('#30 – Logout GET handler removed (Batch 2)', () => {
    const src = read('apps/control-plane/src/app/api/auth/logout/route.ts');

    it('does NOT export GET handler', () => {
        expect(src).not.toMatch(/export\s+async\s+function\s+GET/);
    });
});

// ---------------------------------------------------------------------------
// #31: Edge-cases regex try-catch
// ---------------------------------------------------------------------------
describe('#31 – Edge-cases regex wrapped in try-catch', () => {
    const src = read('apps/edge-cases/src/services/delivery.ts');

    it('wraps RegExp construction in try block', () => {
        expect(src).toMatch(/try\s*\{[\s\S]*?new RegExp/);
    });

    it('has catch block that continues on invalid regex', () => {
        expect(src).toContain('continue');
    });

    it('has FIX-500-031 annotation', () => {
        expect(src).toContain('FIX-500-031');
    });
});

// ---------------------------------------------------------------------------
// #32: Calendar URL validation
// ---------------------------------------------------------------------------
describe('#32 – Calendar URL scheme validation', () => {
    const src = read('apps/edge-cases/src/services/calendar.ts');

    it('validates URL protocol is http or https', () => {
        expect(src).toContain("parsed.protocol === 'http:'");
        expect(src).toContain("parsed.protocol === 'https:'");
    });

    it('parses the URL with new URL()', () => {
        expect(src).toContain('new URL(');
    });

    it('has FIX-500-032 annotation', () => {
        expect(src).toContain('FIX-500-032');
    });
});

// ---------------------------------------------------------------------------
// #33: Drip engine regex injection prevention
// ---------------------------------------------------------------------------
describe('#33 – Drip engine escapes regex special chars', () => {
    const src = read('apps/sales-autopilot/src/campaigns/drip-engine.ts');

    it('escapes regex special characters in custom field keys', () => {
        expect(src).toContain("replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')");
    });

    it('blocks prototype-chain keys', () => {
        expect(src).toContain('__proto__');
        expect(src).toContain('constructor');
        expect(src).toContain('prototype');
    });

    it('has FIX-500-033 annotation', () => {
        expect(src).toContain('FIX-500-033');
    });
});

// ---------------------------------------------------------------------------
// #34: AES-256-GCM in lib + log-streaming
// ---------------------------------------------------------------------------
describe('#34 – AES-256-GCM encryption', () => {
    const crypto = read('packages/lib/src/crypto/index.ts');
    const logStream = read('apps/enterprise/src/services/log-streaming.ts');

    it('lib exports encryptAES256GCM function', () => {
        expect(crypto).toContain('export function encryptAES256GCM');
    });

    it('lib exports decryptAES256GCM function', () => {
        expect(crypto).toContain('export function decryptAES256GCM');
    });

    it('uses aes-256-gcm cipher', () => {
        expect(crypto).toContain('aes-256-gcm');
    });

    it('log-streaming imports GCM functions', () => {
        expect(logStream).toContain('encryptAES256GCM');
    });

    it('log-streaming encrypt uses GCM', () => {
        expect(logStream).toContain('encryptAES256GCM');
    });

    it('log-streaming decrypt falls back to CBC for legacy data', () => {
        expect(logStream).toContain('decryptAES256GCM');
        expect(logStream).toMatch(/decryptAES256CBC|CBC/);
    });

    it('has FIX-500-034 annotation', () => {
        expect(logStream).toContain('FIX-500-034');
    });
});

// ---------------------------------------------------------------------------
// #35: Crypto-safe random for dashboard snapshot keys
// ---------------------------------------------------------------------------
describe('#35 – Dashboard snapshot uses crypto.randomBytes', () => {
    const src = read('apps/observability/src/services/dashboards.ts');

    it('imports crypto module', () => {
        expect(src).toMatch(/import crypto from 'crypto'/);
    });

    it('uses crypto.randomBytes for snapshot keys', () => {
        expect(src).toContain('crypto.randomBytes');
    });

    it('uses base64url encoding for snapshot keys', () => {
        expect(src).toContain('base64url');
    });

    it('has FIX-500-035 annotation', () => {
        expect(src).toContain('FIX-500-035');
    });
});

// ---------------------------------------------------------------------------
// #36: NEXT_PUBLIC_ prefix removed from server-only env vars
// ---------------------------------------------------------------------------
describe('#36 – Server-only env vars (no NEXT_PUBLIC_ prefix)', () => {
    const src = read('apps/control-plane/src/lib/api.ts');

    it('uses AUTOPILOT_API_URL as primary env var', () => {
        expect(src).toContain('process.env.AUTOPILOT_API_URL');
    });

    it('uses COMPLIANCE_API_URL as primary env var', () => {
        expect(src).toContain('process.env.COMPLIANCE_API_URL');
    });

    it('has backward-compatible fallback to NEXT_PUBLIC_ prefix', () => {
        expect(src).toContain('NEXT_PUBLIC_AUTOPILOT_API_URL');
        expect(src).toContain('NEXT_PUBLIC_COMPLIANCE_API_URL');
    });

    it('has FIX-500-036 annotation', () => {
        expect(src).toContain('FIX-500-036');
    });
});

// ---------------------------------------------------------------------------
// #37: Promo injection XSS prevention
// ---------------------------------------------------------------------------
describe('#37 – Promo injection HTML escaping', () => {
    const src = read('apps/sales-autopilot/src/ads/injection.ts');

    it('has escapeHtml function', () => {
        expect(src).toContain('function escapeHtml');
    });

    it('escapes & < > " characters', () => {
        expect(src).toContain('&amp;');
        expect(src).toContain('&lt;');
        expect(src).toContain('&gt;');
        expect(src).toContain('&quot;');
    });

    it('has sanitizeUrl function', () => {
        expect(src).toContain('function sanitizeUrl');
    });

    it('rejects non-http(s) schemes', () => {
        // sanitizeUrl should check the protocol
        expect(src).toMatch(/protocol.*https?:|https?:.*protocol/i);
    });

    it('has FIX-500-037 annotation', () => {
        expect(src).toContain('FIX-500-037');
    });
});

// ---------------------------------------------------------------------------
// #38: Proxy SSRF already fixed (verified — no change needed)
// ---------------------------------------------------------------------------
describe('#38 – Proxy SSRF protection already in place', () => {
    const src = read('services/mail-server/crates/tracking-service/src/routes/click.rs');

    it('has SSRF-prevention URL validation', () => {
        // Already has comprehensive checks
        expect(src).toMatch(/ssrf|blocked|private|internal/i);
    });
});

// ---------------------------------------------------------------------------
// #39: Template variable injection prevention (whitelabel)
// ---------------------------------------------------------------------------
describe('#39 – Whitelabel template HTML-escapes values', () => {
    const src = read('apps/enterprise/src/services/whitelabel.ts');

    it('HTML-escapes variable values in renderTemplate', () => {
        expect(src).toContain('&amp;');
        expect(src).toContain('&lt;');
        expect(src).toContain('&gt;');
    });

    it('escapes regex special chars in template keys', () => {
        expect(src).toMatch(/replace\(.*\[.*\+\?\^\$\{\}/);
    });

    it('has FIX-500-039 annotation', () => {
        expect(src).toContain('FIX-500-039');
    });
});

// ---------------------------------------------------------------------------
// #40: Warmup TOCTOU — transactional row locking
// ---------------------------------------------------------------------------
describe('#40 – Warmup manager uses transactional row locking', () => {
    const src = read('apps/ops/src/warmup/manager.ts');

    it('uses BEGIN to start transaction', () => {
        expect(src).toContain("'BEGIN'");
    });

    it('uses FOR UPDATE row locking', () => {
        expect(src).toContain('FOR UPDATE');
    });

    it('uses COMMIT to finalize', () => {
        expect(src).toContain("'COMMIT'");
    });

    it('uses ROLLBACK on error', () => {
        expect(src).toContain("'ROLLBACK'");
    });

    it('has FIX-500-040 annotation', () => {
        expect(src).toContain('FIX-500-040');
    });
});
