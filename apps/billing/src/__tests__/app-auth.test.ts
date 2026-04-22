import { beforeAll, describe, expect, it, vi } from 'vitest';
import { createHmac, createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

process.env.NODE_ENV = 'test';
process.env.PORT = '4100';
process.env.HOST = '127.0.0.1';
process.env.DATABASE_URL = 'http://localhost:5432';
process.env.REDIS_URL = 'http://localhost:6379';
process.env.STRIPE_SECRET_KEY = 'sk_test_123456789012345678901234';
process.env.STRIPE_WEBHOOK_SECRET = 'whsec_123456789012345678901234';
process.env.SERVICE_AUTH_TOKEN = 'service-auth-token-1234567890123456';
process.env.JWT_PUBLIC_KEY_PEM = publicKeyPem;
delete process.env.JWT_SECRET;

vi.mock('@apexmail/db', () => ({
  ApiKeysRepository: class {},
  createDatabase: vi.fn(),
}));

vi.mock('ioredis', () => ({
  Redis: class {
    on() {}
  },
}));

vi.mock('../services/index.js', () => {
  const makeService = class {
    startSync() {}
  };
  return {
    MeteringService: makeService,
    UsageAlertsService: makeService,
    PlansService: makeService,
    ProrationEngine: makeService,
    InvoiceService: makeService,
    StripeService: makeService,
    DunningService: makeService,
    SlaCreditsService: makeService,
    EnterpriseContractService: makeService,
    WalletService: makeService,
    ViralLoopService: makeService,
    CostCircuitService: makeService,
    DedicatedIpBillingService: makeService,
  };
});

vi.mock('../routes/index.js', () => ({
  billingRoutes: vi.fn(),
  plansRoutes: vi.fn(),
  enterpriseRoutes: vi.fn(),
  webhooksRoutes: vi.fn(),
  adminRoutes: vi.fn(),
}));

vi.mock('../lib/logger.js', () => ({
  logger: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
  },
}));

import { loadConfig } from '../config.js';
import { resolveClientIp, verifyJwt } from '../app.js';

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function signRs256Token(payload: Record<string, unknown>): string {
  const headerB64 = base64UrlJson({ alg: 'RS256', typ: 'JWT' });
  const payloadB64 = base64UrlJson(payload);
  const signature = sign('RSA-SHA256', Buffer.from(`${headerB64}.${payloadB64}`), createPrivateKey(privateKeyPem));
  return `${headerB64}.${payloadB64}.${signature.toString('base64url')}`;
}

function signHs256Token(payload: Record<string, unknown>, secret: string): string {
  const headerB64 = base64UrlJson({ alg: 'HS256', typ: 'JWT' });
  const payloadB64 = base64UrlJson(payload);
  const signature = createHmac('sha256', secret)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64url');
  return `${headerB64}.${payloadB64}.${signature}`;
}

beforeAll(() => {
  loadConfig();
});

describe('billing JWT verification', () => {
  it('accepts RS256 JWTs issued by the mail-server auth model', () => {
    const token = signRs256Token({
      sub: 'usr_123',
      tenant_id: 'ten_123',
      scopes: ['billing:read'],
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    expect(verifyJwt(token)).toEqual({
      sub: 'usr_123',
      tenant_id: 'ten_123',
      scopes: ['billing:read'],
      admin: false,
      exp: expect.any(Number),
    });
  });

  it('rejects JWTs with a missing tenant_id claim', () => {
    const token = signRs256Token({
      sub: 'usr_123',
      scopes: ['billing:read'],
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    expect(verifyJwt(token)).toBeNull();
  });

  it('rejects JWTs with an empty subject claim', () => {
    const token = signRs256Token({
      sub: '   ',
      tenant_id: 'ten_123',
      scopes: ['billing:read'],
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    expect(verifyJwt(token)).toBeNull();
  });

  it('rejects legacy HS256 JWTs when no legacy secret is configured', () => {
    const token = signHs256Token({
      sub: 'usr_123',
      tenant_id: 'ten_123',
      exp: Math.floor(Date.now() / 1000) + 300,
    }, 'legacy-secret-123456789012345678901234');

    expect(verifyJwt(token)).toBeNull();
  });
});

describe('billing client IP resolution', () => {
  it('ignores forwarded headers unless proxy trust is explicitly enabled', () => {
    expect(resolveClientIp({
      remoteAddress: '::ffff:127.0.0.1',
      xForwardedFor: '198.51.100.10, 203.0.113.8',
      xRealIp: '198.51.100.11',
      trustProxyHeaders: false,
    })).toBe('127.0.0.1');
  });

  it('uses the forwarded client IP when proxy trust is enabled', () => {
    expect(resolveClientIp({
      remoteAddress: '::ffff:127.0.0.1',
      xForwardedFor: '198.51.100.10, 203.0.113.8',
      xRealIp: '198.51.100.11',
      trustProxyHeaders: true,
    })).toBe('198.51.100.10');
  });
});