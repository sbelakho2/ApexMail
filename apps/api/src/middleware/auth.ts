/**
 * Authentication Middleware
 * Supports both API Key and JWT Bearer token authentication
 */

import type { MiddlewareHandler } from 'hono';
import type { AppEnv, AppContext } from '../app.js';
import { ApiKeysRepository } from '@apexmail/db';
import { ApiError } from './error-handler.js';
import { createHmacSignature, timingSafeCompare } from '@apexmail/lib/crypto';
import { isTokenBlacklisted } from './token-blacklist.js';

interface JwtPayload {
  sub: string;       // User ID
  tid: string;       // Tenant ID
  iat: number;       // Issued at
  exp: number;       // Expiration
  scopes?: string[]; // Permission scopes
}

export function authMiddleware(ctx: AppContext): MiddlewareHandler<AppEnv> {
  const apiKeysRepo = new ApiKeysRepository(ctx.db);

  return async (c, next) => {
    const apiKey = c.req.header('X-API-Key');
    const authHeader = c.req.header('Authorization');
    const logger = c.get('logger');

    // Try API Key first
    if (apiKey) {
      const result = await verifyApiKey(apiKey, apiKeysRepo, getClientIp(c));
      
      if (!result.valid) {
        logger.warn('API key authentication failed', { reason: result.reason });
        throw ApiError.unauthorized(`Invalid API key: ${result.reason}`, 'INVALID_API_KEY');
      }

      c.set('tenantId', result.tenantId!);
      c.set('userId', result.userId ?? null);
      c.set('apiKeyId', result.apiKeyId!);
      c.set('scopes', result.scopes ?? ['*']);
      
      logger.info('Authenticated via API key', {
        tenantId: result.tenantId,
        apiKeyId: result.apiKeyId,
      });
      
      return next();
    }

    // Try Bearer token
    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      const result = await verifyJwt(token, ctx.config.auth.jwtSecret);
      
      if (!result.valid) {
        logger.warn('JWT authentication failed', { reason: result.reason });
        throw ApiError.unauthorized(`Invalid token: ${result.reason}`, 'INVALID_TOKEN');
      }

      // SECURITY FIX: Check server-side token blacklist for logged-out tokens
      const tokenSignature = token.split('.')[2];
      if (tokenSignature) {
        const blacklisted = await isTokenBlacklisted(ctx.config, tokenSignature);
        if (blacklisted) {
          logger.warn('Rejected blacklisted token', { userId: result.payload!.sub });
          throw ApiError.unauthorized('Token has been invalidated', 'TOKEN_REVOKED');
        }
      }

      c.set('tenantId', result.payload!.tid);
      c.set('userId', result.payload!.sub);
      c.set('apiKeyId', null);
      c.set('scopes', result.payload!.scopes ?? ['*']);
      
      logger.info('Authenticated via JWT', {
        tenantId: result.payload!.tid,
        userId: result.payload!.sub,
      });
      
      return next();
    }

    // No authentication provided
    logger.warn('No authentication provided');
    throw ApiError.unauthorized('Authentication required', 'AUTH_REQUIRED');
  };
}

interface ApiKeyVerifyResult {
  valid: boolean;
  reason?: string;
  tenantId?: string;
  userId?: string | null;
  apiKeyId?: string;
  scopes?: string[];
}

async function verifyApiKey(
  key: string,
  repo: ApiKeysRepository,
  clientIp: string
): Promise<ApiKeyVerifyResult> {
  const result = await repo.verify(key, clientIp);
  
  if (!result.ok) {
    return { valid: false, reason: 'verification_error' };
  }

  const { valid, apiKey, reason } = result.value;
  
  if (!valid || !apiKey) {
    return { valid: false, reason };
  }

  return {
    valid: true,
    tenantId: apiKey.tenantId,
    userId: apiKey.userId,
    apiKeyId: apiKey.id,
    scopes: apiKey.scopes,
  };
}

interface JwtVerifyResult {
  valid: boolean;
  reason?: string;
  payload?: JwtPayload;
}

async function verifyJwt(token: string, secret: string): Promise<JwtVerifyResult> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, reason: 'malformed_token' };
    }

    const [headerB64, payloadB64, signatureB64] = parts;
    
    // Ensure all parts exist after split
    if (!headerB64 || !payloadB64 || !signatureB64) {
      return { valid: false, reason: 'malformed_token' };
    }

    // SECURITY FIX: Validate algorithm header to prevent algorithm confusion attacks
    // Attackers can:
    // 1. Set alg: 'none' to bypass signature verification entirely
    // 2. Use algorithm confusion (RS256 -> HS256) to forge signatures
    // We MUST verify the algorithm matches what we expect before verifying the signature
    try {
      const headerJson = Buffer.from(headerB64, 'base64url').toString('utf8');
      const header = JSON.parse(headerJson) as { alg?: string; typ?: string };
      
      // Only accept HS256 algorithm - reject 'none', RS256, or any other algorithm
      if (header.alg !== 'HS256') {
        return { valid: false, reason: 'invalid_algorithm' };
      }
      
      // Verify type is JWT
      if (header.typ && header.typ !== 'JWT') {
        return { valid: false, reason: 'invalid_token_type' };
      }
    } catch {
      return { valid: false, reason: 'invalid_header' };
    }

    // Verify signature using constant-time comparison
    const signatureInput = `${headerB64}.${payloadB64}`;
    const expectedSignature = createHmacSignature(secret, signatureInput, 'sha256', 'base64url');

    // SECURITY FIX: Use timing-safe comparison to prevent timing attacks
    if (!timingSafeCompare(signatureB64, expectedSignature)) {
      return { valid: false, reason: 'invalid_signature' };
    }

    // Parse payload with safety wrapper
    let payload: JwtPayload;
    try {
      const payloadJson = Buffer.from(payloadB64, 'base64url').toString('utf8');
      payload = JSON.parse(payloadJson) as JwtPayload;
    } catch {
      return { valid: false, reason: 'invalid_payload' };
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return { valid: false, reason: 'token_expired' };
    }

    // Check not before (if present)
    if (payload.iat && payload.iat > now + 60) { // 60 second clock skew tolerance
      return { valid: false, reason: 'token_not_yet_valid' };
    }

    return { valid: true, payload };
  } catch {
    return { valid: false, reason: 'invalid_token' };
  }
}

export function createJwt(
  payload: Omit<JwtPayload, 'iat' | 'exp'>,
  secret: string,
  expiresIn: string
): string {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + parseExpiry(expiresIn);

  const fullPayload: JwtPayload = {
    ...payload,
    iat: now,
    exp,
  };

  const header = { alg: 'HS256', typ: 'JWT' };
  
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(fullPayload)).toString('base64url');
  
  const signatureInput = `${headerB64}.${payloadB64}`;
  const signature = createHmacSignature(secret, signatureInput, 'sha256', 'base64url');

  return `${headerB64}.${payloadB64}.${signature}`;
}

export function parseExpiry(expiry: string): number {
  const match = expiry.match(/^(\d+)([smhd])$/);
  if (!match || !match[1] || !match[2]) {
    console.warn(`[Auth] Invalid token expiry format "${expiry}", defaulting to 1 hour. Expected format: <number><s|m|h|d>`);
    return 3600; // Default 1 hour
  }

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case 's': return value;
    case 'm': return value * 60;
    case 'h': return value * 3600;
    case 'd': return value * 86400;
    default: return 3600;
  }
}

function getClientIp(c: { req: { header: (name: string) => string | undefined } }): string {
  // Prefer the validated IP set by the trusted-proxy middleware
  const validatedIp = c.req.header('X-Validated-Client-IP');
  if (validatedIp) return validatedIp;

  // Fallback: read proxy headers directly (less trustworthy)
  // FIX: Use || instead of ?? for X-Forwarded-For to handle empty string correctly
  // ''.split(',')[0]?.trim() returns '' which is falsy but not null/undefined
  const forwardedFor = c.req.header('X-Forwarded-For')?.split(',')[0]?.trim();
  return (
    c.req.header('CF-Connecting-IP') ??
    (forwardedFor || undefined) ??
    c.req.header('X-Real-IP') ??
    'unknown'
  );
}

/**
 * Require specific scopes for an endpoint
 */
export function requireScopes(...requiredScopes: string[]): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const apiKeyId = c.get('apiKeyId');
    const logger = c.get('logger');
    
    // JWT users have all scopes (managed by RBAC at user level)
    if (!apiKeyId) {
      return next();
    }

    // For API keys, check scopes from context
    const userScopes = c.get('scopes');
    
    if (userScopes && requiredScopes.length > 0) {
      // Check if user has wildcard scope or all required scopes
      const hasWildcard = userScopes.includes('*');
      const hasAllScopes = requiredScopes.every(scope => userScopes.includes(scope));
      
      if (!hasWildcard && !hasAllScopes) {
        logger.warn('Insufficient scopes', {
          required: requiredScopes,
          actual: userScopes,
        });
        throw ApiError.forbidden('Insufficient permissions', 'INSUFFICIENT_SCOPE');
      }
    }
    
    return next();
  };
}
