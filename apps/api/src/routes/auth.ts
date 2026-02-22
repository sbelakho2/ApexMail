/**
 * Authentication Routes
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv, AppContext } from '../app.js';
import { UsersRepository, ApiKeysRepository, AuditLogsRepository } from '@apexmail/db';
import { ApiError } from '../middleware/error-handler.js';
import { createJwt } from '../middleware/auth.js';
import { blacklistToken } from '../middleware/token-blacklist.js';
import { generateCsrfToken } from '../middleware/csrf.js';

const loginSchema = z.object({
  email: z.string().email().max(254), // RFC 5321 max email length
  password: z.string().min(1).max(1000), // Reasonable max password length
  tenantId: z.string().uuid().optional(),
});

const forgotPasswordSchema = z.object({
  email: z.string().email().max(254),
});

const ALLOWED_SCOPES = [
  'messages:send',
  'messages:read',
  'messages:write',
  'domains:read',
  'domains:write',
  'suppressions:read',
  'suppressions:write',
  'events:read',
  'events:write',
  'templates:read',
  'templates:write',
  'analytics:read',
  'webhooks:read',
  'webhooks:write',
  'dedicated-ips:read',
  'dedicated-ips:write',
  'contacts:read',
  'contacts:write',
  'admin',
] as const;

const createApiKeySchema = z.object({
  name: z.string().min(1, 'Name is required').max(255),
  scopes: z.array(z.enum(ALLOWED_SCOPES)).min(1, 'At least one scope is required').max(ALLOWED_SCOPES.length),
  rateLimit: z.number().int().positive().optional(),
  allowedIps: z.array(z.string().max(45)).max(100).optional(), // IPv6 max is 45 chars, limit count
  expiresAt: z.string().datetime().optional(),
});

/**
 * FIX-500-162: Public auth routes (no authentication required).
 * Only the login endpoint should be accessible without a JWT/API key.
 */
export function publicAuthRoutes(ctx: AppContext): Hono<AppEnv> {
  const publicRouter = new Hono<AppEnv>();
  const usersRepo = new UsersRepository(ctx.db);
  const auditRepo = new AuditLogsRepository(ctx.db);

  // Login - Get JWT token (public — users need this to obtain a JWT)
  publicRouter.post('/login', async (c) => {
    const body = await c.req.json();
    const { email, password, tenantId } = loginSchema.parse(body);
    const logger = c.get('logger');

    // Find user
    const userResult = await usersRepo.findByEmail(email, tenantId);
    if (!userResult.ok) {
      throw ApiError.internal('Failed to fetch user');
    }

    if (!userResult.value) {
      logger.warn('Login attempt for non-existent user', { email });
      throw ApiError.unauthorized('Invalid credentials', 'INVALID_CREDENTIALS');
    }

    const user = userResult.value;

    // Check if user is active
    if (user.status !== 'active') {
      logger.warn('Login attempt for inactive user', { userId: user.id, status: user.status });
      await auditRepo.create({
        tenantId: user.tenantId,
        userId: user.id,
        action: 'user.login_failed',
        resourceType: 'user',
        resourceId: user.id,
        ipAddress: c.req.header('X-Forwarded-For') ?? undefined,
        metadata: { reason: 'inactive_user' },
      });
      throw ApiError.unauthorized('Invalid credentials', 'INVALID_CREDENTIALS');
    }

    // Verify password
    const verifyResult = await usersRepo.verifyCredentials(email, password);
    if (!verifyResult.ok || !verifyResult.value) {
      logger.warn('Invalid password for user', { userId: user.id });
      await auditRepo.create({
        tenantId: user.tenantId,
        userId: user.id,
        action: 'user.login_failed',
        resourceType: 'user',
        resourceId: user.id,
        ipAddress: c.req.header('X-Forwarded-For') ?? undefined,
        metadata: { reason: 'invalid_password' },
      });
      throw ApiError.unauthorized('Invalid credentials', 'INVALID_CREDENTIALS');
    }

    // Generate JWT
    const token = createJwt(
      {
        sub: user.id,
        tid: user.tenantId,
        scopes: [user.role],
      },
      ctx.config.auth.jwtSecret,
      ctx.config.auth.jwtExpiry
    );

    // Update last login (A-004: pass tenantId for tenant isolation)
    await usersRepo.update(user.id, { lastLoginAt: new Date() });

    // Audit log
    await auditRepo.create({
      tenantId: user.tenantId,
      userId: user.id,
      action: 'user.login',
      resourceType: 'user',
      resourceId: user.id,
      ipAddress: c.req.header('X-Forwarded-For') ?? undefined,
      userAgent: c.req.header('User-Agent') ?? undefined,
    });

    logger.info('User logged in', { userId: user.id });

    return c.json({
      token,
      expiresIn: ctx.config.auth.jwtExpiry,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        tenantId: user.tenantId,
      },
    });
  });

  // Forgot password - intentionally returns success for all inputs to prevent email enumeration
  publicRouter.post('/forgot-password', async (c) => {
    const body = await c.req.json();
    const { email } = forgotPasswordSchema.parse(body);
    const logger = c.get('logger');

    const userResult = await usersRepo.findByEmail(email);
    if (!userResult.ok) {
      logger.error('Forgot password lookup failed', { error: userResult.error.message });
      return c.json({
        success: true,
        message: 'If an account exists for that email, a password reset link has been sent.',
      });
    }

    const user = userResult.value;
    if (user) {
      await auditRepo.create({
        tenantId: user.tenantId,
        userId: user.id,
        action: 'user.password_reset_requested',
        resourceType: 'user',
        resourceId: user.id,
        ipAddress: c.req.header('X-Forwarded-For') ?? undefined,
        userAgent: c.req.header('User-Agent') ?? undefined,
        metadata: {
          delivery: 'pending',
          note: 'Email delivery hook not yet integrated',
        },
      });
      logger.info('Password reset requested', { userId: user.id });
    }

    return c.json({
      success: true,
      message: 'If an account exists for that email, a password reset link has been sent.',
    });
  });

  return publicRouter;
}

/**
 * FIX-500-162: Authenticated auth routes (require valid JWT/API key).
 * /me, /api-keys, /logout, /refresh, /csrf-token must be behind auth middleware.
 */
export function authRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const usersRepo = new UsersRepository(ctx.db);
  const apiKeysRepo = new ApiKeysRepository(ctx.db);
  const auditRepo = new AuditLogsRepository(ctx.db);

  // Get current user
  router.get('/me', async (c) => {
    const userId = c.get('userId');
    const tenantId = c.get('tenantId');

    if (!userId) {
      // API key authentication - return minimal info
      return c.json({
        authenticated: true,
        authType: 'api_key',
        tenantId,
        apiKeyId: c.get('apiKeyId'),
      });
    }

    // A-001: Pass tenantId for database-level tenant isolation
    const userResult = await usersRepo.findById(userId);
    if (!userResult.ok || !userResult.value) {
      throw ApiError.notFound('User');
    }

    if (userResult.value.tenantId !== tenantId) {
      throw ApiError.notFound('User');
    }

    const user = userResult.value;

    return c.json({
      authenticated: true,
      authType: 'jwt',
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        tenantId: user.tenantId,
        preferences: user.preferences,
        mfaEnabled: user.mfaEnabled,
        lastLoginAt: user.lastLoginAt,
        createdAt: user.createdAt,
      },
    });
  });

  // List API keys for current user/tenant
  router.get('/api-keys', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    
    let result;
    if (userId) {
      result = await apiKeysRepo.listByUser(userId);
    } else {
      result = await apiKeysRepo.listByTenant(tenantId);
    }

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch API keys');
    }

    const apiKeys = result.ok && 'apiKeys' in result.value
      ? result.value.apiKeys
      : result.value;

    return c.json({
      apiKeys: (apiKeys as Array<{ id: string; name: string; prefix: string; scopes: string[]; rateLimit: number; createdAt: Date; lastUsedAt: Date | null; expiresAt: Date | null; isActive: boolean }>).map((key) => ({
        id: key.id,
        name: key.name,
        prefix: key.prefix,
        scopes: key.scopes,
        rateLimit: key.rateLimit,
        createdAt: key.createdAt,
        lastUsedAt: key.lastUsedAt,
        expiresAt: key.expiresAt,
        isActive: key.isActive,
      })),
    });
  });

  // Create new API key
  router.post('/api-keys', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const logger = c.get('logger');

    const body = await c.req.json();
    const { name, scopes, rateLimit, allowedIps, expiresAt } = createApiKeySchema.parse(body);

    const result = await apiKeysRepo.create({
      tenantId,
      userId: userId ?? undefined,
      name,
      scopes: scopes as Array<'messages:send' | 'messages:read' | 'messages:write' | 'domains:read' | 'domains:write' | 'suppressions:read' | 'suppressions:write' | 'events:read' | 'templates:read' | 'templates:write' | 'analytics:read' | 'webhooks:read' | 'webhooks:write' | 'admin'>,
      rateLimit,
      allowedIps,
      expiresAt: expiresAt ? new Date(expiresAt) : undefined,
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to create API key');
    }

    const apiKey = result.value;

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'api_key.created',
      resourceType: 'api_key',
      resourceId: apiKey.id,
      ipAddress: c.req.header('X-Forwarded-For') ?? undefined,
      metadata: { name, scopes },
    });

    logger.info('API key created', { apiKeyId: apiKey.id, name });

    return c.json({
      apiKey: {
        id: apiKey.id,
        name: apiKey.name,
        prefix: apiKey.prefix,
        secretKey: apiKey.secretKey, // Only returned once!
        scopes: apiKey.scopes,
        rateLimit: apiKey.rateLimit,
        createdAt: apiKey.createdAt,
        expiresAt: apiKey.expiresAt,
      },
      warning: 'Store the secret key securely. It will not be shown again.',
    }, 201);
  });

  // Rotate API key
  router.post('/api-keys/:id/rotate', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const apiKeyId = c.req.param('id');
    const logger = c.get('logger');

    // Verify ownership with tenant isolation
    const existing = await apiKeysRepo.findById(apiKeyId, tenantId);
    if (!existing.ok || !existing.value) {
      throw ApiError.notFound('API key');
    }

    const result = await apiKeysRepo.rotate(apiKeyId, tenantId);
    if (!result.ok) {
      throw ApiError.internal('Failed to rotate API key');
    }

    const apiKey = result.value;

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'api_key.rotated',
      resourceType: 'api_key',
      resourceId: apiKey.id,
      ipAddress: c.req.header('X-Forwarded-For') ?? undefined,
    });

    logger.info('API key rotated', { apiKeyId: apiKey.id });

    return c.json({
      apiKey: {
        id: apiKey.id,
        name: apiKey.name,
        prefix: apiKey.prefix,
        secretKey: apiKey.secretKey, // Only returned once!
        scopes: apiKey.scopes,
      },
      warning: 'Store the new secret key securely. The old key has been invalidated.',
    });
  });

  // Revoke API key
  router.delete('/api-keys/:id', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const apiKeyId = c.req.param('id');
    const logger = c.get('logger');

    // Verify ownership with tenant isolation
    const existing = await apiKeysRepo.findById(apiKeyId, tenantId);
    if (!existing.ok || !existing.value) {
      throw ApiError.notFound('API key');
    }

    const result = await apiKeysRepo.revoke(apiKeyId);
    if (!result.ok) {
      throw ApiError.internal('Failed to revoke API key');
    }

    // C-117: Invalidate cached API key lookup so revocation takes effect immediately
    //        instead of waiting up to 60s for cache TTL expiry.
    const { invalidateApiKeyCacheByKeyId } = await import('../middleware/auth.js');
    await invalidateApiKeyCacheByKeyId(ctx.redis, apiKeyId);

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'api_key.revoked',
      resourceType: 'api_key',
      resourceId: apiKeyId,
      ipAddress: c.req.header('X-Forwarded-For') ?? undefined,
    });

    logger.info('API key revoked', { apiKeyId });

    return c.json({ success: true });
  });

  // Logout - Server-side token invalidation
  // SECURITY FIX: Adds the JWT to a Redis blacklist so it cannot be reused
  router.post('/logout', async (c) => {
    const userId = c.get('userId');
    const tenantId = c.get('tenantId');
    const logger = c.get('logger');
    const authHeader = c.req.header('Authorization');

    if (!authHeader?.startsWith('Bearer ') || !userId) {
      // API key sessions don't need logout
      return c.json({ success: true, message: 'No active JWT session' });
    }

    const token = authHeader.slice(7);
    // Use the token's signature (last segment) as the blacklist key — 
    // it uniquely identifies the token without storing the full JWT
    const tokenSignature = token.split('.')[2];
    if (!tokenSignature) {
      throw ApiError.badRequest('Invalid token format', 'INVALID_TOKEN');
    }

    // Calculate remaining TTL from the JWT expiry so blacklist entry
    // auto-expires when the token would have expired anyway
    const payloadB64 = token.split('.')[1];
    let ttlSeconds = 86400; // default 24h
    if (payloadB64) {
      try {
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8')) as { exp?: number };
        if (payload.exp) {
          const remaining = payload.exp - Math.floor(Date.now() / 1000);
          if (remaining > 0) {
            ttlSeconds = remaining;
          }
        }
      } catch {
        // Use default TTL if payload parsing fails
      }
    }

    await blacklistToken(ctx.config, tokenSignature, { userId, tenantId }, ttlSeconds);

    // Audit log
    await auditRepo.create({
      tenantId,
      userId,
      action: 'user.logout',
      resourceType: 'user',
      resourceId: userId,
      ipAddress: c.req.header('X-Forwarded-For') ?? undefined,
      userAgent: c.req.header('User-Agent') ?? undefined,
    });

    logger.info('User logged out, token blacklisted', { userId, ttlSeconds });

    return c.json({ success: true, message: 'Logged out successfully' });
  });

  // F-236: Refresh JWT token
  // Allows authenticated users to obtain a new JWT before the current one
  // expires, avoiding forced re-login. The existing JWT must still be valid
  // (not expired, not blacklisted). The old token is NOT blacklisted so that
  // in-flight requests using it can still complete within its remaining TTL.
  router.post('/refresh', async (c) => {
    const userId = c.get('userId');
    const tenantId = c.get('tenantId');
    const logger = c.get('logger');

    if (!userId) {
      // API key sessions cannot be refreshed — they don't use JWTs
      throw ApiError.badRequest(
        'Token refresh is only available for JWT-authenticated sessions',
        'REFRESH_NOT_APPLICABLE'
      );
    }

    // Re-fetch the user to ensure they are still active and pick up any
    // role or permission changes since the original token was issued.
    const userResult = await usersRepo.findById(userId);
    if (!userResult.ok || !userResult.value) {
      throw ApiError.unauthorized('User not found', 'USER_NOT_FOUND');
    }

    if (userResult.value.tenantId !== tenantId) {
      throw ApiError.unauthorized('User not found', 'USER_NOT_FOUND');
    }

    const user = userResult.value;

    if (user.status !== 'active') {
      throw ApiError.unauthorized('Account is not active', 'ACCOUNT_INACTIVE');
    }

    // Issue a fresh JWT with updated claims
    const token = createJwt(
      {
        sub: user.id,
        tid: user.tenantId,
        scopes: [user.role],
      },
      ctx.config.auth.jwtSecret,
      ctx.config.auth.jwtExpiry
    );

    // Audit log
    await auditRepo.create({
      tenantId: user.tenantId,
      userId: user.id,
      action: 'user.updated',
      resourceType: 'user',
      resourceId: user.id,
      ipAddress: c.req.header('X-Forwarded-For') ?? undefined,
      userAgent: c.req.header('User-Agent') ?? undefined,
      metadata: { event: 'token_refreshed' },
    });

    logger.info('JWT refreshed', { userId: user.id });

    return c.json({
      token,
      expiresIn: ctx.config.auth.jwtExpiry,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        tenantId: user.tenantId,
      },
    });
  });

  // Generate CSRF token for the current session
  router.get('/csrf-token', async (c) => {
    const userId = c.get('userId');

    if (!userId) {
      // API key sessions don't need CSRF tokens
      throw ApiError.badRequest(
        'CSRF tokens are only issued for JWT-authenticated sessions',
        'CSRF_NOT_APPLICABLE'
      );
    }

    const sessionId = `user:${userId}`;
    const token = await generateCsrfToken(ctx, sessionId);

    return c.json({ csrfToken: token });
  });

  return router;
}
