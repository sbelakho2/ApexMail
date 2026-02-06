/**
 * Token Blacklist - Server-side JWT Invalidation
 * 
 * Maintains a Redis-backed blacklist of invalidated JWT token signatures.
 * Used by the auth middleware to reject tokens that have been explicitly
 * logged out, even if they haven't expired yet.
 * 
 * Blacklist entries automatically expire when the original JWT would have
 * expired, keeping Redis memory usage bounded.
 */

import { createCache, type CacheProvider } from '@apexmail/lib/cache';
import type { Config } from '../config.js';

interface BlacklistConfig {
  redis: Config['redis'];
}

let tokenBlacklistCache: CacheProvider | null = null;

function getTokenBlacklist(config: BlacklistConfig): CacheProvider {
  if (!tokenBlacklistCache) {
    tokenBlacklistCache = createCache({
      type: 'redis',
      prefix: 'apexmail:token-blacklist:',
      redisOptions: {
        host: config.redis.host,
        port: config.redis.port,
        password: config.redis.password,
        db: config.redis.db,
      },
    });
  }
  return tokenBlacklistCache;
}

/**
 * Check if a token's signature has been blacklisted (i.e., the user logged out).
 */
export async function isTokenBlacklisted(config: BlacklistConfig, tokenSignature: string): Promise<boolean> {
  const cache = getTokenBlacklist(config);
  return cache.exists(tokenSignature);
}

/**
 * Add a token's signature to the blacklist with a TTL matching its remaining lifetime.
 */
export async function blacklistToken(
  config: BlacklistConfig,
  tokenSignature: string,
  metadata: { userId: string; tenantId: string },
  ttlSeconds: number
): Promise<void> {
  const cache = getTokenBlacklist(config);
  await cache.set(tokenSignature, {
    ...metadata,
    invalidatedAt: new Date().toISOString(),
  }, { ttlSeconds });
}

/**
 * Disconnect the token blacklist Redis connection during shutdown.
 */
export async function disconnectTokenBlacklist(): Promise<void> {
  if (tokenBlacklistCache) {
    await tokenBlacklistCache.disconnect?.();
    tokenBlacklistCache = null;
  }
}
