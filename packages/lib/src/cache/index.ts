/**
 * Cache Wrapper - Thin Interface over Redis/In-Memory
 * 
 * Provides:
 * - Redis-backed distributed cache
 * - In-memory fallback for development
 * - TTL support
 * - Pub/Sub for cache invalidation
 */

import { Redis, type RedisOptions } from 'ioredis';
import { Result } from '../result.js';
import { getLogger, type Logger } from '../logger/index.js';

export interface CacheOptions {
  ttlSeconds?: number;
  prefix?: string;
}

export interface CacheProvider {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, options?: CacheOptions): Promise<void>;
  setNX<T>(key: string, value: T, options?: CacheOptions): Promise<boolean>; // Atomic set-if-not-exists
  delete(key: string): Promise<void>;
  exists(key: string): Promise<boolean>;
  incr(key: string, by?: number): Promise<number>;
  decr(key: string, by?: number): Promise<number>;
  expire(key: string, ttlSeconds: number): Promise<void>;
  ttl(key: string): Promise<number>;
  keys(pattern: string): Promise<string[]>;
  mget<T>(keys: string[]): Promise<(T | null)[]>;
  mset<T>(entries: Array<{ key: string; value: T; ttlSeconds?: number }>): Promise<void>;
  
  // Pub/Sub
  publish(channel: string, message: string): Promise<number>;
  subscribe(channel: string, handler: (message: string) => void): Promise<void>;
  unsubscribe(channel: string): Promise<void>;
  
  // Connection management
  disconnect(): Promise<void>;
  isConnected(): boolean;
}

/**
 * Redis-backed cache implementation
 */
export class RedisCacheProvider implements CacheProvider {
  private readonly client: Redis;
  private readonly subscriber: Redis;
  private readonly prefix: string;
  private readonly logger: Logger;
  private connected = false;
  private readonly subscriptions: Map<string, (message: string) => void> = new Map();

  constructor(options: RedisOptions & { prefix?: string } = {}) {
    this.prefix = options.prefix ?? 'apexmail:';
    this.logger = getLogger().child({ component: 'cache' });

    const redisConfig: RedisOptions = {
      host: process.env['REDIS_HOST'] ?? 'localhost',
      port: parseInt(process.env['REDIS_PORT'] ?? '6379', 10),
      password: process.env['REDIS_PASSWORD'] ?? undefined,
      db: parseInt(process.env['REDIS_DB'] ?? '0', 10),
      maxRetriesPerRequest: 3,
      retryStrategy: (times) => {
        if (times > 10) return null;
        return Math.min(times * 100, 3000);
      },
      ...options,
    };

    this.client = new Redis(redisConfig);
    this.subscriber = new Redis(redisConfig);

    this.client.on('connect', () => {
      this.connected = true;
      this.logger.info('Redis connected');
    });

    this.client.on('error', (err) => {
      this.logger.error('Redis error', { error: err.message });
    });

    this.client.on('close', () => {
      this.connected = false;
      this.logger.warn('Redis connection closed');
    });

    this.subscriber.on('message', (channel, message) => {
      const handler = this.subscriptions.get(channel);
      if (handler) {
        handler(message);
      }
    });
  }

  private key(k: string): string {
    return `${this.prefix}${k}`;
  }

  async get<T>(key: string): Promise<T | null> {
    const value = await this.client.get(this.key(key));
    if (value === null) return null;

    try {
      return JSON.parse(value) as T;
    } catch {
      return value as T;
    }
  }

  async set<T>(key: string, value: T, options: CacheOptions = {}): Promise<void> {
    const serialized = typeof value === 'string' ? value : JSON.stringify(value);
    
    if (options.ttlSeconds) {
      await this.client.setex(this.key(key), options.ttlSeconds, serialized);
    } else {
      await this.client.set(this.key(key), serialized);
    }
  }

  /**
   * Atomic set-if-not-exists operation
   * Returns true if key was set, false if key already exists
   * SECURITY: Prevents TOCTOU race conditions in lock acquisition
   */
  async setNX<T>(key: string, value: T, options: CacheOptions = {}): Promise<boolean> {
    const serialized = typeof value === 'string' ? value : JSON.stringify(value);
    
    if (options.ttlSeconds) {
      // Use SET with NX and EX flags for atomic operation with TTL
      const result = await this.client.set(this.key(key), serialized, 'EX', options.ttlSeconds, 'NX');
      return result === 'OK';
    } else {
      // Use SETNX for atomic operation without TTL
      const result = await this.client.setnx(this.key(key), serialized);
      return result === 1;
    }
  }

  async delete(key: string): Promise<void> {
    await this.client.del(this.key(key));
  }

  async exists(key: string): Promise<boolean> {
    const result = await this.client.exists(this.key(key));
    return result === 1;
  }

  async incr(key: string, by = 1): Promise<number> {
    if (by === 1) {
      return this.client.incr(this.key(key));
    }
    return this.client.incrby(this.key(key), by);
  }

  async decr(key: string, by = 1): Promise<number> {
    if (by === 1) {
      return this.client.decr(this.key(key));
    }
    return this.client.decrby(this.key(key), by);
  }

  async expire(key: string, ttlSeconds: number): Promise<void> {
    await this.client.expire(this.key(key), ttlSeconds);
  }

  async ttl(key: string): Promise<number> {
    return this.client.ttl(this.key(key));
  }

  async keys(pattern: string): Promise<string[]> {
    const fullPattern = this.key(pattern);
    const keys = await this.client.keys(fullPattern);
    return keys.map((k) => k.slice(this.prefix.length));
  }

  async mget<T>(keys: string[]): Promise<(T | null)[]> {
    if (keys.length === 0) return [];
    
    const prefixedKeys = keys.map((k) => this.key(k));
    const values = await this.client.mget(...prefixedKeys);
    
    return values.map((v) => {
      if (v === null) return null;
      try {
        return JSON.parse(v) as T;
      } catch {
        return v as T;
      }
    });
  }

  async mset<T>(entries: Array<{ key: string; value: T; ttlSeconds?: number }>): Promise<void> {
    const pipeline = this.client.pipeline();
    
    for (const entry of entries) {
      const serialized = typeof entry.value === 'string' 
        ? entry.value 
        : JSON.stringify(entry.value);
      
      if (entry.ttlSeconds) {
        pipeline.setex(this.key(entry.key), entry.ttlSeconds, serialized);
      } else {
        pipeline.set(this.key(entry.key), serialized);
      }
    }
    
    await pipeline.exec();
  }

  async publish(channel: string, message: string): Promise<number> {
    return this.client.publish(channel, message);
  }

  async subscribe(channel: string, handler: (message: string) => void): Promise<void> {
    this.subscriptions.set(channel, handler);
    await this.subscriber.subscribe(channel);
  }

  async unsubscribe(channel: string): Promise<void> {
    this.subscriptions.delete(channel);
    await this.subscriber.unsubscribe(channel);
  }

  async disconnect(): Promise<void> {
    await this.subscriber.quit();
    await this.client.quit();
    this.connected = false;
  }

  isConnected(): boolean {
    return this.connected;
  }
}

/**
 * In-memory cache implementation (for development/testing)
 */
export class InMemoryCacheProvider implements CacheProvider {
  private readonly store: Map<string, { value: string; expiresAt?: number }> = new Map();
  private readonly prefix: string;
  private readonly subscriptions: Map<string, Set<(message: string) => void>> = new Map();

  constructor(options: { prefix?: string } = {}) {
    this.prefix = options.prefix ?? 'apexmail:';
    
    // Cleanup expired entries every 10 seconds
    setInterval(() => this.cleanup(), 10000);
  }

  private key(k: string): string {
    return `${this.prefix}${k}`;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      if (entry.expiresAt && entry.expiresAt < now) {
        this.store.delete(key);
      }
    }
  }

  async get<T>(key: string): Promise<T | null> {
    const entry = this.store.get(this.key(key));
    if (!entry) return null;
    
    if (entry.expiresAt && entry.expiresAt < Date.now()) {
      this.store.delete(this.key(key));
      return null;
    }

    try {
      return JSON.parse(entry.value) as T;
    } catch {
      return entry.value as T;
    }
  }

  async set<T>(key: string, value: T, options: CacheOptions = {}): Promise<void> {
    const serialized = typeof value === 'string' ? value : JSON.stringify(value);
    const expiresAt = options.ttlSeconds 
      ? Date.now() + options.ttlSeconds * 1000 
      : undefined;
    
    this.store.set(this.key(key), { value: serialized, expiresAt });
  }

  /**
   * Atomic set-if-not-exists operation
   * Returns true if key was set, false if key already exists
   */
  async setNX<T>(key: string, value: T, options: CacheOptions = {}): Promise<boolean> {
    const existingEntry = this.store.get(this.key(key));
    
    // Check if key exists and is not expired
    if (existingEntry) {
      if (!existingEntry.expiresAt || existingEntry.expiresAt > Date.now()) {
        return false; // Key exists
      }
      // Key expired, delete it
      this.store.delete(this.key(key));
    }
    
    // Set the new value
    const serialized = typeof value === 'string' ? value : JSON.stringify(value);
    const expiresAt = options.ttlSeconds 
      ? Date.now() + options.ttlSeconds * 1000 
      : undefined;
    
    this.store.set(this.key(key), { value: serialized, expiresAt });
    return true;
  }

  async delete(key: string): Promise<void> {
    this.store.delete(this.key(key));
  }

  async exists(key: string): Promise<boolean> {
    const entry = this.store.get(this.key(key));
    if (!entry) return false;
    
    if (entry.expiresAt && entry.expiresAt < Date.now()) {
      this.store.delete(this.key(key));
      return false;
    }
    
    return true;
  }

  async incr(key: string, by = 1): Promise<number> {
    const current = await this.get<number>(key) ?? 0;
    const newValue = current + by;
    await this.set(key, newValue);
    return newValue;
  }

  async decr(key: string, by = 1): Promise<number> {
    return this.incr(key, -by);
  }

  async expire(key: string, ttlSeconds: number): Promise<void> {
    const entry = this.store.get(this.key(key));
    if (entry) {
      entry.expiresAt = Date.now() + ttlSeconds * 1000;
    }
  }

  async ttl(key: string): Promise<number> {
    const entry = this.store.get(this.key(key));
    if (!entry || !entry.expiresAt) return -1;
    
    const remaining = Math.floor((entry.expiresAt - Date.now()) / 1000);
    return remaining > 0 ? remaining : -2;
  }

  async keys(pattern: string): Promise<string[]> {
    const fullPattern = this.key(pattern);
    const regex = new RegExp(
      '^' + fullPattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$'
    );
    
    const result: string[] = [];
    for (const key of this.store.keys()) {
      if (regex.test(key)) {
        result.push(key.slice(this.prefix.length));
      }
    }
    return result;
  }

  async mget<T>(keys: string[]): Promise<(T | null)[]> {
    return Promise.all(keys.map((k) => this.get<T>(k)));
  }

  async mset<T>(entries: Array<{ key: string; value: T; ttlSeconds?: number }>): Promise<void> {
    for (const entry of entries) {
      await this.set(entry.key, entry.value, { ttlSeconds: entry.ttlSeconds });
    }
  }

  async publish(channel: string, message: string): Promise<number> {
    const handlers = this.subscriptions.get(channel);
    if (!handlers) return 0;
    
    for (const handler of handlers) {
      try {
        handler(message);
      } catch {
        // Ignore handler errors
      }
    }
    
    return handlers.size;
  }

  async subscribe(channel: string, handler: (message: string) => void): Promise<void> {
    let handlers = this.subscriptions.get(channel);
    if (!handlers) {
      handlers = new Set();
      this.subscriptions.set(channel, handlers);
    }
    handlers.add(handler);
  }

  async unsubscribe(channel: string): Promise<void> {
    this.subscriptions.delete(channel);
  }

  async disconnect(): Promise<void> {
    this.store.clear();
    this.subscriptions.clear();
  }

  isConnected(): boolean {
    return true;
  }
}

// Factory function
let cacheProvider: CacheProvider | null = null;

export function getCache(): CacheProvider {
  if (!cacheProvider) {
    const useRedis = process.env['REDIS_HOST'] || process.env['NODE_ENV'] === 'production';
    cacheProvider = useRedis 
      ? new RedisCacheProvider()
      : new InMemoryCacheProvider();
  }
  return cacheProvider;
}

export function createCache(options: {
  type: 'redis' | 'memory';
  prefix?: string;
  redisOptions?: RedisOptions;
}): CacheProvider {
  if (options.type === 'redis') {
    return new RedisCacheProvider({ ...options.redisOptions, prefix: options.prefix });
  }
  return new InMemoryCacheProvider({ prefix: options.prefix });
}

// Sliding window rate limiter using cache
export async function checkRateLimit(
  cache: CacheProvider,
  key: string,
  limit: number,
  windowSeconds: number
): Promise<Result<{ allowed: boolean; remaining: number; resetAt: number }, Error>> {
  const windowKey = `ratelimit:${key}:${Math.floor(Date.now() / (windowSeconds * 1000))}`;
  
  const count = await cache.incr(windowKey);
  
  // Set expiry on first request in window
  if (count === 1) {
    await cache.expire(windowKey, windowSeconds);
  }
  
  const remaining = Math.max(0, limit - count);
  const resetAt = (Math.floor(Date.now() / (windowSeconds * 1000)) + 1) * windowSeconds * 1000;
  
  return Result.ok({
    allowed: count <= limit,
    remaining,
    resetAt,
  });
}
