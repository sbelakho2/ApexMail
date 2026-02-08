/**
 * Circuit Breaker for Worker Processors
 *
 * Implements circuit breaker pattern to prevent cascading failures
 * when external endpoints (webhooks, email servers) are unavailable.
 *
 * States:
 * - CLOSED: Normal operation, all requests pass through
 * - OPEN: Failures exceeded threshold, requests are rejected immediately
 * - HALF_OPEN: Testing if service recovered, limited requests allowed
 */

import type { Redis } from 'ioredis';

export enum CircuitState {
  CLOSED = 'closed',
  OPEN = 'open',
  HALF_OPEN = 'half_open',
}

export interface CircuitBreakerConfig {
  /** Unique name for this circuit (e.g., "webhook:endpoint123") */
  name: string;
  /** Number of failures before opening the circuit */
  failureThreshold: number;
  /** Time in milliseconds before transitioning from OPEN to HALF_OPEN */
  resetTimeout: number;
  /** Number of successful requests in HALF_OPEN needed to close circuit */
  successThreshold: number;
  /** Window in milliseconds to track failures (rolling window) */
  rollingWindowMs: number;
}

interface CircuitStats {
  failures: number;
  successes: number;
  lastFailureTime: number;
  state: CircuitState;
  openedAt: number;
}

const DEFAULT_CONFIG: Omit<CircuitBreakerConfig, 'name'> = {
  failureThreshold: 5,
  resetTimeout: 30000,  // 30 seconds
  successThreshold: 2,
  rollingWindowMs: 60000, // 1 minute
};

/**
 * Redis-backed Circuit Breaker for distributed state
 */
export class CircuitBreaker {
  private readonly redis: Redis;
  private readonly config: CircuitBreakerConfig;
  private readonly keyPrefix: string;

  /**
   * FIX-500-112: Circuit breaker key TTL in seconds (24 hours).
   * Without TTL, abandoned circuit breaker keys persist in Redis forever.
   */
  private static readonly KEY_TTL_SECONDS = 86400;

  constructor(redis: Redis, config: Partial<CircuitBreakerConfig> & { name: string }) {
    this.redis = redis;
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.keyPrefix = `circuit:${this.config.name}`;
  }

  /**
   * Check if a request should be allowed through the circuit
   */
  async canExecute(): Promise<boolean> {
    const state = await this.getState();

    switch (state) {
      case CircuitState.CLOSED:
        return true;

      case CircuitState.OPEN: {
        const stats = await this.getStats();
        const timeSinceOpen = Date.now() - stats.openedAt;

        // Transition to HALF_OPEN if reset timeout has elapsed
        if (timeSinceOpen >= this.config.resetTimeout) {
          // FIX-500-111: Only one caller should transition to HALF_OPEN.
          // Use SET NX to ensure only the first concurrent caller wins.
          const acquired = await this.redis.set(
            `${this.keyPrefix}:half_open_lock`,
            '1',
            'EX', 30,  // lock expires after 30s
            'NX'
          );
          if (!acquired) {
            return false; // Another caller already transitioning
          }
          await this.setState(CircuitState.HALF_OPEN);
          return true; // Allow one request through
        }
        return false;
      }

      case CircuitState.HALF_OPEN:
        // Allow limited requests in half-open state
        return true;

      default:
        return true;
    }
  }

  /**
   * Record a successful request
   */
  async recordSuccess(): Promise<void> {
    const state = await this.getState();

    if (state === CircuitState.HALF_OPEN) {
      // FIX-500-110: Set TTL on successes counter so stale successes
      // from hours ago don't incorrectly close the circuit.
      const successes = await this.redis.incr(`${this.keyPrefix}:successes`);
      await this.redis.expire(`${this.keyPrefix}:successes`, 120); // 2 minute TTL

      if (successes >= this.config.successThreshold) {
        // Circuit recovered, close it
        await this.close();
      }
    }

    // FIX-500-113: In CLOSED state, let the rolling window handle failure
    // expiration naturally instead of wiping all failures on a single success.
  }

  /**
   * Record a failed request
   */
  async recordFailure(): Promise<void> {
    const state = await this.getState();
    const now = Date.now();

    // Track failure timestamp for rolling window
    await this.redis.zadd(`${this.keyPrefix}:failure_times`, now, now.toString());

    // Remove old failures outside the rolling window
    const windowStart = now - this.config.rollingWindowMs;
    await this.redis.zremrangebyscore(`${this.keyPrefix}:failure_times`, '-inf', windowStart);

    // Count failures in the rolling window
    const failureCount = await this.redis.zcard(`${this.keyPrefix}:failure_times`);

    // Update last failure time
    // FIX-500-112: Set TTL on last_failure and failure_times
    await this.redis.set(`${this.keyPrefix}:last_failure`, now.toString(), 'EX', CircuitBreaker.KEY_TTL_SECONDS);
    await this.redis.expire(`${this.keyPrefix}:failure_times`, CircuitBreaker.KEY_TTL_SECONDS);

    if (state === CircuitState.HALF_OPEN) {
      // Any failure in half-open state opens the circuit again
      await this.open();
    } else if (state === CircuitState.CLOSED && failureCount >= this.config.failureThreshold) {
      // Threshold exceeded, open the circuit
      await this.open();
    }
  }

  /**
   * Execute a function with circuit breaker protection
   */
  async execute<T>(fn: () => Promise<T>): Promise<{ ok: true; value: T } | { ok: false; error: Error }> {
    if (!await this.canExecute()) {
      return {
        ok: false,
        error: new Error(`Circuit ${this.config.name} is open`),
      };
    }

    try {
      const result = await fn();
      await this.recordSuccess();
      return { ok: true, value: result };
    } catch (error) {
      await this.recordFailure();
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get current circuit state
   */
  async getState(): Promise<CircuitState> {
    const state = await this.redis.get(`${this.keyPrefix}:state`);
    return (state as CircuitState) || CircuitState.CLOSED;
  }

  /**
   * Get circuit statistics
   */
  async getStats(): Promise<CircuitStats> {
    const [state, failures, successes, lastFailure, openedAt] = await this.redis.mget(
      `${this.keyPrefix}:state`,
      `${this.keyPrefix}:failures`,
      `${this.keyPrefix}:successes`,
      `${this.keyPrefix}:last_failure`,
      `${this.keyPrefix}:opened_at`
    );

    return {
      state: (state as CircuitState) || CircuitState.CLOSED,
      failures: failures ? parseInt(failures, 10) : 0,
      successes: successes ? parseInt(successes, 10) : 0,
      lastFailureTime: lastFailure ? parseInt(lastFailure, 10) : 0,
      openedAt: openedAt ? parseInt(openedAt, 10) : 0,
    };
  }

  /**
   * Manually open the circuit (for testing or emergency)
   */
  async open(): Promise<void> {
    await this.setState(CircuitState.OPEN);
    // FIX-500-112: Set TTL on opened_at to prevent forever accumulation
    await this.redis.set(`${this.keyPrefix}:opened_at`, Date.now().toString(), 'EX', CircuitBreaker.KEY_TTL_SECONDS);
    await this.redis.del(`${this.keyPrefix}:successes`);
  }

  /**
   * Manually close the circuit
   */
  async close(): Promise<void> {
    await this.setState(CircuitState.CLOSED);
    await this.redis.del(
      `${this.keyPrefix}:failures`,
      `${this.keyPrefix}:successes`,
      `${this.keyPrefix}:failure_times`,
      `${this.keyPrefix}:opened_at`
    );
  }

  /**
   * Reset the circuit (clear all state)
   */
  async reset(): Promise<void> {
    await this.close();
  }

  private async setState(state: CircuitState): Promise<void> {
    // FIX-500-112: Set TTL on state key to prevent forever accumulation
    await this.redis.set(`${this.keyPrefix}:state`, state, 'EX', CircuitBreaker.KEY_TTL_SECONDS);
  }
}

/**
 * Factory for creating circuit breakers with shared Redis instance.
 * Includes LRU eviction to prevent unbounded memory growth.
 */
export class CircuitBreakerFactory {
  private readonly redis: Redis;
  private readonly breakers: Map<string, CircuitBreaker> = new Map();
  private readonly defaultConfig: Partial<Omit<CircuitBreakerConfig, 'name'>>;
  private readonly maxSize: number;

  constructor(redis: Redis, defaultConfig?: Partial<Omit<CircuitBreakerConfig, 'name'>>, maxSize: number = 10000) {
    this.redis = redis;
    this.defaultConfig = defaultConfig || {};
    this.maxSize = maxSize;
  }

  /**
   * Get or create a circuit breaker for a given name.
   * Uses LRU eviction: oldest entries removed when maxSize is exceeded.
   */
  get(name: string, config?: Partial<Omit<CircuitBreakerConfig, 'name'>>): CircuitBreaker {
    let breaker = this.breakers.get(name);

    if (breaker) {
      // Move to end (most recently used) by re-inserting
      this.breakers.delete(name);
      this.breakers.set(name, breaker);
      return breaker;
    }

    // Evict oldest entries if at capacity
    while (this.breakers.size >= this.maxSize) {
      const oldestKey = this.breakers.keys().next().value;
      if (oldestKey !== undefined) {
        this.breakers.delete(oldestKey);
      } else {
        break;
      }
    }

    breaker = new CircuitBreaker(this.redis, {
      name,
      ...this.defaultConfig,
      ...config,
    });
    this.breakers.set(name, breaker);

    return breaker;
  }

  /**
   * Get all circuit breaker statistics
   */
  async getAllStats(): Promise<Map<string, CircuitStats & { name: string }>> {
    const stats = new Map<string, CircuitStats & { name: string }>();

    for (const [name, breaker] of this.breakers) {
      const breakerStats = await breaker.getStats();
      stats.set(name, { ...breakerStats, name });
    }

    return stats;
  }
}
