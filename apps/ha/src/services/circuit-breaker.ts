/**
 * Circuit Breaker Service
 * 
 * Implements circuit breaker pattern for resilient service calls:
 * - Automatic failure detection
 * - Graceful degradation
 * - Self-healing
 * - Fallback handling
 * - Half-open state testing
 */

import Redis from 'ioredis';
import { Result } from '@apexmail/lib';

export enum CircuitState {
  CLOSED = 'closed',     // Normal operation
  OPEN = 'open',         // Failures exceeded, rejecting calls
  HALF_OPEN = 'half_open', // Testing if service recovered
}

export interface CircuitConfig {
  name: string;
  failureThreshold: number;       // Failures before opening
  successThreshold: number;       // Successes in half-open to close
  timeout: number;                // Time in open state before half-open
  monitoringWindow: number;       // Window to track failures (ms)
  requestVolumeThreshold: number; // Min requests before evaluating
  fallback?: () => Promise<unknown>;
}

export interface CircuitStats {
  name: string;
  state: CircuitState;
  failures: number;
  successes: number;
  consecutiveSuccesses: number;
  totalRequests: number;
  rejectedRequests: number;
  lastFailure: Date | null;
  lastSuccess: Date | null;
  lastStateChange: Date;
  openedAt: Date | null;
  halfOpenAt: Date | null;
  closedAt: Date | null;
}

interface CircuitData {
  config: CircuitConfig;
  state: CircuitState;
  failures: number;
  successes: number;
  consecutiveSuccesses: number;
  totalRequests: number;
  rejectedRequests: number;
  lastFailure: Date | null;
  lastSuccess: Date | null;
  lastStateChange: Date;
  openedAt: Date | null;
  halfOpenAt: Date | null;
  closedAt: Date | null;
  failureTimestamps: number[];
}

export class CircuitBreakerService {
  private redis: Redis;
  private circuits: Map<string, CircuitData> = new Map();
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(redis: Redis) {
    this.redis = redis;
  }

  /**
   * Initialize circuit breaker service
   */
  async initialize(): Promise<void> {
    // Load circuit states from Redis
    await this.loadCircuitStates();

    // Start cleanup interval
    this.cleanupInterval = setInterval(() => {
      this.cleanupOldFailures();
    }, 60000);

    console.log('[CircuitBreaker] Service initialized');
  }

  /**
   * Register a new circuit breaker
   */
  registerCircuit(config: CircuitConfig): void {
    const circuit: CircuitData = {
      config,
      state: CircuitState.CLOSED,
      failures: 0,
      successes: 0,
      consecutiveSuccesses: 0,
      totalRequests: 0,
      rejectedRequests: 0,
      lastFailure: null,
      lastSuccess: null,
      lastStateChange: new Date(),
      openedAt: null,
      halfOpenAt: null,
      closedAt: new Date(),
      failureTimestamps: [],
    };

    this.circuits.set(config.name, circuit);
    console.log(`[CircuitBreaker] Registered circuit: ${config.name}`);
  }

  /**
   * Execute a function with circuit breaker protection
   */
  async execute<T>(
    circuitName: string,
    fn: () => Promise<T>
  ): Promise<Result<T>> {
    const circuit = this.circuits.get(circuitName);
    if (!circuit) {
      return { ok: false, error: new Error(`Circuit not found: ${circuitName}`) };
    }

    // Check circuit state
    if (!this.canExecute(circuit)) {
      circuit.rejectedRequests++;
      await this.persistCircuitState(circuit);

      // Try fallback if available
      if (circuit.config.fallback) {
        try {
          const fallbackResult = await circuit.config.fallback();
          return { ok: true, value: fallbackResult as T };
        } catch (error) {
          return { ok: false, error: new Error('Circuit open and fallback failed') };
        }
      }

      return { ok: false, error: new Error(`Circuit open: ${circuitName}`) };
    }

    circuit.totalRequests++;

    try {
      const result = await fn();
      this.recordSuccess(circuit);
      await this.persistCircuitState(circuit);
      return { ok: true, value: result };
    } catch (error) {
      this.recordFailure(circuit);
      await this.persistCircuitState(circuit);

      // Try fallback
      if (circuit.config.fallback) {
        try {
          const fallbackResult = await circuit.config.fallback();
          return { ok: true, value: fallbackResult as T };
        } catch {
          // Fallback also failed
        }
      }

      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get circuit breaker stats
   */
  getStats(circuitName: string): CircuitStats | null {
    const circuit = this.circuits.get(circuitName);
    if (!circuit) {
      return null;
    }

    return {
      name: circuit.config.name,
      state: circuit.state,
      failures: circuit.failures,
      successes: circuit.successes,
      consecutiveSuccesses: circuit.consecutiveSuccesses,
      totalRequests: circuit.totalRequests,
      rejectedRequests: circuit.rejectedRequests,
      lastFailure: circuit.lastFailure,
      lastSuccess: circuit.lastSuccess,
      lastStateChange: circuit.lastStateChange,
      openedAt: circuit.openedAt,
      halfOpenAt: circuit.halfOpenAt,
      closedAt: circuit.closedAt,
    };
  }

  /**
   * Get all circuit stats
   */
  getAllStats(): CircuitStats[] {
    return Array.from(this.circuits.values()).map(circuit => ({
      name: circuit.config.name,
      state: circuit.state,
      failures: circuit.failures,
      successes: circuit.successes,
      consecutiveSuccesses: circuit.consecutiveSuccesses,
      totalRequests: circuit.totalRequests,
      rejectedRequests: circuit.rejectedRequests,
      lastFailure: circuit.lastFailure,
      lastSuccess: circuit.lastSuccess,
      lastStateChange: circuit.lastStateChange,
      openedAt: circuit.openedAt,
      halfOpenAt: circuit.halfOpenAt,
      closedAt: circuit.closedAt,
    }));
  }

  /**
   * Force open a circuit
   */
  forceOpen(circuitName: string): Result<void> {
    const circuit = this.circuits.get(circuitName);
    if (!circuit) {
      return { ok: false, error: new Error(`Circuit not found: ${circuitName}`) };
    }

    this.transitionTo(circuit, CircuitState.OPEN);
    console.log(`[CircuitBreaker] Force opened: ${circuitName}`);
    return { ok: true, value: undefined };
  }

  /**
   * Force close a circuit
   */
  forceClose(circuitName: string): Result<void> {
    const circuit = this.circuits.get(circuitName);
    if (!circuit) {
      return { ok: false, error: new Error(`Circuit not found: ${circuitName}`) };
    }

    this.transitionTo(circuit, CircuitState.CLOSED);
    circuit.failures = 0;
    circuit.failureTimestamps = [];
    console.log(`[CircuitBreaker] Force closed: ${circuitName}`);
    return { ok: true, value: undefined };
  }

  /**
   * Reset circuit to initial state
   */
  reset(circuitName: string): Result<void> {
    const circuit = this.circuits.get(circuitName);
    if (!circuit) {
      return { ok: false, error: new Error(`Circuit not found: ${circuitName}`) };
    }

    circuit.state = CircuitState.CLOSED;
    circuit.failures = 0;
    circuit.successes = 0;
    circuit.consecutiveSuccesses = 0;
    circuit.totalRequests = 0;
    circuit.rejectedRequests = 0;
    circuit.lastFailure = null;
    circuit.lastSuccess = null;
    circuit.lastStateChange = new Date();
    circuit.openedAt = null;
    circuit.halfOpenAt = null;
    circuit.closedAt = new Date();
    circuit.failureTimestamps = [];

    console.log(`[CircuitBreaker] Reset: ${circuitName}`);
    return { ok: true, value: undefined };
  }

  /**
   * Get health status of all circuits
   */
  getHealthStatus(): {
    healthy: number;
    degraded: number;
    unhealthy: number;
    circuits: Record<string, { state: CircuitState; health: 'healthy' | 'degraded' | 'unhealthy' }>;
  } {
    let healthy = 0;
    let degraded = 0;
    let unhealthy = 0;
    const circuits: Record<string, { state: CircuitState; health: 'healthy' | 'degraded' | 'unhealthy' }> = {};

    for (const circuit of this.circuits.values()) {
      let health: 'healthy' | 'degraded' | 'unhealthy';

      if (circuit.state === CircuitState.CLOSED) {
        const failureRate = circuit.totalRequests > 0 
          ? circuit.failures / circuit.totalRequests 
          : 0;
        
        if (failureRate < 0.1) {
          health = 'healthy';
          healthy++;
        } else {
          health = 'degraded';
          degraded++;
        }
      } else if (circuit.state === CircuitState.HALF_OPEN) {
        health = 'degraded';
        degraded++;
      } else {
        health = 'unhealthy';
        unhealthy++;
      }

      circuits[circuit.config.name] = { state: circuit.state, health };
    }

    return { healthy, degraded, unhealthy, circuits };
  }

  // Private methods

  private canExecute(circuit: CircuitData): boolean {
    switch (circuit.state) {
      case CircuitState.CLOSED:
        return true;

      case CircuitState.OPEN:
        // Check if timeout has passed
        if (circuit.openedAt) {
          const elapsed = Date.now() - circuit.openedAt.getTime();
          if (elapsed >= circuit.config.timeout) {
            this.transitionTo(circuit, CircuitState.HALF_OPEN);
            return true;
          }
        }
        return false;

      case CircuitState.HALF_OPEN:
        // Allow limited requests in half-open state
        return true;

      default:
        return false;
    }
  }

  private recordSuccess(circuit: CircuitData): void {
    circuit.successes++;
    circuit.consecutiveSuccesses++;
    circuit.lastSuccess = new Date();

    if (circuit.state === CircuitState.HALF_OPEN) {
      if (circuit.consecutiveSuccesses >= circuit.config.successThreshold) {
        this.transitionTo(circuit, CircuitState.CLOSED);
        circuit.failures = 0;
        circuit.failureTimestamps = [];
      }
    }
  }

  private recordFailure(circuit: CircuitData): void {
    const now = Date.now();
    circuit.failures++;
    circuit.consecutiveSuccesses = 0;
    circuit.lastFailure = new Date();
    circuit.failureTimestamps.push(now);

    // Clean up old failures outside monitoring window
    const windowStart = now - circuit.config.monitoringWindow;
    circuit.failureTimestamps = circuit.failureTimestamps.filter(ts => ts > windowStart);

    if (circuit.state === CircuitState.HALF_OPEN) {
      // Any failure in half-open immediately opens the circuit
      this.transitionTo(circuit, CircuitState.OPEN);
    } else if (circuit.state === CircuitState.CLOSED) {
      // Check if we should open
      const recentFailures = circuit.failureTimestamps.length;
      if (
        circuit.totalRequests >= circuit.config.requestVolumeThreshold &&
        recentFailures >= circuit.config.failureThreshold
      ) {
        this.transitionTo(circuit, CircuitState.OPEN);
      }
    }
  }

  private transitionTo(circuit: CircuitData, newState: CircuitState): void {
    const oldState = circuit.state;
    circuit.state = newState;
    circuit.lastStateChange = new Date();

    switch (newState) {
      case CircuitState.OPEN:
        circuit.openedAt = new Date();
        circuit.consecutiveSuccesses = 0;
        break;
      case CircuitState.HALF_OPEN:
        circuit.halfOpenAt = new Date();
        circuit.consecutiveSuccesses = 0;
        break;
      case CircuitState.CLOSED:
        circuit.closedAt = new Date();
        break;
    }

    // Publish state change event
    this.publishStateChange(circuit.config.name, oldState, newState);

    console.log(`[CircuitBreaker] ${circuit.config.name}: ${oldState} -> ${newState}`);
  }

  private async publishStateChange(
    name: string,
    oldState: CircuitState,
    newState: CircuitState
  ): Promise<void> {
    await this.redis.publish('circuit:state', JSON.stringify({
      circuit: name,
      oldState,
      newState,
      timestamp: new Date().toISOString(),
    }));
  }

  private async persistCircuitState(circuit: CircuitData): Promise<void> {
    const key = `circuit:${circuit.config.name}`;
    await this.redis.hset(key, {
      state: circuit.state,
      failures: circuit.failures,
      successes: circuit.successes,
      consecutiveSuccesses: circuit.consecutiveSuccesses,
      totalRequests: circuit.totalRequests,
      rejectedRequests: circuit.rejectedRequests,
      lastFailure: circuit.lastFailure?.toISOString() ?? '',
      lastSuccess: circuit.lastSuccess?.toISOString() ?? '',
      lastStateChange: circuit.lastStateChange.toISOString(),
      openedAt: circuit.openedAt?.toISOString() ?? '',
      halfOpenAt: circuit.halfOpenAt?.toISOString() ?? '',
      closedAt: circuit.closedAt?.toISOString() ?? '',
    });
  }

  private async loadCircuitStates(): Promise<void> {
    for (const circuit of this.circuits.values()) {
      const key = `circuit:${circuit.config.name}`;
      const data = await this.redis.hgetall(key);

      if (data && Object.keys(data).length > 0) {
        circuit.state = data.state as CircuitState;
        circuit.failures = parseInt(data.failures) || 0;
        circuit.successes = parseInt(data.successes) || 0;
        circuit.consecutiveSuccesses = parseInt(data.consecutiveSuccesses) || 0;
        circuit.totalRequests = parseInt(data.totalRequests) || 0;
        circuit.rejectedRequests = parseInt(data.rejectedRequests) || 0;
        circuit.lastFailure = data.lastFailure ? new Date(data.lastFailure) : null;
        circuit.lastSuccess = data.lastSuccess ? new Date(data.lastSuccess) : null;
        circuit.lastStateChange = new Date(data.lastStateChange);
        circuit.openedAt = data.openedAt ? new Date(data.openedAt) : null;
        circuit.halfOpenAt = data.halfOpenAt ? new Date(data.halfOpenAt) : null;
        circuit.closedAt = data.closedAt ? new Date(data.closedAt) : null;
      }
    }
  }

  private cleanupOldFailures(): void {
    const now = Date.now();
    for (const circuit of this.circuits.values()) {
      const windowStart = now - circuit.config.monitoringWindow;
      circuit.failureTimestamps = circuit.failureTimestamps.filter(ts => ts > windowStart);
    }
  }

  /**
   * Shutdown
   */
  shutdown(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}

/**
 * Circuit breaker decorator for methods
 */
export function withCircuitBreaker(
  service: CircuitBreakerService,
  circuitName: string
) {
  return function (
    _target: unknown,
    _propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: unknown[]) {
      const result = await service.execute(circuitName, () => 
        originalMethod.apply(this, args)
      );

      if (!result.ok) {
        throw result.error;
      }

      return result.value;
    };

    return descriptor;
  };
}

/**
 * Create circuit breaker for common services
 */
export function createDefaultCircuits(service: CircuitBreakerService): void {
  // Database circuit
  service.registerCircuit({
    name: 'database',
    failureThreshold: 5,
    successThreshold: 3,
    timeout: 30000,
    monitoringWindow: 60000,
    requestVolumeThreshold: 10,
  });

  // Redis circuit
  service.registerCircuit({
    name: 'redis',
    failureThreshold: 5,
    successThreshold: 3,
    timeout: 15000,
    monitoringWindow: 60000,
    requestVolumeThreshold: 10,
  });

  // External API circuit
  service.registerCircuit({
    name: 'external-api',
    failureThreshold: 3,
    successThreshold: 2,
    timeout: 60000,
    monitoringWindow: 30000,
    requestVolumeThreshold: 5,
  });

  // Email sending circuit
  service.registerCircuit({
    name: 'email-sender',
    failureThreshold: 10,
    successThreshold: 5,
    timeout: 120000,
    monitoringWindow: 300000,
    requestVolumeThreshold: 20,
  });

  // Webhook delivery circuit
  service.registerCircuit({
    name: 'webhook-delivery',
    failureThreshold: 5,
    successThreshold: 3,
    timeout: 60000,
    monitoringWindow: 60000,
    requestVolumeThreshold: 10,
  });

  console.log('[CircuitBreaker] Default circuits registered');
}
