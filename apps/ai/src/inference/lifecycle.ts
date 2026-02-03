/**
 * @apexmail/ai - Model Lifecycle Manager
 * 
 * Manages model loading, warm-up, health checks, and graceful shutdown.
 * Ensures models are ready before serving requests.
 */

import { EventEmitter } from 'events';
import type { ModelStatus, ModelMetrics } from '../types.js';

/**
 * Model health state
 */
export interface ModelHealth {
    status: ModelStatus;
    loadedAt: Date | null;
    lastHealthCheck: Date | null;
    lastError: string | null;
    consecutiveErrors: number;
    warmupComplete: boolean;
}

/**
 * Lifecycle events
 */
export interface LifecycleEvents {
    'loading': () => void;
    'loaded': (info: { modelName: string; loadTime: number }) => void;
    'warmup-start': () => void;
    'warmup-complete': (info: { warmupTime: number }) => void;
    'error': (error: Error) => void;
    'health-check': (health: ModelHealth) => void;
    'shutdown': () => void;
}

/**
 * Lifecycle configuration
 */
export interface LifecycleConfig {
    /** Warm-up iterations to run after loading */
    warmupIterations: number;
    /** Health check interval in ms */
    healthCheckIntervalMs: number;
    /** Maximum consecutive errors before marking unhealthy */
    maxConsecutiveErrors: number;
    /** Timeout for model loading in ms */
    loadTimeoutMs: number;
    /** Whether to auto-load on construction */
    autoLoad: boolean;
}

const DEFAULT_LIFECYCLE_CONFIG: LifecycleConfig = {
    warmupIterations: 3,
    healthCheckIntervalMs: 30000,
    maxConsecutiveErrors: 5,
    loadTimeoutMs: 60000,
    autoLoad: false,
};

/**
 * Model Lifecycle Manager
 * 
 * Handles the complete lifecycle of AI models:
 * 1. Loading with timeout protection
 * 2. Warm-up runs to prime caches
 * 3. Periodic health checks
 * 4. Graceful shutdown
 */
export class ModelLifecycleManager extends EventEmitter {
    private config: LifecycleConfig;
    private health: ModelHealth;
    private healthCheckInterval: NodeJS.Timeout | null = null;
    private metrics: ModelMetrics;
    private loadPromise: Promise<void> | null = null;

    constructor(config?: Partial<LifecycleConfig>) {
        super();
        this.config = { ...DEFAULT_LIFECYCLE_CONFIG, ...config };
        
        this.health = {
            status: 'unloaded',
            loadedAt: null,
            lastHealthCheck: null,
            lastError: null,
            consecutiveErrors: 0,
            warmupComplete: false,
        };

        this.metrics = {
            requestCount: 0,
            avgLatencyMs: 0,
            errorRate: 0,
            tokensProcessed: 0,
        };
    }

    /**
     * Get current health status
     */
    getHealth(): ModelHealth {
        return { ...this.health };
    }

    /**
     * Get metrics
     */
    getMetrics(): ModelMetrics {
        return { ...this.metrics };
    }

    /**
     * Check if model is ready for inference
     */
    isReady(): boolean {
        return this.health.status === 'ready' && this.health.warmupComplete;
    }

    /**
     * Load model with lifecycle management
     */
    async load(loadFn: () => Promise<void>): Promise<void> {
        if (this.loadPromise) {
            return this.loadPromise;
        }

        this.loadPromise = this._doLoad(loadFn);
        return this.loadPromise;
    }

    private async _doLoad(loadFn: () => Promise<void>): Promise<void> {
        const startTime = Date.now();
        this.health.status = 'loading';
        this.emit('loading');

        try {
            // Load with timeout
            await Promise.race([
                loadFn(),
                new Promise<never>((_, reject) => {
                    setTimeout(() => reject(new Error('Model load timeout')), this.config.loadTimeoutMs);
                }),
            ]);

            const loadTime = Date.now() - startTime;
            this.health.status = 'ready';
            this.health.loadedAt = new Date();
            this.health.lastError = null;
            this.health.consecutiveErrors = 0;

            this.emit('loaded', { modelName: 'model', loadTime });

        } catch (error) {
            this.health.status = 'error';
            this.health.lastError = error instanceof Error ? error.message : 'Unknown error';
            this.emit('error', error instanceof Error ? error : new Error(String(error)));
            throw error;
        } finally {
            this.loadPromise = null;
        }
    }

    /**
     * Run warm-up iterations
     */
    async warmup(warmupFn: () => Promise<void>): Promise<void> {
        if (this.health.status !== 'ready') {
            throw new Error('Model must be loaded before warmup');
        }

        this.emit('warmup-start');
        const startTime = Date.now();

        for (let i = 0; i < this.config.warmupIterations; i++) {
            try {
                await warmupFn();
            } catch (error) {
                console.warn(`Warmup iteration ${i + 1} failed:`, error);
            }
        }

        this.health.warmupComplete = true;
        this.emit('warmup-complete', { warmupTime: Date.now() - startTime });
    }

    /**
     * Start periodic health checks
     */
    startHealthChecks(checkFn: () => Promise<boolean>): void {
        if (this.healthCheckInterval) {
            clearInterval(this.healthCheckInterval);
        }

        this.healthCheckInterval = setInterval(async () => {
            try {
                const healthy = await checkFn();
                this.health.lastHealthCheck = new Date();

                if (healthy) {
                    this.health.consecutiveErrors = 0;
                    if (this.health.status === 'error') {
                        this.health.status = 'ready';
                    }
                } else {
                    this.health.consecutiveErrors++;
                    if (this.health.consecutiveErrors >= this.config.maxConsecutiveErrors) {
                        this.health.status = 'error';
                    }
                }

                this.emit('health-check', this.getHealth());

            } catch (error) {
                this.health.lastError = error instanceof Error ? error.message : 'Unknown error';
                this.health.consecutiveErrors++;

                if (this.health.consecutiveErrors >= this.config.maxConsecutiveErrors) {
                    this.health.status = 'error';
                }
            }
        }, this.config.healthCheckIntervalMs);
    }

    /**
     * Stop health checks
     */
    stopHealthChecks(): void {
        if (this.healthCheckInterval) {
            clearInterval(this.healthCheckInterval);
            this.healthCheckInterval = null;
        }
    }

    /**
     * Record a successful request
     */
    recordRequest(latencyMs: number, tokensProcessed: number): void {
        this.metrics.requestCount++;
        this.metrics.tokensProcessed += tokensProcessed;
        this.metrics.lastUsed = new Date();

        // Update rolling average
        this.metrics.avgLatencyMs =
            (this.metrics.avgLatencyMs * (this.metrics.requestCount - 1) + latencyMs) /
            this.metrics.requestCount;
    }

    /**
     * Record an error
     */
    recordError(): void {
        this.metrics.requestCount++;
        this.health.consecutiveErrors++;

        // Update error rate
        this.metrics.errorRate =
            (this.metrics.errorRate * (this.metrics.requestCount - 1) + 1) /
            this.metrics.requestCount;

        if (this.health.consecutiveErrors >= this.config.maxConsecutiveErrors) {
            this.health.status = 'error';
        }
    }

    /**
     * Graceful shutdown
     */
    async shutdown(cleanupFn?: () => Promise<void>): Promise<void> {
        this.emit('shutdown');
        this.stopHealthChecks();

        if (cleanupFn && this.health.status !== 'unloaded') {
            try {
                await cleanupFn();
            } catch (error) {
                console.error('Error during model cleanup:', error);
            }
        }

        this.health.status = 'unloaded';
        this.health.loadedAt = null;
        this.health.warmupComplete = false;
    }
}

/**
 * Circuit breaker for inference requests
 * Prevents cascading failures when model is unhealthy
 */
export class InferenceCircuitBreaker {
    private state: 'closed' | 'open' | 'half-open' = 'closed';
    private failures: number = 0;
    private lastFailure: Date | null = null;
    private successesSinceHalfOpen: number = 0;

    constructor(
        private readonly failureThreshold: number = 5,
        private readonly resetTimeoutMs: number = 30000,
        private readonly halfOpenSuccessThreshold: number = 3
    ) {}

    /**
     * Check if request should be allowed
     */
    canProceed(): boolean {
        if (this.state === 'closed') return true;

        if (this.state === 'open') {
            // Check if we should try half-open
            if (this.lastFailure && Date.now() - this.lastFailure.getTime() > this.resetTimeoutMs) {
                this.state = 'half-open';
                this.successesSinceHalfOpen = 0;
                return true;
            }
            return false;
        }

        // half-open: allow limited requests
        return true;
    }

    /**
     * Record successful request
     */
    recordSuccess(): void {
        if (this.state === 'half-open') {
            this.successesSinceHalfOpen++;
            if (this.successesSinceHalfOpen >= this.halfOpenSuccessThreshold) {
                this.state = 'closed';
                this.failures = 0;
            }
        } else if (this.state === 'closed') {
            this.failures = 0;
        }
    }

    /**
     * Record failed request
     */
    recordFailure(): void {
        this.failures++;
        this.lastFailure = new Date();

        if (this.state === 'half-open') {
            this.state = 'open';
        } else if (this.failures >= this.failureThreshold) {
            this.state = 'open';
        }
    }

    /**
     * Get current state
     */
    getState(): { state: string; failures: number; lastFailure: Date | null } {
        return {
            state: this.state,
            failures: this.failures,
            lastFailure: this.lastFailure,
        };
    }

    /**
     * Force reset the circuit breaker
     */
    reset(): void {
        this.state = 'closed';
        this.failures = 0;
        this.lastFailure = null;
        this.successesSinceHalfOpen = 0;
    }
}

/**
 * Request queue for rate limiting and batching
 */
export class InferenceQueue {
    private queue: Array<{
        id: string;
        resolve: (value: unknown) => void;
        reject: (error: Error) => void;
        request: unknown;
        timestamp: Date;
    }> = [];
    private processing: boolean = false;
    
    constructor(
        private readonly maxQueueSize: number = 100,
        private readonly timeoutMs: number = 30000
    ) {}

    /**
     * Add request to queue
     */
    async enqueue<T, R>(request: T, processFn: (req: T) => Promise<R>): Promise<R> {
        if (this.queue.length >= this.maxQueueSize) {
            throw new Error('Inference queue full');
        }

        return new Promise((resolve, reject) => {
            const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
            
            this.queue.push({
                id,
                resolve: resolve as (value: unknown) => void,
                reject,
                request,
                timestamp: new Date(),
            });

            // Set timeout
            setTimeout(() => {
                const idx = this.queue.findIndex(q => q.id === id);
                if (idx !== -1) {
                    this.queue.splice(idx, 1);
                    reject(new Error('Request timeout'));
                }
            }, this.timeoutMs);

            // Trigger processing
            this.processQueue(processFn as (req: unknown) => Promise<unknown>);
        });
    }

    private async processQueue(processFn: (req: unknown) => Promise<unknown>): Promise<void> {
        if (this.processing || this.queue.length === 0) return;

        this.processing = true;

        while (this.queue.length > 0) {
            const item = this.queue.shift();
            if (!item) continue;

            try {
                const result = await processFn(item.request);
                item.resolve(result);
            } catch (error) {
                item.reject(error instanceof Error ? error : new Error(String(error)));
            }
        }

        this.processing = false;
    }

    /**
     * Get queue statistics
     */
    getStats(): { queueLength: number; processing: boolean } {
        return {
            queueLength: this.queue.length,
            processing: this.processing,
        };
    }

    /**
     * Clear the queue
     */
    clear(): void {
        for (const item of this.queue) {
            item.reject(new Error('Queue cleared'));
        }
        this.queue = [];
    }
}
