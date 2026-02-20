/**
 * @apexmail/ai - Service Bootstrap and Warm-up
 * 
 * Handles service initialization including:
 * - Model pre-loading and warm-up
 * - Cache initialization
 * - Health checks
 * - Graceful shutdown
 */

// FIX-500-130: The planned `services/pattern-store.ts` (RedisPatternStore) was
// never created. Pattern data is stored in-memory within STOOptimizer and
// EmbeddingStore. If Redis-backed pattern persistence is needed, implement it
// as a new module under `src/services/` and wire it here during bootstrap.

import { EventEmitter } from 'events';
import { Redis } from 'ioredis';
import { ModelLifecycleManager, InferenceCircuitBreaker, InferenceQueue } from './inference/lifecycle.js';
import { InferenceEngine } from './inference/engine.js';

/**
 * Service readiness state
 */
export interface ServiceReadiness {
    ready: boolean;
    modelsLoaded: boolean;
    cacheConnected: boolean;
    healthCheckPassing: boolean;
    startupTime: number;
    uptime: number;
}

/**
 * Model configuration for warm-up
 */
export interface ModelConfig {
    name: string;
    path: string;
    priority: number;
    warmupPrompt?: string;
}

/**
 * Warm-up configuration
 */
export interface WarmupConfig {
    /** Models to pre-load */
    models: ModelConfig[];
    /** Enable Redis cache warming */
    warmCache: boolean;
    /** Redis connection string */
    redisUrl?: string;
    /** Number of warm-up iterations per model */
    warmupIterations: number;
    /** Timeout for each model warm-up (ms) */
    warmupTimeout: number;
    /** Enable parallel model loading */
    parallelLoad: boolean;
    /** Max concurrent model loads */
    maxConcurrentLoads: number;
}

const DEFAULT_WARMUP_CONFIG: WarmupConfig = {
    models: [],
    warmCache: false,
    warmupIterations: 3,
    warmupTimeout: 30000,
    parallelLoad: false,
    maxConcurrentLoads: 2,
};

/**
 * Bootstrap event types
 */
type BootstrapEvent = 
    | 'warmup:start'
    | 'warmup:complete'
    | 'warmup:error'
    | 'model:loading'
    | 'model:loaded'
    | 'model:warmed'
    | 'model:error'
    | 'cache:connected'
    | 'cache:error'
    | 'ready'
    | 'shutdown';

/**
 * Service Bootstrap Manager
 * 
 * Manages service initialization, warm-up, and graceful shutdown.
 */
export class ServiceBootstrap extends EventEmitter {
    private config: WarmupConfig;
    private startTime: number;
    private readyState: ServiceReadiness;
    private lifecycleManagers: Map<string, ModelLifecycleManager> = new Map();
    private circuitBreaker: InferenceCircuitBreaker;
    private requestQueue: InferenceQueue;
    private engines: Map<string, InferenceEngine> = new Map();
    private shutdownHandlers: Array<() => Promise<void>> = [];
    private isShuttingDown = false;
    private redisClient: Redis | null = null;

    constructor(config?: Partial<WarmupConfig>) {
        super();
        this.config = { ...DEFAULT_WARMUP_CONFIG, ...config };
        this.startTime = Date.now();
        this.readyState = {
            ready: false,
            modelsLoaded: false,
            cacheConnected: false,
            healthCheckPassing: false,
            startupTime: 0,
            uptime: 0,
        };
        
        // Initialize lifecycle components
        this.circuitBreaker = new InferenceCircuitBreaker(5, 30000, 3);
        this.requestQueue = new InferenceQueue(100, 60000);
    }

    /**
     * Initialize the service with warm-up
     */
    async initialize(): Promise<ServiceReadiness> {
        console.log('🔄 Starting service initialization...');
        this.emit('warmup:start' as BootstrapEvent);

        try {
            // Load and warm-up models
            if (this.config.models.length > 0) {
                await this.loadModels();
                await this.warmupModels();
                this.readyState.modelsLoaded = true;
            } else {
                console.log('⚠️  No models configured for pre-loading');
                this.readyState.modelsLoaded = true;
            }

            // Initialize cache
            if (this.config.warmCache && this.config.redisUrl) {
                await this.initializeCache();
                this.readyState.cacheConnected = true;
            } else {
                this.readyState.cacheConnected = true; // No cache required
            }

            // Run health check
            this.readyState.healthCheckPassing = await this.performHealthCheck();

            // Mark as ready
            this.readyState.ready = 
                this.readyState.modelsLoaded && 
                this.readyState.cacheConnected &&
                this.readyState.healthCheckPassing;
            
            this.readyState.startupTime = Date.now() - this.startTime;

            if (this.readyState.ready) {
                console.log(`✅ Service ready in ${this.readyState.startupTime}ms`);
                this.emit('ready' as BootstrapEvent, this.readyState);
            } else {
                console.error('❌ Service failed to become ready');
                this.emit('warmup:error' as BootstrapEvent, new Error('Service not ready'));
            }

            this.emit('warmup:complete' as BootstrapEvent, this.readyState);
            return this.readyState;
        } catch (error) {
            console.error('❌ Initialization failed:', error);
            this.emit('warmup:error' as BootstrapEvent, error);
            throw error;
        }
    }

    /**
     * Load configured models
     */
    private async loadModels(): Promise<void> {
        const models = [...this.config.models].sort((a, b) => b.priority - a.priority);

        if (this.config.parallelLoad) {
            // Load models in parallel with concurrency limit
            const batches: typeof models[] = [];
            for (let i = 0; i < models.length; i += this.config.maxConcurrentLoads) {
                batches.push(models.slice(i, i + this.config.maxConcurrentLoads));
            }

            for (const batch of batches) {
                await Promise.all(batch.map(model => this.loadModel(model)));
            }
        } else {
            // Load models sequentially
            for (const model of models) {
                await this.loadModel(model);
            }
        }
    }

    /**
     * Load a single model.
     *
     * With the llama-server migration, "loading" means verifying the
     * sidecar is reachable and has finished model warmup.  The actual
     * GGUF model is held by the llama-server process, not Node.
     */
    private async loadModel(model: ModelConfig): Promise<void> {
        console.log(`📥 Connecting to llama-server for model: ${model.name}`);
        this.emit('model:loading' as BootstrapEvent, { modelName: model.name });

        try {
            const timeoutPromise = new Promise<never>((_, reject) => {
                setTimeout(() => reject(new Error(`Model load timeout: ${model.name}`)), 
                    this.config.warmupTimeout);
            });

            const loadPromise = (async () => {
                // Create lifecycle manager for this model
                const lifecycleManager = new ModelLifecycleManager({
                    warmupIterations: this.config.warmupIterations,
                    loadTimeoutMs: this.config.warmupTimeout,
                });
                this.lifecycleManagers.set(model.name, lifecycleManager);

                // Create inference engine — this is now an HTTP client to llama-server
                const engine = new InferenceEngine({
                    modelPath: model.path,
                    modelName: model.name,
                });
                this.engines.set(model.name, engine);

                // loadModel() polls llama-server /health until 'ok'
                await engine.loadModel(model.path);

                // Load through lifecycle manager for event tracking
                await lifecycleManager.load(async () => {
                    console.log(`  llama-server confirmed ready for ${model.name}`);
                });

                // Set up event forwarding
                lifecycleManager.on('loaded', (info) => {
                    this.emit('model:loaded', { modelName: model.name, latency: info.loadTime });
                });

                lifecycleManager.on('warmup-complete', (info) => {
                    this.emit('model:warmed', { modelName: model.name, latency: info.warmupTime });
                });

                lifecycleManager.on('error', (error) => {
                    this.emit('model:error', { modelName: model.name, error });
                });
            })();

            await Promise.race([loadPromise, timeoutPromise]);
            console.log(`✅ llama-server ready: ${model.name}`);
        } catch (error) {
            console.error(`❌ Failed to connect to llama-server for ${model.name}:`, error);
            this.emit('model:error' as BootstrapEvent, { modelName: model.name, error });
            // Don't throw - allow other models to load
        }
    }

    /**
     * Warm-up loaded models with sample requests
     */
    private async warmupModels(): Promise<void> {
        console.log('🔥 Warming up models...');

        for (const model of this.config.models) {
            const engine = this.engines.get(model.name);
            const lifecycleManager = this.lifecycleManagers.get(model.name);
            if (!engine || !lifecycleManager) continue;

            try {
                const warmupPrompt = model.warmupPrompt || 'Hello, this is a warm-up request.';
                
                await lifecycleManager.warmup(async () => {
                    // Run a sample inference
                    await engine.generate(warmupPrompt, { maxTokens: 10 });
                });

                console.log(`✅ Model warmed: ${model.name}`);
                this.emit('model:warmed' as BootstrapEvent, { modelName: model.name });
            } catch (error) {
                console.warn(`⚠️  Warm-up failed for ${model.name}:`, error);
            }
        }
    }

    /**
     * Initialize Redis cache
     */
    private async initializeCache(): Promise<void> {
        console.log('🔌 Connecting to cache...');
        
        try {
            if (!this.config.redisUrl) {
                throw new Error('Redis URL not configured');
            }

            this.redisClient = new Redis(this.config.redisUrl, {
                keyPrefix: 'ai:',
                maxRetriesPerRequest: 3,
                lazyConnect: true,
            });
            await this.redisClient.connect();
            await this.redisClient.ping();
            
            console.log('✅ Cache connected');
            this.emit('cache:connected' as BootstrapEvent);
        } catch (error) {
            console.error('❌ Cache connection failed:', error);
            this.redisClient = null;
            this.emit('cache:error' as BootstrapEvent, error);
            // Don't throw — allow service to run without cache
        }
    }

    /**
     * Get the Redis client (if connected)
     */
    getRedisClient(): Redis | null {
        return this.redisClient;
    }

    /**
     * Perform health check
     */
    private async performHealthCheck(): Promise<boolean> {
        try {
            // Check circuit breaker state
            const circuitState = this.circuitBreaker.getState();
            if (circuitState.state === 'open') {
                console.warn('⚠️  Circuit breaker is open');
                return false;
            }

            // Check queue health
            const queueStats = this.requestQueue.getStats();
            if (queueStats.queueLength > 80) { // 80% of max 100
                console.warn('⚠️  Request queue near capacity');
            }

            // Check model health
            const loadedModels = this.lifecycleManagers.size;
            if (loadedModels === 0 && this.config.models.length > 0) {
                console.warn('⚠️  No models loaded');
                return false;
            }

            // Verify each model is ready
            for (const [name, manager] of this.lifecycleManagers) {
                if (!manager.isReady()) {
                    console.warn(`⚠️  Model ${name} is not ready`);
                    return false;
                }
            }

            return true;
        } catch (error) {
            console.error('❌ Health check failed:', error);
            return false;
        }
    }

    /**
     * Get current readiness state
     */
    getReadiness(): ServiceReadiness {
        return {
            ...this.readyState,
            uptime: Date.now() - this.startTime,
        };
    }

    /**
     * Get inference engine by model name
     */
    getEngine(modelName: string): InferenceEngine | undefined {
        return this.engines.get(modelName);
    }

    /**
     * Get the lifecycle manager for a model
     */
    getLifecycleManager(modelName: string): ModelLifecycleManager | undefined {
        return this.lifecycleManagers.get(modelName);
    }

    /**
     * Get the circuit breaker
     */
    getCircuitBreaker(): InferenceCircuitBreaker {
        return this.circuitBreaker;
    }

    /**
     * Get the request queue
     */
    getRequestQueue(): InferenceQueue {
        return this.requestQueue;
    }

    /**
     * Execute inference with circuit breaker and queue
     */
    async executeInference<T>(
        request: unknown,
        operation: (req: unknown) => Promise<T>
    ): Promise<T> {
        if (!this.circuitBreaker.canProceed()) {
            throw new Error('Circuit breaker is open');
        }

        try {
            const result = await this.requestQueue.enqueue(request, operation) as T;
            this.circuitBreaker.recordSuccess();
            return result;
        } catch (error) {
            this.circuitBreaker.recordFailure();
            throw error;
        }
    }

    /**
     * Register shutdown handler
     */
    onShutdown(handler: () => Promise<void>): void {
        this.shutdownHandlers.push(handler);
    }

    /**
     * Graceful shutdown
     */
    async shutdown(): Promise<void> {
        if (this.isShuttingDown) {
            console.log('⚠️  Shutdown already in progress');
            return;
        }

        this.isShuttingDown = true;
        console.log('🔄 Starting graceful shutdown...');
        this.emit('shutdown' as BootstrapEvent);

        try {
            // Run custom shutdown handlers
            for (const handler of this.shutdownHandlers) {
                try {
                    await handler();
                } catch (error) {
                    console.error('Shutdown handler error:', error);
                }
            }

            // Shutdown all lifecycle managers
            for (const [modelName, manager] of this.lifecycleManagers) {
                try {
                    await manager.shutdown();
                    console.log(`  Unloaded model: ${modelName}`);
                } catch (error) {
                    console.error(`Error unloading model ${modelName}:`, error);
                }
            }
            this.lifecycleManagers.clear();
            this.engines.clear();

            // Clear queue
            this.requestQueue.clear();

            // Close Redis connection
            if (this.redisClient) {
                try {
                    await this.redisClient.quit();
                    this.redisClient = null;
                } catch { /* best-effort */ }
            }

            console.log('✅ Shutdown complete');
        } catch (error) {
            console.error('❌ Shutdown error:', error);
            throw error;
        }
    }

    /**
     * Setup process signal handlers
     */
    setupSignalHandlers(): void {
        const signals: NodeJS.Signals[] = ['SIGTERM', 'SIGINT', 'SIGUSR2'];

        // FIX-500-391: Use process.once to avoid registering duplicate handlers
        // if setupSignalHandlers() is called more than once
        for (const signal of signals) {
            process.once(signal, async () => {
                console.log(`\n📬 Received ${signal}`);
                await this.shutdown();
                process.exit(0);
            });
        }

        process.once('uncaughtException', async (error) => {
            console.error('Uncaught exception:', error);
            await this.shutdown();
            process.exit(1);
        });

        process.once('unhandledRejection', async (reason) => {
            console.error('Unhandled rejection:', reason);
            // Don't exit on unhandled rejection, but log it
        });
    }
}

/**
 * Create and initialize service bootstrap
 */
export async function createServiceBootstrap(
    config?: Partial<WarmupConfig>
): Promise<ServiceBootstrap> {
    const bootstrap = new ServiceBootstrap(config);
    await bootstrap.initialize();
    return bootstrap;
}

/**
 * Quick start helper for development
 */
export function quickStart(options?: {
    port?: number;
    host?: string;
    models?: WarmupConfig['models'];
}): ServiceBootstrap {
    const bootstrap = new ServiceBootstrap({
        models: options?.models || [],
        warmCache: false,
        warmupIterations: 1,
        warmupTimeout: 10000,
    });

    bootstrap.setupSignalHandlers();

    // Initialize in background
    bootstrap.initialize().catch(error => {
        console.error('Quick start initialization failed:', error);
    });

    return bootstrap;
}

// FIX-500-134: Removed dead module-level `serviceBootstrap` singleton.
// `index.ts` calls `createServiceBootstrap()` which creates and initializes
// its own instance. The previous un-initialized singleton was never used
// externally and only consumed memory.
