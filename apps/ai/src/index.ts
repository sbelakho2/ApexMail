/**
 * @apexmail/ai - AI Intelligence Suite Entry Point
 * 
 * Main entry point for the AI service. Starts the Hono HTTP server
 * and initializes all AI services with proper warm-up.
 */

import { serve } from '@hono/node-server';
import { app } from './routes.js';
import { ServiceBootstrap, createServiceBootstrap } from './bootstrap.js';

// Structured logger for AI service (local — no @apexmail/lib dependency)
const logger = {
    error(msg: string, meta?: Record<string, unknown>) {
        console.error(JSON.stringify({ level: 'error', service: 'ai', msg, ...meta, ts: new Date().toISOString() }));
    },
    info(msg: string, meta?: Record<string, unknown>) {
        console.log(JSON.stringify({ level: 'info', service: 'ai', msg, ...meta, ts: new Date().toISOString() }));
    },
};

// Service configuration
const PORT = parseInt(process.env.AI_PORT || '3012', 10);
const HOST = process.env.AI_HOST || '0.0.0.0';

// Model configuration from environment
// FIX-500-017: Wrap JSON.parse in try-catch to prevent crash on malformed AI_MODELS env
let MODELS_TO_LOAD: ModelConfig[] = [];
if (process.env.AI_MODELS) {
    try {
        MODELS_TO_LOAD = JSON.parse(process.env.AI_MODELS);
    } catch (e) {
        logger.error('Failed to parse AI_MODELS env variable', { error: e instanceof Error ? e.message : String(e) });
    }
}

interface ModelConfig {
    name: string;
    path: string;
    priority: number;
    warmupPrompt?: string;
}

// Export all modules for programmatic use
export * from './types.js';
export * from './inference/index.js';
export * from './chatbot/index.js';
export * from './mailbot/index.js';
export * from './sto/index.js';
export * from './content/index.js';
export * from './analytics/index.js';
export * from './bandits/index.js';
export * from './bootstrap.js';
export { app } from './routes.js';

// Global bootstrap instance
let bootstrap: ServiceBootstrap | null = null;
// FIX-500-392: Track initialization failure to report unhealthy status
let initFailed = false;

/** Returns true if the AI service failed to initialize */
export function isInitFailed(): boolean { return initFailed; }

/**
 * Start the AI service with warm-up
 */
async function startService(): Promise<void> {
    logger.info('ApexMail AI Intelligence Suite v1.0.0');

    logger.info('Starting AI Intelligence Suite...');

    // Initialize with warm-up
    try {
        bootstrap = await createServiceBootstrap({
            models: MODELS_TO_LOAD,
            warmCache: !!process.env.REDIS_URL,
            redisUrl: process.env.REDIS_URL,
            warmupIterations: parseInt(process.env.AI_WARMUP_ITERATIONS || '3', 10),
            warmupTimeout: parseInt(process.env.AI_WARMUP_TIMEOUT || '30000', 10),
            parallelLoad: process.env.AI_PARALLEL_LOAD === 'true',
            maxConcurrentLoads: parseInt(process.env.AI_MAX_CONCURRENT_LOADS || '2', 10),
        });

        // Setup signal handlers for graceful shutdown
        bootstrap.setupSignalHandlers();

        // Add shutdown handler to close server
        bootstrap.onShutdown(async () => {
            logger.info('Closing HTTP server...');
        });

        const readiness = bootstrap.getReadiness();
        logger.info(`Service initialized in ${readiness.startupTime}ms`);
    } catch (error) {
        // FIX-500-392: Mark service as unhealthy so /health returns 503
        // instead of silently serving with no models loaded
        logger.error('Warm-up failed, starting in degraded mode', { error: error instanceof Error ? error.message : String(error) });
        bootstrap = new ServiceBootstrap();
        bootstrap.setupSignalHandlers();
        initFailed = true;
    }

    logger.info(`Binding to ${HOST}:${PORT}`);

    serve({
        fetch: app.fetch,
        port: PORT,
        hostname: HOST,
    }, (info) => {
        logger.info(`AI service listening on http://${info.address}:${info.port}`, {
            endpoints: [
                'POST /api/inference/generate',
                'POST /api/inference/chat',
                'POST /api/inference/embed',
                'POST /api/chatbot/session',
                'POST /api/chatbot/message',
                'POST /api/mailbot/command',
                'POST /api/sto/optimize',
                'POST /api/content/generate',
                'POST /api/content/subject-lines',
                'POST /api/analytics/predict',
                'POST /api/analytics/segment',
                'POST /api/analytics/ab-test',
                'POST /api/vectors/search',
                'GET  /health',
                'GET  /ready',
            ],
        });
    });
}

// Get bootstrap instance (for health checks etc)
export function getBootstrap(): ServiceBootstrap | null {
    return bootstrap;
}

// Start server if running directly
// FIX-500-190: Robust entry point detection — works for both CJS and ESM
const isMainModule = (() => {
    // CJS: require.main check
    try {
        if (typeof require !== 'undefined' && require.main === module) return true;
    } catch {
        // ESM environment — require not available
    }
    // Suffix match as fallback (handles ts-node, compiled output, etc.)
    const arg = process.argv[1] ?? '';
    return arg.endsWith('/ai/src/index.js') ||
        arg.endsWith('/ai/src/index.ts') ||
        arg.endsWith('/ai/dist/index.js');
})();

if (isMainModule) {
    startService().catch(error => {
        logger.error('Fatal error starting service', { error: error instanceof Error ? error.message : String(error) });
        process.exit(1);
    });
}
