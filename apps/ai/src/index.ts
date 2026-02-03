/**
 * @apexmail/ai - AI Intelligence Suite Entry Point
 * 
 * Main entry point for the AI service. Starts the Hono HTTP server
 * and initializes all AI services with proper warm-up.
 */

import { serve } from '@hono/node-server';
import { app } from './routes.js';
import { ServiceBootstrap, createServiceBootstrap } from './bootstrap.js';

// Service configuration
const PORT = parseInt(process.env.AI_PORT || '3012', 10);
const HOST = process.env.AI_HOST || '0.0.0.0';

// Model configuration from environment
const MODELS_TO_LOAD = process.env.AI_MODELS 
    ? JSON.parse(process.env.AI_MODELS)
    : [];

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

/**
 * Start the AI service with warm-up
 */
async function startService(): Promise<void> {
    console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     █████╗ ██████╗ ███████╗██╗  ██╗    █████╗ ██╗            ║
║    ██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝   ██╔══██╗██║            ║
║    ███████║██████╔╝█████╗   ╚███╔╝    ███████║██║            ║
║    ██╔══██║██╔═══╝ ██╔══╝   ██╔██╗    ██╔══██║██║            ║
║    ██║  ██║██║     ███████╗██╔╝ ██╗   ██║  ██║██║            ║
║    ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝  ╚═╝╚═╝            ║
║                                                               ║
║    AI Intelligence Suite v1.0.0                               ║
║    Local LLM Inference • Chatbot • Mailbot • STO             ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
`);

    console.log('🚀 Starting AI Intelligence Suite...');

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
            console.log('Closing HTTP server...');
        });

        const readiness = bootstrap.getReadiness();
        console.log(`✅ Service initialized in ${readiness.startupTime}ms`);
    } catch (error) {
        console.error('⚠️  Warm-up failed, starting without pre-loaded models:', error);
        bootstrap = new ServiceBootstrap();
        bootstrap.setupSignalHandlers();
    }

    console.log(`📍 Binding to ${HOST}:${PORT}`);

    serve({
        fetch: app.fetch,
        port: PORT,
        hostname: HOST,
    }, (info) => {
        console.log(`✅ AI service listening on http://${info.address}:${info.port}`);
        console.log(`📚 API Documentation: http://${info.address}:${info.port}/`);
        console.log('');
        console.log('Available endpoints:');
        console.log('  POST /api/inference/generate     - Text generation');
        console.log('  POST /api/inference/chat         - Chat completion');
        console.log('  POST /api/inference/embed        - Text embedding');
        console.log('  POST /api/chatbot/session        - Start chat session');
        console.log('  POST /api/chatbot/message        - Send message');
        console.log('  POST /api/mailbot/command        - Execute command');
        console.log('  POST /api/sto/optimize           - Get optimal send time');
        console.log('  POST /api/content/generate       - Generate content');
        console.log('  POST /api/content/subject-lines  - Generate subject lines');
        console.log('  POST /api/analytics/predict      - Make predictions');
        console.log('  POST /api/analytics/segment      - Segment audience');
        console.log('  POST /api/analytics/ab-test      - Analyze A/B test');
        console.log('  POST /api/vectors/search         - Semantic search');
        console.log('  GET  /health                     - Health check');
        console.log('  GET  /ready                      - Readiness check');
        console.log('');
    });
}

// Get bootstrap instance (for health checks etc)
export function getBootstrap(): ServiceBootstrap | null {
    return bootstrap;
}

// Start server if running directly
// Check if this module is the entry point
const isMainModule = typeof require !== 'undefined' && require.main === module;

if (isMainModule) {
    startService().catch(error => {
        console.error('Fatal error starting service:', error);
        process.exit(1);
    });
}
