/**
 * @apexmail/ai - AI Intelligence Suite Entry Point
 * 
 * Main entry point for the AI service. Starts the Hono HTTP server
 * and initializes all AI services.
 */

import { serve } from '@hono/node-server';
import { app } from './routes.js';

// Service configuration
const PORT = parseInt(process.env.AI_PORT || '3012', 10);
const HOST = process.env.AI_HOST || '0.0.0.0';

// Export all modules for programmatic use
export * from './types.js';
export * from './inference/index.js';
export * from './chatbot/index.js';
export * from './mailbot/index.js';
export * from './sto/index.js';
export * from './content/index.js';
export * from './analytics/index.js';
export { app } from './routes.js';

// Start server if running directly
const isMainModule = import.meta.url === `file://${process.argv[1]}`;

if (isMainModule) {
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
        console.log('');
    });
}
