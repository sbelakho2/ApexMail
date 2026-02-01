/**
 * Sales Autopilot Entry Point
 */

import { serve } from '@hono/node-server';
import { createLogger } from '@apexmail/lib';
import { config } from './config.js';
import app from './routes.js';
import { startCampaignProcessor, stopCampaignProcessor } from './campaigns/index.js';
import { getLead } from './crm/index.js';

const logger = createLogger({ name: 'autopilot', level: 'info' });

async function main(): Promise<void> {
    logger.info('Starting Sales Autopilot service', {
        port: config.port,
        env: config.nodeEnv,
    });

    // Start the campaign processor
    startCampaignProcessor(
        async (leadId) => getLead(leadId),
        async (params) => {
            // In production, this would send via the actual email API
            logger.info('Would send email', { to: params.to, subject: params.subject });
            return { messageId: `msg_${Date.now()}` };
        }
    );

    // Start the server
    const server = serve({
        fetch: app.fetch,
        port: config.port,
    });

    logger.info(`Sales Autopilot API running on port ${config.port}`);

    // Graceful shutdown
    const shutdown = async (): Promise<void> => {
        logger.info('Shutting down Sales Autopilot...');
        stopCampaignProcessor();
        server.close();
        process.exit(0);
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
}

main().catch((error) => {
    logger.error('Failed to start Sales Autopilot', { error });
    process.exit(1);
});
