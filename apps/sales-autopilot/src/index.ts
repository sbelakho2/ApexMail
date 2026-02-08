/**
 * Sales Autopilot Entry Point
 */

import { serve } from '@hono/node-server';
import { createLogger } from '@apexmail/lib';
import { Redis } from 'ioredis';
import { config } from './config.js';
import app from './routes.js';
import { startCampaignProcessor, stopCampaignProcessor, setCampaignRepository, CampaignRepository } from './campaigns/index.js';
import { getLead, initCrmDatabase } from './crm/index.js';
import { closeDbPool, getDbPool } from './db.js';

const logger = createLogger({ name: 'autopilot', level: 'info' });

async function main(): Promise<void> {
    logger.info('Starting Sales Autopilot service', {
        port: config.port,
        env: config.nodeEnv,
    });

    const pool = getDbPool();
    initCrmDatabase(pool);

    // FIX-500-121: Wire CampaignRepository so the drip engine persists to Postgres
    // instead of using ephemeral in-memory Maps that lose state on restart.
    const campaignRepo = new CampaignRepository(pool);
    setCampaignRepository(campaignRepo);

    // FIX-500-122: Create Redis connection from parsed config. The config.redis.url
    // was parsed but never used to create a connection. ioredis is already in
    // package.json dependencies, so we wire it here for use by future subsystems
    // (e.g. caching, pub/sub, rate limiting).
    const redis = new Redis(config.redis.url, {
        keyPrefix: config.redis.keyPrefix,
        maxRetriesPerRequest: 3,
        lazyConnect: true,
    });
    redis.connect().catch((err: unknown) => {
        logger.warn('Redis connection failed — operating without Redis', {
            error: err instanceof Error ? err.message : String(err),
        });
    });

    // Start the campaign processor
    const apiBaseUrl = process.env.API_BASE_URL || 'http://localhost:3010';
    startCampaignProcessor(
        async (leadId) => getLead(leadId),
        async (params) => {
            // FIX-500-015: Wire actual email API instead of no-op logger
            try {
                const response = await fetch(`${apiBaseUrl}/api/v1/messages/send`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        to: params.to,
                        subject: params.subject,
                        htmlBody: params.htmlBody,
                        textBody: params.textBody,
                        from: process.env.DEFAULT_FROM_EMAIL || 'noreply@apexmail.io',
                    }),
                });
                if (!response.ok) {
                    logger.error('Email API returned error', { status: response.status, to: params.to });
                    return { messageId: `failed_${Date.now()}` };
                }
                const result = await response.json() as { messageId?: string };
                return { messageId: result.messageId || `msg_${Date.now()}` };
            } catch (error) {
                logger.error('Failed to send email via API', { error: error instanceof Error ? error.message : String(error), to: params.to });
                return { messageId: `failed_${Date.now()}` };
            }
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
        // FIX-500-122: Disconnect Redis on shutdown
        await redis.quit().catch(() => { /* ignore */ });
        await closeDbPool();
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
