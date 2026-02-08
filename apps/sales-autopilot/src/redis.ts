/**
 * Sales Autopilot Redis Client Singleton
 * FIX-500-153/154: Provide Redis access to sub-modules (rate-limiter, robots-service).
 */

import { Redis } from 'ioredis';
import { config } from './config.js';

let redis: Redis | null = null;

export function getRedisClient(): Redis {
    if (!redis) {
        redis = new Redis(config.redis.url, {
            keyPrefix: config.redis.keyPrefix,
            maxRetriesPerRequest: 3,
            lazyConnect: true,
        });
        redis.connect().catch(() => {
            // Caller should handle unavailability gracefully
        });
    }
    return redis;
}

export async function closeRedisClient(): Promise<void> {
    if (redis) {
        await redis.quit().catch(() => { /* ignore */ });
        redis = null;
    }
}
