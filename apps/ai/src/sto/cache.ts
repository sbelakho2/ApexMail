/**
 * @apexmail/ai - Redis-backed STO Cache
 * 
 * Persistent caching layer for Send Time Optimization.
 * Stores engagement patterns and computed recommendations in Redis
 * for durability across service restarts.
 */

import type { Redis } from 'ioredis';
import type { EngagementPattern, STORecommendation } from '../types.js';

/**
 * Cache configuration
 */
export interface STOCacheConfig {
    /** Key prefix for all STO keys */
    keyPrefix: string;
    /** TTL for engagement patterns in seconds */
    patternTTL: number;
    /** TTL for computed recommendations in seconds */
    recommendationTTL: number;
    /** Maximum patterns to cache per subscriber */
    maxPatternsPerSubscriber: number;
    /** Maximum patterns to cache per list */
    maxPatternsPerList: number;
}

const DEFAULT_CACHE_CONFIG: STOCacheConfig = {
    keyPrefix: 'sto:',
    patternTTL: 30 * 24 * 60 * 60, // 30 days
    recommendationTTL: 24 * 60 * 60, // 24 hours
    maxPatternsPerSubscriber: 100,
    maxPatternsPerList: 10000,
};

/**
 * Redis-backed STO Cache
 */
export class STOCache {
    private redis: Redis | null = null;
    private config: STOCacheConfig;
    private connected: boolean = false;

    constructor(config?: Partial<STOCacheConfig>) {
        this.config = { ...DEFAULT_CACHE_CONFIG, ...config };
    }

    /**
     * Connect to Redis
     */
    async connect(redis: Redis): Promise<void> {
        this.redis = redis;
        
        // Test connection
        await redis.ping();
        this.connected = true;
    }

    /**
     * Check if connected
     */
    isConnected(): boolean {
        return this.connected && this.redis !== null;
    }

    /**
     * Disconnect from Redis
     */
    async disconnect(): Promise<void> {
        this.connected = false;
        this.redis = null;
    }

    // ========================================
    // ENGAGEMENT PATTERNS
    // ========================================

    /**
     * Store engagement pattern for a subscriber
     */
    async storePattern(subscriberId: string, pattern: EngagementPattern): Promise<void> {
        if (!this.redis) return;

        const key = this.getSubscriberPatternKey(subscriberId);
        const serialized = JSON.stringify({
            ...pattern,
            timestamp: pattern.timestamp.toISOString(),
            sentAt: pattern.sentAt?.toISOString(),
            openedAt: pattern.openedAt?.toISOString(),
            clickedAt: pattern.clickedAt?.toISOString(),
            lastEngagement: pattern.lastEngagement?.toISOString(),
        });

        // Use sorted set with timestamp as score for automatic ordering
        await this.redis.zadd(key, pattern.timestamp.getTime(), serialized);
        await this.redis.expire(key, this.config.patternTTL);

        // Trim to max patterns
        await this.redis.zremrangebyrank(key, 0, -this.config.maxPatternsPerSubscriber - 1);
    }

    /**
     * Store multiple patterns efficiently
     */
    async storePatternssBatch(patterns: Array<{ subscriberId: string; pattern: EngagementPattern }>): Promise<void> {
        if (!this.redis || patterns.length === 0) return;

        const pipeline = this.redis.pipeline();

        for (const { subscriberId, pattern } of patterns) {
            const key = this.getSubscriberPatternKey(subscriberId);
            const serialized = JSON.stringify({
                ...pattern,
                timestamp: pattern.timestamp.toISOString(),
                sentAt: pattern.sentAt?.toISOString(),
                openedAt: pattern.openedAt?.toISOString(),
                clickedAt: pattern.clickedAt?.toISOString(),
                lastEngagement: pattern.lastEngagement?.toISOString(),
            });

            pipeline.zadd(key, pattern.timestamp.getTime(), serialized);
            pipeline.expire(key, this.config.patternTTL);
        }

        await pipeline.exec();
    }

    /**
     * Get patterns for a subscriber
     */
    async getPatterns(subscriberId: string, limit?: number): Promise<EngagementPattern[]> {
        if (!this.redis) return [];

        const key = this.getSubscriberPatternKey(subscriberId);
        const count = limit || this.config.maxPatternsPerSubscriber;

        // Get most recent patterns
        const results = await this.redis.zrevrange(key, 0, count - 1);

        return results.map(r => {
            const parsed = JSON.parse(r);
            return {
                ...parsed,
                timestamp: new Date(parsed.timestamp),
                sentAt: parsed.sentAt ? new Date(parsed.sentAt) : undefined,
                openedAt: parsed.openedAt ? new Date(parsed.openedAt) : undefined,
                clickedAt: parsed.clickedAt ? new Date(parsed.clickedAt) : undefined,
                lastEngagement: parsed.lastEngagement ? new Date(parsed.lastEngagement) : undefined,
            };
        });
    }

    /**
     * Get patterns for multiple subscribers
     */
    async getPatternsBatch(subscriberIds: string[], limit?: number): Promise<Map<string, EngagementPattern[]>> {
        if (!this.redis || subscriberIds.length === 0) return new Map();

        const pipeline = this.redis.pipeline();
        const count = limit || this.config.maxPatternsPerSubscriber;

        for (const subscriberId of subscriberIds) {
            const key = this.getSubscriberPatternKey(subscriberId);
            pipeline.zrevrange(key, 0, count - 1);
        }

        const results = await pipeline.exec();
        const map = new Map<string, EngagementPattern[]>();

        if (results) {
            for (let i = 0; i < subscriberIds.length; i++) {
                const [err, data] = results[i] || [];
                if (!err && Array.isArray(data)) {
                    const patterns = (data as string[]).map(r => {
                        const parsed = JSON.parse(r);
                        return {
                            ...parsed,
                            timestamp: new Date(parsed.timestamp),
                            sentAt: parsed.sentAt ? new Date(parsed.sentAt) : undefined,
                            openedAt: parsed.openedAt ? new Date(parsed.openedAt) : undefined,
                            clickedAt: parsed.clickedAt ? new Date(parsed.clickedAt) : undefined,
                            lastEngagement: parsed.lastEngagement ? new Date(parsed.lastEngagement) : undefined,
                        };
                    });
                    map.set(subscriberIds[i], patterns);
                }
            }
        }

        return map;
    }

    /**
     * Delete patterns for a subscriber
     */
    async deletePatterns(subscriberId: string): Promise<void> {
        if (!this.redis) return;
        await this.redis.del(this.getSubscriberPatternKey(subscriberId));
    }

    // ========================================
    // RECOMMENDATIONS CACHE
    // ========================================

    /**
     * Cache computed recommendations
     */
    async cacheRecommendations(
        cacheKey: string,
        recommendations: STORecommendation[],
        ttl?: number
    ): Promise<void> {
        if (!this.redis) return;

        const key = this.getRecommendationKey(cacheKey);
        const serialized = JSON.stringify(recommendations.map(r => ({
            ...r,
            sendTime: r.sendTime.toISOString(),
            optimalSendTime: r.optimalSendTime?.toISOString(),
            alternativeTimes: r.alternativeTimes?.map(t => t.toISOString()),
        })));

        await this.redis.setex(key, ttl || this.config.recommendationTTL, serialized);
    }

    /**
     * Get cached recommendations
     */
    async getCachedRecommendations(cacheKey: string): Promise<STORecommendation[] | null> {
        if (!this.redis) return null;

        const key = this.getRecommendationKey(cacheKey);
        const data = await this.redis.get(key);

        if (!data) return null;

        const parsed = JSON.parse(data);
        return parsed.map((r: Record<string, unknown>) => ({
            ...r,
            sendTime: new Date(r.sendTime as string),
            optimalSendTime: r.optimalSendTime ? new Date(r.optimalSendTime as string) : undefined,
            alternativeTimes: (r.alternativeTimes as string[] | undefined)?.map((t: string) => new Date(t)),
        }));
    }

    /**
     * Invalidate cached recommendations
     */
    async invalidateRecommendations(cacheKey: string): Promise<void> {
        if (!this.redis) return;
        await this.redis.del(this.getRecommendationKey(cacheKey));
    }

    // ========================================
    // AGGREGATE STATISTICS
    // ========================================

    /**
     * Store hourly aggregate for a list
     */
    async storeHourlyAggregate(
        listId: string,
        hour: number,
        day: number,
        stats: { sends: number; opens: number; clicks: number }
    ): Promise<void> {
        if (!this.redis) return;

        const key = this.getListAggregateKey(listId);
        const field = `${day}:${hour}`;
        const current = await this.redis.hget(key, field);
        
        const aggregate = current ? JSON.parse(current) : { sends: 0, opens: 0, clicks: 0 };
        aggregate.sends += stats.sends;
        aggregate.opens += stats.opens;
        aggregate.clicks += stats.clicks;

        await this.redis.hset(key, field, JSON.stringify(aggregate));
        await this.redis.expire(key, this.config.patternTTL);
    }

    /**
     * Get hourly aggregates for a list
     */
    async getHourlyAggregates(listId: string): Promise<Map<string, { sends: number; opens: number; clicks: number }>> {
        if (!this.redis) return new Map();

        const key = this.getListAggregateKey(listId);
        const data = await this.redis.hgetall(key);

        const map = new Map<string, { sends: number; opens: number; clicks: number }>();
        for (const [field, value] of Object.entries(data)) {
            map.set(field, JSON.parse(value));
        }

        return map;
    }

    /**
     * Get engagement heatmap for a list
     */
    async getEngagementHeatmap(listId: string): Promise<Array<{ hour: number; day: number; score: number }>> {
        const aggregates = await this.getHourlyAggregates(listId);
        const heatmap: Array<{ hour: number; day: number; score: number }> = [];

        for (let day = 0; day < 7; day++) {
            for (let hour = 0; hour < 24; hour++) {
                const key = `${day}:${hour}`;
                const stats = aggregates.get(key);
                
                if (stats && stats.sends > 0) {
                    const openRate = stats.opens / stats.sends;
                    const clickRate = stats.clicks / stats.sends;
                    const score = openRate * 0.6 + clickRate * 0.4;
                    heatmap.push({ hour, day, score });
                } else {
                    heatmap.push({ hour, day, score: 0 });
                }
            }
        }

        return heatmap;
    }

    // ========================================
    // STATISTICS & MAINTENANCE
    // ========================================

    /**
     * Get cache statistics
     */
    async getStats(): Promise<{
        connected: boolean;
        subscribersWithPatterns: number;
        cachedRecommendations: number;
        memoryUsage: string;
    }> {
        if (!this.redis) {
            return {
                connected: false,
                subscribersWithPatterns: 0,
                cachedRecommendations: 0,
                memoryUsage: '0',
            };
        }

        const [subscriberKeys, recommendationKeys, info] = await Promise.all([
            this.redis.keys(`${this.config.keyPrefix}pattern:*`),
            this.redis.keys(`${this.config.keyPrefix}rec:*`),
            this.redis.info('memory'),
        ]);

        const memMatch = info.match(/used_memory_human:(\S+)/);

        return {
            connected: this.connected,
            subscribersWithPatterns: subscriberKeys.length,
            cachedRecommendations: recommendationKeys.length,
            memoryUsage: memMatch ? memMatch[1] : 'unknown',
        };
    }

    /**
     * Clear all STO cache data
     */
    async clearAll(): Promise<void> {
        if (!this.redis) return;

        const keys = await this.redis.keys(`${this.config.keyPrefix}*`);
        if (keys.length > 0) {
            await this.redis.del(...keys);
        }
    }

    // ========================================
    // PRIVATE METHODS
    // ========================================

    private getSubscriberPatternKey(subscriberId: string): string {
        return `${this.config.keyPrefix}pattern:${subscriberId}`;
    }

    private getRecommendationKey(cacheKey: string): string {
        return `${this.config.keyPrefix}rec:${cacheKey}`;
    }

    private getListAggregateKey(listId: string): string {
        return `${this.config.keyPrefix}agg:${listId}`;
    }
}

/**
 * Create a cache key for STO recommendations
 */
export function createSTOCacheKey(params: {
    tenantId: string;
    campaignId?: string;
    listId?: string;
    timezone?: string;
}): string {
    const parts = [params.tenantId];
    if (params.campaignId) parts.push(`c:${params.campaignId}`);
    if (params.listId) parts.push(`l:${params.listId}`);
    if (params.timezone) parts.push(`tz:${params.timezone.replace(/\//g, '-')}`);
    return parts.join(':');
}
