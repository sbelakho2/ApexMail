/**
 * @apexmail/ai - Send Time Optimization (STO) Engine
 * 
 * ML-based send time optimization using engagement patterns.
 * Analyzes historical data to determine optimal delivery times.
 */

import type { Redis } from 'ioredis';
import type {
    STORequest,
    STOResult,
    STORecommendation,
    STOFactor,
    EngagementPattern,
} from '../types.js';

/**
 * STO configuration
 */
export interface STOConfig {
    minDataPoints: number;
    confidenceThreshold: number;
    defaultTimezone: string;
    lookbackDays: number;
    predictionHorizonHours: number;
}

/**
 * Hour slot with engagement score
 */
interface HourSlot {
    hour: number;
    dayOfWeek: number;
    score: number;
    opens: number;
    clicks: number;
    sends: number;
    confidence: number;
}

/**
 * Default STO configuration
 */
const DEFAULT_STO_CONFIG: STOConfig = {
    minDataPoints: 100,
    confidenceThreshold: 0.6,
    defaultTimezone: 'America/New_York',
    lookbackDays: 90,
    predictionHorizonHours: 168, // 1 week
};

/**
 * Hard limits to prevent unbounded memory growth
 */
const MAX_PATTERNS_PER_SUBSCRIBER = 10_000;
const MAX_SUBSCRIBERS = 50_000;

/**
 * Send Time Optimization Engine
 * 
 * Analyzes engagement patterns to recommend optimal send times
 * for email campaigns based on subscriber behavior.
 */
export class STOOptimizer {
    private config: STOConfig;
    private engagementData: Map<string, EngagementPattern[]> = new Map();
    private redis: Redis | null = null;
    private static readonly REDIS_KEY_PREFIX = 'sto:engagement:';

    constructor(config?: Partial<STOConfig>, redis?: Redis) {
        this.config = { ...DEFAULT_STO_CONFIG, ...config };
        this.redis = redis ?? null;
    }

    /**
     * Connect to Redis for persistent engagement storage
     */
    connectRedis(redis: Redis): void {
        this.redis = redis;
    }

    /**
     * Get optimized send time recommendation
     */
    async optimize(request: STORequest): Promise<STOResult> {
        const startTime = Date.now();

        try {
            // Get or compute engagement patterns
            const patterns = await this.getEngagementPatterns(
                request.subscriberIds,
                request.listId
            );

            // Compute optimal times
            const recommendations = this.computeOptimalTimes(
                patterns,
                request.timezone || this.config.defaultTimezone,
                request.constraints
            );

            // Calculate contributing factors
            const factors = this.analyzeFactors(patterns, recommendations);

            // Compute overall confidence
            const confidence = this.computeConfidence(patterns, recommendations);

            return {
                recommendations,
                factors,
                confidence,
                dataPoints: patterns.length,
                latencyMs: Date.now() - startTime,
            };
        } catch (error) {
            throw new Error(`STO optimization failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Add engagement data for learning (persists to Redis if available)
     */
    addEngagementData(
        subscriberId: string,
        pattern: EngagementPattern
    ): void {
        const existing = this.engagementData.get(subscriberId) || [];
        existing.push(pattern);

        // Keep only recent data
        const cutoff = new Date();
        cutoff.setDate(cutoff.getDate() - this.config.lookbackDays);

        let filtered = existing.filter(
            (p) => p.timestamp >= cutoff
        );

        // Cap per-subscriber patterns to prevent unbounded growth
        if (filtered.length > MAX_PATTERNS_PER_SUBSCRIBER) {
            filtered = filtered
                .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
                .slice(0, MAX_PATTERNS_PER_SUBSCRIBER);
        }

        this.engagementData.set(subscriberId, filtered);

        // Evict oldest subscriber if Map exceeds cap
        if (this.engagementData.size > MAX_SUBSCRIBERS) {
            let oldestKey: string | null = null;
            let oldestTime = Infinity;
            for (const [key, patterns] of this.engagementData.entries()) {
                if (patterns.length === 0) { oldestKey = key; break; }
                const newest = patterns[patterns.length - 1].timestamp.getTime();
                if (newest < oldestTime) {
                    oldestTime = newest;
                    oldestKey = key;
                }
            }
            if (oldestKey && oldestKey !== subscriberId) {
                this.engagementData.delete(oldestKey);
            }
        }

        // Persist to Redis asynchronously
        if (this.redis) {
            const key = `${STOOptimizer.REDIS_KEY_PREFIX}${subscriberId}`;
            const serialized = JSON.stringify({
                ...pattern,
                timestamp: pattern.timestamp.toISOString(),
                sentAt: pattern.sentAt?.toISOString() ?? null,
                openedAt: pattern.openedAt?.toISOString() ?? null,
                clickedAt: pattern.clickedAt?.toISOString() ?? null,
                lastEngagement: pattern.lastEngagement?.toISOString() ?? null,
            });
            this.redis.zadd(key, pattern.timestamp.getTime(), serialized)
                .then(() => this.redis!.expire(key, this.config.lookbackDays * 86400))
                .then(() => this.redis!.zremrangebyrank(key, 0, -MAX_PATTERNS_PER_SUBSCRIBER - 1))
                .catch(() => {/* best-effort */});
        }
    }

    /**
     * Bulk add engagement data
     */
    addBulkEngagementData(
        data: Array<{ subscriberId: string; pattern: EngagementPattern }>
    ): void {
        for (const { subscriberId, pattern } of data) {
            this.addEngagementData(subscriberId, pattern);
        }
    }

    /**
     * Get engagement summary for a subscriber
     */
    getSubscriberPattern(subscriberId: string): {
        preferredHours: number[];
        preferredDays: number[];
        avgResponseTime: number;
        engagementScore: number;
    } | null {
        const patterns = this.engagementData.get(subscriberId);
        if (!patterns || patterns.length === 0) return null;

        // Aggregate patterns
        const hourCounts = new Map<number, number>();
        const dayCounts = new Map<number, number>();
        let totalResponseTime = 0;
        let responseCount = 0;

        for (const pattern of patterns) {
            if (pattern.openedAt) {
                const openHour = pattern.openedAt.getHours();
                const openDay = pattern.openedAt.getDay();
                
                hourCounts.set(openHour, (hourCounts.get(openHour) || 0) + 1);
                dayCounts.set(openDay, (dayCounts.get(openDay) || 0) + 1);

                if (pattern.sentAt) {
                    totalResponseTime += pattern.openedAt.getTime() - pattern.sentAt.getTime();
                    responseCount++;
                }
            }
        }

        // Find preferred hours (top 3)
        const sortedHours = Array.from(hourCounts.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3)
            .map(([hour]) => hour);

        // Find preferred days (top 2)
        const sortedDays = Array.from(dayCounts.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 2)
            .map(([day]) => day);

        // Calculate engagement score
        const opens = patterns.filter((p) => p.opened).length;
        const clicks = patterns.filter((p) => p.clicked).length;
        const engagementScore = (opens / patterns.length) * 0.6 + (clicks / patterns.length) * 0.4;

        return {
            preferredHours: sortedHours,
            preferredDays: sortedDays,
            avgResponseTime: responseCount > 0 ? totalResponseTime / responseCount : 0,
            engagementScore,
        };
    }

    /**
     * Get aggregate patterns for a list
     */
    getListPattern(_listId: string): {
        heatmap: Array<{ hour: number; day: number; score: number }>;
        peakHours: number[];
        peakDays: number[];
        avgEngagementRate: number;
    } {
        // Compute engagement heatmap
        const heatmap: Array<{ hour: number; day: number; score: number }> = [];
        const hourScores = new Map<string, { total: number; count: number }>();

        for (const patterns of this.engagementData.values()) {
            for (const pattern of patterns) {
                if (pattern.openedAt) {
                    const hour = pattern.openedAt.getHours();
                    const day = pattern.openedAt.getDay();
                    const key = `${day}-${hour}`;

                    const existing = hourScores.get(key) || { total: 0, count: 0 };
                    existing.total += pattern.opened ? 1 : 0;
                    existing.count += 1;
                    hourScores.set(key, existing);
                }
            }
        }

        // Build heatmap
        for (let day = 0; day < 7; day++) {
            for (let hour = 0; hour < 24; hour++) {
                const key = `${day}-${hour}`;
                const data = hourScores.get(key);
                const score = data ? data.total / data.count : 0;
                heatmap.push({ hour, day, score });
            }
        }

        // Find peak hours and days
        const hourTotals = new Map<number, number>();
        const dayTotals = new Map<number, number>();

        for (const item of heatmap) {
            hourTotals.set(item.hour, (hourTotals.get(item.hour) || 0) + item.score);
            dayTotals.set(item.day, (dayTotals.get(item.day) || 0) + item.score);
        }

        const peakHours = Array.from(hourTotals.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3)
            .map(([hour]) => hour);

        const peakDays = Array.from(dayTotals.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 2)
            .map(([day]) => day);

        // Calculate average engagement
        const allPatterns = Array.from(this.engagementData.values()).flat();
        const avgEngagementRate = allPatterns.length > 0
            ? allPatterns.filter((p) => p.opened).length / allPatterns.length
            : 0;

        return {
            heatmap,
            peakHours,
            peakDays,
            avgEngagementRate,
        };
    }

    /**
     * Predict engagement for a specific send time
     */
    predictEngagement(
        subscriberIds: string[],
        sendTime: Date
    ): {
        expectedOpenRate: number;
        expectedClickRate: number;
        confidence: number;
    } {
        const hour = sendTime.getHours();
        const day = sendTime.getDay();

        let totalOpenScore = 0;
        let totalClickScore = 0;
        let contributingSubscribers = 0;

        for (const subscriberId of subscriberIds) {
            const patterns = this.engagementData.get(subscriberId);
            if (!patterns || patterns.length === 0) continue;

            // Find similar time slots
            const similar = patterns.filter((p) => {
                if (!p.sentAt) return false;
                const pHour = p.sentAt.getHours();
                const pDay = p.sentAt.getDay();
                return Math.abs(pHour - hour) <= 2 && pDay === day;
            });

            if (similar.length > 0) {
                totalOpenScore += similar.filter((p) => p.opened).length / similar.length;
                totalClickScore += similar.filter((p) => p.clicked).length / similar.length;
                contributingSubscribers++;
            }
        }

        const confidence = Math.min(
            contributingSubscribers / subscriberIds.length,
            1
        );

        return {
            expectedOpenRate: contributingSubscribers > 0 ? totalOpenScore / contributingSubscribers : 0,
            expectedClickRate: contributingSubscribers > 0 ? totalClickScore / contributingSubscribers : 0,
            confidence,
        };
    }

    /**
     * Clear all engagement data (local + Redis)
     * FIX-500-396: Pipeline DEL instead of per-batch DEL for efficiency
     */
    async clearData(): Promise<void> {
        this.engagementData.clear();
        if (this.redis) {
            try {
                const allKeys: string[] = [];
                let cursor = '0';
                do {
                    const [next, keys] = await this.redis.scan(cursor, 'MATCH', `${STOOptimizer.REDIS_KEY_PREFIX}*`, 'COUNT', '200');
                    cursor = next;
                    allKeys.push(...keys);
                } while (cursor !== '0');

                if (allKeys.length > 0) {
                    const pipeline = this.redis.pipeline();
                    for (const key of allKeys) {
                        pipeline.del(key);
                    }
                    await pipeline.exec();
                }
            } catch { /* best-effort */ }
        }
    }

    /**
     * Get data statistics
     */
    getStats(): {
        subscriberCount: number;
        totalPatterns: number;
        oldestData: Date | null;
        newestData: Date | null;
    } {
        let totalPatterns = 0;
        let oldest: Date | null = null;
        let newest: Date | null = null;

        for (const patterns of this.engagementData.values()) {
            totalPatterns += patterns.length;

            for (const pattern of patterns) {
                if (!oldest || pattern.timestamp < oldest) {
                    oldest = pattern.timestamp;
                }
                if (!newest || pattern.timestamp > newest) {
                    newest = pattern.timestamp;
                }
            }
        }

        return {
            subscriberCount: this.engagementData.size,
            totalPatterns,
            oldestData: oldest,
            newestData: newest,
        };
    }

    // ========================================
    // PRIVATE METHODS
    // ========================================

    private async getEngagementPatterns(
        subscriberIds?: string[],
        _listId?: string
    ): Promise<EngagementPattern[]> {
        const patterns: EngagementPattern[] = [];
        // FIX-500-399: Cap total patterns to avoid unbounded memory usage
        const MAX_PATTERNS = 100_000;

        if (subscriberIds && subscriberIds.length > 0) {
            for (const id of subscriberIds) {
                let subscriberPatterns = this.engagementData.get(id);
                // On local miss, try loading from Redis
                if ((!subscriberPatterns || subscriberPatterns.length === 0) && this.redis) {
                    subscriberPatterns = await this.loadSubscriberFromRedis(id);
                }
                if (subscriberPatterns) {
                    patterns.push(...subscriberPatterns);
                    if (patterns.length >= MAX_PATTERNS) break;
                }
            }
        } else {
            // Use all data — sample if too large
            for (const subscriberPatterns of this.engagementData.values()) {
                patterns.push(...subscriberPatterns);
                if (patterns.length >= MAX_PATTERNS) break;
            }
        }

        // FIX-500-399: If we exceeded the cap, randomly sample down
        if (patterns.length > MAX_PATTERNS) {
            // Fisher-Yates partial shuffle to pick MAX_PATTERNS items
            for (let i = patterns.length - 1; i > MAX_PATTERNS - 1; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [patterns[i], patterns[j]] = [patterns[j], patterns[i]];
            }
            patterns.length = MAX_PATTERNS;
        }

        return patterns;
    }

    /**
     * Load a subscriber's engagement data from Redis into local cache
     */
    private async loadSubscriberFromRedis(subscriberId: string): Promise<EngagementPattern[]> {
        if (!this.redis) return [];
        try {
            const key = `${STOOptimizer.REDIS_KEY_PREFIX}${subscriberId}`;
            const cutoff = new Date();
            cutoff.setDate(cutoff.getDate() - this.config.lookbackDays);
            const members = await this.redis.zrangebyscore(key, cutoff.getTime(), '+inf');
            if (!members || members.length === 0) return [];

            const patterns: EngagementPattern[] = members.map((raw: string) => {
                let obj: Record<string, unknown>;
                try { obj = JSON.parse(raw); }
                catch { return null; }
                return {
                    ...obj,
                    timestamp: new Date(obj.timestamp as string),
                    sentAt: obj.sentAt ? new Date(obj.sentAt as string) : undefined,
                    openedAt: obj.openedAt ? new Date(obj.openedAt as string) : undefined,
                    clickedAt: obj.clickedAt ? new Date(obj.clickedAt as string) : undefined,
                    lastEngagement: obj.lastEngagement ? new Date(obj.lastEngagement as string) : undefined,
                } as EngagementPattern;
            }).filter(Boolean) as EngagementPattern[];
            this.engagementData.set(subscriberId, patterns);
            return patterns;
        } catch {
            return [];
        }
    }

    private computeOptimalTimes(
        patterns: EngagementPattern[],
        timezone: string,
        constraints?: STORequest['constraints']
    ): STORecommendation[] {
        // Build hour slots
        const slots: Map<string, HourSlot> = new Map();

        for (let day = 0; day < 7; day++) {
            for (let hour = 0; hour < 24; hour++) {
                const key = `${day}-${hour}`;
                slots.set(key, {
                    hour,
                    dayOfWeek: day,
                    score: 0,
                    opens: 0,
                    clicks: 0,
                    sends: 0,
                    confidence: 0,
                });
            }
        }

        // Aggregate pattern data into slots
        for (const pattern of patterns) {
            if (pattern.sentAt) {
                const sentHour = pattern.sentAt.getHours();
                const sentDay = pattern.sentAt.getDay();
                const key = `${sentDay}-${sentHour}`;

                const slot = slots.get(key);
                if (slot) {
                    slot.sends++;
                    if (pattern.opened) slot.opens++;
                    if (pattern.clicked) slot.clicks++;
                }
            }
        }

        // Calculate scores for each slot
        for (const slot of slots.values()) {
            if (slot.sends >= this.config.minDataPoints) {
                const openRate = slot.opens / slot.sends;
                const clickRate = slot.clicks / slot.sends;
                slot.score = openRate * 0.6 + clickRate * 0.4;
                slot.confidence = Math.min(slot.sends / (this.config.minDataPoints * 2), 1);
            }
        }

        // Apply constraints
        const filteredSlots = Array.from(slots.values()).filter((slot) => {
            if (constraints?.excludeWeekends && (slot.dayOfWeek === 0 || slot.dayOfWeek === 6)) {
                return false;
            }
            if (constraints?.businessHoursOnly && (slot.hour < 9 || slot.hour > 17)) {
                return false;
            }
            if (constraints?.excludeHours?.includes(slot.hour)) {
                return false;
            }
            return true;
        });

        // Sort by score and take top recommendations
        const sorted = filteredSlots
            .filter((s) => s.confidence >= this.config.confidenceThreshold)
            .sort((a, b) => b.score - a.score);

        // Build recommendations
        const recommendations: STORecommendation[] = [];

        for (let i = 0; i < Math.min(5, sorted.length); i++) {
            const slot = sorted[i];
            
            // Calculate next occurrence
            const sendTime = this.getNextOccurrence(slot.hour, slot.dayOfWeek, timezone);

            recommendations.push({
                sendTime,
                timezone,
                expectedOpenRate: slot.sends > 0 ? slot.opens / slot.sends : 0,
                expectedClickRate: slot.sends > 0 ? slot.clicks / slot.sends : 0,
                confidence: slot.confidence,
                reason: this.buildRecommendationReason(slot),
            });
        }

        // If no data-driven recommendations, provide defaults
        if (recommendations.length === 0) {
            recommendations.push(
                this.getDefaultRecommendation(timezone, 'Tuesday', 10),
                this.getDefaultRecommendation(timezone, 'Thursday', 14)
            );
        }

        return recommendations;
    }

    /**
     * IMP-007: Timezone-aware next occurrence calculation.
     *
     * Previously the `_timezone` parameter was ignored and `new Date()` was
     * used, which returns the *server's* local time. For a subscriber in
     * Asia/Tokyo the computed "Tuesday 10 AM" would actually be server-local
     * Tuesday 10 AM — potentially the middle of the night for the recipient.
     *
     * Now we use `Intl.DateTimeFormat` to find the current hour and weekday
     * in the *subscriber's* timezone, then calculate the correct UTC Date
     * for the next occurrence of the requested (hour, dayOfWeek) in that tz.
     */
    private getNextOccurrence(hour: number, dayOfWeek: number, timezone: string): Date {
        // Resolve recipient's current time components in their timezone
        let resolvedTz = timezone;
        try {
            // Validate timezone by attempting to create a formatter
            Intl.DateTimeFormat('en-US', { timeZone: resolvedTz });
        } catch {
            resolvedTz = this.config.defaultTimezone;
        }

        const now = new Date();

        // Get current weekday and hour in the target timezone
        const formatter = new Intl.DateTimeFormat('en-US', {
            timeZone: resolvedTz,
            weekday: 'short',
            hour: 'numeric',
            hour12: false,
        });
        const parts = formatter.formatToParts(now);
        const currentDayStr = parts.find(p => p.type === 'weekday')?.value ?? '';
        const currentHour = parseInt(parts.find(p => p.type === 'hour')?.value ?? '0', 10);

        const dayMap: Record<string, number> = {
            Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6,
        };
        const currentDay = dayMap[currentDayStr] ?? now.getDay();

        let daysUntil = dayOfWeek - currentDay;
        if (daysUntil < 0 || (daysUntil === 0 && currentHour >= hour)) {
            daysUntil += 7;
        }

        // Build an ISO date string in the target timezone, then convert to UTC.
        // Start from the current UTC date, offset by daysUntil, then set the
        // hour using the timezone offset.
        const targetLocal = new Date(now);
        targetLocal.setDate(targetLocal.getDate() + daysUntil);

        // Format the target date at the desired hour in the target timezone
        // by computing the difference between UTC and local time in that tz.
        const utcDate = new Date(Date.UTC(
            targetLocal.getFullYear(),
            targetLocal.getMonth(),
            targetLocal.getDate(),
            hour, 0, 0, 0
        ));

        // Adjust for timezone offset: find what UTC hour produces `hour` in `resolvedTz`
        // FIX-500-390: Compute the offset for the actual target date (not today)
        // to correctly handle DST transitions. Iteratively adjust because the
        // first correction may itself shift across a DST boundary.
        const testFormatter = new Intl.DateTimeFormat('en-US', {
            timeZone: resolvedTz,
            hour: 'numeric',
            hour12: false,
        });
        let testHour = parseInt(
            testFormatter.formatToParts(utcDate).find(p => p.type === 'hour')?.value ?? '0',
            10
        );
        let tzOffsetHours = testHour - hour;
        utcDate.setHours(utcDate.getHours() - tzOffsetHours);

        // Verify after adjustment (DST edge case: the adjustment itself may
        // land on a different offset). Re-check once.
        const verifyHour = parseInt(
            testFormatter.formatToParts(utcDate).find(p => p.type === 'hour')?.value ?? '0',
            10
        );
        if (verifyHour !== hour) {
            utcDate.setHours(utcDate.getHours() - (verifyHour - hour));
        }

        return utcDate;
    }

    private getDefaultRecommendation(
        timezone: string,
        day: string,
        hour: number
    ): STORecommendation {
        const dayMap: Record<string, number> = {
            Sunday: 0, Monday: 1, Tuesday: 2, Wednesday: 3,
            Thursday: 4, Friday: 5, Saturday: 6,
        };

        const sendTime = this.getNextOccurrence(hour, dayMap[day] ?? 2, timezone);

        return {
            sendTime,
            timezone,
            expectedOpenRate: 0.22, // Industry average
            expectedClickRate: 0.03,
            confidence: 0.3,
            reason: 'Based on industry best practices (insufficient historical data)',
        };
    }

    private buildRecommendationReason(slot: HourSlot): string {
        const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
        const dayName = days[slot.dayOfWeek];
        const timeStr = slot.hour === 0 ? '12 AM' :
            slot.hour < 12 ? `${slot.hour} AM` :
            slot.hour === 12 ? '12 PM' :
            `${slot.hour - 12} PM`;

        const openRate = (slot.opens / slot.sends * 100).toFixed(1);
        const clickRate = (slot.clicks / slot.sends * 100).toFixed(1);

        return `${dayName}s at ${timeStr} have shown ${openRate}% open rate and ${clickRate}% click rate based on ${slot.sends} sends`;
    }

    private analyzeFactors(
        patterns: EngagementPattern[],
        recommendations: STORecommendation[]
    ): STOFactor[] {
        const factors: STOFactor[] = [];

        // Time of day factor
        if (recommendations.length > 0) {
            const avgHour = recommendations.reduce((sum, r) => sum + r.sendTime.getHours(), 0) / recommendations.length;
            const timeOfDay = avgHour < 12 ? 'morning' : avgHour < 17 ? 'afternoon' : 'evening';
            
            factors.push({
                name: 'Time of Day',
                impact: 0.35,
                description: `Your audience tends to engage more during ${timeOfDay} hours`,
            });
        }

        // Day of week factor
        const dayEngagement = new Map<number, { opens: number; total: number }>();
        for (const pattern of patterns) {
            if (pattern.sentAt) {
                const day = pattern.sentAt.getDay();
                const existing = dayEngagement.get(day) || { opens: 0, total: 0 };
                existing.total++;
                if (pattern.opened) existing.opens++;
                dayEngagement.set(day, existing);
            }
        }

        let bestDay = 2; // Default Tuesday
        let bestRate = 0;
        for (const [day, data] of dayEngagement) {
            const rate = data.total > 0 ? data.opens / data.total : 0;
            if (rate > bestRate) {
                bestRate = rate;
                bestDay = day;
            }
        }

        const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
        factors.push({
            name: 'Day of Week',
            impact: 0.25,
            description: `${days[bestDay]}s show the highest engagement in your data`,
        });

        // Recency factor
        const recentPatterns = patterns.filter((p) => {
            const cutoff = new Date();
            cutoff.setDate(cutoff.getDate() - 30);
            return p.timestamp >= cutoff;
        });

        if (recentPatterns.length > patterns.length * 0.3) {
            factors.push({
                name: 'Recent Behavior',
                impact: 0.2,
                description: 'Recommendations weighted towards recent engagement patterns',
            });
        }

        // Device/engagement type factor
        factors.push({
            name: 'Engagement Type',
            impact: 0.15,
            description: 'Optimized for email opens with consideration for click-through',
        });

        // Timezone factor
        factors.push({
            name: 'Timezone',
            impact: 0.05,
            description: 'Send times adjusted for recipient timezone',
        });

        return factors;
    }

    private computeConfidence(
        patterns: EngagementPattern[],
        recommendations: STORecommendation[]
    ): number {
        if (patterns.length < this.config.minDataPoints) {
            return 0.3; // Low confidence without sufficient data
        }

        // Base confidence from data quantity
        const dataConfidence = Math.min(patterns.length / (this.config.minDataPoints * 5), 0.4);

        // Confidence from recommendation quality
        const recConfidence = recommendations.length > 0
            ? recommendations.reduce((sum, r) => sum + r.confidence, 0) / recommendations.length * 0.4
            : 0;

        // Confidence from data recency
        const recent = patterns.filter((p) => {
            const cutoff = new Date();
            cutoff.setDate(cutoff.getDate() - 30);
            return p.timestamp >= cutoff;
        });
        const recencyConfidence = (recent.length / patterns.length) * 0.2;

        return Math.min(dataConfidence + recConfidence + recencyConfidence, 1);
    }

    // FIX-500-133: Export/import engagement data for persistence.
    // The engagementData Map is in-memory only; without serialization all
    // learned patterns are lost on restart. These methods mirror the NDJSON
    // approach used by FIX-500-087 in the embeddings store.

    /**
     * Export engagement data as NDJSON string for persistence.
     * Each line is a JSON object: { subscriberId, patterns: [...] }
     */
    exportNdjson(): string {
        const lines: string[] = [];
        for (const [subscriberId, patterns] of this.engagementData.entries()) {
            lines.push(JSON.stringify({ subscriberId, patterns }));
        }
        return lines.join('\n');
    }

    /**
     * Import engagement data from an NDJSON string (as produced by exportNdjson).
     * Merges with any existing data — duplicates are filtered by the
     * lookbackDays window in addEngagementData.
     */
    importNdjson(ndjson: string): { imported: number; errors: number } {
        let imported = 0;
        let errors = 0;
        for (const line of ndjson.split('\n')) {
            if (!line.trim()) continue;
            try {
                const record = JSON.parse(line) as {
                    subscriberId: string;
                    patterns: EngagementPattern[];
                };
                // Rehydrate Date objects
                for (const p of record.patterns) {
                    p.timestamp = new Date(p.timestamp as unknown as string);
                    if (p.sentAt) p.sentAt = new Date(p.sentAt as unknown as string);
                    if (p.openedAt) p.openedAt = new Date(p.openedAt as unknown as string);
                    if (p.clickedAt) p.clickedAt = new Date(p.clickedAt as unknown as string);
                }
                for (const pattern of record.patterns) {
                    this.addEngagementData(record.subscriberId, pattern);
                }
                imported++;
            } catch {
                errors++;
            }
        }
        return { imported, errors };
    }
}

export { DEFAULT_STO_CONFIG };
