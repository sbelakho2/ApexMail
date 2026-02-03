/**
 * Send Time Optimization (STO) Engine
 * 
 * Analyzes recipient engagement patterns to determine optimal send times.
 * Uses historical open/click data to learn when each recipient is most active.
 * 
 * Data Science Methodology:
 * - Collects engagement timestamps per recipient email hash
 * - Builds hour-of-day and day-of-week probability distributions
 * - Uses Bayesian averaging with global priors for cold-start
 * - Returns optimal send windows with confidence scores
 * 
 * Reference: Industry standard for +15-20% open rate improvement
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';

interface STOConfig {
    db: Pool;
    redis: Redis;
    logger: Logger;
}

interface HourDistribution {
    hour: number;
    engagementScore: number;
    sampleSize: number;
    confidence: 'high' | 'medium' | 'low';
}

interface DayDistribution {
    dayOfWeek: number; // 0 = Sunday, 6 = Saturday
    dayName: string;
    engagementScore: number;
    sampleSize: number;
}

interface OptimalSendWindow {
    hour: number;
    dayOfWeek: number;
    score: number;
    confidence: 'high' | 'medium' | 'low';
    localTime: string; // e.g., "Tuesday 10:00 AM"
}

interface RecipientProfile {
    emailHash: string;
    timezone: string | null;
    totalEngagements: number;
    optimalWindows: OptimalSendWindow[];
    hourlyDistribution: HourDistribution[];
    dailyDistribution: DayDistribution[];
    lastUpdated: Date;
}

interface BulkOptimizationResult {
    recipientEmail: string;
    suggestedSendTime: Date;
    confidence: 'high' | 'medium' | 'low';
    reason: string;
}

// Day names for human-readable output
const DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

// Global priors (industry averages for email engagement)
const GLOBAL_HOUR_PRIORS: Record<number, number> = {
    0: 0.02, 1: 0.01, 2: 0.01, 3: 0.01, 4: 0.01, 5: 0.02,
    6: 0.04, 7: 0.06, 8: 0.08, 9: 0.10, 10: 0.11, 11: 0.10,
    12: 0.08, 13: 0.07, 14: 0.07, 15: 0.06, 16: 0.05, 17: 0.04,
    18: 0.03, 19: 0.02, 20: 0.02, 21: 0.02, 22: 0.02, 23: 0.02,
};

const GLOBAL_DAY_PRIORS: Record<number, number> = {
    0: 0.08, // Sunday
    1: 0.17, // Monday
    2: 0.18, // Tuesday (highest)
    3: 0.17, // Wednesday
    4: 0.17, // Thursday
    5: 0.15, // Friday
    6: 0.08, // Saturday
};

// Minimum samples needed for high confidence
const HIGH_CONFIDENCE_THRESHOLD = 50;
const MEDIUM_CONFIDENCE_THRESHOLD = 20;

export class SendTimeOptimizer {
    private readonly db: Pool;
    private readonly redis: Redis;
    // @ts-expect-error Reserved for future logging implementation
    private readonly _logger: Logger;
    private readonly cachePrefix = 'sto:';
    private readonly cacheTTL = 24 * 60 * 60; // 24 hours

    constructor(config: STOConfig) {
        this.db = config.db;
        this.redis = config.redis;
        this._logger = config.logger;
    }

    /**
     * Get optimal send time for a single recipient
     */
    async getOptimalSendTime(
        recipientEmail: string,
        tenantId?: string
    ): Promise<{
        suggestedTime: Date;
        confidence: 'high' | 'medium' | 'low';
        profile: RecipientProfile | null;
    }> {
        const emailHash = this.hashEmail(recipientEmail);
        
        // Try cache first
        const cached = await this.getCachedProfile(emailHash);
        if (cached) {
            const bestWindow = cached.optimalWindows[0];
            return {
                suggestedTime: this.computeNextSendTime(bestWindow),
                confidence: bestWindow?.confidence || 'low',
                profile: cached,
            };
        }

        // Build profile from database
        const profile = await this.buildRecipientProfile(emailHash, tenantId);
        
        if (profile.totalEngagements === 0) {
            // Cold start: use global priors
            return {
                suggestedTime: this.getGlobalOptimalTime(),
                confidence: 'low',
                profile: null,
            };
        }

        // Cache the profile
        await this.cacheProfile(emailHash, profile);

        const bestWindow = profile.optimalWindows[0];
        return {
            suggestedTime: this.computeNextSendTime(bestWindow),
            confidence: bestWindow?.confidence || 'low',
            profile,
        };
    }

    /**
     * Optimize send times for a batch of recipients
     */
    async optimizeBatch(
        recipients: Array<{ email: string; originalScheduledTime?: Date }>,
        tenantId?: string
    ): Promise<BulkOptimizationResult[]> {
        const results: BulkOptimizationResult[] = [];

        // Process in parallel with concurrency limit
        const batchSize = 50;
        for (let i = 0; i < recipients.length; i += batchSize) {
            const batch = recipients.slice(i, i + batchSize);
            const batchResults = await Promise.all(
                batch.map(async (recipient) => {
                    const { suggestedTime, confidence, profile } = await this.getOptimalSendTime(
                        recipient.email,
                        tenantId
                    );

                    let reason = 'Using global engagement patterns';
                    if (profile && profile.totalEngagements > 0) {
                        reason = `Based on ${profile.totalEngagements} historical engagements`;
                    }

                    return {
                        recipientEmail: recipient.email,
                        suggestedSendTime: suggestedTime,
                        confidence,
                        reason,
                    };
                })
            );
            results.push(...batchResults);
        }

        return results;
    }

    /**
     * Build engagement profile for a recipient
     */
    private async buildRecipientProfile(
        emailHash: string,
        tenantId?: string
    ): Promise<RecipientProfile> {
        const tenantFilter = tenantId ? 'AND tenant_id = $2' : '';
        const params = tenantId ? [emailHash, tenantId] : [emailHash];

        // Get hourly engagement distribution
        const hourlyResult = await this.db.query<{
            hour: string;
            count: string;
        }>(`
            SELECT 
                EXTRACT(HOUR FROM timestamp AT TIME ZONE COALESCE(
                    (location->>'timezone')::text, 
                    'UTC'
                ))::int as hour,
                COUNT(*) as count
            FROM events
            WHERE recipient_email_hash = $1
                AND event_type IN ('opened', 'clicked')
                ${tenantFilter}
            GROUP BY hour
            ORDER BY hour
        `, params);

        // Get daily engagement distribution
        const dailyResult = await this.db.query<{
            day_of_week: string;
            count: string;
        }>(`
            SELECT 
                EXTRACT(DOW FROM timestamp)::int as day_of_week,
                COUNT(*) as count
            FROM events
            WHERE recipient_email_hash = $1
                AND event_type IN ('opened', 'clicked')
                ${tenantFilter}
            GROUP BY day_of_week
            ORDER BY day_of_week
        `, params);

        // Get timezone if available
        const tzResult = await this.db.query<{ timezone: string | null }>(`
            SELECT (location->>'timezone') as timezone
            FROM events
            WHERE recipient_email_hash = $1
                AND location->>'timezone' IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT 1
        `, [emailHash]);

        // Calculate total engagements
        const totalEngagements = hourlyResult.rows.reduce(
            (sum, row) => sum + parseInt(row.count, 10),
            0
        );

        // Build hourly distribution with Bayesian smoothing
        const hourlyDistribution = this.computeHourlyDistribution(hourlyResult.rows, totalEngagements);
        
        // Build daily distribution with Bayesian smoothing
        const dailyDistribution = this.computeDailyDistribution(dailyResult.rows, totalEngagements);

        // Find optimal send windows (top 3 hour+day combinations)
        const optimalWindows = this.computeOptimalWindows(
            hourlyDistribution,
            dailyDistribution,
            totalEngagements
        );

        return {
            emailHash,
            timezone: tzResult.rows[0]?.timezone || null,
            totalEngagements,
            optimalWindows,
            hourlyDistribution,
            dailyDistribution,
            lastUpdated: new Date(),
        };
    }

    /**
     * Compute hourly distribution with Bayesian smoothing
     */
    private computeHourlyDistribution(
        rawData: Array<{ hour: string; count: string }>,
        totalEngagements: number
    ): HourDistribution[] {
        const distribution: HourDistribution[] = [];
        const rawMap = new Map(rawData.map(r => [parseInt(r.hour, 10), parseInt(r.count, 10)]));
        
        // Smoothing factor (higher = more weight to priors)
        const alpha = Math.max(1, 10 - Math.log10(totalEngagements + 1) * 3);

        for (let hour = 0; hour < 24; hour++) {
            const observed = rawMap.get(hour) || 0;
            const prior = GLOBAL_HOUR_PRIORS[hour] || 0.04;
            
            // Bayesian update: posterior = (observed + alpha * prior) / (total + alpha)
            const posterior = totalEngagements > 0
                ? (observed + alpha * prior * 24) / (totalEngagements + alpha * 24)
                : prior;

            const sampleSize = observed;
            const confidence = this.computeConfidence(sampleSize);

            distribution.push({
                hour,
                engagementScore: posterior,
                sampleSize,
                confidence,
            });
        }

        return distribution;
    }

    /**
     * Compute daily distribution with Bayesian smoothing
     */
    private computeDailyDistribution(
        rawData: Array<{ day_of_week: string; count: string }>,
        totalEngagements: number
    ): DayDistribution[] {
        const distribution: DayDistribution[] = [];
        const rawMap = new Map(rawData.map(r => [parseInt(r.day_of_week, 10), parseInt(r.count, 10)]));

        const alpha = Math.max(1, 5 - Math.log10(totalEngagements + 1) * 2);

        for (let day = 0; day < 7; day++) {
            const observed = rawMap.get(day) || 0;
            const prior = GLOBAL_DAY_PRIORS[day] || 0.14;

            const posterior = totalEngagements > 0
                ? (observed + alpha * prior * 7) / (totalEngagements + alpha * 7)
                : prior;

            distribution.push({
                dayOfWeek: day,
                dayName: DAY_NAMES[day] ?? 'Unknown',
                engagementScore: posterior,
                sampleSize: observed,
            });
        }

        return distribution;
    }

    /**
     * Find optimal send windows by combining hour and day distributions
     */
    private computeOptimalWindows(
        hourly: HourDistribution[],
        daily: DayDistribution[],
        _totalEngagements: number
    ): OptimalSendWindow[] {
        const windows: OptimalSendWindow[] = [];

        // Generate all hour+day combinations and score them
        for (const hour of hourly) {
            for (const day of daily) {
                const combinedScore = hour.engagementScore * day.engagementScore;
                const combinedSampleSize = Math.min(hour.sampleSize, day.sampleSize);
                
                windows.push({
                    hour: hour.hour,
                    dayOfWeek: day.dayOfWeek,
                    score: combinedScore,
                    confidence: this.computeConfidence(combinedSampleSize),
                    localTime: `${day.dayName} ${this.formatHour(hour.hour)}`,
                });
            }
        }

        // Sort by score descending and return top 3
        windows.sort((a, b) => b.score - a.score);
        return windows.slice(0, 3);
    }

    /**
     * Compute confidence level based on sample size
     */
    private computeConfidence(sampleSize: number): 'high' | 'medium' | 'low' {
        if (sampleSize >= HIGH_CONFIDENCE_THRESHOLD) return 'high';
        if (sampleSize >= MEDIUM_CONFIDENCE_THRESHOLD) return 'medium';
        return 'low';
    }

    /**
     * Calculate next occurrence of optimal send time
     */
    private computeNextSendTime(window: OptimalSendWindow | undefined): Date {
        if (!window) {
            return this.getGlobalOptimalTime();
        }

        const now = new Date();
        const result = new Date(now);
        
        // Set to the optimal hour
        result.setHours(window.hour, 0, 0, 0);
        
        // Find the next occurrence of the optimal day
        const currentDay = now.getDay();
        let daysUntil = window.dayOfWeek - currentDay;
        
        // If it's the same day but the time has passed, go to next week
        if (daysUntil === 0 && result <= now) {
            daysUntil = 7;
        } else if (daysUntil < 0) {
            daysUntil += 7;
        }
        
        result.setDate(result.getDate() + daysUntil);
        
        // Don't schedule more than 7 days out
        const maxDate = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
        if (result > maxDate) {
            // Just use optimal hour today/tomorrow
            result.setDate(now.getDate());
            if (result <= now) {
                result.setDate(now.getDate() + 1);
            }
        }

        return result;
    }

    /**
     * Get global optimal time based on industry priors
     */
    private getGlobalOptimalTime(): Date {
        const now = new Date();
        const result = new Date(now);
        
        // Best global time: Tuesday at 10 AM
        const optimalHour = 10;
        const optimalDay = 2; // Tuesday
        
        result.setHours(optimalHour, 0, 0, 0);
        
        const currentDay = now.getDay();
        let daysUntil = optimalDay - currentDay;
        
        if (daysUntil === 0 && result <= now) {
            daysUntil = 7;
        } else if (daysUntil < 0) {
            daysUntil += 7;
        }
        
        result.setDate(result.getDate() + daysUntil);
        return result;
    }

    /**
     * Format hour for display
     */
    private formatHour(hour: number): string {
        const suffix = hour >= 12 ? 'PM' : 'AM';
        const displayHour = hour % 12 || 12;
        return `${displayHour}:00 ${suffix}`;
    }

    /**
     * Hash email for privacy
     */
    private hashEmail(email: string): string {
        const crypto = require('crypto');
        return crypto.createHash('sha256').update(email.toLowerCase().trim()).digest('hex');
    }

    /**
     * Get cached profile
     */
    private async getCachedProfile(emailHash: string): Promise<RecipientProfile | null> {
        const cached = await this.redis.get(`${this.cachePrefix}${emailHash}`);
        if (cached) {
            try {
                return JSON.parse(cached);
            } catch {
                return null;
            }
        }
        return null;
    }

    /**
     * Cache profile
     */
    private async cacheProfile(emailHash: string, profile: RecipientProfile): Promise<void> {
        await this.redis.setex(
            `${this.cachePrefix}${emailHash}`,
            this.cacheTTL,
            JSON.stringify(profile)
        );
    }

    /**
     * Invalidate cache for a recipient (call after new engagement)
     */
    async invalidateCache(recipientEmail: string): Promise<void> {
        const emailHash = this.hashEmail(recipientEmail);
        await this.redis.del(`${this.cachePrefix}${emailHash}`);
    }

    /**
     * Get aggregated optimal send times for a tenant
     */
    async getTenantOptimalTimes(tenantId: string): Promise<{
        bestHours: HourDistribution[];
        bestDays: DayDistribution[];
        totalEngagements: number;
    }> {
        const result = await this.db.query<{
            hour: string;
            day_of_week: string;
            count: string;
        }>(`
            SELECT 
                EXTRACT(HOUR FROM timestamp)::int as hour,
                EXTRACT(DOW FROM timestamp)::int as day_of_week,
                COUNT(*) as count
            FROM events
            WHERE tenant_id = $1
                AND event_type IN ('opened', 'clicked')
                AND timestamp >= NOW() - INTERVAL '90 days'
            GROUP BY hour, day_of_week
        `, [tenantId]);

        const totalEngagements = result.rows.reduce((sum, r) => sum + parseInt(r.count, 10), 0);

        // Aggregate by hour
        const hourMap = new Map<number, number>();
        for (const row of result.rows) {
            const hour = parseInt(row.hour, 10);
            const count = parseInt(row.count, 10);
            hourMap.set(hour, (hourMap.get(hour) || 0) + count);
        }

        // Aggregate by day
        const dayMap = new Map<number, number>();
        for (const row of result.rows) {
            const day = parseInt(row.day_of_week, 10);
            const count = parseInt(row.count, 10);
            dayMap.set(day, (dayMap.get(day) || 0) + count);
        }

        const bestHours = this.computeHourlyDistribution(
            Array.from(hourMap.entries()).map(([hour, count]) => ({
                hour: hour.toString(),
                count: count.toString(),
            })),
            totalEngagements
        ).sort((a, b) => b.engagementScore - a.engagementScore);

        const bestDays = this.computeDailyDistribution(
            Array.from(dayMap.entries()).map(([day, count]) => ({
                day_of_week: day.toString(),
                count: count.toString(),
            })),
            totalEngagements
        ).sort((a, b) => b.engagementScore - a.engagementScore);

        return { bestHours, bestDays, totalEngagements };
    }
}
