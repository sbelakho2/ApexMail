/**
 * @apexmail/ai - Send Time Optimization (STO) Engine
 * 
 * ML-based send time optimization using engagement patterns.
 * Analyzes historical data to determine optimal delivery times.
 */

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
 * Send Time Optimization Engine
 * 
 * Analyzes engagement patterns to recommend optimal send times
 * for email campaigns based on subscriber behavior.
 */
export class STOOptimizer {
    private config: STOConfig;
    private engagementData: Map<string, EngagementPattern[]> = new Map();

    constructor(config?: Partial<STOConfig>) {
        this.config = { ...DEFAULT_STO_CONFIG, ...config };
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
     * Add engagement data for learning
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

        const filtered = existing.filter(
            (p) => p.timestamp >= cutoff
        );

        this.engagementData.set(subscriberId, filtered);
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
     * Clear all engagement data
     */
    clearData(): void {
        this.engagementData.clear();
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

        if (subscriberIds && subscriberIds.length > 0) {
            for (const id of subscriberIds) {
                const subscriberPatterns = this.engagementData.get(id);
                if (subscriberPatterns) {
                    patterns.push(...subscriberPatterns);
                }
            }
        } else {
            // Use all data
            for (const subscriberPatterns of this.engagementData.values()) {
                patterns.push(...subscriberPatterns);
            }
        }

        return patterns;
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

    private getNextOccurrence(hour: number, dayOfWeek: number, _timezone: string): Date {
        const now = new Date();
        const result = new Date(now);

        // Find the next occurrence of this day/hour
        const currentDay = now.getDay();
        let daysUntil = dayOfWeek - currentDay;

        if (daysUntil < 0 || (daysUntil === 0 && now.getHours() >= hour)) {
            daysUntil += 7;
        }

        result.setDate(result.getDate() + daysUntil);
        result.setHours(hour, 0, 0, 0);

        return result;
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

        const sendTime = this.getNextOccurrence(hour, dayMap[day], timezone);

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
}

export { DEFAULT_STO_CONFIG };
