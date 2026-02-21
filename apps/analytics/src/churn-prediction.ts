/**
 * Churn Prediction Engine
 * 
 * Predicts tenant and recipient churn risk using engagement decay analysis.
 * Uses logistic regression-inspired scoring on engagement features.
 * 
 * Data Science Methodology:
 * - Tracks engagement velocity (rate of change over time)
 * - Monitors unsubscribe/complaint signals
 * - Calculates recency-frequency-monetary (RFM) inspired scores
 * - Outputs churn probability with actionable risk tiers
 * 
 * Business Value:
 * - Early warning for at-risk accounts
 * - Trigger automated re-engagement campaigns
 * - Reduce subscriber list decay
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';

interface ChurnEngineConfig {
    db: Pool;
    redis: Redis;
    logger: Logger;
}

// Risk tiers with associated actions
export type RiskTier = 'critical' | 'high' | 'medium' | 'low' | 'healthy';

export interface ChurnPrediction {
    entityId: string;
    entityType: 'tenant' | 'recipient';
    churnProbability: number; // 0-1
    riskTier: RiskTier;
    riskScore: number; // 0-100
    signals: ChurnSignal[];
    recommendation: string;
    predictedChurnDate: Date | null;
    lastEngagement: Date | null;
    engagementTrend: 'declining' | 'stable' | 'improving';
}

export interface ChurnSignal {
    type: string;
    severity: 'critical' | 'warning' | 'info';
    message: string;
    value: number;
    threshold: number;
}

export interface TenantHealthMetrics {
    tenantId: string;
    tenantName: string;
    emailsSent30d: number;
    deliveryRate: number;
    openRate: number;
    clickRate: number;
    bounceRate: number;
    complaintRate: number;
    unsubscribeRate: number;
    engagementVelocity: number; // Rate of change
    daysSinceLastEmail: number;
    churnPrediction: ChurnPrediction;
}

export interface RecipientChurnBatch {
    recipientEmail: string;
    emailHash: string;
    churnPrediction: ChurnPrediction;
}

// Feature weights for churn model (calibrated from industry data)
// Reserved for future ML model integration
// @ts-expect-error Reserved for future ML model integration
const _FEATURE_WEIGHTS = {
    engagementDecay: 0.25,      // How much engagement has dropped
    recencyPenalty: 0.20,       // Days since last open/click
    complaintSignal: 0.20,      // Complaint rate (strongest signal)
    unsubscribeSignal: 0.15,    // Unsubscribe tendency
    bounceSignal: 0.10,         // Delivery issues
    frequencyDrop: 0.10,        // Reduced email frequency
};

// Thresholds for risk signals
const THRESHOLDS = {
    criticalComplaintRate: 0.003,   // 0.3% - major ISP threshold
    highComplaintRate: 0.001,       // 0.1%
    criticalBounceRate: 0.10,       // 10%
    highBounceRate: 0.05,           // 5%
    engagementDecayThreshold: -0.30, // 30% drop
    inactiveDaysCritical: 90,
    inactiveDaysHigh: 60,
    inactiveDaysMedium: 30,
};

export class ChurnPredictionEngine {
    private readonly db: Pool;
    private readonly redis: Redis;
    private readonly logger: Logger;
    private readonly cachePrefix = 'churn:';
    private readonly cacheTTL = 6 * 60 * 60; // 6 hours

    constructor(config: ChurnEngineConfig) {
        this.db = config.db;
        this.redis = config.redis;
        this.logger = config.logger;
    }

    /**
     * Predict churn risk for a tenant
     */
    async predictTenantChurn(tenantId: string): Promise<TenantHealthMetrics> {
        // Check cache first
        const cacheKey = `${this.cachePrefix}tenant:${tenantId}`;
        try {
            const cached = await this.redis.get(cacheKey);
            if (cached) {
                try { return JSON.parse(cached); } catch { /* recalculate */ }
            }
        } catch {
            // Redis down — proceed without cache
        }

        // Get tenant info
        const tenantResult = await this.db.query<{ name: string }>(`
            SELECT name FROM tenants WHERE id = $1
        `, [tenantId]);

        const tenantName = tenantResult.rows[0]?.name || 'Unknown';

        // Run 3 independent metric queries in parallel
        const [metricsResult, velocityResult, lastEmailResult] = await Promise.all([
            // Get engagement metrics for last 30 days
            this.db.query<{
                event_type: string;
                count: string;
            }>(`
                SELECT event_type, COUNT(*) as count
                FROM events
                WHERE tenant_id = $1
                    AND timestamp >= NOW() - INTERVAL '30 days'
                GROUP BY event_type
            `, [tenantId]),

            // Get engagement velocity (compare current 30d to previous 30d)
            this.db.query<{
                period: string;
                engagement_count: string;
            }>(`
                SELECT 
                    CASE 
                        WHEN timestamp >= NOW() - INTERVAL '30 days' THEN 'current'
                        ELSE 'previous'
                    END as period,
                    COUNT(*) as engagement_count
                FROM events
                WHERE tenant_id = $1
                    AND timestamp >= NOW() - INTERVAL '60 days'
                    AND event_type IN ('opened', 'clicked')
                GROUP BY period
            `, [tenantId]),

            // Days since last email
            this.db.query<{ days: string | null }>(`
                SELECT EXTRACT(DAY FROM NOW() - MAX(timestamp))::int as days
                FROM events
                WHERE tenant_id = $1 AND event_type = 'sent'
            `, [tenantId]),
        ]);

        // Extract metrics from query results
        const metrics: Record<string, number> = {};
        for (const row of metricsResult.rows) {
            metrics[row.event_type] = parseInt(row.count, 10);
        }

        const sent = metrics['sent'] || 0;
        const delivered = metrics['delivered'] || 0;
        const opened = metrics['opened'] || 0;
        const clicked = metrics['clicked'] || 0;
        const bounced = metrics['bounced'] || 0;
        const complained = metrics['complained'] || 0;
        const unsubscribed = metrics['unsubscribed'] || 0;

        // Calculate rates
        const deliveryRate = sent > 0 ? delivered / sent : 0;
        const openRate = delivered > 0 ? opened / delivered : 0;
        const clickRate = delivered > 0 ? clicked / delivered : 0;
        const bounceRate = sent > 0 ? bounced / sent : 0;
        const complaintRate = delivered > 0 ? complained / delivered : 0;
        const unsubscribeRate = delivered > 0 ? unsubscribed / delivered : 0;

        let currentEngagement = 0;
        let previousEngagement = 0;
        for (const row of velocityResult.rows) {
            if (row.period === 'current') {
                currentEngagement = parseInt(row.engagement_count, 10);
            } else {
                previousEngagement = parseInt(row.engagement_count, 10);
            }
        }

        const engagementVelocity = previousEngagement > 0 
            ? (currentEngagement - previousEngagement) / previousEngagement 
            : 0;

        // Days since last email — distinguish "never sent" from "sent long ago"
        const rawDays = lastEmailResult.rows[0]?.days;
        // NULL means the tenant has never sent email; don't penalize as critical inactivity
        const daysSinceLastEmail = rawDays != null ? parseInt(rawDays, 10) : 0;
        const hasNeverSent = rawDays == null;

        // Build churn prediction
        const churnPrediction = this.computeChurnPrediction({
            entityId: tenantId,
            entityType: 'tenant',
            openRate,
            clickRate,
            bounceRate,
            complaintRate,
            unsubscribeRate,
            engagementVelocity,
            daysSinceLastEngagement: daysSinceLastEmail,
            hasNeverSent,
        });

        const healthMetrics = {
            tenantId,
            tenantName,
            emailsSent30d: sent,
            deliveryRate,
            openRate,
            clickRate,
            bounceRate,
            complaintRate,
            unsubscribeRate,
            engagementVelocity,
            daysSinceLastEmail,
            churnPrediction,
        };

        // Cache the result
        try {
            await this.redis.setex(cacheKey, this.cacheTTL, JSON.stringify(healthMetrics));
        } catch {
            // Non-fatal
        }

        return healthMetrics;
    }

    /**
     * Predict churn for recipients in a tenant
     */
    async predictRecipientChurnBatch(
        tenantId: string,
        limit = 1000
    ): Promise<RecipientChurnBatch[]> {
        // Get recipient engagement summary
        const result = await this.db.query<{
            recipient_email: string;
            recipient_email_hash: string;
            last_open: Date | null;
            last_click: Date | null;
            total_sent: string;
            total_opened: string;
            total_clicked: string;
            total_unsubscribed: string;
            total_complained: string;
            recent_opens: string;
            previous_opens: string;
        }>(`
            WITH recipient_stats AS (
                SELECT 
                    recipient_email,
                    recipient_email_hash,
                    MAX(CASE WHEN event_type = 'opened' THEN timestamp END) as last_open,
                    MAX(CASE WHEN event_type = 'clicked' THEN timestamp END) as last_click,
                    COUNT(*) FILTER (WHERE event_type = 'sent') as total_sent,
                    COUNT(*) FILTER (WHERE event_type = 'opened') as total_opened,
                    COUNT(*) FILTER (WHERE event_type = 'clicked') as total_clicked,
                    COUNT(*) FILTER (WHERE event_type = 'unsubscribed') as total_unsubscribed,
                    COUNT(*) FILTER (WHERE event_type = 'complained') as total_complained,
                    COUNT(*) FILTER (
                        WHERE event_type IN ('opened', 'clicked') 
                        AND timestamp >= NOW() - INTERVAL '30 days'
                    ) as recent_opens,
                    COUNT(*) FILTER (
                        WHERE event_type IN ('opened', 'clicked') 
                        AND timestamp >= NOW() - INTERVAL '60 days'
                        AND timestamp < NOW() - INTERVAL '30 days'
                    ) as previous_opens
                FROM events
                WHERE tenant_id = $1
                GROUP BY recipient_email, recipient_email_hash
                HAVING COUNT(*) FILTER (WHERE event_type = 'sent') >= 3
            )
            SELECT * FROM recipient_stats
            ORDER BY 
                (total_unsubscribed::float + total_complained::float * 5) / NULLIF(total_sent::float, 0) DESC,
                last_open ASC NULLS FIRST
            LIMIT $2
        `, [tenantId, limit]);

        const predictions: RecipientChurnBatch[] = [];

        for (const row of result.rows) {
            const totalSent = parseInt(row.total_sent, 10);
            const totalOpened = parseInt(row.total_opened, 10);
            const totalClicked = parseInt(row.total_clicked, 10);
            const totalUnsubscribed = parseInt(row.total_unsubscribed, 10);
            const totalComplained = parseInt(row.total_complained, 10);
            const recentOpens = parseInt(row.recent_opens, 10);
            const previousOpens = parseInt(row.previous_opens, 10);

            const openRate = totalSent > 0 ? totalOpened / totalSent : 0;
            const clickRate = totalSent > 0 ? totalClicked / totalSent : 0;
            const unsubscribeRate = totalSent > 0 ? totalUnsubscribed / totalSent : 0;
            const complaintRate = totalSent > 0 ? totalComplained / totalSent : 0;
            
            const engagementVelocity = previousOpens > 0 
                ? (recentOpens - previousOpens) / previousOpens 
                : (recentOpens > 0 ? 0 : -1);

            const lastEngagement = row.last_open || row.last_click;
            const daysSinceLastEngagement = lastEngagement 
                ? Math.floor((Date.now() - new Date(lastEngagement).getTime()) / (1000 * 60 * 60 * 24))
                : 999;

            const churnPrediction = this.computeChurnPrediction({
                entityId: row.recipient_email_hash,
                entityType: 'recipient',
                openRate,
                clickRate,
                bounceRate: 0, // Not tracked per recipient
                complaintRate,
                unsubscribeRate,
                engagementVelocity,
                daysSinceLastEngagement,
            });

            predictions.push({
                recipientEmail: row.recipient_email,
                emailHash: row.recipient_email_hash,
                churnPrediction,
            });
        }

        return predictions;
    }

    /**
     * Get all at-risk tenants
     */
    async getAtRiskTenants(minRiskTier: RiskTier = 'medium'): Promise<TenantHealthMetrics[]> {
        const tenantsResult = await this.db.query<{ id: string }>(`
            SELECT id FROM tenants WHERE status = 'active'
        `);

        const results: TenantHealthMetrics[] = [];
        const riskOrder: Record<RiskTier, number> = {
            critical: 4,
            high: 3,
            medium: 2,
            low: 1,
            healthy: 0,
        };

        for (const { id } of tenantsResult.rows) {
            try {
                const metrics = await this.predictTenantChurn(id);
                if (riskOrder[metrics.churnPrediction.riskTier] >= riskOrder[minRiskTier]) {
                    results.push(metrics);
                }
            } catch (error) {
                this.logger.error('Failed to predict churn for tenant', { tenantId: id, error });
            }
        }

        // Sort by risk score descending
        results.sort((a, b) => b.churnPrediction.riskScore - a.churnPrediction.riskScore);

        return results;
    }

    /**
     * Compute churn prediction from features
     */
    private computeChurnPrediction(input: {
        entityId: string;
        entityType: 'tenant' | 'recipient';
        openRate: number;
        clickRate: number;
        bounceRate: number;
        complaintRate: number;
        unsubscribeRate: number;
        engagementVelocity: number;
        daysSinceLastEngagement: number;
        hasNeverSent?: boolean;
    }): ChurnPrediction {
        const signals: ChurnSignal[] = [];
        let riskScore = 0;

        // New account that has never sent email — not a churn risk, just onboarding
        if (input.hasNeverSent) {
            return {
                entityId: input.entityId,
                entityType: input.entityType,
                churnProbability: 0.1,
                riskTier: 'low',
                riskScore: 5,
                signals: [{
                    type: 'new_account',
                    severity: 'info',
                    message: 'Tenant has not sent any emails yet. Monitor for onboarding progress.',
                    value: 0,
                    threshold: 0,
                }],
                recommendation: 'New account detected. Guide through onboarding and first campaign setup.',
                predictedChurnDate: null,
                lastEngagement: null,
                engagementTrend: 'stable',
            };
        }

        // Complaint rate signal (highest weight)
        if (input.complaintRate >= THRESHOLDS.criticalComplaintRate) {
            signals.push({
                type: 'complaint_rate',
                severity: 'critical',
                message: `Complaint rate ${(input.complaintRate * 100).toFixed(3)}% exceeds ISP threshold`,
                value: input.complaintRate,
                threshold: THRESHOLDS.criticalComplaintRate,
            });
            riskScore += 35;
        } else if (input.complaintRate >= THRESHOLDS.highComplaintRate) {
            signals.push({
                type: 'complaint_rate',
                severity: 'warning',
                message: `Complaint rate ${(input.complaintRate * 100).toFixed(3)}% approaching danger zone`,
                value: input.complaintRate,
                threshold: THRESHOLDS.highComplaintRate,
            });
            riskScore += 20;
        }

        // Bounce rate signal
        if (input.bounceRate >= THRESHOLDS.criticalBounceRate) {
            signals.push({
                type: 'bounce_rate',
                severity: 'critical',
                message: `Bounce rate ${(input.bounceRate * 100).toFixed(1)}% indicates list quality issues`,
                value: input.bounceRate,
                threshold: THRESHOLDS.criticalBounceRate,
            });
            riskScore += 25;
        } else if (input.bounceRate >= THRESHOLDS.highBounceRate) {
            signals.push({
                type: 'bounce_rate',
                severity: 'warning',
                message: `Bounce rate ${(input.bounceRate * 100).toFixed(1)}% is elevated`,
                value: input.bounceRate,
                threshold: THRESHOLDS.highBounceRate,
            });
            riskScore += 15;
        }

        // Engagement decay signal
        if (input.engagementVelocity <= THRESHOLDS.engagementDecayThreshold) {
            signals.push({
                type: 'engagement_decay',
                severity: 'warning',
                message: `Engagement dropped ${Math.abs(input.engagementVelocity * 100).toFixed(0)}% vs previous period`,
                value: input.engagementVelocity,
                threshold: THRESHOLDS.engagementDecayThreshold,
            });
            riskScore += 20;
        }

        // Inactivity signal
        if (input.daysSinceLastEngagement >= THRESHOLDS.inactiveDaysCritical) {
            signals.push({
                type: 'inactivity',
                severity: 'critical',
                message: `No engagement in ${input.daysSinceLastEngagement} days`,
                value: input.daysSinceLastEngagement,
                threshold: THRESHOLDS.inactiveDaysCritical,
            });
            riskScore += 30;
        } else if (input.daysSinceLastEngagement >= THRESHOLDS.inactiveDaysHigh) {
            signals.push({
                type: 'inactivity',
                severity: 'warning',
                message: `No engagement in ${input.daysSinceLastEngagement} days`,
                value: input.daysSinceLastEngagement,
                threshold: THRESHOLDS.inactiveDaysHigh,
            });
            riskScore += 15;
        } else if (input.daysSinceLastEngagement >= THRESHOLDS.inactiveDaysMedium) {
            signals.push({
                type: 'inactivity',
                severity: 'info',
                message: `No engagement in ${input.daysSinceLastEngagement} days`,
                value: input.daysSinceLastEngagement,
                threshold: THRESHOLDS.inactiveDaysMedium,
            });
            riskScore += 8;
        }

        // Low open rate signal
        if (input.openRate < 0.05 && input.entityType === 'tenant') {
            signals.push({
                type: 'low_open_rate',
                severity: 'warning',
                message: `Open rate ${(input.openRate * 100).toFixed(1)}% is below industry average`,
                value: input.openRate,
                threshold: 0.05,
            });
            riskScore += 10;
        }

        // Unsubscribe rate signal
        if (input.unsubscribeRate >= 0.02) {
            signals.push({
                type: 'unsubscribe_rate',
                severity: 'warning',
                message: `Unsubscribe rate ${(input.unsubscribeRate * 100).toFixed(2)}% indicates content mismatch`,
                value: input.unsubscribeRate,
                threshold: 0.02,
            });
            riskScore += 12;
        }

        // Cap risk score at 100
        riskScore = Math.min(100, riskScore);

        // Convert to probability using sigmoid-like mapping
        const churnProbability = 1 / (1 + Math.exp(-(riskScore - 50) / 15));

        // Determine risk tier
        let riskTier: RiskTier;
        if (riskScore >= 80) {
            riskTier = 'critical';
        } else if (riskScore >= 60) {
            riskTier = 'high';
        } else if (riskScore >= 40) {
            riskTier = 'medium';
        } else if (riskScore >= 20) {
            riskTier = 'low';
        } else {
            riskTier = 'healthy';
        }

        // Determine engagement trend
        let engagementTrend: 'declining' | 'stable' | 'improving';
        if (input.engagementVelocity <= -0.15) {
            engagementTrend = 'declining';
        } else if (input.engagementVelocity >= 0.15) {
            engagementTrend = 'improving';
        } else {
            engagementTrend = 'stable';
        }

        // Generate recommendation
        const recommendation = this.generateRecommendation(riskTier, signals);

        // Predict churn date (rough estimate)
        let predictedChurnDate: Date | null = null;
        if (riskTier === 'critical') {
            predictedChurnDate = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000); // 2 weeks
        } else if (riskTier === 'high') {
            predictedChurnDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 1 month
        } else if (riskTier === 'medium') {
            predictedChurnDate = new Date(Date.now() + 60 * 24 * 60 * 60 * 1000); // 2 months
        }

        // Last engagement date
        const lastEngagement = input.daysSinceLastEngagement < 999
            ? new Date(Date.now() - input.daysSinceLastEngagement * 24 * 60 * 60 * 1000)
            : null;

        return {
            entityId: input.entityId,
            entityType: input.entityType,
            churnProbability,
            riskTier,
            riskScore,
            signals,
            recommendation,
            predictedChurnDate,
            lastEngagement,
            engagementTrend,
        };
    }

    /**
     * Generate actionable recommendation
     */
    private generateRecommendation(riskTier: RiskTier, signals: ChurnSignal[]): string {
        if (riskTier === 'healthy') {
            return 'Continue current engagement strategy. Monitor for changes.';
        }

        const criticalSignals = signals.filter(s => s.severity === 'critical');
        const warningSignals = signals.filter(s => s.severity === 'warning');

        if (criticalSignals.some(s => s.type === 'complaint_rate')) {
            return 'URGENT: Review email content and sending practices immediately. Consider pausing campaigns until complaint sources are identified.';
        }

        if (criticalSignals.some(s => s.type === 'bounce_rate')) {
            return 'URGENT: Clean email list immediately. Remove invalid addresses and implement better validation at signup.';
        }

        if (criticalSignals.some(s => s.type === 'inactivity')) {
            return 'Launch re-engagement campaign targeting inactive subscribers. Consider win-back offer or content refresh.';
        }

        if (warningSignals.some(s => s.type === 'engagement_decay')) {
            return 'Test new subject lines and content formats. Consider segmenting list by engagement level.';
        }

        if (warningSignals.some(s => s.type === 'unsubscribe_rate')) {
            return 'Review email frequency and content relevance. Survey unsubscribers to understand reasons.';
        }

        return 'Review engagement metrics and consider A/B testing content and send times.';
    }
}
