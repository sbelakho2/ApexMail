/**
 * Tenant Risk Scoring Engine
 *
 * Provides comprehensive risk assessment for tenants based on
 * multiple factors including sending behavior, content quality,
 * complaint rates, and account history.
 */

import { Pool } from 'pg';
import { Redis } from 'ioredis';
import {
    TenantRiskProfile,
    RiskLevel,
    RiskFactor,
    RiskFactorType,
    TenantLimits,
    RiskFlag,
    RiskFlagType,
} from '../types';
import { complianceConfig } from '../config';

interface TenantMetrics {
    tenantId: string;
    accountAgeDays: number;
    totalEmailsSent: number;
    emailsSentLast24h: number;
    emailsSentLast7d: number;
    bounceRate: number;
    spamComplaintRate: number;
    unsubscribeRate: number;
    openRate: number;
    clickRate: number;
    verifiedDomains: number;
    paymentFailures: number;
    abuseReports: number;
    contentViolations: number;
    phishingDetections: number;
}

interface BlocklistStatus {
    isListed: boolean;
    lists: string[];
    firstListedAt: Date | null;
}

export class RiskScoringEngine {
    private db: Pool;
    private redis: Redis;
    private config = complianceConfig.riskScoring;

    constructor(db: Pool, redis: Redis) {
        this.db = db;
        this.redis = redis;
    }

    /**
     * Perform full risk assessment for a tenant
     */
    async assessTenant(tenantId: string): Promise<TenantRiskProfile> {
        const metrics = await this.collectMetrics(tenantId);
        const blocklistStatus = await this.checkBlocklists(tenantId);

        const factors = this.calculateFactors(metrics, blocklistStatus);
        const riskScore = this.calculateOverallScore(factors);
        const riskLevel = this.determineRiskLevel(riskScore);
        const limits = this.calculateLimits(riskLevel, metrics);
        const flags = await this.evaluateFlags(tenantId, metrics, blocklistStatus);

        const profile: TenantRiskProfile = {
            tenantId,
            riskScore,
            riskLevel,
            factors,
            limits,
            flags,
            lastAssessedAt: new Date(),
            nextAssessmentAt: this.calculateNextAssessment(riskLevel),
            createdAt: new Date(),
            updatedAt: new Date(),
        };

        await this.saveProfile(profile);
        await this.cacheProfile(profile);

        return profile;
    }

    /**
     * Get cached risk profile or assess if expired
     */
    async getProfile(tenantId: string): Promise<TenantRiskProfile | null> {
        const cacheKey = `risk:profile:${tenantId}`;
        const cached = await this.redis.get(cacheKey);

        if (cached) {
            try { return JSON.parse(cached); }
            catch { await this.redis.del(cacheKey); }
        }

        const result = await this.db.query<TenantRiskProfile>(
            `SELECT * FROM risk_profiles WHERE tenant_id = $1`,
            [tenantId]
        );

        if (result.rows.length > 0) {
            const profile = this.mapRowToProfile(result.rows[0]!);

            if (new Date() > profile.nextAssessmentAt) {
                return this.assessTenant(tenantId);
            }

            await this.cacheProfile(profile);
            return profile;
        }

        return this.assessTenant(tenantId);
    }

    /**
     * Collect all metrics needed for risk assessment.
     *
     * C-137: Index advisory for compliance report query performance.
     * The queries below use correlated subqueries across multiple tables.
     * Ensure the following indexes exist to prevent sequential scans:
     *
     *   -- Core message stats (getSendingStats)
     *   CREATE INDEX IF NOT EXISTS idx_messages_tenant_created
     *     ON messages (tenant_id, created_at);
     *   CREATE INDEX IF NOT EXISTS idx_messages_tenant_status_created
     *     ON messages (tenant_id, status, created_at);
     *
     *   -- Spam / unsubscribe lookups
     *   CREATE INDEX IF NOT EXISTS idx_spam_complaints_tenant_created
     *     ON spam_complaints (tenant_id, created_at);
     *   CREATE INDEX IF NOT EXISTS idx_unsubscribes_tenant_created
     *     ON unsubscribes (tenant_id, created_at);
     *
     *   -- Violation stats (getViolationStats)
     *   CREATE INDEX IF NOT EXISTS idx_abuse_reports_tenant_created
     *     ON abuse_reports (tenant_id, created_at);
     *   CREATE INDEX IF NOT EXISTS idx_content_violations_tenant_created
     *     ON content_violations (tenant_id, created_at);
     *   CREATE INDEX IF NOT EXISTS idx_scan_results_tenant_phishing_created
     *     ON scan_results (tenant_id, phishing_detected, created_at);
     *
     *   -- Account info subqueries
     *   CREATE INDEX IF NOT EXISTS idx_domains_tenant_verified
     *     ON domains (tenant_id, verified);
     *   CREATE INDEX IF NOT EXISTS idx_payment_events_tenant_type_created
     *     ON payment_events (tenant_id, type, created_at);
     *
     *   -- Engagement stats
     *   CREATE INDEX IF NOT EXISTS idx_campaign_stats_tenant_created
     *     ON campaign_stats (tenant_id, created_at);
     *
     *   -- Blocklist join
     *   CREATE INDEX IF NOT EXISTS idx_tenant_ips_tenant
     *     ON tenant_ips (tenant_id);
     *   CREATE INDEX IF NOT EXISTS idx_blocklist_entries_ip_removed
     *     ON blocklist_entries (ip_address, removed_at);
     *
     *   -- Audit log queries (used by audit export/stats)
     *   CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created
     *     ON audit_logs (tenant_id, created_at);
     */
    private async collectMetrics(tenantId: string): Promise<TenantMetrics> {
        const [
            accountInfo,
            sendingStats,
            engagementStats,
            violationStats,
        ] = await Promise.all([
            this.getAccountInfo(tenantId),
            this.getSendingStats(tenantId),
            this.getEngagementStats(tenantId),
            this.getViolationStats(tenantId),
        ]);

        return {
            tenantId,
            ...accountInfo,
            ...sendingStats,
            ...engagementStats,
            ...violationStats,
        };
    }

    private async getAccountInfo(
        tenantId: string
    ): Promise<{ accountAgeDays: number; verifiedDomains: number; paymentFailures: number }> {
        const result = await this.db.query(
            `SELECT
                EXTRACT(EPOCH FROM (NOW() - created_at)) / 86400 as account_age_days,
                (SELECT COUNT(*) FROM domains WHERE tenant_id = t.id AND verified = true) as verified_domains,
                (SELECT COUNT(*) FROM payment_events WHERE tenant_id = t.id AND type = 'failure' AND created_at > NOW() - INTERVAL '30 days') as payment_failures
            FROM tenants t
            WHERE id = $1`,
            [tenantId]
        );

        if (result.rows.length === 0) {
            return { accountAgeDays: 0, verifiedDomains: 0, paymentFailures: 0 };
        }

        return {
            accountAgeDays: Math.floor(result.rows[0].account_age_days),
            verifiedDomains: parseInt(result.rows[0].verified_domains, 10),
            paymentFailures: parseInt(result.rows[0].payment_failures, 10),
        };
    }

    private async getSendingStats(
        tenantId: string
    ): Promise<{
        totalEmailsSent: number;
        emailsSentLast24h: number;
        emailsSentLast7d: number;
        bounceRate: number;
        spamComplaintRate: number;
        unsubscribeRate: number;
    }> {
        const result = await this.db.query(
            `SELECT
                (SELECT COUNT(*) FROM messages WHERE tenant_id = $1) as total_sent,
                (SELECT COUNT(*) FROM messages WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '24 hours') as sent_24h,
                (SELECT COUNT(*) FROM messages WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '7 days') as sent_7d,
                COALESCE(
                    (SELECT COUNT(*) FILTER (WHERE status = 'bounced') * 100.0 / NULLIF(COUNT(*), 0)
                     FROM messages WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '7 days'), 0
                ) as bounce_rate,
                COALESCE(
                    (SELECT COUNT(*) * 100.0 / NULLIF((SELECT COUNT(*) FROM messages WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '7 days'), 0)
                     FROM spam_complaints WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '7 days'), 0
                ) as spam_rate,
                COALESCE(
                    (SELECT COUNT(*) * 100.0 / NULLIF((SELECT COUNT(*) FROM messages WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '7 days'), 0)
                     FROM unsubscribes WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '7 days'), 0
                ) as unsub_rate`,
            [tenantId]
        );

        const row = result.rows[0] || {};
        return {
            totalEmailsSent: parseInt(row.total_sent || '0', 10),
            emailsSentLast24h: parseInt(row.sent_24h || '0', 10),
            emailsSentLast7d: parseInt(row.sent_7d || '0', 10),
            bounceRate: parseFloat(row.bounce_rate || '0'),
            spamComplaintRate: parseFloat(row.spam_rate || '0'),
            unsubscribeRate: parseFloat(row.unsub_rate || '0'),
        };
    }

    private async getEngagementStats(
        tenantId: string
    ): Promise<{ openRate: number; clickRate: number }> {
        const result = await this.db.query(
            `SELECT
                COALESCE(AVG(open_rate), 0) as avg_open_rate,
                COALESCE(AVG(click_rate), 0) as avg_click_rate
            FROM campaign_stats
            WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '30 days'`,
            [tenantId]
        );

        return {
            openRate: parseFloat(result.rows[0]?.avg_open_rate || '0'),
            clickRate: parseFloat(result.rows[0]?.avg_click_rate || '0'),
        };
    }

    private async getViolationStats(
        tenantId: string
    ): Promise<{ abuseReports: number; contentViolations: number; phishingDetections: number }> {
        const result = await this.db.query(
            `SELECT
                (SELECT COUNT(*) FROM abuse_reports WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '30 days') as abuse_count,
                (SELECT COUNT(*) FROM content_violations WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '30 days') as violation_count,
                (SELECT COUNT(*) FROM scan_results WHERE tenant_id = $1 AND phishing_detected = true AND created_at > NOW() - INTERVAL '30 days') as phishing_count`,
            [tenantId]
        );

        return {
            abuseReports: parseInt(result.rows[0]?.abuse_count || '0', 10),
            contentViolations: parseInt(result.rows[0]?.violation_count || '0', 10),
            phishingDetections: parseInt(result.rows[0]?.phishing_count || '0', 10),
        };
    }

    /**
     * Check tenant IPs/domains against known blocklists
     */
    private async checkBlocklists(tenantId: string): Promise<BlocklistStatus> {
        const result = await this.db.query(
            `SELECT bl.list_name, bl.listed_at
            FROM blocklist_entries bl
            JOIN tenant_ips ti ON ti.ip_address = bl.ip_address
            WHERE ti.tenant_id = $1 AND bl.removed_at IS NULL`,
            [tenantId]
        );

        if (result.rows.length === 0) {
            return { isListed: false, lists: [], firstListedAt: null };
        }

        const lists = result.rows.map((r) => r.list_name);
        const firstListed = result.rows.reduce(
            (min, r) => (r.listed_at < min ? r.listed_at : min),
            result.rows[0].listed_at
        );

        return { isListed: true, lists, firstListedAt: firstListed };
    }

    /**
     * Calculate individual risk factors
     */
    private calculateFactors(
        metrics: TenantMetrics,
        blocklistStatus: BlocklistStatus
    ): RiskFactor[] {
        const factors: RiskFactor[] = [];

        // Spam complaints factor
        factors.push(this.calculateSpamFactor(metrics));

        // Bounce rate factor
        factors.push(this.calculateBounceFactor(metrics));

        // Phishing detection factor
        factors.push(this.calculatePhishingFactor(metrics));

        // Content violation factor
        factors.push(this.calculateContentViolationFactor(metrics));

        // Sending pattern factor
        factors.push(this.calculateSendingPatternFactor(metrics));

        // Account age factor
        factors.push(this.calculateAccountAgeFactor(metrics));

        // Verification status factor
        factors.push(this.calculateVerificationFactor(metrics));

        // Payment history factor
        factors.push(this.calculatePaymentFactor(metrics));

        // List quality factor (based on bounce + complaint rates)
        factors.push(this.calculateListQualityFactor(metrics));

        // Engagement rate factor
        factors.push(this.calculateEngagementFactor(metrics));

        // Blocklist factor (if listed)
        if (blocklistStatus.isListed) {
            factors.push({
                type: 'spam_complaints',
                score: 80 + blocklistStatus.lists.length * 5,
                weight: this.config.weights.spamComplaints,
                details: `Listed on ${blocklistStatus.lists.length} blocklist(s)`,
                evidence: { lists: blocklistStatus.lists },
            });
        }

        return factors;
    }

    private calculateSpamFactor(metrics: TenantMetrics): RiskFactor {
        let score = 0;
        const threshold = this.config.thresholds.spamComplaintRate;

        if (metrics.spamComplaintRate >= threshold * 2) {
            score = 100;
        } else if (metrics.spamComplaintRate >= threshold) {
            score = 70;
        } else if (metrics.spamComplaintRate >= threshold * 0.5) {
            score = 40;
        } else {
            score = Math.max(0, metrics.spamComplaintRate * 100);
        }

        return {
            type: 'spam_complaints' as RiskFactorType,
            score,
            weight: this.config.weights.spamComplaints,
            details: `Spam complaint rate: ${metrics.spamComplaintRate.toFixed(3)}%`,
            evidence: { rate: metrics.spamComplaintRate, threshold },
        };
    }

    private calculateBounceFactor(metrics: TenantMetrics): RiskFactor {
        let score = 0;
        const threshold = this.config.thresholds.bounceRate;

        if (metrics.bounceRate >= threshold * 2) {
            score = 90;
        } else if (metrics.bounceRate >= threshold) {
            score = 60;
        } else if (metrics.bounceRate >= threshold * 0.5) {
            score = 30;
        } else {
            score = Math.max(0, (metrics.bounceRate / threshold) * 20);
        }

        return {
            type: 'bounce_rate' as RiskFactorType,
            score,
            weight: this.config.weights.bounceRate,
            details: `Bounce rate: ${metrics.bounceRate.toFixed(2)}%`,
            evidence: { rate: metrics.bounceRate, threshold },
        };
    }

    private calculatePhishingFactor(metrics: TenantMetrics): RiskFactor {
        const score = Math.min(100, metrics.phishingDetections * 25);

        return {
            type: 'phishing_detection' as RiskFactorType,
            score,
            weight: this.config.weights.phishingDetection,
            details: `${metrics.phishingDetections} phishing detection(s) in last 30 days`,
            evidence: { count: metrics.phishingDetections },
        };
    }

    private calculateContentViolationFactor(metrics: TenantMetrics): RiskFactor {
        const score = Math.min(100, metrics.contentViolations * 20);

        return {
            type: 'content_violation' as RiskFactorType,
            score,
            weight: this.config.weights.contentViolation,
            details: `${metrics.contentViolations} content violation(s) in last 30 days`,
            evidence: { count: metrics.contentViolations },
        };
    }

    private calculateSendingPatternFactor(metrics: TenantMetrics): RiskFactor {
        // Check for unusual sending spikes
        const avgDaily = metrics.emailsSentLast7d / 7;
        const spikeRatio = avgDaily > 0 ? metrics.emailsSentLast24h / avgDaily : 0;

        let score = 0;
        if (spikeRatio > 5) {
            score = 80;
        } else if (spikeRatio > 3) {
            score = 50;
        } else if (spikeRatio > 2) {
            score = 20;
        }

        return {
            type: 'sending_pattern' as RiskFactorType,
            score,
            weight: this.config.weights.sendingPattern,
            details: `Sending spike ratio: ${spikeRatio.toFixed(2)}x average`,
            evidence: { ratio: spikeRatio, last24h: metrics.emailsSentLast24h, avgDaily },
        };
    }

    private calculateAccountAgeFactor(metrics: TenantMetrics): RiskFactor {
        // Newer accounts are higher risk
        let score = 0;
        if (metrics.accountAgeDays < 7) {
            score = 60;
        } else if (metrics.accountAgeDays < 30) {
            score = 40;
        } else if (metrics.accountAgeDays < 90) {
            score = 20;
        } else {
            score = 0;
        }

        return {
            type: 'account_age' as RiskFactorType,
            score,
            weight: this.config.weights.accountAge,
            details: `Account age: ${metrics.accountAgeDays} days`,
            evidence: { days: metrics.accountAgeDays },
        };
    }

    private calculateVerificationFactor(metrics: TenantMetrics): RiskFactor {
        // More verified domains = lower risk
        let score = 0;
        if (metrics.verifiedDomains === 0) {
            score = 50;
        } else if (metrics.verifiedDomains === 1) {
            score = 20;
        } else {
            score = 0;
        }

        return {
            type: 'verification_status' as RiskFactorType,
            score,
            weight: this.config.weights.verificationStatus,
            details: `Verified domains: ${metrics.verifiedDomains}`,
            evidence: { count: metrics.verifiedDomains },
        };
    }

    private calculatePaymentFactor(metrics: TenantMetrics): RiskFactor {
        const score = Math.min(100, metrics.paymentFailures * 30);

        return {
            type: 'payment_history' as RiskFactorType,
            score,
            weight: this.config.weights.paymentHistory,
            details: `Payment failures in last 30 days: ${metrics.paymentFailures}`,
            evidence: { failures: metrics.paymentFailures },
        };
    }

    private calculateListQualityFactor(metrics: TenantMetrics): RiskFactor {
        // Combined bounce + complaint rate as list quality indicator
        const combinedRate = metrics.bounceRate + metrics.spamComplaintRate * 10;
        const score = Math.min(100, combinedRate * 5);

        return {
            type: 'list_quality' as RiskFactorType,
            score,
            weight: this.config.weights.listQuality,
            details: `Combined quality score: ${combinedRate.toFixed(2)}`,
            evidence: { bounceRate: metrics.bounceRate, spamRate: metrics.spamComplaintRate },
        };
    }

    private calculateEngagementFactor(metrics: TenantMetrics): RiskFactor {
        // Low engagement can indicate poor list quality
        let score = 0;
        if (metrics.openRate < 5) {
            score = 50;
        } else if (metrics.openRate < 10) {
            score = 30;
        } else if (metrics.openRate < 15) {
            score = 10;
        }

        return {
            type: 'engagement_rate' as RiskFactorType,
            score,
            weight: this.config.weights.engagementRate,
            details: `Open rate: ${metrics.openRate.toFixed(2)}%, Click rate: ${metrics.clickRate.toFixed(2)}%`,
            evidence: { openRate: metrics.openRate, clickRate: metrics.clickRate },
        };
    }

    /**
     * Calculate overall risk score from weighted factors
     */
    private calculateOverallScore(factors: RiskFactor[]): number {
        let totalWeight = 0;
        let weightedSum = 0;

        for (const factor of factors) {
            weightedSum += factor.score * factor.weight;
            totalWeight += factor.weight;
        }

        return totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;
    }

    /**
     * Determine risk level from score
     */
    private determineRiskLevel(score: number): RiskLevel {
        if (score >= 75) return 'critical';
        if (score >= 50) return 'high';
        if (score >= 25) return 'medium';
        return 'low';
    }

    /**
     * Calculate sending limits based on risk level
     */
    private calculateLimits(riskLevel: RiskLevel, _metrics: TenantMetrics): TenantLimits {
        const baseLimits = this.config.baseLimits;

        const multipliers: Record<RiskLevel, number> = {
            low: 1.0,
            medium: 0.75,
            high: 0.5,
            critical: 0.1,
        };

        const multiplier = multipliers[riskLevel];

        return {
            maxDailyEmails: Math.floor(baseLimits.maxDailyEmails * multiplier),
            maxHourlyEmails: Math.floor(baseLimits.maxHourlyEmails * multiplier),
            maxRecipients: Math.floor(baseLimits.maxRecipients * multiplier),
            maxAttachmentSizeMb: baseLimits.maxAttachmentSizeMb,
            requireDoubleOptIn: riskLevel === 'high' || riskLevel === 'critical',
            requireUnsubscribeLink: true,
            allowedDomains: [],
            blockedRecipientPatterns: [],
        };
    }

    /**
     * Evaluate and create risk flags
     */
    private async evaluateFlags(
        _tenantId: string,
        metrics: TenantMetrics,
        blocklistStatus: BlocklistStatus
    ): Promise<RiskFlag[]> {
        const flags: RiskFlag[] = [];
        const now = new Date();

        if (metrics.bounceRate > this.config.thresholds.bounceRate) {
            flags.push({
                type: 'high_bounce_rate' as RiskFlagType,
                severity: metrics.bounceRate > this.config.thresholds.bounceRate * 2 ? 'critical' : 'alert',
                message: `Bounce rate of ${metrics.bounceRate.toFixed(2)}% exceeds threshold`,
                raisedAt: now,
                resolvedAt: null,
                autoResolved: false,
            });
        }

        if (metrics.spamComplaintRate > this.config.thresholds.spamComplaintRate) {
            flags.push({
                type: 'spam_trap_hit' as RiskFlagType,
                severity: 'critical',
                message: `Spam complaint rate of ${metrics.spamComplaintRate.toFixed(3)}% exceeds threshold`,
                raisedAt: now,
                resolvedAt: null,
                autoResolved: false,
            });
        }

        if (blocklistStatus.isListed) {
            flags.push({
                type: 'blocklist_detected' as RiskFlagType,
                severity: 'critical',
                message: `Listed on blocklists: ${blocklistStatus.lists.join(', ')}`,
                raisedAt: now,
                resolvedAt: null,
                autoResolved: false,
            });
        }

        // Check for unusual sending pattern
        const avgDaily = metrics.emailsSentLast7d / 7;
        if (avgDaily > 0 && metrics.emailsSentLast24h / avgDaily > 3) {
            flags.push({
                type: 'unusual_sending_pattern' as RiskFlagType,
                severity: 'warning',
                message: `Sending volume is ${(metrics.emailsSentLast24h / avgDaily).toFixed(1)}x higher than average`,
                raisedAt: now,
                resolvedAt: null,
                autoResolved: false,
            });
        }

        if (metrics.phishingDetections > 0) {
            flags.push({
                type: 'phishing_content' as RiskFlagType,
                severity: 'critical',
                message: `${metrics.phishingDetections} phishing detection(s) in last 30 days`,
                raisedAt: now,
                resolvedAt: null,
                autoResolved: false,
            });
        }

        return flags;
    }

    /**
     * Calculate next assessment time based on risk level
     */
    private calculateNextAssessment(riskLevel: RiskLevel): Date {
        const intervals: Record<RiskLevel, number> = {
            low: 24 * 60 * 60 * 1000, // 24 hours
            medium: 6 * 60 * 60 * 1000, // 6 hours
            high: 1 * 60 * 60 * 1000, // 1 hour
            critical: 15 * 60 * 1000, // 15 minutes
        };

        return new Date(Date.now() + intervals[riskLevel]);
    }

    /**
     * Save profile to database
     */
    private async saveProfile(profile: TenantRiskProfile): Promise<void> {
        await this.db.query(
            `INSERT INTO risk_profiles (
                tenant_id, risk_score, risk_level, factors, limits, flags,
                last_assessed_at, next_assessment_at, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (tenant_id) DO UPDATE SET
                risk_score = EXCLUDED.risk_score,
                risk_level = EXCLUDED.risk_level,
                factors = EXCLUDED.factors,
                limits = EXCLUDED.limits,
                flags = EXCLUDED.flags,
                last_assessed_at = EXCLUDED.last_assessed_at,
                next_assessment_at = EXCLUDED.next_assessment_at,
                updated_at = EXCLUDED.updated_at`,
            [
                profile.tenantId,
                profile.riskScore,
                profile.riskLevel,
                JSON.stringify(profile.factors),
                JSON.stringify(profile.limits),
                JSON.stringify(profile.flags),
                profile.lastAssessedAt,
                profile.nextAssessmentAt,
                profile.createdAt,
                profile.updatedAt,
            ]
        );
    }

    /**
     * Cache profile in Redis
     */
    private async cacheProfile(profile: TenantRiskProfile): Promise<void> {
        const cacheKey = `risk:profile:${profile.tenantId}`;
        const ttl = Math.floor(
            (profile.nextAssessmentAt.getTime() - Date.now()) / 1000
        );

        if (ttl > 0) {
            await this.redis.set(cacheKey, JSON.stringify(profile), 'EX', ttl);
        }
    }

    /**
     * Map database row to profile object
     */
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    private mapRowToProfile(row: any): TenantRiskProfile {
        return {
            tenantId: row.tenant_id as string,
            riskScore: row.risk_score as number,
            riskLevel: row.risk_level as RiskLevel,
            factors: row.factors as RiskFactor[],
            limits: row.limits as TenantLimits,
            flags: row.flags as RiskFlag[],
            lastAssessedAt: new Date(row.last_assessed_at as string),
            nextAssessmentAt: new Date(row.next_assessment_at as string),
            createdAt: new Date(row.created_at as string),
            updatedAt: new Date(row.updated_at as string),
        };
    }

    /**
     * Manually trigger reassessment
     * FIX-500-182: Use Redis NX lock to prevent concurrent reassessments for the same tenant.
     */
    async forceReassessment(tenantId: string): Promise<TenantRiskProfile> {
        const lockKey = `risk:reassessment:lock:${tenantId}`;
        const lockAcquired = await this.redis.set(lockKey, '1', 'EX', 60, 'NX');
        if (!lockAcquired) {
            // Another reassessment is in progress — return current profile instead
            const existing = await this.getProfile(tenantId);
            if (existing) return existing;
        }
        try {
            await this.redis.del(`risk:profile:${tenantId}`);
            return await this.assessTenant(tenantId);
        } finally {
            await this.redis.del(lockKey).catch(() => {});
        }
    }

    /**
     * Update limits for a specific tenant
     */
    async updateLimits(tenantId: string, limits: Partial<TenantLimits>): Promise<void> {
        await this.db.query(
            `UPDATE risk_profiles
            SET limits = limits || $2::jsonb, updated_at = NOW()
            WHERE tenant_id = $1`,
            [tenantId, JSON.stringify(limits)]
        );

        await this.redis.del(`risk:profile:${tenantId}`);
    }

    /**
     * Resolve a risk flag
     */
    async resolveFlag(
        tenantId: string,
        flagType: RiskFlagType,
        resolution: string
    ): Promise<void> {
        const profile = await this.getProfile(tenantId);
        if (!profile) return;

        const updatedFlags = profile.flags.map((flag) =>
            flag.type === flagType && !flag.resolvedAt
                ? { ...flag, resolvedAt: new Date(), autoResolved: false }
                : flag
        );

        await this.db.query(
            `UPDATE risk_profiles
            SET flags = $2, updated_at = NOW()
            WHERE tenant_id = $1`,
            [tenantId, JSON.stringify(updatedFlags)]
        );

        await this.redis.del(`risk:profile:${tenantId}`);

        // Log the resolution
        await this.db.query(
            `INSERT INTO flag_resolutions (tenant_id, flag_type, resolution, resolved_at)
            VALUES ($1, $2, $3, NOW())`,
            [tenantId, flagType, resolution]
        );
    }

    /**
     * Get all tenants with critical risk
     */
    async getCriticalRiskTenants(): Promise<TenantRiskProfile[]> {
        const result = await this.db.query(
            `SELECT * FROM risk_profiles
            WHERE risk_level = 'critical'
            ORDER BY risk_score DESC`
        );

        return result.rows.map(this.mapRowToProfile);
    }

    /**
     * Get risk statistics for dashboard
     */
    async getRiskStats(): Promise<{
        total: number;
        byLevel: Record<RiskLevel, number>;
        avgScore: number;
        flaggedTenants: number;
    }> {
        const result = await this.db.query(
            `SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE risk_level = 'low') as low_count,
                COUNT(*) FILTER (WHERE risk_level = 'medium') as medium_count,
                COUNT(*) FILTER (WHERE risk_level = 'high') as high_count,
                COUNT(*) FILTER (WHERE risk_level = 'critical') as critical_count,
                AVG(risk_score) as avg_score,
                COUNT(*) FILTER (WHERE jsonb_array_length(flags) > 0) as flagged_count
            FROM risk_profiles`
        );

        const row = result.rows[0];
        return {
            total: parseInt(row.total, 10),
            byLevel: {
                low: parseInt(row.low_count, 10),
                medium: parseInt(row.medium_count, 10),
                high: parseInt(row.high_count, 10),
                critical: parseInt(row.critical_count, 10),
            },
            avgScore: parseFloat(row.avg_score || '0'),
            flaggedTenants: parseInt(row.flagged_count, 10),
        };
    }
}

export default RiskScoringEngine;
