/**
 * Campaign Autopilot - Multi-Armed Bandit Template Optimizer
 * 
 * Automatically optimizes email template selection using Thompson Sampling.
 * Self-optimizing revenue machine that routes traffic to winning templates.
 * 
 * Algorithm: Thompson Sampling (Beta-Bernoulli Bandit)
 * - Models each template as a Beta distribution
 * - Balances exploration vs exploitation naturally
 * - Converges to best template while still testing others
 * 
 * Benefits:
 * - No manual A/B test management required
 * - Minimizes regret (lost conversions during testing)
 * - Adapts to changing performance over time
 * - Handles multiple variants efficiently
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';

interface CampaignAutopilotConfig {
    db: Pool;
    redis: Redis;
    logger: Logger;
}

export interface TemplateArm {
    templateId: string;
    name: string;
    // Beta distribution parameters
    alpha: number; // Successes + 1 (prior)
    beta: number;  // Failures + 1 (prior)
    // Stats
    impressions: number;
    conversions: number;
    conversionRate: number;
    // Thompson sampling
    sampledValue: number;
    selectionProbability: number;
}

export interface BanditState {
    campaignId: string;
    tenantId: string;
    targetMetric: 'open' | 'click' | 'reply' | 'conversion';
    arms: TemplateArm[];
    totalImpressions: number;
    totalConversions: number;
    bestArmId: string | null;
    confidenceInBest: number;
    phase: 'exploration' | 'exploitation' | 'converged';
    createdAt: Date;
    updatedAt: Date;
}

export interface TemplateSelection {
    templateId: string;
    reason: 'thompson_sampling' | 'exploration' | 'exploitation' | 'default';
    confidence: number;
    armStats: TemplateArm;
}

export interface OptimizationReport {
    campaignId: string;
    reportDate: Date;
    arms: Array<{
        templateId: string;
        name: string;
        impressions: number;
        conversions: number;
        conversionRate: number;
        credibleInterval: { lower: number; upper: number };
        probabilityOfBest: number;
    }>;
    bestPerformer: {
        templateId: string;
        name: string;
        lift: number; // vs average
    } | null;
    recommendation: string;
    expectedRegret: number;
}

// Prior strength (higher = more conservative, slower to update)
const PRIOR_STRENGTH = 1;

// Minimum impressions before we trust the data
const MIN_IMPRESSIONS_FOR_CONFIDENCE = 50;

// Threshold for "converged" state
const CONVERGENCE_THRESHOLD = 0.95;

// Exploration boost for new templates
const EXPLORATION_BONUS = 0.1;

export class CampaignAutopilot {
    private readonly db: Pool;
    private readonly redis: Redis;
    private readonly logger: Logger;
    private readonly cachePrefix = 'bandit:';
    private readonly cacheTTL = 300; // 5 minutes

    constructor(config: CampaignAutopilotConfig) {
        this.db = config.db;
        this.redis = config.redis;
        this.logger = config.logger;
    }

    /**
     * Initialize bandit for a campaign with multiple templates
     */
    async initializeCampaign(
        campaignId: string,
        tenantId: string,
        templateIds: string[],
        targetMetric: BanditState['targetMetric'] = 'open'
    ): Promise<BanditState> {
        // Get template names
        const templateResult = await this.db.query<{ id: string; name: string }>(`
            SELECT id, name FROM templates WHERE id = ANY($1)
        `, [templateIds]);

        const templateMap = new Map(templateResult.rows.map(r => [r.id, r.name]));

        const arms: TemplateArm[] = templateIds.map(templateId => ({
            templateId,
            name: templateMap.get(templateId) || templateId,
            alpha: PRIOR_STRENGTH, // Prior: 1 success
            beta: PRIOR_STRENGTH,  // Prior: 1 failure
            impressions: 0,
            conversions: 0,
            conversionRate: 0.5, // Prior expectation
            sampledValue: 0.5,
            selectionProbability: 1 / templateIds.length,
        }));

        const state: BanditState = {
            campaignId,
            tenantId,
            targetMetric,
            arms,
            totalImpressions: 0,
            totalConversions: 0,
            bestArmId: null,
            confidenceInBest: 0,
            phase: 'exploration',
            createdAt: new Date(),
            updatedAt: new Date(),
        };

        // Store in database
        await this.saveBanditState(state);

        return state;
    }

    /**
     * Select best template for next send using Thompson Sampling
     */
    async selectTemplate(campaignId: string): Promise<TemplateSelection> {
        const state = await this.getBanditState(campaignId);
        
        if (!state || state.arms.length === 0) {
            throw new Error(`Campaign ${campaignId} not found or has no templates`);
        }

        // Sample from each arm's beta distribution
        for (const arm of state.arms) {
            arm.sampledValue = this.sampleBeta(arm.alpha, arm.beta);
            
            // Add exploration bonus for under-sampled arms
            if (arm.impressions < MIN_IMPRESSIONS_FOR_CONFIDENCE) {
                const explorationBoost = EXPLORATION_BONUS * (1 - arm.impressions / MIN_IMPRESSIONS_FOR_CONFIDENCE);
                arm.sampledValue += explorationBoost;
            }
        }

        // Select arm with highest sampled value
        let bestArm = state.arms[0];
        if (bestArm) {
            for (const arm of state.arms) {
                if (arm.sampledValue > bestArm.sampledValue) {
                    bestArm = arm;
                }
            }
        }

        if (!bestArm) {
            throw new Error(`No arms available for campaign ${campaignId}`);
        }

        // Determine selection reason
        let reason: TemplateSelection['reason'] = 'thompson_sampling';
        if (state.phase === 'exploration') {
            reason = 'exploration';
        } else if (state.phase === 'converged') {
            reason = 'exploitation';
        }

        return {
            templateId: bestArm.templateId,
            reason,
            confidence: state.confidenceInBest,
            armStats: bestArm,
        };
    }

    /**
     * Record outcome for a sent email
     */
    async recordOutcome(
        campaignId: string,
        templateId: string,
        success: boolean
    ): Promise<void> {
        const state = await this.getBanditState(campaignId);
        if (!state) return;

        const arm = state.arms.find(a => a.templateId === templateId);
        if (!arm) return;

        // Update beta distribution
        if (success) {
            arm.alpha += 1;
            arm.conversions += 1;
            state.totalConversions += 1;
        } else {
            arm.beta += 1;
        }
        arm.impressions += 1;
        state.totalImpressions += 1;

        // Recalculate conversion rate (posterior mean)
        arm.conversionRate = arm.alpha / (arm.alpha + arm.beta);

        // Update selection probabilities via Monte Carlo
        this.updateSelectionProbabilities(state);

        // Determine best arm and confidence
        state.arms.sort((a, b) => b.selectionProbability - a.selectionProbability);
        state.bestArmId = state.arms[0]?.templateId || null;
        state.confidenceInBest = state.arms[0]?.selectionProbability || 0;

        // Determine phase
        if (state.totalImpressions < MIN_IMPRESSIONS_FOR_CONFIDENCE * state.arms.length) {
            state.phase = 'exploration';
        } else if (state.confidenceInBest >= CONVERGENCE_THRESHOLD) {
            state.phase = 'converged';
        } else {
            state.phase = 'exploitation';
        }

        state.updatedAt = new Date();

        await this.saveBanditState(state);
    }

    /**
     * Get optimization report for a campaign
     */
    async getOptimizationReport(campaignId: string): Promise<OptimizationReport> {
        const state = await this.getBanditState(campaignId);
        if (!state) {
            throw new Error(`Campaign ${campaignId} not found`);
        }

        const avgRate = state.totalImpressions > 0 
            ? state.totalConversions / state.totalImpressions 
            : 0;

        const arms = state.arms.map(arm => ({
            templateId: arm.templateId,
            name: arm.name,
            impressions: arm.impressions,
            conversions: arm.conversions,
            conversionRate: arm.conversionRate,
            credibleInterval: this.getCredibleInterval(arm.alpha, arm.beta),
            probabilityOfBest: arm.selectionProbability,
        }));

        // Find best performer
        let bestPerformer: OptimizationReport['bestPerformer'] = null;
        const topArm = arms.sort((a, b) => b.conversionRate - a.conversionRate)[0];
        if (topArm && topArm.impressions >= MIN_IMPRESSIONS_FOR_CONFIDENCE) {
            bestPerformer = {
                templateId: topArm.templateId,
                name: topArm.name,
                lift: avgRate > 0 ? (topArm.conversionRate - avgRate) / avgRate : 0,
            };
        }

        // Calculate expected regret
        const expectedRegret = this.calculateExpectedRegret(state);

        // Generate recommendation
        const recommendation = this.generateRecommendation(state, arms);

        return {
            campaignId,
            reportDate: new Date(),
            arms,
            bestPerformer,
            recommendation,
            expectedRegret,
        };
    }

    /**
     * Batch update from analytics events
     */
    async syncFromEvents(
        campaignId: string,
        startDate?: Date
    ): Promise<{ updated: number; errors: number }> {
        const state = await this.getBanditState(campaignId);
        if (!state) {
            return { updated: 0, errors: 0 };
        }

        const eventType = this.getEventTypeForMetric(state.targetMetric);
        const since = startDate || new Date(Date.now() - 24 * 60 * 60 * 1000);

        // Get event counts per template
        const result = await this.db.query<{
            template_id: string;
            sent_count: string;
            success_count: string;
        }>(`
            SELECT 
                m.template_id,
                COUNT(*) FILTER (WHERE e.event_type = 'sent') as sent_count,
                COUNT(*) FILTER (WHERE e.event_type = $1) as success_count
            FROM messages m
            JOIN events e ON e.message_id = m.message_id
            WHERE m.campaign_id = $2
                AND m.template_id IS NOT NULL
                AND e.timestamp >= $3
            GROUP BY m.template_id
        `, [eventType, campaignId, since]);

        let updated = 0;
        let errors = 0;

        for (const row of result.rows) {
            const arm = state.arms.find(a => a.templateId === row.template_id);
            if (!arm) {
                errors++;
                continue;
            }

            const sent = parseInt(row.sent_count, 10);
            const successes = parseInt(row.success_count, 10);
            const failures = sent - successes;

            // Update beta distribution (additive)
            arm.alpha += successes;
            arm.beta += failures;
            arm.impressions += sent;
            arm.conversions += successes;
            arm.conversionRate = arm.alpha / (arm.alpha + arm.beta);

            state.totalImpressions += sent;
            state.totalConversions += successes;
            updated++;
        }

        this.updateSelectionProbabilities(state);
        state.updatedAt = new Date();
        await this.saveBanditState(state);

        return { updated, errors };
    }

    /**
     * Sample from Beta distribution using Box-Muller approximation
     */
    private sampleBeta(alpha: number, beta: number): number {
        // For large alpha, beta, use normal approximation
        if (alpha > 10 && beta > 10) {
            const mean = alpha / (alpha + beta);
            const variance = (alpha * beta) / ((alpha + beta) ** 2 * (alpha + beta + 1));
            return Math.max(0, Math.min(1, mean + Math.sqrt(variance) * this.sampleNormal()));
        }

        // Use inverse CDF method for small alpha, beta
        const u1 = this.sampleGamma(alpha);
        const u2 = this.sampleGamma(beta);
        return u1 / (u1 + u2);
    }

    /**
     * Sample from Gamma distribution using Marsaglia and Tsang's method
     */
    private sampleGamma(shape: number): number {
        if (shape < 1) {
            return this.sampleGamma(shape + 1) * Math.pow(Math.random(), 1 / shape);
        }

        const d = shape - 1 / 3;
        const c = 1 / Math.sqrt(9 * d);

        // Marsaglia-Tsang method - guaranteed to converge
        const sampling = true;
        while (sampling) {
            let x: number;
            let v: number;
            
            do {
                x = this.sampleNormal();
                v = 1 + c * x;
            } while (v <= 0);

            v = v * v * v;
            const u = Math.random();

            if (u < 1 - 0.0331 * (x * x) * (x * x)) {
                return d * v;
            }

            if (Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) {
                return d * v;
            }
        }

        // Fallback (unreachable in practice)
        return d;
    }

    /**
     * Sample from standard normal distribution using Box-Muller
     */
    private sampleNormal(): number {
        const u1 = Math.random();
        const u2 = Math.random();
        return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
    }

    /**
     * Update selection probabilities via Monte Carlo simulation
     */
    private updateSelectionProbabilities(state: BanditState): void {
        const numSimulations = 10000;
        const winCounts = new Map<string, number>();

        for (const arm of state.arms) {
            winCounts.set(arm.templateId, 0);
        }

        for (let i = 0; i < numSimulations; i++) {
            let bestArm = state.arms[0];
            let bestSample = -1;

            for (const arm of state.arms) {
                const sample = this.sampleBeta(arm.alpha, arm.beta);
                if (sample > bestSample) {
                    bestSample = sample;
                    bestArm = arm;
                }
            }

            if (bestArm) {
                winCounts.set(bestArm.templateId, (winCounts.get(bestArm.templateId) || 0) + 1);
            }
        }

        for (const arm of state.arms) {
            arm.selectionProbability = (winCounts.get(arm.templateId) || 0) / numSimulations;
        }
    }

    /**
     * Get 95% credible interval for conversion rate
     */
    private getCredibleInterval(alpha: number, beta: number): { lower: number; upper: number } {
        // Use normal approximation for posterior
        const mean = alpha / (alpha + beta);
        const variance = (alpha * beta) / ((alpha + beta) ** 2 * (alpha + beta + 1));
        const std = Math.sqrt(variance);

        return {
            lower: Math.max(0, mean - 1.96 * std),
            upper: Math.min(1, mean + 1.96 * std),
        };
    }

    /**
     * Calculate expected regret
     */
    private calculateExpectedRegret(state: BanditState): number {
        if (state.arms.length < 2) return 0;

        // Find best arm
        const sortedArms = [...state.arms].sort((a, b) => b.conversionRate - a.conversionRate);
        const bestRate = sortedArms[0]?.conversionRate || 0;

        // Calculate regret: sum of (best_rate - arm_rate) * arm_impressions
        let regret = 0;
        for (const arm of state.arms) {
            regret += (bestRate - arm.conversionRate) * arm.impressions;
        }

        return regret;
    }

    /**
     * Generate recommendation based on state
     */
    private generateRecommendation(
        state: BanditState,
        arms: OptimizationReport['arms']
    ): string {
        if (state.totalImpressions < MIN_IMPRESSIONS_FOR_CONFIDENCE) {
            return 'Continue testing - need more data to determine winner.';
        }

        if (state.phase === 'converged') {
            const winner = arms.find(a => a.templateId === state.bestArmId);
            if (winner) {
                return `Template "${winner.name}" is the clear winner with ${(state.confidenceInBest * 100).toFixed(0)}% confidence. Consider promoting to 100% traffic.`;
            }
        }

        // Check for underperforming arms
        const avgRate = state.totalConversions / state.totalImpressions;
        const underperformers = arms.filter(a => 
            a.impressions >= MIN_IMPRESSIONS_FOR_CONFIDENCE && 
            a.credibleInterval.upper < avgRate
        );

        if (underperformers.length > 0) {
            const names = underperformers.map(a => `"${a.name}"`).join(', ');
            return `Consider removing underperforming templates: ${names}. They are consistently below average.`;
        }

        if (state.phase === 'exploitation') {
            return 'System is optimizing towards best performer. No action needed.';
        }

        return 'Continue A/B testing. Results are still inconclusive.';
    }

    /**
     * Get event type for target metric
     */
    private getEventTypeForMetric(metric: BanditState['targetMetric']): string {
        switch (metric) {
            case 'open': return 'opened';
            case 'click': return 'clicked';
            case 'reply': return 'replied';
            case 'conversion': return 'converted';
            default: return 'opened';
        }
    }

    /**
     * Get bandit state from cache or database
     */
    private async getBanditState(campaignId: string): Promise<BanditState | null> {
        // Try cache first
        const cached = await this.redis.get(`${this.cachePrefix}${campaignId}`);
        if (cached) {
            try {
                return JSON.parse(cached);
            } catch {
                // Fall through to database
            }
        }

        // Query database
        const result = await this.db.query<{ state: string }>(`
            SELECT state FROM campaign_bandit_state WHERE campaign_id = $1
        `, [campaignId]);

        if (result.rows[0]) {
            const state = JSON.parse(result.rows[0].state);
            await this.redis.setex(`${this.cachePrefix}${campaignId}`, this.cacheTTL, result.rows[0].state);
            return state;
        }

        return null;
    }

    /**
     * Save bandit state to database and cache
     */
    private async saveBanditState(state: BanditState): Promise<void> {
        const stateJson = JSON.stringify(state);

        await this.db.query(`
            INSERT INTO campaign_bandit_state (campaign_id, tenant_id, state, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (campaign_id) DO UPDATE SET state = $3, updated_at = NOW()
        `, [state.campaignId, state.tenantId, stateJson]);

        await this.redis.setex(`${this.cachePrefix}${state.campaignId}`, this.cacheTTL, stateJson);
    }

    /**
     * List all active bandits
     */
    async listActiveBandits(tenantId?: string): Promise<BanditState[]> {
        const tenantFilter = tenantId ? 'WHERE tenant_id = $1' : '';
        const params = tenantId ? [tenantId] : [];

        const result = await this.db.query<{ state: string }>(`
            SELECT state FROM campaign_bandit_state ${tenantFilter}
            ORDER BY updated_at DESC
        `, params);

        return result.rows.map(r => JSON.parse(r.state));
    }

    /**
     * Pause/disable bandit for a campaign
     */
    async pauseCampaign(campaignId: string, winningTemplateId?: string): Promise<void> {
        const state = await this.getBanditState(campaignId);
        if (!state) return;

        state.phase = 'converged';
        if (winningTemplateId) {
            state.bestArmId = winningTemplateId;
            state.confidenceInBest = 1;
        }

        await this.saveBanditState(state);
        this.logger.info('Campaign bandit paused', { campaignId, winningTemplateId });
    }

    /**
     * Reset bandit state for a campaign
     */
    async resetCampaign(campaignId: string): Promise<void> {
        const state = await this.getBanditState(campaignId);
        if (!state) return;

        // Reset all arms to priors
        for (const arm of state.arms) {
            arm.alpha = PRIOR_STRENGTH;
            arm.beta = PRIOR_STRENGTH;
            arm.impressions = 0;
            arm.conversions = 0;
            arm.conversionRate = 0.5;
            arm.sampledValue = 0.5;
            arm.selectionProbability = 1 / state.arms.length;
        }

        state.totalImpressions = 0;
        state.totalConversions = 0;
        state.bestArmId = null;
        state.confidenceInBest = 0;
        state.phase = 'exploration';
        state.updatedAt = new Date();

        await this.saveBanditState(state);
        this.logger.info('Campaign bandit reset', { campaignId });
    }
}
