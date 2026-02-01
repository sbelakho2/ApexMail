/**
 * Lead Scoring Engine
 * Calculates lead scores based on engagement, firmographics, and behavior
 */

import { createLogger } from '@apexmail/lib';
import type {
    Lead,
    EnrichmentResult,
    LeadActivity,
    PipelineStage,
} from '../types.js';

const logger = createLogger('lead-scoring');

interface ScoringWeights {
    firmographic: FirmographicWeights;
    engagement: EngagementWeights;
    behavior: BehaviorWeights;
    timing: TimingWeights;
}

interface FirmographicWeights {
    employeeRangeMultiplier: Record<string, number>;
    industryMultiplier: Record<string, number>;
    technologyBonus: Record<string, number>;
    locationBonus: Record<string, number>;
}

interface EngagementWeights {
    emailOpened: number;
    emailClicked: number;
    emailReplied: number;
    websiteVisit: number;
    pageView: number;
    documentDownload: number;
    demoRequested: number;
    formSubmission: number;
}

interface BehaviorWeights {
    recentActivityBonus: number; // Bonus for activity in last 7 days
    frequencyMultiplier: number; // Multiplier based on activity frequency
    stageProgressBonus: number; // Bonus for moving through pipeline
}

interface TimingWeights {
    decayRateDays: number; // Days for score to decay by half
    recencyBoostDays: number; // Days to apply recency boost
    recencyMultiplier: number;
}

const DEFAULT_WEIGHTS: ScoringWeights = {
    firmographic: {
        employeeRangeMultiplier: {
            '1-10': 0.8,
            '11-50': 1.0,
            '51-200': 1.2,
            '201-500': 1.4,
            '501-1000': 1.3,
            '1001-5000': 1.1,
            '5001-10000': 0.9,
            '10000+': 0.7,
        },
        industryMultiplier: {
            saas: 1.5,
            software: 1.4,
            technology: 1.3,
            fintech: 1.3,
            'e-commerce': 1.2,
            marketing: 1.2,
            healthcare: 1.1,
            education: 1.0,
            default: 1.0,
        },
        technologyBonus: {
            HubSpot: 10,
            Salesforce: 15,
            Intercom: 8,
            Zendesk: 5,
            Stripe: 10,
            Shopify: 8,
        },
        locationBonus: {
            US: 10,
            UK: 8,
            CA: 8,
            AU: 7,
            DE: 7,
            NL: 6,
            EE: 5,
        },
    },
    engagement: {
        emailOpened: 5,
        emailClicked: 15,
        emailReplied: 25,
        websiteVisit: 10,
        pageView: 2,
        documentDownload: 20,
        demoRequested: 50,
        formSubmission: 30,
    },
    behavior: {
        recentActivityBonus: 20,
        frequencyMultiplier: 1.5,
        stageProgressBonus: 15,
    },
    timing: {
        decayRateDays: 30,
        recencyBoostDays: 7,
        recencyMultiplier: 1.3,
    },
};

/**
 * Calculates firmographic score based on company data
 */
function calculateFirmographicScore(
    lead: Lead,
    enrichment: EnrichmentResult | null,
    weights: FirmographicWeights
): number {
    let score = 0;

    // Employee count scoring
    const employeeRange = enrichment?.employeeRange?.label || lead.employeeCount;
    if (employeeRange) {
        const multiplier =
            weights.employeeRangeMultiplier[employeeRange] || 1.0;
        score += 20 * multiplier;
    }

    // Industry scoring
    const industry = enrichment?.industry || lead.industry;
    if (industry) {
        const normalizedIndustry = industry.toLowerCase().replace(/\s+/g, '-');
        const multiplier =
            weights.industryMultiplier[normalizedIndustry] ||
            weights.industryMultiplier['default'] ||
            1.0;
        score += 15 * multiplier;
    }

    // Technology stack scoring
    const technologies = enrichment?.technologies || [];
    for (const tech of technologies) {
        const bonus = weights.technologyBonus[tech.name] || 0;
        score += bonus * tech.confidence;
    }

    // Location scoring
    const location = enrichment?.location || lead.location;
    if (location?.countryCode) {
        const bonus = weights.locationBonus[location.countryCode] || 0;
        score += bonus;
    }

    // Email provider quality (custom domain = higher score)
    if (lead.emailProvider === 'Self-Hosted' || lead.emailProvider === 'Google Workspace') {
        score += 10;
    } else if (lead.emailProvider === 'Microsoft 365') {
        score += 8;
    }

    // Social presence
    const socialProfiles = enrichment?.socialProfiles || lead.socialProfiles || [];
    score += Math.min(15, socialProfiles.length * 5);

    return Math.round(score);
}

/**
 * Calculates engagement score based on activities
 */
function calculateEngagementScore(
    activities: LeadActivity[],
    weights: EngagementWeights
): number {
    let score = 0;

    const activityCounts: Record<string, number> = {};

    for (const activity of activities) {
        activityCounts[activity.type] = (activityCounts[activity.type] || 0) + 1;
    }

    // Map activity types to weights
    const activityWeightMap: Record<string, keyof EngagementWeights> = {
        email_opened: 'emailOpened',
        email_clicked: 'emailClicked',
        email_replied: 'emailReplied',
    };

    for (const [activityType, count] of Object.entries(activityCounts)) {
        const weightKey = activityWeightMap[activityType];
        if (weightKey && weights[weightKey]) {
            // Diminishing returns for repeated actions
            const effectiveCount = Math.log2(count + 1);
            score += weights[weightKey] * effectiveCount;
        }
    }

    return Math.round(score);
}

/**
 * Calculates behavior score based on patterns
 */
function calculateBehaviorScore(
    lead: Lead,
    activities: LeadActivity[],
    weights: BehaviorWeights
): number {
    let score = 0;

    // Recent activity bonus
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const recentActivities = activities.filter(
        (a) => a.createdAt > sevenDaysAgo
    );

    if (recentActivities.length > 0) {
        score += weights.recentActivityBonus;
    }

    // Activity frequency multiplier
    if (activities.length > 10) {
        score *= weights.frequencyMultiplier;
    } else if (activities.length > 5) {
        score *= 1.2;
    }

    // Stage progress bonus
    const stageOrder: PipelineStage[] = [
        'prospect',
        'outreach',
        'engaged',
        'demo_scheduled',
        'proposal',
        'negotiation',
        'closed_won',
    ];

    const currentStageIndex = stageOrder.indexOf(lead.stage);
    if (currentStageIndex > 0) {
        score += weights.stageProgressBonus * currentStageIndex;
    }

    return Math.round(score);
}

/**
 * Applies time decay to historical scores
 */
function applyTimeDecay(
    score: number,
    lastActivityDate: Date | null,
    weights: TimingWeights
): number {
    if (!lastActivityDate) {
        return score;
    }

    const daysSinceActivity =
        (Date.now() - lastActivityDate.getTime()) / (24 * 60 * 60 * 1000);

    // Apply recency boost if within window
    if (daysSinceActivity <= weights.recencyBoostDays) {
        return score * weights.recencyMultiplier;
    }

    // Apply decay after window
    const decayFactor = Math.pow(0.5, daysSinceActivity / weights.decayRateDays);
    return Math.round(score * decayFactor);
}

/**
 * Calculates the complete lead score
 */
export function calculateLeadScore(
    lead: Lead,
    enrichment: EnrichmentResult | null,
    activities: LeadActivity[],
    customWeights?: Partial<ScoringWeights>
): {
    totalScore: number;
    breakdown: {
        firmographic: number;
        engagement: number;
        behavior: number;
        timeAdjusted: number;
    };
    grade: 'A' | 'B' | 'C' | 'D' | 'F';
} {
    const weights: ScoringWeights = {
        ...DEFAULT_WEIGHTS,
        ...customWeights,
    };

    // Calculate component scores
    const firmographicScore = calculateFirmographicScore(
        lead,
        enrichment,
        weights.firmographic
    );

    const engagementScore = calculateEngagementScore(
        activities,
        weights.engagement
    );

    const behaviorScore = calculateBehaviorScore(
        lead,
        activities,
        weights.behavior
    );

    // Combine scores
    let totalScore = firmographicScore + engagementScore + behaviorScore;

    // Apply time decay
    const lastActivity = activities.length > 0
        ? activities.reduce((latest, a) =>
            a.createdAt > latest.createdAt ? a : latest
        ).createdAt
        : lead.lastContactedAt;

    totalScore = applyTimeDecay(totalScore, lastActivity, weights.timing);

    // Calculate grade
    let grade: 'A' | 'B' | 'C' | 'D' | 'F';
    if (totalScore >= 80) {
        grade = 'A';
    } else if (totalScore >= 60) {
        grade = 'B';
    } else if (totalScore >= 40) {
        grade = 'C';
    } else if (totalScore >= 20) {
        grade = 'D';
    } else {
        grade = 'F';
    }

    logger.debug('Calculated lead score', {
        leadId: lead.id,
        totalScore,
        grade,
    });

    return {
        totalScore,
        breakdown: {
            firmographic: firmographicScore,
            engagement: engagementScore,
            behavior: behaviorScore,
            timeAdjusted: totalScore,
        },
        grade,
    };
}

/**
 * Bulk score multiple leads
 */
export function bulkScoreLeads(
    leads: Lead[],
    enrichments: Map<string, EnrichmentResult>,
    activities: Map<string, LeadActivity[]>,
    customWeights?: Partial<ScoringWeights>
): Map<string, ReturnType<typeof calculateLeadScore>> {
    const results = new Map<string, ReturnType<typeof calculateLeadScore>>();

    for (const lead of leads) {
        const enrichment = enrichments.get(lead.domain) || null;
        const leadActivities = activities.get(lead.id) || [];

        const score = calculateLeadScore(
            lead,
            enrichment,
            leadActivities,
            customWeights
        );

        results.set(lead.id, score);
    }

    return results;
}

/**
 * Returns leads sorted by score
 */
export function getTopLeads(
    scoredLeads: Map<string, ReturnType<typeof calculateLeadScore>>,
    limit: number = 10
): Array<{ leadId: string; score: ReturnType<typeof calculateLeadScore> }> {
    const sorted = Array.from(scoredLeads.entries())
        .map(([leadId, score]) => ({ leadId, score }))
        .sort((a, b) => b.score.totalScore - a.score.totalScore);

    return sorted.slice(0, limit);
}

/**
 * Identifies leads needing attention (high score but no recent contact)
 */
export function getLeadsNeedingAttention(
    leads: Lead[],
    scoredLeads: Map<string, ReturnType<typeof calculateLeadScore>>,
    options: {
        minScore?: number;
        daysSinceContact?: number;
    } = {}
): Lead[] {
    const minScore = options.minScore ?? 50;
    const daysSinceContact = options.daysSinceContact ?? 7;
    const cutoffDate = new Date(
        Date.now() - daysSinceContact * 24 * 60 * 60 * 1000
    );

    return leads.filter((lead) => {
        const scoreData = scoredLeads.get(lead.id);
        if (!scoreData || scoreData.totalScore < minScore) {
            return false;
        }

        if (
            lead.lastContactedAt &&
            lead.lastContactedAt > cutoffDate
        ) {
            return false;
        }

        return true;
    });
}
