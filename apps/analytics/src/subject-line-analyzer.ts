/**
 * Subject Line NLP Analyzer
 * 
 * Analyzes subject line effectiveness using NLP techniques and engagement correlation.
 * Identifies "power words" that drive opens for your specific audience.
 * 
 * Data Science Methodology:
 * - Tokenizes subject lines into unigrams and bigrams
 * - Correlates token presence with open rates
 * - Calculates lift (token open rate vs baseline)
 * - Identifies sentiment, urgency, and personalization patterns
 * - Provides A/B test recommendations
 * 
 * Reference: "Words that sell" analysis for email marketing
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';

interface SubjectLineAnalyzerConfig {
    db: Pool;
    redis: Redis;
    logger: Logger;
}

export interface TokenAnalysis {
    token: string;
    frequency: number;
    avgOpenRate: number;
    lift: number; // vs baseline
    sampleSize: number;
    confidence: 'high' | 'medium' | 'low';
    sentiment: 'positive' | 'negative' | 'neutral';
    category: TokenCategory;
}

export type TokenCategory = 
    | 'urgency'      // "now", "today", "limited"
    | 'exclusivity'  // "exclusive", "vip", "members"
    | 'benefit'      // "free", "save", "get"
    | 'curiosity'    // "secret", "discover", "revealed"
    | 'social_proof' // "trending", "popular", "millions"
    | 'personalization' // name, company, industry
    | 'question'     // "are you", "do you", "what if"
    | 'number'       // numbers in subject line
    | 'emoji'        // emoji usage
    | 'other';

export interface SubjectLineScore {
    subject: string;
    predictedOpenRate: number;
    scores: {
        overall: number;
        length: number;
        urgency: number;
        personalization: number;
        clarity: number;
        spamRisk: number;
    };
    issues: SubjectLineIssue[];
    suggestions: string[];
    powerTokens: string[];
    riskTokens: string[];
}

export interface SubjectLineIssue {
    type: 'warning' | 'error';
    message: string;
    position?: { start: number; end: number };
}

export interface AudienceInsights {
    tenantId: string;
    baselineOpenRate: number;
    totalSubjects: number;
    totalEmails: number;
    topPowerWords: TokenAnalysis[];
    topRiskWords: TokenAnalysis[];
    optimalLength: { min: number; max: number };
    emojiEffect: { lift: number; sampleSize: number };
    questionEffect: { lift: number; sampleSize: number };
    numberEffect: { lift: number; sampleSize: number };
    personalizationEffect: { lift: number; sampleSize: number };
}

// Token categorization patterns
const URGENCY_TOKENS = new Set(['now', 'today', 'urgent', 'limited', 'last', 'chance', 'expires', 'hurry', 'ending', 'final', 'deadline', 'asap', 'immediately']);
const EXCLUSIVITY_TOKENS = new Set(['exclusive', 'vip', 'members', 'only', 'invitation', 'private', 'selected', 'special']);
const BENEFIT_TOKENS = new Set(['free', 'save', 'get', 'win', 'earn', 'bonus', 'discount', 'deal', 'offer', 'gift']);
const CURIOSITY_TOKENS = new Set(['secret', 'discover', 'revealed', 'truth', 'hidden', 'mystery', 'surprising', 'shocking', 'unexpected']);
const SOCIAL_PROOF_TOKENS = new Set(['trending', 'popular', 'millions', 'thousands', 'everyone', 'best', 'top', 'rated', 'loved', 'trusted']);
const QUESTION_STARTERS = ['are you', 'do you', 'have you', 'what if', 'why', 'how', 'when', 'where', 'who', 'which', 'can you', 'did you', 'would you'];

// Spam trigger words (reduce deliverability)
const SPAM_TOKENS = new Set(['free', 'winner', 'congratulations', 'urgent', 'act now', 'limited time', 'click here', 'buy now', 'order now', 'no obligation', 'risk free', 'guaranteed', 'cash', 'money', 'dollars', 'cheap', 'lowest price']);

// Positive sentiment words
const POSITIVE_TOKENS = new Set(['love', 'amazing', 'awesome', 'great', 'fantastic', 'wonderful', 'excellent', 'best', 'happy', 'excited', 'thrilled', 'perfect', 'beautiful', 'incredible']);

// Negative sentiment words (can be effective for fear-based marketing)
const NEGATIVE_TOKENS = new Set(['miss', 'lose', 'mistake', 'wrong', 'bad', 'problem', 'issue', 'fail', 'terrible', 'worst', 'avoid', 'never', 'stop']);

export class SubjectLineAnalyzer {
    private readonly db: Pool;
    private readonly redis: Redis;
    // @ts-expect-error Reserved for future logging implementation
    private readonly _logger: Logger;
    private readonly cachePrefix = 'subject:';
    private readonly cacheTTL = 24 * 60 * 60; // 24 hours

    constructor(config: SubjectLineAnalyzerConfig) {
        this.db = config.db;
        this.redis = config.redis;
        this._logger = config.logger;
    }

    /**
     * Score a subject line before sending
     */
    async scoreSubjectLine(
        subject: string,
        tenantId?: string
    ): Promise<SubjectLineScore> {
        // Get audience insights for context
        let insights: AudienceInsights | null = null;
        if (tenantId) {
            insights = await this.getAudienceInsights(tenantId);
        }

        const tokens = this.tokenize(subject);
        const issues: SubjectLineIssue[] = [];
        const suggestions: string[] = [];
        const powerTokens: string[] = [];
        const riskTokens: string[] = [];

        // Length analysis
        const length = subject.length;
        let lengthScore = 100;
        if (length < 20) {
            lengthScore = 60;
            issues.push({ type: 'warning', message: 'Subject line may be too short. Consider adding more context.' });
        } else if (length > 60) {
            lengthScore = 70;
            issues.push({ type: 'warning', message: 'Subject line may be truncated on mobile. Keep under 60 characters.' });
        } else if (length >= 30 && length <= 50) {
            lengthScore = 100;
        }

        // Urgency analysis
        let urgencyScore = 0;
        for (const token of tokens) {
            if (URGENCY_TOKENS.has(token)) {
                urgencyScore += 25;
                powerTokens.push(token);
            }
        }
        urgencyScore = Math.min(100, urgencyScore);

        // Personalization analysis
        let personalizationScore = 0;
        if (subject.includes('{{') || subject.includes('{%')) {
            personalizationScore = 80;
            powerTokens.push('personalization');
        }
        if (/\b(you|your|you're)\b/i.test(subject)) {
            personalizationScore = Math.max(personalizationScore, 50);
        }

        // Clarity analysis
        let clarityScore = 100;
        if (subject.toUpperCase() === subject && subject.length > 5) {
            clarityScore -= 30;
            issues.push({ type: 'error', message: 'ALL CAPS reduces credibility and may trigger spam filters.' });
        }
        if (/[!]{2,}/.test(subject)) {
            clarityScore -= 20;
            issues.push({ type: 'warning', message: 'Multiple exclamation marks appear spammy.' });
        }
        if (/\${1,}/.test(subject)) {
            clarityScore -= 15;
            issues.push({ type: 'warning', message: 'Dollar signs may trigger spam filters.' });
        }

        // Spam risk analysis
        let spamRiskScore = 0;
        for (const token of tokens) {
            if (SPAM_TOKENS.has(token)) {
                spamRiskScore += 15;
                riskTokens.push(token);
            }
        }
        spamRiskScore = Math.min(100, spamRiskScore);
        if (spamRiskScore > 30) {
            issues.push({ 
                type: spamRiskScore > 50 ? 'error' : 'warning', 
                message: `Contains potential spam triggers: ${riskTokens.join(', ')}` 
            });
        }

        // Check for power words from audience insights
        if (insights) {
            for (const pw of insights.topPowerWords.slice(0, 10)) {
                if (tokens.includes(pw.token) && !powerTokens.includes(pw.token)) {
                    powerTokens.push(pw.token);
                }
            }
        }

        // Question effect
        const hasQuestion = QUESTION_STARTERS.some(q => subject.toLowerCase().startsWith(q)) || 
                           subject.includes('?');
        if (hasQuestion) {
            suggestions.push('Questions engage readers - good choice!');
        }

        // Emoji effect
        const hasEmoji = /[\u{1F600}-\u{1F64F}]|[\u{1F300}-\u{1F5FF}]|[\u{1F680}-\u{1F6FF}]|[\u{2600}-\u{26FF}]/u.test(subject);
        if (hasEmoji) {
            suggestions.push('Emojis can increase opens but use sparingly.');
        }

        // Number effect
        const hasNumber = /\d/.test(subject);
        if (hasNumber) {
            powerTokens.push('number');
        }

        // Generate suggestions
        if (urgencyScore === 0 && !hasQuestion) {
            suggestions.push('Consider adding urgency words like "today" or "limited" to increase opens.');
        }
        if (personalizationScore === 0) {
            suggestions.push('Personalized subject lines (using {{name}}) typically see +20% higher opens.');
        }
        if (!hasNumber) {
            suggestions.push('Numbers in subject lines (e.g., "5 tips") can increase engagement.');
        }

        // Calculate overall score
        const overallScore = Math.round(
            (lengthScore * 0.2) +
            (urgencyScore * 0.15) +
            (personalizationScore * 0.2) +
            (clarityScore * 0.25) +
            ((100 - spamRiskScore) * 0.2)
        );

        // Predict open rate (based on score and baseline)
        const baselineOpenRate = insights?.baselineOpenRate || 0.20;
        const scoreMultiplier = 0.5 + (overallScore / 100);
        const predictedOpenRate = baselineOpenRate * scoreMultiplier;

        return {
            subject,
            predictedOpenRate: Math.min(1, predictedOpenRate),
            scores: {
                overall: overallScore,
                length: lengthScore,
                urgency: urgencyScore,
                personalization: personalizationScore,
                clarity: clarityScore,
                spamRisk: spamRiskScore,
            },
            issues,
            suggestions,
            powerTokens,
            riskTokens,
        };
    }

    /**
     * Get audience-specific insights based on historical data
     */
    async getAudienceInsights(tenantId: string): Promise<AudienceInsights> {
        // Check cache
        const cacheKey = `${this.cachePrefix}insights:${tenantId}`;
        const cached = await this.redis.get(cacheKey);
        if (cached) {
            try {
                return JSON.parse(cached);
            } catch {
                // Continue to calculate
            }
        }

        // Get baseline metrics
        const baselineResult = await this.db.query<{
            total_subjects: string;
            total_sent: string;
            total_opened: string;
        }>(`
            SELECT 
                COUNT(DISTINCT subject) as total_subjects,
                COUNT(*) FILTER (WHERE event_type = 'sent') as total_sent,
                COUNT(*) FILTER (WHERE event_type = 'opened') as total_opened
            FROM messages m
            JOIN events e ON e.message_id = m.message_id
            WHERE m.tenant_id = $1
                AND m.created_at >= NOW() - INTERVAL '90 days'
        `, [tenantId]);

        const totalSubjects = parseInt(baselineResult.rows[0]?.total_subjects || '0', 10);
        const totalEmails = parseInt(baselineResult.rows[0]?.total_sent || '0', 10);
        const totalOpened = parseInt(baselineResult.rows[0]?.total_opened || '0', 10);
        const baselineOpenRate = totalEmails > 0 ? totalOpened / totalEmails : 0.20;

        // Get subject line performance data
        const subjectResult = await this.db.query<{
            subject: string;
            sent_count: string;
            open_count: string;
        }>(`
            SELECT 
                m.subject,
                COUNT(*) FILTER (WHERE e.event_type = 'sent') as sent_count,
                COUNT(*) FILTER (WHERE e.event_type = 'opened') as open_count
            FROM messages m
            JOIN events e ON e.message_id = m.message_id
            WHERE m.tenant_id = $1
                AND m.created_at >= NOW() - INTERVAL '90 days'
            GROUP BY m.subject
            HAVING COUNT(*) FILTER (WHERE e.event_type = 'sent') >= 10
        `, [tenantId]);

        // Analyze tokens
        const tokenStats = new Map<string, { opens: number; total: number }>();

        for (const row of subjectResult.rows) {
            const tokens = this.tokenize(row.subject);
            const sentCount = parseInt(row.sent_count, 10);
            const openCount = parseInt(row.open_count, 10);

            for (const token of new Set(tokens)) { // Unique tokens per subject
                const existing = tokenStats.get(token) || { opens: 0, total: 0 };
                existing.opens += openCount;
                existing.total += sentCount;
                tokenStats.set(token, existing);
            }
        }

        // Convert to token analysis
        const tokenAnalyses: TokenAnalysis[] = [];
        for (const [token, stats] of tokenStats) {
            if (stats.total < 20) continue; // Minimum sample size

            const openRate = stats.opens / stats.total;
            const lift = baselineOpenRate > 0 ? (openRate - baselineOpenRate) / baselineOpenRate : 0;

            tokenAnalyses.push({
                token,
                frequency: stats.total,
                avgOpenRate: openRate,
                lift,
                sampleSize: stats.total,
                confidence: stats.total >= 100 ? 'high' : stats.total >= 50 ? 'medium' : 'low',
                sentiment: this.categorizeSentiment(token),
                category: this.categorizeToken(token),
            });
        }

        // Sort by lift to find power words and risk words
        const sortedByLift = [...tokenAnalyses].sort((a, b) => b.lift - a.lift);
        const topPowerWords = sortedByLift.filter(t => t.lift > 0).slice(0, 20);
        const topRiskWords = sortedByLift.filter(t => t.lift < -0.1).reverse().slice(0, 10);

        // Analyze length effect
        const lengthResult = await this.db.query<{
            length_bucket: string;
            open_rate: string;
        }>(`
            SELECT 
                CASE 
                    WHEN LENGTH(m.subject) < 20 THEN 'short'
                    WHEN LENGTH(m.subject) <= 40 THEN 'medium'
                    WHEN LENGTH(m.subject) <= 60 THEN 'optimal'
                    ELSE 'long'
                END as length_bucket,
                AVG(CASE WHEN e.event_type = 'opened' THEN 1 ELSE 0 END) as open_rate
            FROM messages m
            JOIN events e ON e.message_id = m.message_id
            WHERE m.tenant_id = $1
                AND m.created_at >= NOW() - INTERVAL '90 days'
                AND e.event_type IN ('sent', 'opened')
            GROUP BY length_bucket
        `, [tenantId]);

        // Find optimal length range
        let optimalLength = { min: 30, max: 50 };
        let bestRate = 0;
        for (const row of lengthResult.rows) {
            const rate = parseFloat(row.open_rate);
            if (rate > bestRate) {
                bestRate = rate;
                switch (row.length_bucket) {
                    case 'short': optimalLength = { min: 10, max: 20 }; break;
                    case 'medium': optimalLength = { min: 20, max: 40 }; break;
                    case 'optimal': optimalLength = { min: 40, max: 60 }; break;
                    case 'long': optimalLength = { min: 60, max: 80 }; break;
                }
            }
        }

        // Analyze special features
        const emojiEffect = this.analyzeFeatureEffect(subjectResult.rows, baselineOpenRate, 
            (s) => /[\u{1F600}-\u{1F64F}]|[\u{1F300}-\u{1F5FF}]|[\u{1F680}-\u{1F6FF}]|[\u{2600}-\u{26FF}]/u.test(s));
        
        const questionEffect = this.analyzeFeatureEffect(subjectResult.rows, baselineOpenRate,
            (s) => s.includes('?') || QUESTION_STARTERS.some(q => s.toLowerCase().startsWith(q)));
        
        const numberEffect = this.analyzeFeatureEffect(subjectResult.rows, baselineOpenRate,
            (s) => /\d/.test(s));
        
        const personalizationEffect = this.analyzeFeatureEffect(subjectResult.rows, baselineOpenRate,
            (s) => s.includes('{{') || s.includes('{%'));

        const insights: AudienceInsights = {
            tenantId,
            baselineOpenRate,
            totalSubjects,
            totalEmails,
            topPowerWords,
            topRiskWords,
            optimalLength,
            emojiEffect,
            questionEffect,
            numberEffect,
            personalizationEffect,
        };

        // Cache insights
        await this.redis.setex(cacheKey, this.cacheTTL, JSON.stringify(insights));

        return insights;
    }

    /**
     * Suggest subject line variations for A/B testing
     */
    async suggestVariations(
        originalSubject: string,
        tenantId?: string
    ): Promise<{
        original: SubjectLineScore;
        variations: Array<{
            subject: string;
            score: SubjectLineScore;
            changeDescription: string;
        }>;
    }> {
        const original = await this.scoreSubjectLine(originalSubject, tenantId);
        const variations: Array<{
            subject: string;
            score: SubjectLineScore;
            changeDescription: string;
        }> = [];

        // Variation 1: Add urgency
        if (!URGENCY_TOKENS.has(this.tokenize(originalSubject)[0] || '')) {
            const urgentVersion = `🚀 ${originalSubject}`;
            variations.push({
                subject: urgentVersion,
                score: await this.scoreSubjectLine(urgentVersion, tenantId),
                changeDescription: 'Added emoji for urgency',
            });
        }

        // Variation 2: Question format
        if (!originalSubject.includes('?')) {
            const questionVersion = `Ready for ${originalSubject.toLowerCase()}?`;
            variations.push({
                subject: questionVersion,
                score: await this.scoreSubjectLine(questionVersion, tenantId),
                changeDescription: 'Converted to question format',
            });
        }

        // Variation 3: Shorter version
        if (originalSubject.length > 50) {
            const words = originalSubject.split(' ');
            const shorterVersion = words.slice(0, Math.ceil(words.length * 0.6)).join(' ');
            variations.push({
                subject: shorterVersion,
                score: await this.scoreSubjectLine(shorterVersion, tenantId),
                changeDescription: 'Shortened for mobile optimization',
            });
        }

        // Variation 4: Number format
        if (!/\d/.test(originalSubject)) {
            const numberVersion = `3 reasons: ${originalSubject}`;
            variations.push({
                subject: numberVersion,
                score: await this.scoreSubjectLine(numberVersion, tenantId),
                changeDescription: 'Added number for specificity',
            });
        }

        // Sort by predicted open rate
        variations.sort((a, b) => b.score.predictedOpenRate - a.score.predictedOpenRate);

        return { original, variations: variations.slice(0, 3) };
    }

    /**
     * Tokenize subject line
     */
    private tokenize(subject: string): string[] {
        // Lowercase and split on non-word characters
        return subject
            .toLowerCase()
            .replace(/[^\w\s]/g, ' ')
            .split(/\s+/)
            .filter(token => token.length > 2);
    }

    /**
     * Categorize token
     */
    private categorizeToken(token: string): TokenCategory {
        if (URGENCY_TOKENS.has(token)) return 'urgency';
        if (EXCLUSIVITY_TOKENS.has(token)) return 'exclusivity';
        if (BENEFIT_TOKENS.has(token)) return 'benefit';
        if (CURIOSITY_TOKENS.has(token)) return 'curiosity';
        if (SOCIAL_PROOF_TOKENS.has(token)) return 'social_proof';
        if (/^\d+$/.test(token)) return 'number';
        return 'other';
    }

    /**
     * Categorize sentiment
     */
    private categorizeSentiment(token: string): 'positive' | 'negative' | 'neutral' {
        if (POSITIVE_TOKENS.has(token)) return 'positive';
        if (NEGATIVE_TOKENS.has(token)) return 'negative';
        return 'neutral';
    }

    /**
     * Analyze effect of a feature on open rates
     */
    private analyzeFeatureEffect(
        data: Array<{ subject: string; sent_count: string; open_count: string }>,
        baseline: number,
        hasFeature: (subject: string) => boolean
    ): { lift: number; sampleSize: number } {
        let withFeatureSent = 0;
        let withFeatureOpened = 0;

        for (const row of data) {
            if (hasFeature(row.subject)) {
                withFeatureSent += parseInt(row.sent_count, 10);
                withFeatureOpened += parseInt(row.open_count, 10);
            }
        }

        if (withFeatureSent < 20) {
            return { lift: 0, sampleSize: withFeatureSent };
        }

        const featureOpenRate = withFeatureOpened / withFeatureSent;
        const lift = baseline > 0 ? (featureOpenRate - baseline) / baseline : 0;

        return { lift, sampleSize: withFeatureSent };
    }
}
