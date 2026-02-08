/**
 * @apexmail/ai - Content Generation Engine
 * 
 * AI-powered content generation for email marketing including
 * subject lines, email bodies, CTAs, and content analysis.
 */

import { InferenceEngine } from '../inference/engine.js';
import { getSharedEngine } from '../inference/index.js';
import { sentimentAnalyzer } from './sentiment.js';
import type { SentimentAnalyzer } from './sentiment.js';
import type {
    ContentGenerationRequest,
    ContentGenerationResult,
    ContentType,
    ContentAnalysis,
    SubjectLineRequest,
    SubjectLineResult,
    SubjectLineVariant,
    SubjectLineAnalysis,
    SubjectLineIssue,
    SentimentRequest,
    SentimentResult,
} from '../types.js';

/**
 * Content generation configuration
 */
export interface ContentGeneratorConfig {
    defaultStyle: string;
    maxSubjectLength: number;
    maxPreheaderLength: number;
    enableEmoji: boolean;
    enablePersonalization: boolean;
    industryContext: string;
}

/**
 * Default configuration
 */
const DEFAULT_CONTENT_CONFIG: ContentGeneratorConfig = {
    defaultStyle: 'professional',
    maxSubjectLength: 60,
    maxPreheaderLength: 100,
    enableEmoji: true,
    enablePersonalization: true,
    industryContext: 'general',
};

/**
 * Subject line patterns and templates
 */
const SUBJECT_PATTERNS = {
    urgency: [
        '🔥 {topic} - Only {timeframe} left!',
        'Last chance: {offer}',
        '⏰ Expires {timeframe}: {topic}',
        "Don't miss out on {topic}",
        '{timeframe} only: {offer}',
    ],
    curiosity: [
        'The secret to {topic} revealed',
        "You won't believe {topic}",
        '{number} things you need to know about {topic}',
        'What {audience} are saying about {topic}',
        'The truth about {topic}',
    ],
    benefit: [
        'Get {benefit} with {product}',
        'How to {benefit} in {timeframe}',
        '{benefit}: Your guide to {topic}',
        'Achieve {benefit} starting today',
        '{product} helps you {benefit}',
    ],
    personalized: [
        '{name}, your {topic} awaits',
        'Exclusive for {name}: {offer}',
        '{name}, we picked these for you',
        'Your personalized {topic} inside',
        '{name}, don\'t forget about {topic}',
    ],
    question: [
        'Ready to {benefit}?',
        'Want to know the secret to {topic}?',
        'Looking for {topic}?',
        'Need help with {topic}?',
        'Struggling with {topic}?',
    ],
    listicle: [
        '{number} ways to {benefit}',
        '{number} {topic} tips you need',
        'Top {number} {topic} of {year}',
        '{number} mistakes to avoid with {topic}',
        '{number} reasons to {action}',
    ],
    announcement: [
        '🎉 Introducing {product}',
        'New: {product} is here',
        'Just launched: {topic}',
        'Announcing {product}',
        'Big news: {topic}',
    ],
};

/**
 * CTA patterns and templates
 */
const CTA_PATTERNS = {
    action: ['Shop Now', 'Get Started', 'Learn More', 'Try Free', 'Claim Offer'],
    urgency: ['Get It Now', 'Claim Before Midnight', 'Grab Yours', 'Act Fast', 'Limited Time'],
    benefit: ['Start Saving', 'Boost Your Results', 'Transform Today', 'Unlock Access', 'See Results'],
    soft: ['Explore', 'Discover', 'See How', 'Find Out More', 'Take a Look'],
};

/**
 * Content Generation Engine
 * 
 * Generates email marketing content using AI and template-based approaches.
 */
export class ContentGenerator {
    private engine: InferenceEngine;
    private config: ContentGeneratorConfig;
    private sentimentAnalyzer: SentimentAnalyzer;

    constructor(config?: Partial<ContentGeneratorConfig>) {
        this.config = { ...DEFAULT_CONTENT_CONFIG, ...config };
        // FIX-500-099: Use shared engine instead of creating a new instance
        this.engine = getSharedEngine({
            temperature: 0.8, // Higher creativity for content
        });
        // FIX-500-131: Use canonical singleton instead of creating a new instance.
        // This shares custom lexicon entries across all callers.
        this.sentimentAnalyzer = sentimentAnalyzer;
        
        // Add email marketing specific words to lexicon
        this.sentimentAnalyzer.addCustomWords({
            'sale': 1, 'deal': 1, 'offer': 1, 'promo': 1, 'coupon': 1,
            'clearance': 1, 'flash': 1, 'membership': 1, 'vip': 2,
            'premium': 1, 'upgrade': 1, 'unlock': 1, 'access': 1,
        });
    }

    /**
     * Generate content based on request
     */
    async generate(request: ContentGenerationRequest): Promise<ContentGenerationResult> {
        const startTime = Date.now();

        try {
            let content: string;
            let analysis: ContentAnalysis;

            switch (request.type) {
                case 'subject_line': {
                    const subjectResult = await this.generateSubjectLines({
                        topic: request.topic ?? '',
                        tone: typeof request.style === 'string' ? request.style : this.config.defaultStyle,
                        industry: request.industry || this.config.industryContext,
                        keywords: request.keywords,
                        count: request.variants || 5,
                    });
                    content = subjectResult.variants.map((v) => v.text ?? '').join('\n');
                    analysis = this.buildAnalysis(content, request.type);
                    break;
                }

                case 'preheader':
                    content = await this.generatePreheader(request);
                    analysis = this.buildAnalysis(content, request.type);
                    break;

                case 'email_body':
                    content = await this.generateEmailBody(request);
                    analysis = this.buildAnalysis(content, request.type);
                    break;

                case 'cta':
                    content = this.generateCTAs(request);
                    analysis = this.buildAnalysis(content, request.type);
                    break;

                case 'product_description':
                    content = await this.generateProductDescription(request);
                    analysis = this.buildAnalysis(content, request.type);
                    break;

                case 'social_proof':
                    content = await this.generateSocialProof(request);
                    analysis = this.buildAnalysis(content, request.type);
                    break;

                case 'ps_line':
                    content = await this.generatePSLine(request);
                    analysis = this.buildAnalysis(content, request.type);
                    break;

                default:
                    throw new Error(`Unknown content type: ${request.type}`);
            }

            return {
                content,
                type: request.type,
                style: request.style || this.config.defaultStyle,
                analysis,
                variants: request.variants ? content.split('\n').filter(Boolean) : undefined,
                latencyMs: Date.now() - startTime,
            };
        } catch (error) {
            throw new Error(`Content generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Generate subject line variants
     */
    async generateSubjectLines(request: SubjectLineRequest): Promise<SubjectLineResult> {
        const startTime = Date.now();
        const variants: SubjectLineVariant[] = [];
        const requestCount = request.count ?? 5;

        // Select appropriate patterns based on tone
        const selectedPatterns = this.selectPatterns(request.tone ?? 'professional');

        // Generate variants from patterns
        for (let i = 0; i < requestCount && i < selectedPatterns.length; i++) {
            const pattern = selectedPatterns[i];
            const text = this.fillPattern(pattern, request);

            // Analyze the subject line
            const analysis = this.analyzeSubjectLine(text);

            variants.push({
                text: this.trimToLength(text, this.config.maxSubjectLength),
                score: analysis.score ?? 0,
                analysis,
            });
        }

        // Generate AI-powered variants if needed
        if (variants.length < requestCount) {
            const aiVariants = await this.generateAISubjectLines(request, requestCount - variants.length);
            variants.push(...aiVariants);
        }

        // Sort by score
        variants.sort((a, b) => b.score - a.score);

        return {
            variants: variants.slice(0, request.count),
            bestVariant: variants[0],
            latencyMs: Date.now() - startTime,
        };
    }

    /**
     * Analyze content sentiment using ML-based analyzer
     * 
     * Uses AFINN lexicon with negation handling, intensifiers,
     * and NRC emotion detection for comprehensive sentiment analysis.
     */
    async analyzeSentiment(request: SentimentRequest): Promise<SentimentResult> {
        // Use the enhanced ML-based sentiment analyzer
        const result = this.sentimentAnalyzer.analyze(request.text);
        
        // If granularity is specified, add additional analysis
        if (request.granularity === 'sentence') {
            const sentences = this.sentimentAnalyzer.analyzeBySentence(request.text);
            return {
                ...result,
                sentences: sentences.map((s, idx) => ({
                    text: s.sentence,
                    sentiment: {
                        label: s.sentiment,
                        score: s.score,
                        confidence: result.confidence ?? 0,
                    },
                    span: { start: idx, end: idx },
                })),
            };
        }

        if (request.granularity === 'aspect' && request.aspects) {
            const aspects = this.sentimentAnalyzer.analyzeAspects(
                request.text,
                request.aspects
            );
            return {
                ...result,
                aspects: aspects.map((a) => ({
                    aspect: a.aspect,
                    sentiment: {
                        label: a.sentiment,
                        score: a.score,
                        confidence: result.confidence ?? 0,
                    },
                    mentions: [a.aspect],
                })),
            };
        }

        return result;
    }

    /**
     * Analyze email content for quality
     */
    analyzeContent(content: string): ContentAnalysis {
        return this.buildAnalysis(content, 'email_body');
    }

    /**
     * Get content suggestions
     */
    getSuggestions(content: string, type: ContentType): string[] {
        const suggestions: string[] = [];
        const analysis = this.buildAnalysis(content, type);

        if (analysis.readabilityScore < 60) {
            suggestions.push('Simplify your language - aim for 8th grade reading level');
        }

        if (analysis.wordCount > 500 && type === 'email_body') {
            suggestions.push('Consider shortening your email - optimal length is 50-125 words');
        }

        if (analysis.spamScore > 0.3) {
            suggestions.push('Reduce spam trigger words like "FREE", "BUY NOW", excessive caps');
        }

        if (type === 'subject_line') {
            if (content.length > 60) {
                suggestions.push('Subject line is too long - keep under 60 characters');
            }
            if (!content.match(/[?!🔥⏰🎉]/u)) {
                suggestions.push('Consider adding urgency or emotion with punctuation or emoji');
            }
        }

        if (!content.includes('{{') && this.config.enablePersonalization) {
            suggestions.push('Add personalization tokens like {{firstName}} for better engagement');
        }

        return suggestions;
    }

    // ========================================
    // PRIVATE METHODS
    // ========================================

    private selectPatterns(tone: string): string[] {
        const patterns: string[] = [];

        switch (tone) {
            case 'urgent':
                patterns.push(...SUBJECT_PATTERNS.urgency);
                patterns.push(...SUBJECT_PATTERNS.question);
                break;
            case 'casual':
                patterns.push(...SUBJECT_PATTERNS.curiosity);
                patterns.push(...SUBJECT_PATTERNS.question);
                patterns.push(...SUBJECT_PATTERNS.personalized);
                break;
            case 'professional':
                patterns.push(...SUBJECT_PATTERNS.benefit);
                patterns.push(...SUBJECT_PATTERNS.announcement);
                patterns.push(...SUBJECT_PATTERNS.listicle);
                break;
            case 'playful':
                patterns.push(...SUBJECT_PATTERNS.curiosity);
                patterns.push(...SUBJECT_PATTERNS.personalized);
                break;
            default:
                patterns.push(...SUBJECT_PATTERNS.benefit);
                patterns.push(...SUBJECT_PATTERNS.curiosity);
        }

        // Shuffle for variety
        // FIX-500-382: Fisher-Yates shuffle instead of biased sort(() => Math.random() - 0.5)
        for (let i = patterns.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [patterns[i], patterns[j]] = [patterns[j], patterns[i]];
        }
        return patterns;
    }

    private fillPattern(
        pattern: string,
        request: SubjectLineRequest
    ): string {
        let result = pattern;

        // Replace placeholders
        result = result.replace(/{topic}/g, request.topic);
        result = result.replace(/{product}/g, request.product || request.topic);
        result = result.replace(/{benefit}/g, request.benefit || 'amazing results');
        result = result.replace(/{offer}/g, request.offer || 'exclusive offer');
        result = result.replace(/{audience}/g, request.audience || 'customers');
        result = result.replace(/{name}/g, '{{firstName}}');
        result = result.replace(/{timeframe}/g, request.timeframe || '24 hours');
        result = result.replace(/{number}/g, String(request.number || Math.floor(Math.random() * 7) + 3));
        result = result.replace(/{year}/g, String(new Date().getFullYear()));
        result = result.replace(/{action}/g, request.action || 'start today');

        // Remove emoji if disabled
        if (!this.config.enableEmoji) {
            result = result.replace(/[\u{1F300}-\u{1F9FF}]/gu, '').trim();
        }

        return result;
    }

    private analyzeSubjectLine(text: string): SubjectLineAnalysis {
        const issues: SubjectLineIssue[] = [];
        let score = 80; // Start with good score

        // Length check
        // FIX-500-381: Check > 70 first — the old order (> 60 then else-if > 70)
        // made the > 70 branch unreachable since > 70 is always > 60.
        if (text.length > 70) {
            issues.push({
                type: 'length',
                severity: 'error',
                message: `Subject line is too long (${text.length} characters)`,
            });
            score -= 20;
        } else if (text.length > 60) {
            issues.push({
                type: 'length',
                severity: 'warning',
                message: `Subject line is ${text.length} characters (recommended: under 60)`,
            });
            score -= 10;
        }

        // Spam words check
        // FIX-500-400: Use word-boundary regex to avoid false positives
        // (e.g. "freedom" matching "free", "browse" matching "buy now")
        const spamWords = ['free', 'winner', 'click here', 'act now', 'limited time', 'buy now'];
        const lowerText = text.toLowerCase();
        for (const word of spamWords) {
            const re = new RegExp(`\\b${word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
            if (re.test(lowerText)) {
                issues.push({
                    type: 'spam',
                    severity: 'warning',
                    message: `Contains potential spam trigger: "${word}"`,
                });
                score -= 5;
            }
        }

        // All caps check
        const capsRatio = (text.match(/[A-Z]/g)?.length || 0) / text.length;
        if (capsRatio > 0.5) {
            issues.push({
                type: 'caps',
                severity: 'warning',
                message: 'Too many capital letters may trigger spam filters',
            });
            score -= 10;
        }

        // Emoji check (positive if present)
        if (text.match(/[\u{1F300}-\u{1F9FF}]/gu)) {
            score += 5;
        }

        // Personalization check
        if (text.includes('{{')) {
            score += 10;
        }

        // Question or exclamation (engagement boost)
        if (text.includes('?') || text.includes('!')) {
            score += 5;
        }

        return {
            score: Math.max(0, Math.min(100, score)),
            issues,
            predictions: {
                openRate: score / 100 * 0.35, // Estimate based on score
                spamProbability: issues.filter((i) => i.type === 'spam').length * 0.1,
            },
        };
    }

    private async generateAISubjectLines(
        request: SubjectLineRequest,
        count: number
    ): Promise<SubjectLineVariant[]> {
        const prompt = `Generate ${count} email subject lines for:
Topic: ${request.topic}
Tone: ${request.tone}
Industry: ${request.industry}
${request.keywords ? `Keywords to include: ${request.keywords.join(', ')}` : ''}

Requirements:
- Under 60 characters each
- Compelling and engaging
- Appropriate for email marketing
- No spam trigger words

Return only the subject lines, one per line.`;

        try {
            const result = await this.engine.generate(prompt, { maxTokens: 500 });
            const lines = result.text.split('\n').filter(Boolean).slice(0, count);

            return lines.map((line) => {
                const text = line.replace(/^\d+\.\s*/, '').trim();
                const analysis = this.analyzeSubjectLine(text);
                return {
                    text: this.trimToLength(text, this.config.maxSubjectLength),
                    score: analysis.score ?? 0,
                    analysis,
                };
            });
        } catch {
            return [];
        }
    }

    private async generatePreheader(request: ContentGenerationRequest): Promise<string> {
        const prompt = `Generate an email preheader (preview text) for:
Topic: ${request.topic}
Style: ${request.style || 'professional'}
${request.subjectLine ? `Subject line: ${request.subjectLine}` : ''}

Requirements:
- 40-100 characters
- Complements the subject line
- Adds value or context
- Encourages opening

Return only the preheader text.`;

        const result = await this.engine.generate(prompt, { maxTokens: 150 });
        return this.trimToLength(result.text.trim(), this.config.maxPreheaderLength);
    }

    private async generateEmailBody(request: ContentGenerationRequest): Promise<string> {
        const prompt = `Write an email body for:
Topic: ${request.topic}
Style: ${request.style || 'professional'}
Goal: ${request.goal || 'engagement'}
${request.keyPoints ? `Key points: ${request.keyPoints.join(', ')}` : ''}

Requirements:
- 100-250 words
- Clear and compelling
- Include a call-to-action
- Personalization-ready (use {{firstName}} where appropriate)
- Easy to scan with short paragraphs

Write the email body only.`;

        const result = await this.engine.generate(prompt, { maxTokens: 800 });
        return result.text.trim();
    }

    private generateCTAs(request: ContentGenerationRequest): string {
        const style = request.style || this.config.defaultStyle;
        const ctas: string[] = [];

        // Select appropriate CTA patterns
        let patterns: string[];
        switch (style) {
            case 'urgent':
                patterns = CTA_PATTERNS.urgency;
                break;
            case 'casual':
            case 'playful':
                patterns = CTA_PATTERNS.soft;
                break;
            case 'professional':
                patterns = [...CTA_PATTERNS.action, ...CTA_PATTERNS.benefit];
                break;
            default:
                patterns = CTA_PATTERNS.action;
        }

        // Generate variants
        // FIX-500-382: Fisher-Yates shuffle instead of biased sort
        for (let i = patterns.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [patterns[i], patterns[j]] = [patterns[j], patterns[i]];
        }
        ctas.push(...patterns.slice(0, request.variants || 5));

        // Customize with topic if provided
        if (request.topic) {
            ctas.push(`Get Your ${request.topic}`);
            ctas.push(`Start ${request.topic}`);
        }

        return ctas.slice(0, request.variants || 5).join('\n');
    }

    private async generateProductDescription(request: ContentGenerationRequest): Promise<string> {
        const prompt = `Write a compelling product description for email:
Product/Topic: ${request.topic}
Style: ${request.style || 'professional'}
${request.features ? `Features: ${request.features.join(', ')}` : ''}

Requirements:
- 50-150 words
- Focus on benefits
- Engaging and persuasive
- Easy to scan

Write the description only.`;

        const result = await this.engine.generate(prompt, { maxTokens: 400 });
        return result.text.trim();
    }

    private async generateSocialProof(request: ContentGenerationRequest): Promise<string> {
        const prompt = `Write social proof content for email:
Topic: ${request.topic}
Style: ${request.style || 'professional'}

Generate:
1. A customer testimonial quote
2. A statistic or metric
3. A brief case study mention

Keep each under 50 words.`;

        const result = await this.engine.generate(prompt, { maxTokens: 400 });
        return result.text.trim();
    }

    private async generatePSLine(request: ContentGenerationRequest): Promise<string> {
        const prompt = `Write a P.S. line for an email about:
Topic: ${request.topic}
Style: ${request.style || 'professional'}

Requirements:
- Under 100 characters
- Add urgency or extra value
- Compelling final hook

Write only the P.S. line (including "P.S.").`;

        const result = await this.engine.generate(prompt, { maxTokens: 100 });
        return result.text.trim();
    }

    private buildAnalysis(content: string, type: ContentType): ContentAnalysis {
        const words = content.split(/\s+/).filter(Boolean);
        const sentences = content.split(/[.!?]+/).filter(Boolean);

        // Flesch-Kincaid readability approximation
        const syllables = this.countSyllables(content);
        const readabilityScore = Math.max(0, Math.min(100,
            206.835 - 1.015 * (words.length / sentences.length) - 84.6 * (syllables / words.length)
        ));

        // Spam score
        // FIX-500-400: Use word-boundary regex to avoid false positives
        const spamWords = ['free', 'winner', 'click', 'buy now', 'limited', 'act now', 'urgent'];
        const lowerContent = content.toLowerCase();
        const spamCount = spamWords.filter((w) => {
            const re = new RegExp(`\\b${w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
            return re.test(lowerContent);
        }).length;
        const spamScore = Math.min(spamCount * 0.1, 1);

        // Engagement score based on various factors
        let engagementScore = 70;
        if (content.includes('{{')) engagementScore += 10;
        if (content.includes('?')) engagementScore += 5;
        if (content.includes('!')) engagementScore += 3;
        if (readabilityScore > 60) engagementScore += 5;
        if (spamScore < 0.2) engagementScore += 7;
        engagementScore = Math.min(100, engagementScore);

        return {
            wordCount: words.length,
            sentenceCount: sentences.length,
            readabilityScore,
            spamScore,
            engagementScore,
            suggestions: this.getSuggestions(content, type),
        };
    }

    private countSyllables(text: string): number {
        const words = text.toLowerCase().replace(/[^a-z\s]/g, '').split(/\s+/);
        let total = 0;

        for (const word of words) {
            let count = word.replace(/(?:[^laeiouy]es|ed|[^laeiouy]e)$/, '')
                .match(/[aeiouy]{1,2}/g)?.length || 0;
            if (count === 0) count = 1;
            total += count;
        }

        return total;
    }

    private trimToLength(text: string, maxLength: number): string {
        if (text.length <= maxLength) return text;
        return text.slice(0, maxLength - 3).trim() + '...';
    }
}

export {
    DEFAULT_CONTENT_CONFIG,
    SUBJECT_PATTERNS,
    CTA_PATTERNS,
};
