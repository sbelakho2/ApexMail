/**
 * Content Scanner
 *
 * Comprehensive content analysis for email messages including
 * spam detection, phishing analysis, malware scanning, and
 * policy compliance checking. Supports OCR for image-based content.
 */

import { createWorker, Worker } from 'tesseract.js';
import { Pool } from 'pg';
import { Redis } from 'ioredis';
import {
    ContentScanResult,
    SpamAnalysis,
    SpamTrigger,
    PhishingAnalysis,
    PhishingIndicator,
    MalwareAnalysis,
    MalwareThreat,
    PolicyAnalysis,
    PolicyViolation,
    ContentAction,
    ScanVerdict,
} from '../types';
import { complianceConfig } from '../config';
import { generateUUID } from '@apexmail/lib/crypto';

interface EmailContent {
    messageId: string;
    tenantId: string;
    from: string;
    to: string[];
    subject: string;
    textBody: string | null;
    htmlBody: string | null;
    attachments: Attachment[];
    headers: Record<string, string>;
}

interface Attachment {
    filename: string;
    contentType: string;
    size: number;
    content: Buffer;
}

interface SpamRule {
    name: string;
    pattern: RegExp | string;
    score: number;
    description: string;
    checkFn?: (content: EmailContent) => boolean;
    /**
     * Which content to test the pattern against.
     * - 'text'  — stripped plain text (default, works for body/subject spam phrases)
     * - 'html'  — raw HTML body (needed for CSS-hiding patterns like display:none)
     * Rules with a checkFn ignore this field.
     */
    checkTarget?: 'text' | 'html';
}

interface PhishingRule {
    name: string;
    type: 'url' | 'content' | 'sender' | 'attachment';
    pattern?: RegExp | string;
    checkFn?: (content: EmailContent) => PhishingIndicator[];
}

export class ContentScanner {
    private db: Pool;
    // @ts-expect-error Reserved for future caching implementation
    private _redis: Redis;
    private config = complianceConfig.contentScanning;
    private ocrWorker: Worker | null = null;
    private spamRules: SpamRule[];
    // @ts-expect-error Reserved for future phishing rules implementation  
    private _phishingRules: PhishingRule[];
    /**
     * Pre-compiled combined alternation of all TEXT-based spam patterns.
     * Allows a single O(1) existence check before looping individual rules —
     * on clean emails (the common case) we skip all N individual regex tests.
     * Compiled once in the constructor; never mutated.
     */
    private spamFastCheckPattern!: RegExp;

    constructor(db: Pool, redis: Redis) {
        this.db = db;
        this._redis = redis;
        this.spamRules = this.initializeSpamRules();
        this._phishingRules = this.initializePhishingRules();
        // Build fast-check pattern AFTER spamRules is assigned
        this.spamFastCheckPattern = this.buildSpamFastCheckPattern();
    }

    /**
     * Initialize OCR worker for image text extraction
     */
    async initializeOCR(): Promise<void> {
        if (this.config.ocrEnabled && !this.ocrWorker) {
            this.ocrWorker = await createWorker('eng');
        }
    }

    /**
     * Shut down OCR worker
     */
    async shutdownOCR(): Promise<void> {
        if (this.ocrWorker) {
            await this.ocrWorker.terminate();
            this.ocrWorker = null;
        }
    }

    /**
     * Perform full content scan on an email
     */
    async scanEmail(content: EmailContent): Promise<ContentScanResult> {
        const [spamAnalysis, phishingAnalysis, malwareAnalysis, policyAnalysis] =
            await Promise.all([
                this.analyzeSpam(content),
                this.analyzePhishing(content),
                this.analyzeMalware(content),
                this.analyzePolicy(content),
            ]);

        const overallVerdict = this.determineVerdict(
            spamAnalysis,
            phishingAnalysis,
            malwareAnalysis,
            policyAnalysis
        );

        const actions = this.determineActions(
            overallVerdict,
            spamAnalysis,
            phishingAnalysis,
            malwareAnalysis,
            policyAnalysis
        );

        const result: ContentScanResult = {
            id: generateUUID(),
            tenantId: content.tenantId,
            messageId: content.messageId,
            scannedAt: new Date(),
            results: {
                spam: spamAnalysis,
                phishing: phishingAnalysis,
                malware: malwareAnalysis,
                policy: policyAnalysis,
            },
            overallVerdict,
            actions,
        };

        await this.saveResult(result);

        return result;
    }

    /**
     * Analyze content for spam characteristics
     */
    private async analyzeSpam(content: EmailContent): Promise<SpamAnalysis> {
        const triggers: SpamTrigger[] = [];
        let totalScore = 0;

        const textContent = this.extractAllText(content);

        // Fast existence check: single combined regex over all text-based pattern rules.
        // On clean emails (no spam signals) this single test short-circuits the entire
        // per-rule loop, replacing O(n) sequential regex calls with O(1).
        const hasTextSpamSignal = this.spamFastCheckPattern.test(textContent);

        for (const rule of this.spamRules) {
            let matched = false;

            if (rule.checkFn) {
                // Structural / functional checks must always run.
                matched = rule.checkFn(content);
            } else if (rule.pattern instanceof RegExp) {
                const target = rule.checkTarget === 'html'
                    ? (content.htmlBody ?? '')
                    : textContent;
                // For text rules, skip entirely when fast-check found no signal.
                if (rule.checkTarget !== 'html' && !hasTextSpamSignal) continue;
                matched = rule.pattern.test(target);
            } else if (rule.pattern) {
                if (!hasTextSpamSignal) continue;
                matched = textContent.toLowerCase().includes((rule.pattern as string).toLowerCase());
            }

            if (matched) {
                triggers.push({
                    rule: rule.name,
                    score: rule.score,
                    description: rule.description,
                });
                totalScore += rule.score;
            }
        }

        // Check for excessive capitalization
        const capsRatio = this.calculateCapsRatio(textContent);
        if (capsRatio > 0.3) {
            const score = Math.round(capsRatio * 10);
            triggers.push({
                rule: 'EXCESSIVE_CAPS',
                score,
                description: `${Math.round(capsRatio * 100)}% uppercase letters`,
            });
            totalScore += score;
        }

        // Check for excessive punctuation
        const punctRatio = this.calculatePunctRatio(textContent);
        if (punctRatio > 0.1) {
            const score = Math.round(punctRatio * 15);
            triggers.push({
                rule: 'EXCESSIVE_PUNCT',
                score,
                description: `${Math.round(punctRatio * 100)}% punctuation`,
            });
            totalScore += score;
        }

        // Perform OCR on image attachments for hidden text
        if (this.config.ocrEnabled && this.ocrWorker) {
            const imageAttachments = content.attachments.filter((a) =>
                a.contentType.startsWith('image/')
            );

            for (const img of imageAttachments.slice(0, this.config.maxOcrImages)) {
                const ocrText = await this.extractTextFromImage(img.content);
                if (ocrText) {
                    for (const rule of this.spamRules.filter(
                        (r) => typeof r.pattern === 'string' || r.pattern instanceof RegExp
                    )) {
                        const matched =
                            rule.pattern instanceof RegExp
                                ? rule.pattern.test(ocrText)
                                : ocrText.toLowerCase().includes((rule.pattern as string).toLowerCase());

                        if (matched && !triggers.find((t) => t.rule === `OCR_${rule.name}`)) {
                            triggers.push({
                                rule: `OCR_${rule.name}`,
                                score: rule.score * 1.5, // Higher score for hidden text
                                description: `${rule.description} (detected in image)`,
                            });
                            totalScore += rule.score * 1.5;
                        }
                    }
                }
            }
        }

        return {
            score: Math.min(100, totalScore),
            isSpam: totalScore >= this.config.spamThreshold,
            triggers,
        };
    }

    /**
     * Analyze content for phishing attempts
     */
    private async analyzePhishing(content: EmailContent): Promise<PhishingAnalysis> {
        const indicators: PhishingIndicator[] = [];
        let totalScore = 0;

        // Check URLs in content
        const urls = this.extractUrls(content);
        for (const url of urls) {
            const urlIndicators = await this.analyzeUrl(url);
            indicators.push(...urlIndicators);
        }

        // Check sender authentication
        const senderIndicators = this.analyzeSender(content);
        indicators.push(...senderIndicators);

        // Check for suspicious content patterns
        const contentIndicators = this.analyzeContentPatterns(content);
        indicators.push(...contentIndicators);

        // Check attachments
        const attachmentIndicators = this.analyzeAttachmentsForPhishing(content);
        indicators.push(...attachmentIndicators);

        // Calculate total score
        for (const indicator of indicators) {
            totalScore += indicator.confidence * 100;
        }

        return {
            score: Math.min(100, totalScore / Math.max(1, indicators.length)),
            isPhishing: indicators.some((i) => i.confidence > 0.7),
            indicators,
        };
    }

    /**
     * Analyze attachments for malware
     */
    private async analyzeMalware(content: EmailContent): Promise<MalwareAnalysis> {
        const threats: MalwareThreat[] = [];

        for (const attachment of content.attachments) {
            // Check for dangerous file types
            if (this.isDangerousFileType(attachment.filename)) {
                threats.push({
                    name: 'DANGEROUS_FILE_TYPE',
                    type: 'suspicious_extension',
                    severity: 'high',
                    location: attachment.filename,
                });
            }

            // Check for double extensions
            if (this.hasDoubleExtension(attachment.filename)) {
                threats.push({
                    name: 'DOUBLE_EXTENSION',
                    type: 'extension_masquerading',
                    severity: 'high',
                    location: attachment.filename,
                });
            }

            // Check file signature vs extension mismatch
            const signatureMatch = this.checkFileSignature(attachment);
            if (!signatureMatch) {
                threats.push({
                    name: 'SIGNATURE_MISMATCH',
                    type: 'content_type_mismatch',
                    severity: 'medium',
                    location: attachment.filename,
                });
            }

            // Check for macro-enabled documents
            if (this.hasMacros(attachment)) {
                threats.push({
                    name: 'MACRO_DETECTED',
                    type: 'macro_enabled',
                    severity: 'medium',
                    location: attachment.filename,
                });
            }

            // Check for password-protected archives
            if (this.isPasswordProtectedArchive(attachment)) {
                threats.push({
                    name: 'PASSWORD_PROTECTED_ARCHIVE',
                    type: 'encrypted_archive',
                    severity: 'medium',
                    location: attachment.filename,
                });
            }

            // Check for oversized attachments
            if (attachment.size > this.config.maxAttachmentSize) {
                threats.push({
                    name: 'OVERSIZED_ATTACHMENT',
                    type: 'size_violation',
                    severity: 'low',
                    location: attachment.filename,
                });
            }
        }

        return {
            clean: threats.length === 0,
            threats,
        };
    }

    /**
     * Check content against policy rules
     */
    private async analyzePolicy(content: EmailContent): Promise<PolicyAnalysis> {
        const violations: PolicyViolation[] = [];

        // Load tenant-specific policies
        const policies = await this.loadTenantPolicies(content.tenantId);

        for (const policy of policies) {
            const policyViolations = this.checkPolicy(content, policy);
            violations.push(...policyViolations);
        }

        // Check standard compliance rules
        violations.push(...this.checkStandardCompliance(content));

        return {
            compliant: violations.filter((v) => v.severity === 'error').length === 0,
            violations,
        };
    }

    /**
     * Initialize spam detection rules
     */
    private initializeSpamRules(): SpamRule[] {
        return [
            // Common spam phrases
            {
                name: 'FREE_MONEY',
                pattern: /free\s*(money|cash|gift)/i,
                score: 3,
                description: 'Contains "free money/cash" phrase',
            },
            {
                name: 'WINNER',
                pattern: /you\s*(have\s+)?won|winner|winning/i,
                score: 3,
                description: 'Contains winner/winning claims',
            },
            {
                name: 'URGENT_ACTION',
                pattern: /urgent|immediate\s+action|act\s+now/i,
                score: 2,
                description: 'Contains urgency phrases',
            },
            {
                name: 'BANK_TRANSFER',
                pattern: /bank\s+transfer|wire\s+transfer|western\s+union/i,
                score: 3,
                description: 'References bank/wire transfers',
            },
            {
                name: 'NIGERIAN_PRINCE',
                pattern: /prince|royal\s+family|inheritance.*million/i,
                score: 5,
                description: 'Classic scam pattern detected',
            },
            {
                name: 'MEDICATION_SPAM',
                pattern: /viagra|cialis|pharmacy|prescription.*discount/i,
                score: 4,
                description: 'Pharmaceutical spam detected',
            },
            {
                name: 'WEIGHT_LOSS',
                pattern: /lose\s+weight|diet\s+pill|fat\s+burn/i,
                score: 3,
                description: 'Weight loss spam detected',
            },
            {
                name: 'CRYPTOCURRENCY_SCAM',
                pattern: /bitcoin.*profit|crypto.*invest|guaranteed.*return/i,
                score: 4,
                description: 'Cryptocurrency scam patterns',
            },
            {
                name: 'UNSUBSCRIBE_MISSING',
                pattern: '',
                score: 2,
                description: 'No unsubscribe mechanism found',
                checkFn: (c) => !this.hasUnsubscribe(c),
            },
            {
                name: 'SENDER_ADDRESS_MISMATCH',
                pattern: '',
                score: 2,
                description: 'From address domain mismatch',
                checkFn: (c) => this.hasSenderMismatch(c),
            },
            {
                name: 'HIDDEN_TEXT',
                pattern: /<[^>]*display\s*:\s*none[^>]*>/i,
                score: 3,
                description: 'Contains hidden text in HTML',
                // Must test against raw HTML — stripHtml() removes the tag so this pattern
                // would never match against textContent (latent bug fix).
                checkTarget: 'html',
            },
            {
                name: 'TINY_FONT',
                pattern: /font-size\s*:\s*[0-3]px/i,
                score: 2,
                description: 'Contains tiny unreadable text',
                checkTarget: 'html',
            },
            {
                name: 'IMAGE_ONLY',
                pattern: '',
                score: 3,
                description: 'Email contains mostly images',
                checkFn: (c) => this.isImageOnlyEmail(c),
            },
            {
                name: 'EXCESSIVE_LINKS',
                pattern: '',
                score: 2,
                description: 'Contains excessive number of links',
                checkFn: (c) => this.hasExcessiveLinks(c),
            },
        ];
    }

    /**
     * Initialize phishing detection rules
     */
    private initializePhishingRules(): PhishingRule[] {
        return [
            {
                name: 'HOMOGRAPH_ATTACK',
                type: 'url',
                checkFn: (c) => this.detectHomographAttacks(c),
            },
            {
                name: 'URL_SHORTENER',
                type: 'url',
                pattern: /(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly)/i,
            },
            {
                name: 'IP_URL',
                type: 'url',
                pattern: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
            },
            {
                name: 'LOGIN_REQUEST',
                type: 'content',
                pattern: /(verify|confirm|update)\s+(your\s+)?(account|password|login)/i,
            },
            {
                name: 'SUSPENDED_ACCOUNT',
                type: 'content',
                pattern: /account\s+(suspended|locked|limited|restricted)/i,
            },
            {
                name: 'FAKE_BRAND',
                type: 'sender',
                checkFn: (c) => this.detectFakeBrands(c),
            },
        ];
    }

    /**
     * Extract all text content from email
     */
    private extractAllText(content: EmailContent): string {
        let text = content.subject + '\n';

        if (content.textBody) {
            text += content.textBody + '\n';
        }

        if (content.htmlBody) {
            text += this.stripHtml(content.htmlBody);
        }

        return text;
    }

    /**
     * Strip HTML tags from content
     */
    private stripHtml(html: string): string {
        return html
            .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
            .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
            .replace(/<[^>]+>/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    }

    /**
     * Calculate ratio of uppercase letters
     */
    private calculateCapsRatio(text: string): number {
        const letters = text.replace(/[^a-zA-Z]/g, '');
        if (letters.length === 0) return 0;

        const caps = letters.replace(/[^A-Z]/g, '');
        return caps.length / letters.length;
    }

    /**
     * Calculate ratio of punctuation marks
     */
    private calculatePunctRatio(text: string): number {
        if (text.length === 0) return 0;

        const punct = text.replace(/[^!?.,;:]+/g, '');
        return punct.length / text.length;
    }

    /**
     * Extract text from image using OCR
     */
    private async extractTextFromImage(imageBuffer: Buffer): Promise<string | null> {
        if (!this.ocrWorker) return null;

        try {
            const {
                data: { text },
            } = await this.ocrWorker.recognize(imageBuffer);
            return text;
        } catch (error) {
            // OCR worker may have crashed (OOM, codec error, etc.).
            // Terminate the old worker and restart so subsequent scans succeed.
            console.warn('[ContentScanner] OCR recognition failed, attempting worker restart', error);
            try {
                await this.ocrWorker.terminate();
            } catch {
                // Ignore terminate errors — the worker may already be dead.
            }
            this.ocrWorker = null;

            if (this.config.ocrEnabled) {
                try {
                    this.ocrWorker = await createWorker('eng');
                    console.info('[ContentScanner] OCR worker restarted successfully');
                } catch (restartError) {
                    console.error('[ContentScanner] OCR worker restart failed', restartError);
                    // Leave ocrWorker null — subsequent calls will return null gracefully.
                }
            }
            // Return null for THIS extraction — the restarted worker handles the next one.
            return null;
        }
    }

    /**
     * Build the combined fast-check pattern from all text-based (non-html, non-checkFn) rules.
     * Called once in the constructor after spamRules is populated.
     */
    private buildSpamFastCheckPattern(): RegExp {
        const patterns = this.spamRules
            .filter(
                (r) =>
                    !r.checkFn &&
                    r.pattern instanceof RegExp &&
                    r.checkTarget !== 'html',
            )
            .map((r) => `(?:${(r.pattern as RegExp).source})`);
        // Fallback: a pattern that never matches (in case all rules have checkFn)
        if (patterns.length === 0) return /(?!)/;
        return new RegExp(patterns.join('|'), 'i');
    }

    /**
     * Extract all URLs from content
     */
    private extractUrls(content: EmailContent): string[] {
        const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
        const text = this.extractAllText(content);
        const htmlUrls = content.htmlBody?.match(/href=["']([^"']+)["']/gi) || [];

        const urls = new Set<string>();

        const textMatches = text.match(urlRegex) || [];
        textMatches.forEach((url) => urls.add(url));

        htmlUrls.forEach((match) => {
            const url = match.replace(/href=["']|["']$/gi, '');
            if (url.startsWith('http')) {
                urls.add(url);
            }
        });

        return Array.from(urls);
    }

    /**
     * Analyze a URL for phishing indicators
     */
    private async analyzeUrl(url: string): Promise<PhishingIndicator[]> {
        const indicators: PhishingIndicator[] = [];

        try {
            const parsed = new URL(url);

            // Check for IP address URLs
            if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(parsed.hostname)) {
                indicators.push({
                    type: 'url',
                    indicator: url,
                    confidence: 0.7,
                    description: 'URL uses IP address instead of domain',
                });
            }

            // Check for known URL shorteners
            const shorteners = ['bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd'];
            if (shorteners.includes(parsed.hostname.toLowerCase())) {
                indicators.push({
                    type: 'url',
                    indicator: url,
                    confidence: 0.5,
                    description: 'URL uses shortening service',
                });
            }

            // Check for suspicious TLDs
            const suspiciousTlds = ['.xyz', '.top', '.click', '.loan', '.work'];
            if (suspiciousTlds.some((tld) => parsed.hostname.endsWith(tld))) {
                indicators.push({
                    type: 'url',
                    indicator: url,
                    confidence: 0.4,
                    description: 'URL uses suspicious TLD',
                });
            }

            // Check for brand impersonation in subdomain
            const brands = ['paypal', 'apple', 'amazon', 'microsoft', 'google', 'facebook'];
            for (const brand of brands) {
                if (
                    parsed.hostname.includes(brand) &&
                    !parsed.hostname.endsWith(`.${brand}.com`)
                ) {
                    indicators.push({
                        type: 'url',
                        indicator: url,
                        confidence: 0.8,
                        description: `Possible ${brand} impersonation`,
                    });
                }
            }

            // Check for excessive subdomains
            const subdomainCount = parsed.hostname.split('.').length - 2;
            if (subdomainCount > 3) {
                indicators.push({
                    type: 'url',
                    indicator: url,
                    confidence: 0.5,
                    description: 'URL has excessive subdomains',
                });
            }
        } catch {
            // Invalid URL
            indicators.push({
                type: 'url',
                indicator: url,
                confidence: 0.3,
                description: 'Malformed URL detected',
            });
        }

        return indicators;
    }

    /**
     * Analyze sender for phishing indicators
     */
    private analyzeSender(content: EmailContent): PhishingIndicator[] {
        const indicators: PhishingIndicator[] = [];

        // Check for display name mismatch
        const fromMatch = content.from.match(/^"?([^"<]+)"?\s*<([^>]+)>/);
        if (fromMatch && fromMatch[1] && fromMatch[2]) {
            const displayName = fromMatch[1].toLowerCase();
            const email = fromMatch[2].toLowerCase();
            const emailDomain = email.split('@')[1];

            // Check if display name contains a domain that doesn't match
            const domainInName = displayName.match(/\w+\.(com|org|net|io)/);
            if (domainInName && emailDomain && domainInName[0] && !emailDomain.includes(domainInName[0].split('.')[0]!)) {
                indicators.push({
                    type: 'sender',
                    indicator: content.from,
                    confidence: 0.7,
                    description: 'Display name domain does not match sender domain',
                });
            }

            // Check for impersonation patterns
            const brands = ['paypal', 'apple', 'amazon', 'microsoft', 'google'];
            for (const brand of brands) {
                if (displayName.includes(brand) && emailDomain && !emailDomain.includes(brand)) {
                    indicators.push({
                        type: 'sender',
                        indicator: content.from,
                        confidence: 0.8,
                        description: `Display name suggests ${brand} but domain doesn't match`,
                    });
                }
            }
        }

        return indicators;
    }

    /**
     * Analyze content patterns for phishing
     */
    private analyzeContentPatterns(content: EmailContent): PhishingIndicator[] {
        const indicators: PhishingIndicator[] = [];
        const text = this.extractAllText(content).toLowerCase();

        // Check for urgency + action patterns
        const urgencyPatterns = [
            { pattern: /your account (will be|has been) (suspended|locked)/i, confidence: 0.8 },
            { pattern: /verify your (account|identity|email) immediately/i, confidence: 0.7 },
            { pattern: /unusual (activity|sign-in|login) detected/i, confidence: 0.6 },
            { pattern: /confirm your (password|credentials)/i, confidence: 0.7 },
            { pattern: /update your (payment|billing) information/i, confidence: 0.6 },
        ];

        for (const { pattern, confidence } of urgencyPatterns) {
            if (pattern.test(text)) {
                indicators.push({
                    type: 'content',
                    indicator: text.match(pattern)?.[0] || '',
                    confidence,
                    description: 'Contains phishing urgency pattern',
                });
            }
        }

        return indicators;
    }

    /**
     * Analyze attachments for phishing indicators
     */
    private analyzeAttachmentsForPhishing(content: EmailContent): PhishingIndicator[] {
        const indicators: PhishingIndicator[] = [];

        for (const attachment of content.attachments) {
            // Check for HTML attachments
            if (
                attachment.contentType === 'text/html' ||
                attachment.filename.endsWith('.html') ||
                attachment.filename.endsWith('.htm')
            ) {
                indicators.push({
                    type: 'attachment',
                    indicator: attachment.filename,
                    confidence: 0.6,
                    description: 'HTML attachment may contain phishing form',
                });
            }

            // Check for form-like content in HTML attachments
            if (attachment.contentType === 'text/html') {
                const html = attachment.content.toString('utf-8');
                if (/<form[^>]*>/i.test(html) && /<input[^>]*type=["']password["']/i.test(html)) {
                    indicators.push({
                        type: 'attachment',
                        indicator: attachment.filename,
                        confidence: 0.9,
                        description: 'HTML attachment contains password form',
                    });
                }
            }
        }

        return indicators;
    }

    /**
     * Detect homograph attacks in URLs
     */
    private detectHomographAttacks(content: EmailContent): PhishingIndicator[] {
        const indicators: PhishingIndicator[] = [];
        const urls = this.extractUrls(content);

        // Characters that look similar to ASCII
        const homoglyphs: Record<string, string[]> = {
            a: ['а', 'ạ', 'ă', 'ắ'],
            e: ['е', 'ẹ', 'ę'],
            i: ['і', 'ị'],
            o: ['о', 'ọ', 'ơ'],
            c: ['с', 'ć'],
            p: ['р'],
            s: ['ѕ'],
            x: ['х'],
        };

        for (const url of urls) {
            try {
                const parsed = new URL(url);
                const hostname = parsed.hostname;

                // Check for non-ASCII characters
                // eslint-disable-next-line no-control-regex
                if (/[^\x00-\x7F]/.test(hostname)) {
                    // Check if it contains known homoglyphs
                    for (const [ascii, glyphs] of Object.entries(homoglyphs)) {
                        for (const glyph of glyphs) {
                            if (hostname.includes(glyph)) {
                                indicators.push({
                                    type: 'url',
                                    indicator: url,
                                    confidence: 0.9,
                                    description: `Homograph attack detected: '${glyph}' looks like '${ascii}'`,
                                });
                            }
                        }
                    }
                }
            } catch {
                // Invalid URL, skip
            }
        }

        return indicators;
    }

    /**
     * Detect fake brand impersonation
     */
    private detectFakeBrands(content: EmailContent): PhishingIndicator[] {
        const indicators: PhishingIndicator[] = [];

        const brandPatterns = [
            { brand: 'PayPal', patterns: ['paypa1', 'paypai', 'pay-pal', 'paypal-secure'] },
            { brand: 'Apple', patterns: ['app1e', 'appie', 'apple-id', 'apple-support'] },
            { brand: 'Amazon', patterns: ['amaz0n', 'arnazon', 'amazon-security'] },
            { brand: 'Microsoft', patterns: ['micros0ft', 'rnicrosoft', 'microsoft-support'] },
            { brand: 'Google', patterns: ['g00gle', 'googie', 'google-support'] },
        ];

        const senderDomain = content.from.split('@')[1]?.toLowerCase() || '';
        const text = this.extractAllText(content).toLowerCase();

        for (const { brand, patterns } of brandPatterns) {
            for (const pattern of patterns) {
                if (senderDomain.includes(pattern) || text.includes(pattern)) {
                    indicators.push({
                        type: 'sender',
                        indicator: pattern,
                        confidence: 0.85,
                        description: `Possible ${brand} impersonation detected`,
                    });
                }
            }
        }

        return indicators;
    }

    /**
     * Check if dangerous file type
     */
    private isDangerousFileType(filename: string): boolean {
        const dangerous = [
            '.exe',
            '.bat',
            '.cmd',
            '.com',
            '.pif',
            '.scr',
            '.js',
            '.jse',
            '.vbs',
            '.vbe',
            '.wsf',
            '.wsh',
            '.msi',
            '.ps1',
            '.hta',
            '.cpl',
        ];

        return dangerous.some((ext) => filename.toLowerCase().endsWith(ext));
    }

    /**
     * Check for double extension
     */
    private hasDoubleExtension(filename: string): boolean {
        const parts = filename.split('.');
        if (parts.length < 3) return false;

        const lastExt = parts[parts.length - 1]?.toLowerCase();
        const secondLastExt = parts[parts.length - 2]?.toLowerCase();

        if (!lastExt || !secondLastExt) return false;

        const executableExts = ['exe', 'bat', 'cmd', 'scr', 'pif', 'js', 'vbs'];
        const documentExts = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'png'];

        return (
            executableExts.includes(lastExt) && documentExts.includes(secondLastExt)
        );
    }

    /**
     * Check file signature matches extension
     */
    private checkFileSignature(attachment: Attachment): boolean {
        const signatures: Record<string, number[]> = {
            pdf: [0x25, 0x50, 0x44, 0x46],
            zip: [0x50, 0x4b, 0x03, 0x04],
            rar: [0x52, 0x61, 0x72, 0x21],
            exe: [0x4d, 0x5a],
            png: [0x89, 0x50, 0x4e, 0x47],
            jpg: [0xff, 0xd8, 0xff],
            gif: [0x47, 0x49, 0x46, 0x38],
        };

        const ext = attachment.filename.split('.').pop()?.toLowerCase();
        if (!ext || !signatures[ext]) return true;

        const sig = signatures[ext]!;
        const header = Array.from(attachment.content.slice(0, sig.length));

        return sig.every((byte, i) => header[i] === byte);
    }

    /**
     * Check for macro-enabled documents
     */
    private hasMacros(attachment: Attachment): boolean {
        const macroExtensions = ['.docm', '.xlsm', '.pptm', '.dotm', '.xltm'];
        return macroExtensions.some((ext) =>
            attachment.filename.toLowerCase().endsWith(ext)
        );
    }

    /**
     * Check for password-protected archives
     */
    private isPasswordProtectedArchive(attachment: Attachment): boolean {
        if (!attachment.filename.toLowerCase().match(/\.(zip|rar|7z)$/)) {
            return false;
        }

        // Check ZIP encryption flag
        if (attachment.filename.toLowerCase().endsWith('.zip')) {
            const flagByte = attachment.content[6];
            return flagByte !== undefined && (flagByte & 0x01) !== 0;
        }

        return false;
    }

    /**
     * Check if email has unsubscribe mechanism
     */
    private hasUnsubscribe(content: EmailContent): boolean {
        const text = this.extractAllText(content).toLowerCase();
        const headers = content.headers;

        return (
            text.includes('unsubscribe') ||
            !!headers['list-unsubscribe'] ||
            !!headers['List-Unsubscribe']
        );
    }

    /**
     * Check for sender address mismatch
     */
    private hasSenderMismatch(content: EmailContent): boolean {
        const fromMatch = content.from.match(/<([^>]+)>/);
        const fromEmail = fromMatch?.[1] ?? content.from;
        const fromDomain = fromEmail.split('@')[1]?.toLowerCase();

        const replyTo = content.headers['reply-to'] || content.headers['Reply-To'];
        if (replyTo) {
            const replyMatch = replyTo.match(/<([^>]+)>/);
            const replyEmail = replyMatch?.[1] ?? replyTo;
            const replyDomain = replyEmail.split('@')[1]?.toLowerCase();

            if (replyDomain && fromDomain && replyDomain !== fromDomain) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if email is image-only
     */
    private isImageOnlyEmail(content: EmailContent): boolean {
        if (!content.htmlBody) return false;

        const text = this.stripHtml(content.htmlBody);
        const imageCount = (content.htmlBody.match(/<img/gi) || []).length;

        return text.length < 100 && imageCount > 0;
    }

    /**
     * Check for excessive links
     */
    private hasExcessiveLinks(content: EmailContent): boolean {
        const urls = this.extractUrls(content);
        const text = this.extractAllText(content);

        // More than 1 link per 50 characters
        return urls.length > text.length / 50;
    }

    /**
     * Load tenant-specific policies
     */
    private async loadTenantPolicies(
        tenantId: string
    ): Promise<Array<{ name: string; rules: unknown[] }>> {
        const result = await this.db.query(
            `SELECT name, rules FROM content_policies
            WHERE tenant_id = $1 AND active = true`,
            [tenantId]
        );

        return result.rows;
    }

    /**
     * Check content against a policy.
     *
     * SECURITY: Policy rule patterns are tenant-supplied and may contain
     * ReDoS-prone constructs (nested quantifiers, catastrophic backtracking).
     * We: (1) enforce a max pattern length, (2) wrap regex evaluation in a
     * try/catch to reject invalid patterns, and (3) limit input text to
     * MAX_POLICY_TEXT_LEN to bound worst-case evaluation time.
     */
    private checkPolicy(
        content: EmailContent,
        policy: { name: string; rules: unknown[] }
    ): PolicyViolation[] {
        const MAX_PATTERN_LEN = 512;
        const MAX_POLICY_TEXT_LEN = 50_000;
        const violations: PolicyViolation[] = [];

        for (const rule of policy.rules as Array<{
            type: string;
            pattern?: string;
            severity: 'warning' | 'error';
            description: string;
        }>) {
            if (rule.type === 'forbidden_content' && rule.pattern) {
                // Guard: reject overly long patterns that are likely malicious.
                if (rule.pattern.length > MAX_PATTERN_LEN) continue;

                let regex: RegExp;
                try {
                    regex = new RegExp(rule.pattern, 'i');
                } catch {
                    // Invalid regex — skip this rule rather than crash.
                    continue;
                }

                const text = this.extractAllText(content).slice(0, MAX_POLICY_TEXT_LEN);

                if (regex.test(text)) {
                    violations.push({
                        policy: policy.name,
                        rule: rule.type,
                        description: rule.description,
                        severity: rule.severity,
                    });
                }
            }
        }

        return violations;
    }

    /**
     * Check standard compliance rules
     */
    private checkStandardCompliance(content: EmailContent): PolicyViolation[] {
        const violations: PolicyViolation[] = [];

        // CAN-SPAM: Physical address requirement
        const text = this.extractAllText(content).toLowerCase();
        if (!this.hasPhysicalAddress(text)) {
            violations.push({
                policy: 'CAN-SPAM',
                rule: 'physical_address',
                description: 'Commercial email must include physical postal address',
                severity: 'warning',
            });
        }

        // Check for required headers
        if (!content.headers['message-id'] && !content.headers['Message-ID']) {
            violations.push({
                policy: 'RFC5322',
                rule: 'message_id',
                description: 'Email must have Message-ID header',
                severity: 'error',
            });
        }

        return violations;
    }

    /**
     * Check if content contains physical address
     */
    private hasPhysicalAddress(text: string): boolean {
        // Simple check for street address patterns
        const addressPattern =
            /\d+\s+[\w\s]+(?:street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln|way|court|ct)/i;
        return addressPattern.test(text);
    }

    /**
     * Determine overall verdict
     */
    private determineVerdict(
        spam: SpamAnalysis,
        phishing: PhishingAnalysis,
        _malware: MalwareAnalysis,
        _policy: PolicyAnalysis
    ): ScanVerdict {
        if (phishing.isPhishing || !_malware.clean) {
            return 'blocked';
        }

        if (spam.isSpam || !_policy.compliant) {
            return 'suspicious';
        }

        return 'clean';
    }

    /**
     * Determine actions to take
     */
    private determineActions(
        verdict: ScanVerdict,
        spam: SpamAnalysis,
        phishing: PhishingAnalysis,
        // @ts-expect-error Reserved for future malware handling
        malware: MalwareAnalysis,
        policy: PolicyAnalysis
    ): ContentAction[] {
        const actions: ContentAction[] = [];
        const now = new Date();

        switch (verdict) {
            case 'blocked':
                actions.push({
                    action: 'reject',
                    reason: phishing.isPhishing
                        ? 'Phishing content detected'
                        : 'Malware detected',
                    appliedAt: now,
                });
                break;

            case 'suspicious':
                if (spam.isSpam) {
                    actions.push({
                        action: 'quarantine',
                        reason: `Spam score: ${spam.score}`,
                        appliedAt: now,
                    });
                }
                if (!policy.compliant) {
                    actions.push({
                        action: 'quarantine',
                        reason: 'Policy violations detected',
                        appliedAt: now,
                    });
                }
                break;

            case 'clean':
                actions.push({
                    action: 'allow',
                    reason: 'Content passed all checks',
                    appliedAt: now,
                });
                break;
        }

        return actions;
    }

    /**
     * Save scan result to database
     */
    private async saveResult(result: ContentScanResult): Promise<void> {
        await this.db.query(
            `INSERT INTO scan_results (
                id, tenant_id, message_id, scanned_at, results,
                overall_verdict, actions, spam_detected, phishing_detected
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
            [
                result.id,
                result.tenantId,
                result.messageId,
                result.scannedAt,
                JSON.stringify(result.results),
                result.overallVerdict,
                JSON.stringify(result.actions),
                result.results.spam.isSpam,
                result.results.phishing.isPhishing,
            ]
        );
    }

    /**
     * Get scan result by ID
     */
    async getResult(resultId: string): Promise<ContentScanResult | null> {
        const result = await this.db.query(
            `SELECT * FROM scan_results WHERE id = $1`,
            [resultId]
        );

        if (result.rows.length === 0) return null;

        const row = result.rows[0];
        return {
            id: row.id,
            tenantId: row.tenant_id,
            messageId: row.message_id,
            scannedAt: new Date(row.scanned_at),
            results: row.results,
            overallVerdict: row.overall_verdict,
            actions: row.actions,
        };
    }

    /**
     * Get scan statistics
     */
    async getStats(
        tenantId?: string,
        startDate?: Date,
        endDate?: Date
    ): Promise<{
        total: number;
        clean: number;
        suspicious: number;
        blocked: number;
        spamDetected: number;
        phishingDetected: number;
    }> {
        let query = `
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE overall_verdict = 'clean') as clean,
                COUNT(*) FILTER (WHERE overall_verdict = 'suspicious') as suspicious,
                COUNT(*) FILTER (WHERE overall_verdict = 'blocked') as blocked,
                COUNT(*) FILTER (WHERE spam_detected = true) as spam,
                COUNT(*) FILTER (WHERE phishing_detected = true) as phishing
            FROM scan_results
            WHERE 1=1
        `;

        const params: unknown[] = [];
        let paramIndex = 1;

        if (tenantId) {
            query += ` AND tenant_id = $${paramIndex++}`;
            params.push(tenantId);
        }

        if (startDate) {
            query += ` AND scanned_at >= $${paramIndex++}`;
            params.push(startDate);
        }

        if (endDate) {
            query += ` AND scanned_at <= $${paramIndex++}`;
            params.push(endDate);
        }

        const result = await this.db.query(query, params);
        const row = result.rows[0];

        return {
            total: parseInt(row.total, 10),
            clean: parseInt(row.clean, 10),
            suspicious: parseInt(row.suspicious, 10),
            blocked: parseInt(row.blocked, 10),
            spamDetected: parseInt(row.spam, 10),
            phishingDetected: parseInt(row.phishing, 10),
        };
    }
}

export default ContentScanner;
