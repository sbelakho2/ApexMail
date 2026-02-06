/**
 * AI Reply Handler (Inbox Autopilot)
 * 
 * Automatically classifies and handles inbound email replies using NLP patterns.
 * Reduces manual work by 90% for common reply types.
 * 
 * Classification Categories:
 * - Out of Office: Snooze lead for specified period
 * - Not Interested: Mark as lost, add to suppression
 * - Tell Me More: Flag for sales follow-up
 * - Wrong Person: Attempt to get referral
 * - Positive Intent: High priority for demo scheduling
 * - Unsubscribe Request: Process immediately
 * - Bounce/Delivery Issue: Handle accordingly
 * 
 * This module can work standalone with pattern matching or integrate with LLM
 * for more nuanced classification.
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';

interface ReplyHandlerConfig {
    db: Pool;
    redis: Redis;
    logger: Logger;
    llmEnabled?: boolean;
    llmEndpoint?: string;
    llmApiKey?: string;
}

export type ReplyClassification =
    | 'out_of_office'
    | 'not_interested'
    | 'interested'
    | 'tell_me_more'
    | 'wrong_person'
    | 'referral'
    | 'unsubscribe'
    | 'bounce'
    | 'positive_intent'
    | 'meeting_request'
    | 'question'
    | 'complaint'
    | 'spam'
    | 'unknown';

export interface ClassificationResult {
    classification: ReplyClassification;
    confidence: number; // 0-1
    subType?: string;
    extractedData: {
        returnDate?: Date;        // For OOO
        referredContact?: string; // For wrong person
        meetingRequest?: boolean;
        sentiment: 'positive' | 'negative' | 'neutral';
        urgency: 'high' | 'medium' | 'low';
    };
    suggestedAction: SuggestedAction;
    reasoning: string;
}

export interface SuggestedAction {
    action: 'snooze' | 'suppress' | 'flag_sales' | 'schedule_demo' | 'request_referral' | 'unsubscribe' | 'ignore' | 'escalate' | 'auto_reply';
    parameters: Record<string, unknown>;
    autoExecute: boolean;
    priority: 'high' | 'medium' | 'low';
}

export interface ProcessedReply {
    inboundMessageId: string;
    leadId?: string;
    tenantId: string;
    fromEmail: string;
    subject: string;
    bodyPreview: string;
    classification: ClassificationResult;
    actionTaken: string | null;
    processedAt: Date;
}

// Pattern matchers for classification
const PATTERNS = {
    out_of_office: [
        /out of (?:the )?office/i,
        /away from (?:my )?(?:desk|office|email)/i,
        /on (?:annual |paid )?(?:leave|vacation|holiday|pto)/i,
        /currently (?:out|away|traveling|unavailable)/i,
        /limited access to email/i,
        /auto[- ]?reply/i,
        /automatic reply/i,
        /i(?:'m| am) (?:currently )?(?:out|away|on leave)/i,
        /will (?:be )?(?:back|return(?:ing)?|in the office)(?: on)?/i,
        /maternity|paternity leave/i,
        /(?:sick|medical) leave/i,
    ],
    not_interested: [
        /not interested/i,
        /no(?:t)? thank(?:s| you)/i,
        /please remove (?:me|us)/i,
        /don't contact (?:me|us)/i,
        /stop (?:emailing|contacting|sending)/i,
        /we(?:'re| are) not (?:looking|interested)/i,
        /not a good fit/i,
        /not (?:right|the right) time/i,
        /pass(?:ing)? on this/i,
        /we(?:'ll| will) pass/i,
        /decline/i,
        /not for us/i,
    ],
    interested: [
        /(?:i(?:'m| am)|we(?:'re| are)) interested/i,
        /tell (?:me|us) more/i,
        /(?:can|could) you (?:send|share|provide)/i,
        /(?:i|we) (?:would |'d )?like (?:to )?(?:learn|know|hear|see) more/i,
        /sounds (?:interesting|great|good)/i,
        /let(?:'s| us) (?:chat|talk|connect|discuss)/i,
        /when (?:can|could) we (?:meet|talk|chat)/i,
        /schedule (?:a )?(?:call|meeting|demo)/i,
        /book (?:a )?(?:time|meeting|call)/i,
        /(?:free|available) (?:for a )?(?:call|chat|meeting)/i,
    ],
    wrong_person: [
        /(?:i(?:'m| am)|i) not the (?:right|correct) person/i,
        /wrong (?:person|contact|department)/i,
        /you (?:should|need to) (?:contact|reach out to|speak with)/i,
        /try (?:contacting|reaching)/i,
        /(?:forward|forwarding) (?:this )?to/i,
        /(?:cc|copying|adding).{0,20}(?:who|that|the person)/i,
        /no longer (?:work|at|with)/i,
        /left the company/i,
        /moved to (?:a )?(?:different|another)/i,
    ],
    unsubscribe: [
        /unsubscribe/i,
        /remove (?:me|my email|us)/i,
        /opt[- ]?out/i,
        /stop (?:sending|emailing)/i,
        /take (?:me|us) off (?:your |the )?list/i,
        /gdpr|ccpa|data (?:deletion|removal)/i,
        /do not (?:email|contact)/i,
    ],
    meeting_request: [
        /(?:schedule|book|set up) (?:a )?(?:call|meeting|demo|time)/i,
        /(?:when|what time)(?:'s| is| are) (?:good|available)/i,
        /(?:free|available) (?:on|this|next)/i,
        /(?:let(?:'s| us)|can we) (?:meet|connect|chat|talk)/i,
        /calendly|hubspot|zoom|teams/i,
        /(?:morning|afternoon|monday|tuesday|wednesday|thursday|friday)/i,
    ],
    question: [
        /\?/,
        /(?:can|could|would) you (?:explain|clarify|tell me)/i,
        /(?:what|how|why|when|where|who) (?:is|are|does|do|can|could|would)/i,
        /(?:i|we) (?:have|had) (?:a )?(?:question|few questions)/i,
        /(?:curious|wondering) (?:about|if|whether)/i,
    ],
    bounce: [
        /(?:mail|message) (?:delivery|undeliverable)/i,
        /(?:mailbox|address) (?:not found|unavailable|does not exist)/i,
        /delivery (?:failed|failure|error)/i,
        /(?:550|551|552|553|554) /i,
        /permanent (?:error|failure)/i,
        /user unknown/i,
        /mailer[- ]daemon/i,
        /postmaster/i,
    ],
    complaint: [
        /spam/i,
        /unsolicited/i,
        /(?:how|where) did you get my (?:email|address|contact)/i,
        /(?:i |we )(?:never|didn(?:'t| not)) (?:sign(?:ed)? up|subscribe|opt(?:ed)? in)/i,
        /report(?:ing)? (?:this|you)/i,
        /harassment/i,
        /legal (?:action|team)/i,
    ],
};

// Return date extraction patterns
const RETURN_DATE_PATTERNS = [
    /(?:back|return(?:ing)?|available|in the office)(?: on)? (\w+ \d{1,2}(?:st|nd|rd|th)?(?:,? \d{4})?)/i,
    /(?:back|return(?:ing)?|available|in the office)(?: on)? (\d{1,2}[/\-.](\d{1,2})[/\-.](?:\d{2,4})?)/i,
    /(?:back|return(?:ing)?|available)(?: on)? (monday|tuesday|wednesday|thursday|friday|saturday|sunday)/i,
    /until (\w+ \d{1,2}(?:st|nd|rd|th)?(?:,? \d{4})?)/i,
];

// Referral extraction patterns
const REFERRAL_PATTERNS = [
    /(?:contact|reach|try|email|speak (?:with|to)) (\w+(?:\.\w+)?@[\w.-]+\.\w+)/i,
    /(?:cc|copied|adding) (\w+(?:\.\w+)?@[\w.-]+\.\w+)/i,
    /forward(?:ed|ing)? (?:this )?to (\w+(?:\.\w+)?@[\w.-]+\.\w+)/i,
];

export class ReplyHandler {
    private readonly db: Pool;
    // @ts-expect-error Reserved for future queue management
    private readonly _redis: Redis;
    private readonly logger: Logger;
    private readonly llmEnabled: boolean;
    private readonly llmEndpoint?: string;
    private readonly llmApiKey?: string;
    // @ts-expect-error Reserved for future queue management
    private readonly _queueKey = 'reply:process:queue';
    // @ts-expect-error Reserved for future deduplication
    private readonly _processedKey = 'reply:processed:';

    constructor(config: ReplyHandlerConfig) {
        this.db = config.db;
        this._redis = config.redis;
        this.logger = config.logger;
        this.llmEnabled = config.llmEnabled ?? false;
        this.llmEndpoint = config.llmEndpoint;
        this.llmApiKey = config.llmApiKey;
    }

    /**
     * Classify an inbound email reply
     */
    async classifyReply(
        subject: string,
        body: string,
        _fromEmail: string,
        headers?: Record<string, string>
    ): Promise<ClassificationResult> {
        const fullText = `${subject}\n\n${body}`.toLowerCase();
        
        // Check for auto-reply headers first
        if (headers) {
            if (headers['auto-submitted'] === 'auto-replied' ||
                headers['x-auto-response-suppress'] ||
                headers['precedence'] === 'bulk' ||
                headers['x-autoreply']) {
                return this.buildResult('out_of_office', 0.95, fullText, body);
            }
        }

        // Pattern-based classification
        const matches: Array<{ type: ReplyClassification; score: number }> = [];

        for (const [type, patterns] of Object.entries(PATTERNS)) {
            let score = 0;
            let matchCount = 0;
            
            for (const pattern of patterns) {
                if (pattern.test(fullText)) {
                    matchCount++;
                    score += 0.3;
                }
            }
            
            if (matchCount > 0) {
                score = Math.min(0.95, score);
                matches.push({ type: type as ReplyClassification, score });
            }
        }

        // Sort by score
        matches.sort((a, b) => b.score - a.score);

        // Get best match
        const bestMatch = matches[0];
        
        if (!bestMatch || bestMatch.score < 0.3) {
            // Use LLM if enabled and pattern matching is uncertain
            if (this.llmEnabled && this.llmEndpoint) {
                return this.classifyWithLLM(subject, body);
            }
            
            // Default to unknown with low confidence
            return this.buildResult('unknown', 0.3, fullText, body);
        }

        return this.buildResult(bestMatch.type, bestMatch.score, fullText, body);
    }

    /**
     * Build classification result with extracted data and suggested action
     */
    private buildResult(
        classification: ReplyClassification,
        confidence: number,
        fullText: string,
        _body: string
    ): ClassificationResult {
        const extractedData: ClassificationResult['extractedData'] = {
            sentiment: this.detectSentiment(fullText),
            urgency: this.detectUrgency(fullText),
        };

        // Extract return date for OOO
        if (classification === 'out_of_office') {
            const returnDate = this.extractReturnDate(fullText);
            if (returnDate) {
                extractedData.returnDate = returnDate;
            }
        }

        // Extract referral contact
        if (classification === 'wrong_person') {
            const referredContact = this.extractReferral(fullText);
            if (referredContact) {
                extractedData.referredContact = referredContact;
            }
        }

        // Check for meeting request intent
        if (classification === 'interested' || classification === 'meeting_request') {
            extractedData.meetingRequest = PATTERNS.meeting_request.some(p => p.test(fullText));
        }

        // Determine suggested action
        const suggestedAction = this.determineSuggestedAction(classification, extractedData);

        // Generate reasoning
        const reasoning = this.generateReasoning(classification, confidence, extractedData);

        return {
            classification,
            confidence,
            extractedData,
            suggestedAction,
            reasoning,
        };
    }

    /**
     * Determine suggested action based on classification
     */
    private determineSuggestedAction(
        classification: ReplyClassification,
        extractedData: ClassificationResult['extractedData']
    ): SuggestedAction {
        switch (classification) {
            case 'out_of_office': {
                const snoozeUntil = extractedData.returnDate || 
                    new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
                return {
                    action: 'snooze',
                    parameters: { until: snoozeUntil.toISOString() },
                    autoExecute: true,
                    priority: 'low',
                };
            }

            case 'not_interested':
                return {
                    action: 'suppress',
                    parameters: { 
                        reason: 'not_interested',
                        addToSuppression: true,
                        markLeadStatus: 'lost',
                    },
                    autoExecute: true,
                    priority: 'low',
                };

            case 'interested':
            case 'tell_me_more':
                return {
                    action: 'flag_sales',
                    parameters: { 
                        priority: 'high',
                        reason: 'expressed_interest',
                    },
                    autoExecute: true,
                    priority: 'high',
                };

            case 'meeting_request':
            case 'positive_intent':
                return {
                    action: 'schedule_demo',
                    parameters: { 
                        sendCalendarLink: true,
                        priority: 'urgent',
                    },
                    autoExecute: false, // Requires human review
                    priority: 'high',
                };

            case 'wrong_person':
                if (extractedData.referredContact) {
                    return {
                        action: 'request_referral',
                        parameters: { 
                            newContact: extractedData.referredContact,
                            createNewLead: true,
                        },
                        autoExecute: false,
                        priority: 'medium',
                    };
                }
                return {
                    action: 'flag_sales',
                    parameters: { reason: 'wrong_contact_needs_referral' },
                    autoExecute: true,
                    priority: 'medium',
                };

            case 'unsubscribe':
                return {
                    action: 'unsubscribe',
                    parameters: { 
                        addToSuppression: true,
                        reason: 'user_request',
                    },
                    autoExecute: true,
                    priority: 'high',
                };

            case 'bounce':
                return {
                    action: 'suppress',
                    parameters: { 
                        reason: 'bounce',
                        bounceType: 'hard',
                    },
                    autoExecute: true,
                    priority: 'low',
                };

            case 'complaint':
                return {
                    action: 'escalate',
                    parameters: { 
                        reason: 'complaint',
                        notifyOwner: true,
                        addToSuppression: true,
                    },
                    autoExecute: false,
                    priority: 'high',
                };

            case 'question':
                return {
                    action: 'flag_sales',
                    parameters: { 
                        reason: 'has_question',
                        needsResponse: true,
                    },
                    autoExecute: true,
                    priority: 'medium',
                };

            case 'spam':
                return {
                    action: 'ignore',
                    parameters: { reason: 'spam' },
                    autoExecute: true,
                    priority: 'low',
                };

            default:
                return {
                    action: 'flag_sales',
                    parameters: { reason: 'needs_review' },
                    autoExecute: false,
                    priority: 'low',
                };
        }
    }

    /**
     * Generate human-readable reasoning
     */
    private generateReasoning(
        classification: ReplyClassification,
        confidence: number,
        extractedData: ClassificationResult['extractedData']
    ): string {
        const confidenceText = confidence >= 0.8 ? 'High confidence' : 
                               confidence >= 0.5 ? 'Medium confidence' : 'Low confidence';
        
        switch (classification) {
            case 'out_of_office': {
                const returnText = extractedData.returnDate 
                    ? `. Expected return: ${extractedData.returnDate.toLocaleDateString()}`
                    : '';
                return `${confidenceText} OOO auto-reply detected${returnText}. Lead will be snoozed.`;
            }
            
            case 'not_interested':
                return `${confidenceText} negative response. Lead marked as lost and added to suppression list.`;
            
            case 'interested':
            case 'tell_me_more':
                return `${confidenceText} positive intent detected! Flagged for immediate sales follow-up.`;
            
            case 'meeting_request':
                return `${confidenceText} meeting request! Requires immediate attention to schedule call.`;
            
            case 'wrong_person': {
                const referralText = extractedData.referredContact 
                    ? `. Referred to: ${extractedData.referredContact}`
                    : '';
                return `${confidenceText} wrong contact identified${referralText}. Update lead record.`;
            }
            
            case 'unsubscribe':
                return `${confidenceText} unsubscribe request. Processing immediately per compliance requirements.`;
            
            case 'bounce':
                return `${confidenceText} bounce/delivery failure. Email added to suppression list.`;
            
            case 'complaint':
                return `${confidenceText} complaint detected. Escalating to owner for review.`;
            
            case 'question':
                return `${confidenceText} question detected. Queued for sales response.`;
            
            default:
                return `${confidenceText} classification. Manual review recommended.`;
        }
    }

    /**
     * Detect sentiment from text
     */
    private detectSentiment(text: string): 'positive' | 'negative' | 'neutral' {
        const positiveWords = ['interested', 'great', 'love', 'excited', 'perfect', 'thanks', 'wonderful', 'amazing', 'yes', 'absolutely'];
        const negativeWords = ['not interested', 'no thanks', 'spam', 'stop', 'remove', 'unsubscribe', 'annoying', 'never', 'hate', 'terrible'];
        
        let positiveCount = 0;
        let negativeCount = 0;
        
        for (const word of positiveWords) {
            if (text.includes(word)) positiveCount++;
        }
        for (const word of negativeWords) {
            if (text.includes(word)) negativeCount++;
        }
        
        if (positiveCount > negativeCount + 1) return 'positive';
        if (negativeCount > positiveCount + 1) return 'negative';
        return 'neutral';
    }

    /**
     * Detect urgency from text
     */
    private detectUrgency(text: string): 'high' | 'medium' | 'low' {
        const highUrgency = ['urgent', 'asap', 'immediately', 'today', 'now', 'emergency', 'critical'];
        const mediumUrgency = ['soon', 'this week', 'when possible', 'at your earliest'];
        
        for (const word of highUrgency) {
            if (text.includes(word)) return 'high';
        }
        for (const word of mediumUrgency) {
            if (text.includes(word)) return 'medium';
        }
        return 'low';
    }

    /**
     * Extract return date from OOO message
     */
    private extractReturnDate(text: string): Date | undefined {
        for (const pattern of RETURN_DATE_PATTERNS) {
            const match = text.match(pattern);
            if (match && match[1]) {
                try {
                    // Try to parse the date
                    const dateStr = match[1];
                    
                    // Handle day names
                    const dayNames = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
                    const dayIndex = dayNames.indexOf(dateStr.toLowerCase());
                    if (dayIndex !== -1) {
                        const today = new Date();
                        const daysUntil = (dayIndex - today.getDay() + 7) % 7 || 7;
                        return new Date(today.getTime() + daysUntil * 24 * 60 * 60 * 1000);
                    }
                    
                    // Try standard date parsing
                    const parsed = new Date(dateStr);
                    if (!isNaN(parsed.getTime())) {
                        return parsed;
                    }
                } catch {
                    continue;
                }
            }
        }
        return undefined;
    }

    /**
     * Extract referral email from text
     */
    private extractReferral(text: string): string | undefined {
        for (const pattern of REFERRAL_PATTERNS) {
            const match = text.match(pattern);
            if (match && match[1]) {
                return match[1].toLowerCase();
            }
        }
        
        // Try to find any email address in the text
        const emailMatch = text.match(/[\w.-]+@[\w.-]+\.\w+/);
        return emailMatch?.[0]?.toLowerCase();
    }

    /**
     * Classify using LLM (when enabled)
     */
    private async classifyWithLLM(subject: string, body: string): Promise<ClassificationResult> {
        if (!this.llmEndpoint || !this.llmApiKey) {
            return this.buildResult('unknown', 0.3, `${subject}\n${body}`, body);
        }

        try {
            const response = await fetch(this.llmEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.llmApiKey}`,
                },
                body: JSON.stringify({
                    model: 'gpt-4o-mini',
                    messages: [
                        {
                            role: 'system',
                            content: `You are an email reply classifier for a sales automation system. 
                            Classify the following email reply into one of these categories:
                            - out_of_office: Auto-replies, vacation notices
                            - not_interested: Negative responses, rejections
                            - interested: Positive responses, wants to learn more
                            - meeting_request: Wants to schedule a call/meeting
                            - wrong_person: Not the right contact
                            - unsubscribe: Wants to be removed
                            - question: Has a question
                            - complaint: Upset about receiving email
                            - unknown: Can't determine
                            
                            Respond with JSON: {"classification": "category", "confidence": 0.0-1.0, "reasoning": "brief explanation"}`
                        },
                        {
                            role: 'user',
                            content: `Subject: ${subject}\n\nBody:\n${body.slice(0, 1000)}`
                        }
                    ],
                    max_tokens: 200,
                    temperature: 0.3,
                }),
            });

            if (response.ok) {
                const data = await response.json() as { 
                    choices: Array<{ message: { content: string } }> 
                };
                const content = data.choices[0]?.message?.content;
                if (content) {
                    const parsed = JSON.parse(content);
                    return this.buildResult(
                        parsed.classification as ReplyClassification,
                        parsed.confidence as number,
                        `${subject}\n${body}`,
                        body
                    );
                }
            }
        } catch (error) {
            this.logger.error('LLM classification failed', { error });
        }

        return this.buildResult('unknown', 0.3, `${subject}\n${body}`, body);
    }

    /**
     * Process an inbound message from the queue
     */
    async processInboundMessage(messageId: string): Promise<ProcessedReply | null> {
        // Get inbound message from database
        const result = await this.db.query<{
            id: string;
            tenant_id: string;
            from_address: string;
            to_address: string;
            subject: string;
            text_body: string;
            html_body: string;
            headers: string;
        }>(`
            SELECT id, tenant_id, from_address, to_address, subject, text_body, html_body, headers
            FROM inbound_messages
            WHERE id = $1
        `, [messageId]);

        const message = result.rows[0];
        if (!message) {
            this.logger.warn('Inbound message not found', { messageId });
            return null;
        }

        // Get body (prefer text, fall back to stripped HTML)
        let body = message.text_body || '';
        if (!body && message.html_body) {
            body = message.html_body.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
        }

        // Parse headers
        let headers: Record<string, string> = {};
        try {
            headers = JSON.parse(message.headers || '{}');
        } catch {
            // Ignore parsing errors
        }

        // Classify the reply
        const classification = await this.classifyReply(
            message.subject || '',
            body,
            message.from_address,
            headers
        );

        // Execute suggested action if auto-execute is enabled
        let actionTaken: string | null = null;
        if (classification.suggestedAction.autoExecute) {
            actionTaken = await this.executeAction(
                message.tenant_id,
                message.from_address,
                classification
            );
        }

        // Store result
        const processedReply: ProcessedReply = {
            inboundMessageId: message.id,
            tenantId: message.tenant_id,
            fromEmail: message.from_address,
            subject: message.subject || '',
            bodyPreview: body.slice(0, 200),
            classification,
            actionTaken,
            processedAt: new Date(),
        };

        // Update inbound message with classification
        await this.db.query(`
            UPDATE inbound_messages
            SET classification = $1, action_taken = $2, processed_at = $3, processing_at = NULL
            WHERE id = $4
        `, [
            JSON.stringify(classification),
            actionTaken,
            new Date(),
            messageId,
        ]);

        return processedReply;
    }

    /**
     * Execute the suggested action
     */
    private async executeAction(
        tenantId: string,
        fromEmail: string,
        classification: ClassificationResult
    ): Promise<string> {
        const { action, parameters } = classification.suggestedAction;

        switch (action) {
            case 'snooze':
                // Update lead's next follow-up date
                await this.db.query(`
                    UPDATE leads 
                    SET next_follow_up_at = $1, status = 'nurturing'
                    WHERE tenant_id = $2 AND email = $3
                `, [parameters.until, tenantId, fromEmail]);
                return `Snoozed until ${parameters.until}`;

            case 'suppress':
                // Add to suppression list
                await this.db.query(`
                    INSERT INTO suppressions (tenant_id, email, reason, created_at)
                    VALUES ($1, $2, $3, NOW())
                    ON CONFLICT (tenant_id, email) DO UPDATE SET reason = $3
                `, [tenantId, fromEmail, parameters.reason]);
                
                // Update lead status if applicable
                if (parameters.markLeadStatus) {
                    await this.db.query(`
                        UPDATE leads SET status = $1 WHERE tenant_id = $2 AND email = $3
                    `, [parameters.markLeadStatus, tenantId, fromEmail]);
                }
                return `Suppressed: ${parameters.reason}`;

            case 'flag_sales':
                // Mark lead as high priority
                await this.db.query(`
                    UPDATE leads 
                    SET priority = 'high', 
                        last_activity = NOW(),
                        notes = COALESCE(notes, '') || E'\\n[AUTO] ' || $1
                    WHERE tenant_id = $2 AND email = $3
                `, [`Flagged: ${parameters.reason}`, tenantId, fromEmail]);
                return `Flagged for sales: ${parameters.reason}`;

            case 'unsubscribe':
                // Process unsubscribe
                await this.db.query(`
                    INSERT INTO suppressions (tenant_id, email, reason, created_at)
                    VALUES ($1, $2, 'unsubscribed', NOW())
                    ON CONFLICT (tenant_id, email) DO UPDATE SET reason = 'unsubscribed'
                `, [tenantId, fromEmail]);
                return 'Unsubscribed';

            case 'escalate':
                // Log escalation (would integrate with notification system)
                this.logger.warn('Reply escalated', { 
                    tenantId, 
                    fromEmail, 
                    reason: parameters.reason 
                });
                return `Escalated: ${parameters.reason}`;

            default:
                return 'No action taken';
        }
    }

    /**
     * Get unprocessed replies count
     */
    async getUnprocessedCount(tenantId?: string): Promise<number> {
        const tenantFilter = tenantId ? 'AND tenant_id = $1' : '';
        const params = tenantId ? [tenantId] : [];

        const result = await this.db.query<{ count: string }>(`
            SELECT COUNT(*) as count FROM inbound_messages
            WHERE processed_at IS NULL AND processing_at IS NULL ${tenantFilter}
        `, params);

        return parseInt(result.rows[0]?.count || '0', 10);
    }

    /**
     * Process all pending replies
     */
    async processAllPending(limit = 100): Promise<ProcessedReply[]> {
        const result = await this.db.query<{ id: string }>(`
            UPDATE inbound_messages
            SET processing_at = NOW()
            WHERE id IN (
                SELECT id FROM inbound_messages
                WHERE processed_at IS NULL AND processing_at IS NULL
                ORDER BY received_at ASC
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING id
        `, [limit]);

        const processed: ProcessedReply[] = [];
        
        for (const { id } of result.rows) {
            try {
                const reply = await this.processInboundMessage(id);
                if (reply) {
                    processed.push(reply);
                }
            } catch (error) {
                this.logger.error('Failed to process inbound message', { id, error });
                await this.db.query(
                    'UPDATE inbound_messages SET processing_at = NULL WHERE id = $1',
                    [id]
                );
            }
        }

        return processed;
    }
}
