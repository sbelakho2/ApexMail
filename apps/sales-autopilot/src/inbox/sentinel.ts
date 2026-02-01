/**
 * Inbox Sentinel - Reply Classification Engine
 * Automatically classifies incoming email replies
 */

import { createLogger, generateId } from '@apexmail/lib';
import type {
    InboxMessage,
    MessageClassification,
    SentimentAnalysis,
    IntentAnalysis,
    SuggestedAction,
    EmailAddress,
} from '../types.js';

const logger = createLogger({ name: 'inbox-sentinel', level: 'info' });

// Classification patterns
const CLASSIFICATION_PATTERNS: Array<{
    classification: MessageClassification;
    patterns: RegExp[];
    priority: number;
}> = [
    {
        classification: 'out_of_office',
        patterns: [
            /out of (the )?office/i,
            /on (annual |medical )?leave/i,
            /on vacation/i,
            /away from (my )?email/i,
            /currently traveling/i,
            /auto.?reply/i,
            /automatic reply/i,
            /i('m| am) (currently )?away/i,
            /will (respond|reply|get back) when i return/i,
            /limited access to email/i,
        ],
        priority: 10,
    },
    {
        classification: 'bounce',
        patterns: [
            /mail(box)? (is )?full/i,
            /user (unknown|not found)/i,
            /address rejected/i,
            /delivery (failed|failure)/i,
            /undeliverable/i,
            /message not delivered/i,
            /recipient rejected/i,
            /mailbox unavailable/i,
            /no such user/i,
        ],
        priority: 10,
    },
    {
        classification: 'unsubscribe',
        patterns: [
            /unsubscribe/i,
            /remove (me )?from (your )?(list|mailing)/i,
            /stop (emailing|sending|contacting)/i,
            /opt.?out/i,
            /don'?t (contact|email) me/i,
            /take me off/i,
        ],
        priority: 9,
    },
    {
        classification: 'not_interested',
        patterns: [
            /not interested/i,
            /no thanks?/i,
            /not (for us|for me|a fit)/i,
            /we('re| are) (all )?set/i,
            /pass on this/i,
            /not (right )?now/i,
            /maybe (later|next)/i,
            /not looking/i,
            /we('ve| have) got (it )?covered/i,
            /already (have|use|using)/i,
        ],
        priority: 8,
    },
    {
        classification: 'interested',
        patterns: [
            /interested/i,
            /tell me more/i,
            /sounds (good|great|interesting)/i,
            /let'?s (chat|talk|meet|connect)/i,
            /schedule (a )?(call|meeting|demo)/i,
            /would (like|love) to (learn|know|hear)/i,
            /send (me )?(more )?info/i,
            /how does (it|this) work/i,
            /what('s| is) (the )?(pricing|cost)/i,
            /can (you|we) (discuss|talk)/i,
        ],
        priority: 7,
    },
    {
        classification: 'meeting_request',
        patterns: [
            /schedule (a )?(call|meeting|demo)/i,
            /book (a )?(time|slot|meeting)/i,
            /calendar link/i,
            /free (on|at|for|this)/i,
            /available (on|at|for|this)/i,
            /works for me/i,
            /let me know (your|some) (times|availability)/i,
            /what times? (work|are good)/i,
        ],
        priority: 6,
    },
    {
        classification: 'question',
        patterns: [
            /\?$/,
            /what (is|are|does|do)/i,
            /how (does|do|can|would)/i,
            /can (you|i|we)/i,
            /could (you|i|we)/i,
            /would (you|it)/i,
            /is (it|this|there)/i,
            /are (there|you)/i,
            /do (you|i|we)/i,
        ],
        priority: 5,
    },
    {
        classification: 'objection',
        patterns: [
            /too expensive/i,
            /not in (the )?budget/i,
            /can'?t afford/i,
            /don'?t have (the )?(time|bandwidth|resources)/i,
            /bad timing/i,
            /(locked|committed) (into|to)/i,
            /under contract/i,
            /not (my|the) decision/i,
            /need to (check|ask|consult)/i,
        ],
        priority: 4,
    },
    {
        classification: 'referral',
        patterns: [
            /reach out to/i,
            /contact (instead|directly)/i,
            /cc'?ing|copying/i,
            /better person to (talk|speak)/i,
            /forward(ed|ing)? (this|your email)/i,
            /loop(ed|ing)? in/i,
            /introducing/i,
            /connect(ed|ing)? you with/i,
        ],
        priority: 3,
    },
];

// Sentiment keywords
const POSITIVE_WORDS = new Set([
    'great', 'good', 'excellent', 'amazing', 'wonderful', 'fantastic',
    'love', 'like', 'interested', 'excited', 'happy', 'pleased',
    'thanks', 'thank', 'appreciate', 'helpful', 'perfect', 'awesome',
]);

const NEGATIVE_WORDS = new Set([
    'bad', 'poor', 'terrible', 'awful', 'horrible', 'disappointed',
    'hate', 'dislike', 'annoyed', 'frustrated', 'angry', 'upset',
    'not interested', 'no', 'stop', 'unsubscribe', 'spam',
]);

/**
 * Classifies an email message
 */
export function classifyMessage(
    subject: string,
    body: string
): MessageClassification {
    const fullText = `${subject} ${body}`.toLowerCase();

    // Sort patterns by priority (highest first)
    const sortedPatterns = [...CLASSIFICATION_PATTERNS].sort(
        (a, b) => b.priority - a.priority
    );

    for (const { classification, patterns } of sortedPatterns) {
        for (const pattern of patterns) {
            if (pattern.test(fullText)) {
                logger.debug('Classified message', {
                    classification,
                    pattern: pattern.toString(),
                });
                return classification;
            }
        }
    }

    return 'other';
}

/**
 * Analyzes sentiment of text
 */
export function analyzeSentiment(text: string): SentimentAnalysis {
    const words = text.toLowerCase().split(/\W+/);
    let positiveCount = 0;
    let negativeCount = 0;

    for (const word of words) {
        if (POSITIVE_WORDS.has(word)) {
            positiveCount++;
        }
        if (NEGATIVE_WORDS.has(word)) {
            negativeCount++;
        }
    }

    const total = positiveCount + negativeCount;
    let score: number;
    let label: 'negative' | 'neutral' | 'positive';

    if (total === 0) {
        score = 0;
        label = 'neutral';
    } else {
        score = (positiveCount - negativeCount) / total;
        if (score > 0.2) {
            label = 'positive';
        } else if (score < -0.2) {
            label = 'negative';
        } else {
            label = 'neutral';
        }
    }

    const confidence = total > 0 ? Math.min(1, total / 10) : 0.3;

    return { score, label, confidence };
}

/**
 * Analyzes intent of message
 */
export function analyzeIntent(
    classification: MessageClassification,
    text: string
): IntentAnalysis {
    const intents: string[] = [];

    // Map classifications to primary intents
    const classificationIntentMap: Record<MessageClassification, string> = {
        interested: 'purchase_interest',
        not_interested: 'decline',
        out_of_office: 'defer',
        bounce: 'delivery_failure',
        unsubscribe: 'opt_out',
        meeting_request: 'schedule_meeting',
        question: 'information_request',
        objection: 'negotiation',
        referral: 'redirect',
        spam: 'irrelevant',
        other: 'unknown',
    };

    const primaryIntent = classificationIntentMap[classification];

    // Detect secondary intents from text
    const textLower = text.toLowerCase();

    if (/pric(e|ing)|cost|budget/i.test(textLower)) {
        intents.push('pricing_inquiry');
    }
    if (/feature|capability|can (it|you)/i.test(textLower)) {
        intents.push('feature_inquiry');
    }
    if (/demo|trial|test/i.test(textLower)) {
        intents.push('demo_request');
    }
    if (/competitor|alternative/i.test(textLower)) {
        intents.push('competitive_evaluation');
    }
    if (/timeline|when|deadline/i.test(textLower)) {
        intents.push('timeline_discussion');
    }

    return {
        primary: primaryIntent,
        secondary: intents,
        confidence: intents.length > 0 ? 0.8 : 0.6,
    };
}

/**
 * Suggests next action based on classification and intent
 */
export function suggestAction(
    classification: MessageClassification,
    _sentiment: SentimentAnalysis,
    _intent: IntentAnalysis
): SuggestedAction | null {
    switch (classification) {
        case 'interested':
            return {
                type: 'follow_up',
                description: 'Send additional information and schedule a call',
                priority: 'high',
                dueAt: new Date(Date.now() + 4 * 60 * 60 * 1000), // 4 hours
            };

        case 'meeting_request':
            return {
                type: 'schedule_demo',
                description: 'Send calendar link to schedule meeting',
                priority: 'urgent',
                dueAt: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1 hour
            };

        case 'question':
            return {
                type: 'send_info',
                description: 'Answer question and provide relevant resources',
                priority: 'high',
                dueAt: new Date(Date.now() + 4 * 60 * 60 * 1000), // 4 hours
            };

        case 'objection':
            return {
                type: 'follow_up',
                description: 'Address objection with relevant counter-points',
                priority: 'medium',
                dueAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
            };

        case 'referral':
            return {
                type: 'update_crm',
                description: 'Add referred contact and update lead status',
                priority: 'medium',
                dueAt: new Date(Date.now() + 8 * 60 * 60 * 1000), // 8 hours
            };

        case 'not_interested':
            return {
                type: 'close_lead',
                description: 'Mark as not interested and remove from sequences',
                priority: 'low',
                dueAt: null,
            };

        case 'unsubscribe':
            return {
                type: 'update_crm',
                description: 'Process unsubscribe request immediately',
                priority: 'urgent',
                dueAt: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1 hour
            };

        case 'bounce':
            return {
                type: 'update_crm',
                description: 'Mark email as invalid and find alternate contact',
                priority: 'medium',
                dueAt: null,
            };

        case 'out_of_office':
            return {
                type: 'follow_up',
                description: 'Schedule follow-up after return date',
                priority: 'low',
                dueAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
            };

        default:
            return {
                type: 'follow_up',
                description: 'Review message and determine appropriate response',
                priority: 'medium',
                dueAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
            };
    }
}

/**
 * Parses email address from string
 */
export function parseEmailAddress(rawAddress: string): EmailAddress {
    // Handle formats like "Name <email@example.com>" or just "email@example.com"
    const match = rawAddress.match(/(?:"?([^"<]+)"?\s*)?<?([^<>\s]+@[^<>\s]+)>?/);

    if (match && match[2]) {
        return {
            email: match[2].trim(),
            name: match[1]?.trim() || null,
        };
    }

    return {
        email: rawAddress.trim(),
        name: null,
    };
}

/**
 * Extracts return date from out-of-office messages
 */
export function extractReturnDate(text: string): Date | null {
    // Common date patterns
    const patterns = [
        // "returning on January 15"
        /return(ing)?\s+(on\s+)?(\w+\s+\d{1,2}(,?\s+\d{4})?)/i,
        // "back on 15/01/2025" or "back on 01-15-2025"
        /back\s+(on\s+)?(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})/i,
        // "available again Monday"
        /available\s+(again\s+)?(on\s+)?(\w+day)/i,
        // "until January 20"
        /until\s+(\w+\s+\d{1,2}(,?\s+\d{4})?)/i,
    ];

    for (const pattern of patterns) {
        const match = text.match(pattern);
        if (match) {
            // Try to parse the date
            const dateStr = match[match.length - 1] ?? match[3] ?? match[2];
            if (dateStr) {
                const parsed = new Date(dateStr);

                if (!isNaN(parsed.getTime())) {
                    return parsed;
                }
            }
        }
    }

    return null;
}

/**
 * Processes an incoming message
 */
export function processIncomingMessage(params: {
    tenantId: string;
    leadId: string | null;
    campaignId: string | null;
    messageId: string;
    inReplyTo: string | null;
    from: string;
    to: string[];
    cc?: string[];
    subject: string;
    textBody: string | null;
    htmlBody: string | null;
    receivedAt: Date;
}): InboxMessage {
    const bodyText = params.textBody || stripHtml(params.htmlBody || '');

    const classification = classifyMessage(params.subject, bodyText);
    const sentiment = analyzeSentiment(bodyText);
    const intent = analyzeIntent(classification, bodyText);
    const suggestedAction = suggestAction(classification, sentiment, intent);

    const message: InboxMessage = {
        id: generateId('msg'),
        tenantId: params.tenantId,
        leadId: params.leadId,
        campaignId: params.campaignId,
        messageId: params.messageId,
        inReplyTo: params.inReplyTo,
        from: parseEmailAddress(params.from),
        to: params.to.map(parseEmailAddress),
        cc: (params.cc || []).map(parseEmailAddress),
        subject: params.subject,
        textBody: params.textBody,
        htmlBody: params.htmlBody,
        classification,
        sentiment,
        intent,
        suggestedAction,
        processed: true,
        processedAt: new Date(),
        receivedAt: params.receivedAt,
        createdAt: new Date(),
    };

    logger.info('Processed incoming message', {
        messageId: message.id,
        classification,
        sentiment: sentiment.label,
        suggestedAction: suggestedAction?.type,
    });

    return message;
}

/**
 * Strips HTML tags from text
 */
function stripHtml(html: string): string {
    return html
        .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
        .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
}

/**
 * Batch processes multiple messages
 */
export function batchProcessMessages(
    messages: Array<{
        tenantId: string;
        leadId: string | null;
        campaignId: string | null;
        messageId: string;
        inReplyTo: string | null;
        from: string;
        to: string[];
        cc?: string[];
        subject: string;
        textBody: string | null;
        htmlBody: string | null;
        receivedAt: Date;
    }>
): InboxMessage[] {
    return messages.map(processIncomingMessage);
}

/**
 * Gets messages requiring action by priority
 */
export function getMessagesRequiringAction(
    messages: InboxMessage[],
    priority?: 'urgent' | 'high' | 'medium' | 'low'
): InboxMessage[] {
    let filtered = messages.filter(
        (m) => m.suggestedAction !== null && m.suggestedAction.type !== 'no_action'
    );

    if (priority) {
        filtered = filtered.filter((m) => m.suggestedAction?.priority === priority);
    }

    // Sort by priority
    const priorityOrder = { urgent: 0, high: 1, medium: 2, low: 3 };
    filtered.sort((a, b) => {
        const aPriority = a.suggestedAction?.priority || 'low';
        const bPriority = b.suggestedAction?.priority || 'low';
        return priorityOrder[aPriority] - priorityOrder[bPriority];
    });

    return filtered;
}
