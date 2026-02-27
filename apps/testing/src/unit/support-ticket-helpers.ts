export type ValidationTicketInput = {
    subject?: string;
    description?: string;
    category?: string;
    priority?: string;
};

export type ValidationMessageInput = {
    content?: string;
    attachments?: unknown;
};

export const VALID_CATEGORIES = ['billing', 'technical', 'feature_request', 'bug', 'general'];
export const VALID_PRIORITIES = ['low', 'medium', 'high', 'urgent'];

export function validateCreateTicket(input: ValidationTicketInput): { success: boolean; errors?: string[] } {
    const errors: string[] = [];

    if (!input.subject || typeof input.subject !== 'string') {
        errors.push('Subject is required');
    } else {
        const trimmed = input.subject.trim();
        if (trimmed.length < 5) errors.push('Subject must be at least 5 characters');
        if (trimmed.length > 200) errors.push('Subject must be at most 200 characters');
    }

    if (!input.description || typeof input.description !== 'string') {
        errors.push('Description is required');
    } else {
        const trimmed = input.description.trim();
        if (trimmed.length < 10) errors.push('Description must be at least 10 characters');
        if (trimmed.length > 5000) errors.push('Description must be at most 5000 characters');
    }

    if (!input.category || !VALID_CATEGORIES.includes(input.category)) {
        errors.push(`Category must be one of: ${VALID_CATEGORIES.join(', ')}`);
    }

    if (input.priority && !VALID_PRIORITIES.includes(input.priority)) {
        errors.push(`Priority must be one of: ${VALID_PRIORITIES.join(', ')}`);
    }

    return errors.length === 0 ? { success: true } : { success: false, errors };
}

interface KBEntry {
    keywords: string[];
    answer: string;
}

const KNOWLEDGE_BASE: KBEntry[] = [
    {
        keywords: ['domain', 'verify', 'dns', 'spf', 'dkim', 'dmarc'],
        answer: 'To verify your sending domain, go to Settings → Domains...',
    },
    {
        keywords: ['rate limit', 'sending limit', 'throttl', 'too many'],
        answer: 'Rate limits depend on your plan...',
    },
    {
        keywords: ['bounce', 'bounced', 'hard bounce', 'soft bounce'],
        answer: 'ApexMail automatically processes bounces...',
    },
    {
        keywords: ['webhook', 'webhooks', 'event', 'callback'],
        answer: 'To set up webhooks, go to Settings → API & Webhooks...',
    },
    {
        keywords: ['api key', 'api token', 'authentication', 'auth'],
        answer: 'You can manage API keys in Settings → API & Webhooks...',
    },
    {
        keywords: ['billing', 'invoice', 'payment', 'charge', 'subscription', 'plan', 'upgrade', 'downgrade'],
        answer: 'You can manage your billing and subscription...',
    },
    {
        keywords: ['template', 'email template', 'html', 'design'],
        answer: 'ApexMail supports HTML, MJML, and plain text templates...',
    },
    {
        keywords: ['unsubscribe', 'opt-out', 'list-unsubscribe'],
        answer: 'ApexMail automatically adds List-Unsubscribe headers...',
    },
    {
        keywords: ['campaign', 'send campaign', 'bulk', 'mass email'],
        answer: 'To send a campaign: 1) Create or select a template...',
    },
    {
        keywords: ['deliverability', 'spam', 'inbox', 'reputation'],
        answer: 'To improve deliverability: 1) Verify your domain...',
    },
];

export function findBotAnswer(text: string): string | null {
    const lower = text.toLowerCase();
    let bestMatch: KBEntry | null = null;
    let bestScore = 0;

    for (const entry of KNOWLEDGE_BASE) {
        const score = entry.keywords.filter(kw => lower.includes(kw)).length;
        if (score > bestScore) {
            bestScore = score;
            bestMatch = entry;
        }
    }

    return bestScore >= 1 && bestMatch ? bestMatch.answer : null;
}

export function validateMessage(input: ValidationMessageInput): { success: boolean; errors?: string[] } {
    const errors: string[] = [];

    if (!input.content || typeof input.content !== 'string') {
        errors.push('Message cannot be empty');
    } else {
        const trimmed = input.content.trim();
        if (trimmed.length < 1) errors.push('Message cannot be empty');
        if (trimmed.length > 5000) errors.push('Message must be at most 5000 characters');
    }

    if (input.attachments !== undefined) {
        if (!Array.isArray(input.attachments)) {
            errors.push('Attachments must be an array');
        } else if (input.attachments.length > 5) {
            errors.push('Maximum 5 attachments allowed');
        }
    }

    return errors.length === 0 ? { success: true } : { success: false, errors };
}
