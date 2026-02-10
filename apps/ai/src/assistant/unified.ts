/**
 * @apexmail/ai — Unified Assistant
 *
 * Single assistant that replaces both chatbot and mailbot with:
 *  1. Conversational Q&A (email marketing expertise)
 *  2. Natural-language command execution (campaigns, lists, contacts)
 *  3. Semi-autonomous backend actions (billing, account, diagnostics)
 *
 * Uses the fine-tuned Qwen 7B model (ONNX on VPS) or falls back to
 * template-based responses when no model is loaded.
 */

import { InferenceEngine } from '../inference/engine.js';
import { getSharedEngine } from '../inference/index.js';
import {
    lookupGlossaryTerm,
    matchConversationPattern,
    getIndustryBenchmark,
    getEmailTypeBenchmark,
    GLOSSARY,
    DELIVERABILITY_RULES,
    APEXMAIL_CAPABILITIES,
} from '../training/industry-knowledge-base.js';
import type {
    ChatMessage,
    ChatSession,
    ChatContext,
    ChatResponse,
    SuggestedAction,
    MailbotAction,
    MailbotActionType,
    CustomerProfile,
    AutonomousConfig,
    AutonomousRiskLevel,
    EscalationReason,
    EscalationTicket,
    AutonomousAuditEntry,
    ProactiveTrigger,
} from '../types.js';

// ════════════════════════════════════════════════════════════════
// TYPES
// ════════════════════════════════════════════════════════════════

/** All action types the assistant can trigger */
export type AssistantActionType =
    | MailbotActionType
    // Backend / billing operations
    | 'get_billing_status'
    | 'get_billing_history'
    | 'process_refund'
    | 'upgrade_plan'
    | 'downgrade_plan'
    | 'cancel_subscription'
    | 'create_api_key'
    | 'revoke_api_key'
    | 'check_api_status'
    | 'verify_domain'
    | 'check_deliverability'
    | 'get_sender_reputation'
    | 'get_bounce_report'
    | 'account_health_check'
    | 'analyze_campaigns'
    | 'get_campaign_stats'
    | 'create_ab_test';

/** Parsed action extracted from model output */
export interface AssistantAction {
    action: AssistantActionType;
    params: Record<string, unknown>;
    confirm: boolean;
    reason: string;
}

/** Result from processing a user message */
export interface AssistantResponse {
    message: ChatMessage;
    actions: AssistantAction[];
    suggestedActions: SuggestedAction[];
    requiresConfirmation: boolean;
    confirmationId?: string;
    tokens?: number;
    latencyMs: number;
}

/** Pending confirmation entry */
interface PendingConfirmation {
    action: AssistantAction;
    sessionId: string;
    createdAt: number;
}

/** Assistant configuration */
export interface AssistantConfig {
    maxHistoryLength: number;
    maxContextTokens: number;
    temperature: number;
    sessionTTLMs: number;
    maxSessions: number;
    pendingActionTTLMs: number;
}

const DEFAULT_CONFIG: AssistantConfig = {
    maxHistoryLength: 20,
    maxContextTokens: 2048,
    temperature: 0.7,
    sessionTTLMs: 30 * 60 * 1000,      // 30 minutes
    maxSessions: 1000,
    pendingActionTTLMs: 15 * 60 * 1000, // 15 minutes
};

// ════════════════════════════════════════════════════════════════
// AUTONOMOUS MODE — self-service actions without user intervention
// ════════════════════════════════════════════════════════════════

/**
 * Default autonomous configuration. Control-plane owner overrides via settings.
 *
 * DESIGN PRINCIPLES (from Anthropic & OpenAI research):
 * 1. **Least privilege** — only auto-approve read-only and low-risk actions
 * 2. **Human-in-the-loop** — always escalate billing, deletion, security
 * 3. **Audit everything** — every autonomous action is logged
 * 4. **Confidence gating** — low-confidence intents → escalate
 * 5. **Rate limiting** — cap autonomous actions per session and per hour
 * 6. **Dry-run first** — new deployments start in dry-run mode
 * 7. **Sentiment escalation** — angry/frustrated customers → human
 * 8. **Transparency** — bot always tells user it's acting autonomously
 */
const DEFAULT_AUTONOMOUS_CONFIG: AutonomousConfig = {
    enabled: false,                  // OFF by default — control-plane owner must enable
    autoApproveActions: [
        // Read-only actions — safe to auto-execute
        'get_billing_status', 'get_billing_history', 'get_campaign_stats',
        'check_api_status', 'check_deliverability', 'get_sender_reputation',
        'get_bounce_report', 'account_health_check', 'verify_domain',
        'analyze_campaigns', 'export_data', 'export_report',
    ],
    alwaysEscalateActions: [
        // NEVER auto-execute these — too risky
        'cancel_subscription', 'process_refund', 'delete_campaign',
        'delete_list', 'revoke_api_key', 'downgrade_plan',
        'send_campaign',      // Sending to real subscribers = irreversible
        'import_contacts',    // Bulk data changes
    ],
    confidenceThreshold: 0.7,
    maxAutoActionsPerSession: 10,
    maxAutonomousBillingAmount: 0,   // No autonomous billing by default
    proactiveOutreach: false,
    proactiveTriggers: [],
    sentimentEscalationThreshold: -0.5,
    autonomousActionsPerHour: 50,
    allowedHoursUtc: { start: 0, end: 24 },  // 24/7 by default
    auditAllActions: true,
    dryRun: true,                    // Start in dry-run mode for safety
};

/** Risk classification for autonomous decision-making */
const ACTION_RISK_LEVELS: Record<string, AutonomousRiskLevel> = {
    // Safe — read-only, no side effects
    get_billing_status: 'safe',
    get_billing_history: 'safe',
    get_campaign_stats: 'safe',
    check_api_status: 'safe',
    get_sender_reputation: 'safe',
    get_bounce_report: 'safe',
    account_health_check: 'safe',
    analyze_campaigns: 'safe',
    // Low — read-only but exposes data
    verify_domain: 'low',
    check_deliverability: 'low',
    export_data: 'low',
    export_report: 'low',
    // Medium — creates/modifies resources
    create_campaign: 'medium',
    create_list: 'medium',
    create_segment: 'medium',
    add_contact: 'medium',
    add_contacts: 'medium',
    tag_contacts: 'medium',
    create_ab_test: 'medium',
    set_automation: 'medium',
    generate_content: 'medium',
    schedule_campaign: 'medium',
    pause_campaign: 'medium',
    create_api_key: 'medium',
    // High — destructive or high-impact
    send_campaign: 'high',
    import_contacts: 'high',
    remove_contact: 'high',
    remove_contacts: 'high',
    upgrade_plan: 'high',
    // Critical — irreversible or financial
    delete_campaign: 'critical',
    delete_list: 'critical',
    cancel_subscription: 'critical',
    process_refund: 'critical',
    downgrade_plan: 'critical',
    revoke_api_key: 'critical',
};

/** Detect negative sentiment from message text (simple heuristic) */
function detectSentimentScore(text: string): number {
    const lower = text.toLowerCase();
    let score = 0;

    // Negative signals
    const negativeWords = [
        'angry', 'furious', 'terrible', 'horrible', 'worst', 'hate', 'awful',
        'disgusting', 'unacceptable', 'ridiculous', 'scam', 'fraud', 'stolen',
        'sue', 'lawyer', 'attorney', 'legal action', 'report you', 'complaint',
        'broken', 'useless', 'incompetent', 'waste', 'trash',
    ];
    const frustratedWords = [
        'frustrated', 'annoyed', 'disappointed', 'upset', 'unhappy', 'dissatisfied',
        'fed up', 'sick of', 'tired of', 'not working', 'still broken', 'again',
    ];
    const urgentWords = [
        'urgent', 'emergency', 'asap', 'immediately', 'right now', 'critical',
        'help me', 'please help', 'need help',
    ];

    for (const w of negativeWords) if (lower.includes(w)) score -= 0.3;
    for (const w of frustratedWords) if (lower.includes(w)) score -= 0.15;
    for (const w of urgentWords) if (lower.includes(w)) score -= 0.05;

    // Positive signals
    const positiveWords = ['thanks', 'thank you', 'great', 'awesome', 'love', 'perfect', 'excellent', 'amazing', 'helpful'];
    for (const w of positiveWords) if (lower.includes(w)) score += 0.2;

    // ALL CAPS = shouting
    const capsRatio = (text.match(/[A-Z]/g)?.length ?? 0) / Math.max(text.length, 1);
    if (capsRatio > 0.5 && text.length > 10) score -= 0.2;

    // Multiple exclamation/question marks
    if (/[!?]{3,}/.test(text)) score -= 0.15;

    return Math.max(-1, Math.min(1, score));
}

/**
 * Determine whether an action can be auto-approved in autonomous mode.
 */
function canAutoApprove(
    action: AssistantActionType,
    intent: DetectedIntent,
    context: ChatContext,
    autoConfig: AutonomousConfig,
    sessionAutoActionCount: number,
): { approved: boolean; reason?: EscalationReason; riskLevel: AutonomousRiskLevel } {
    const riskLevel = ACTION_RISK_LEVELS[action] ?? 'high';

    // Always-escalate list
    if (autoConfig.alwaysEscalateActions.includes(action)) {
        return { approved: false, reason: 'high_risk_action', riskLevel };
    }

    // Auto-approve list
    if (!autoConfig.autoApproveActions.includes(action)) {
        return { approved: false, reason: 'high_risk_action', riskLevel };
    }

    // Confidence too low
    if (intent.confidence < autoConfig.confidenceThreshold) {
        return { approved: false, reason: 'confidence_too_low', riskLevel };
    }

    // Session action limit
    if (sessionAutoActionCount >= autoConfig.maxAutoActionsPerSession) {
        return { approved: false, reason: 'multi_step_risky', riskLevel };
    }

    // Time-of-day check (UTC)
    const hour = new Date().getUTCHours();
    if (hour < autoConfig.allowedHoursUtc.start || hour >= autoConfig.allowedHoursUtc.end) {
        return { approved: false, reason: 'high_risk_action', riskLevel };
    }

    // Billing amount check
    if (['upgrade_plan', 'process_refund'].includes(action) && autoConfig.maxAutonomousBillingAmount <= 0) {
        return { approved: false, reason: 'billing_change', riskLevel };
    }

    return { approved: true, riskLevel };
}

/**
 * Create an escalation ticket for the control-plane owner.
 */
function createEscalationTicket(
    sessionId: string,
    context: ChatContext,
    reason: EscalationReason,
    summary: string,
    history: ChatMessage[],
): EscalationTicket {
    const severityMap: Record<EscalationReason, EscalationTicket['severity']> = {
        high_risk_action: 'medium',
        billing_change: 'high',
        account_deletion: 'urgent',
        data_export: 'medium',
        compliance_concern: 'urgent',
        angry_customer: 'high',
        repeated_failure: 'medium',
        ambiguous_intent: 'low',
        security_incident: 'urgent',
        quota_override: 'medium',
        custom_request: 'low',
        confidence_too_low: 'low',
        multi_step_risky: 'medium',
        pii_detected: 'high',
        legal_request: 'urgent',
    };

    return {
        id: `esc_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        sessionId,
        tenantId: context.tenantId ?? 'default',
        userId: context.customer?.email ?? 'unknown',
        reason,
        severity: severityMap[reason] ?? 'medium',
        summary,
        conversationHistory: history.map(m => ({ role: m.role, content: m.content })),
        suggestedAction: undefined,
        customerProfile: context.customer,
        createdAt: new Date(),
        status: 'open',
    };
}

/**
 * Create an audit log entry for an autonomous action.
 */
function createAuditEntry(
    tenantId: string,
    sessionId: string,
    userId: string,
    action: string,
    params: Record<string, unknown>,
    riskLevel: AutonomousRiskLevel,
    autoApproved: boolean,
    escalated: boolean,
    escalationReason?: EscalationReason,
): AutonomousAuditEntry {
    return {
        id: `audit_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        tenantId,
        sessionId,
        userId,
        action,
        params,
        riskLevel,
        autoApproved,
        escalated,
        escalationReason,
        timestamp: new Date(),
        durationMs: 0,
    };
}

/**
 * Generate a proactive outreach message for an event trigger.
 */
function generateProactiveMessage(trigger: ProactiveTrigger, context: ChatContext): string {
    const name = context.customer?.name ?? 'there';
    const templates: Record<string, string> = {
        deliverability_drop: `Hi ${name}! 📉 I noticed your deliverability score has dropped recently. I've automatically run a diagnostic. Would you like me to walk you through the results and suggest fixes?`,
        bounce_rate_spike: `Hey ${name}, ⚠️ your bounce rate has spiked above the safe threshold. I've pulled your bounce report — want me to help clean your list?`,
        quota_approaching: `Hi ${name}! 📊 You've used ${context.customer?.sendsUsed?.toLocaleString() ?? 'most'} of your ${context.customer?.sendQuota?.toLocaleString() ?? ''} send quota. Would you like to review your usage or discuss an upgrade?`,
        domain_expiring: `${name}, 🔐 one of your verified domains may need attention. I can run a quick DNS check to make sure everything is configured properly.`,
        campaign_stalled: `Hi ${name}! It looks like you haven't sent a campaign in a while. Want me to help you draft one, or review your scheduled campaigns?`,
        billing_past_due: `${name}, 💳 it looks like your payment may be past due. I can check your billing status and help resolve this before any service interruption.`,
        new_user_onboarding: `Welcome to ApexMail, ${name}! 🎉 I can help you get started — want me to walk you through setting up your first campaign, verifying your domain, and importing contacts?`,
        engagement_drop: `Hi ${name}, I've noticed your open rates have been trending down. Would you like some tips on improving engagement, or should I analyze your recent campaigns?`,
        compliance_deadline: `${name}, ⚖️ heads up — there may be compliance requirements coming up. Want me to run a compliance check on your setup?`,
        api_errors_spike: `${name}, 🔧 I'm seeing elevated API error rates on your account. I've checked the API status — want me to share the details?`,
    };
    return trigger.messageTemplate || templates[trigger.event] || `Hi ${name}! I noticed something that needs your attention. How can I help?`;
}

// ════════════════════════════════════════════════════════════════
// SECURITY — role-based access, input sanitization, PII redaction
// ════════════════════════════════════════════════════════════════

/** Actions that require at least 'editor' role */
const EDITOR_ACTIONS: Set<AssistantActionType> = new Set([
    'create_campaign', 'send_campaign', 'schedule_campaign', 'pause_campaign',
    'delete_campaign', 'create_list', 'delete_list', 'add_contact', 'add_contacts',
    'remove_contact', 'remove_contacts', 'import_contacts', 'tag_contacts',
    'create_segment', 'generate_content', 'set_automation', 'create_ab_test',
    'export_data', 'export_report', 'analyze_campaigns', 'get_campaign_stats',
]);

/** Actions that require 'admin' or 'owner' role */
const ADMIN_ACTIONS: Set<AssistantActionType> = new Set([
    'create_api_key', 'revoke_api_key', 'upgrade_plan', 'downgrade_plan',
    'cancel_subscription', 'process_refund', 'verify_domain',
]);

/** Actions that require elevated authentication (re-verification) */
const ELEVATED_AUTH_ACTIONS: Set<AssistantActionType> = new Set([
    'cancel_subscription', 'process_refund', 'revoke_api_key',
    'delete_campaign', 'delete_list',
]);

/** Role hierarchy for permission checks */
const ROLE_LEVEL: Record<string, number> = {
    viewer: 0,
    editor: 1,
    admin: 2,
    owner: 3,
};

interface SecurityCheckResult {
    allowed: boolean;
    reason?: string;
    requiredRole?: string;
    requiresElevatedAuth?: boolean;
}

/**
 * Check whether the current session + customer profile authorizes an action.
 */
function checkActionSecurity(
    action: AssistantActionType,
    context: ChatContext,
): SecurityCheckResult {
    const customer = context.customer;
    const role = customer?.role ?? 'viewer';
    const roleLevel = ROLE_LEVEL[role] ?? 0;
    const authenticated = context.authenticated !== false; // default true for backward compat
    const authLevel = customer?.authLevel ?? 'basic';

    // Must be authenticated
    if (!authenticated) {
        return { allowed: false, reason: 'You must be logged in to perform this action.' };
    }

    // Account-level blocks
    if (customer?.accountStatus === 'suspended') {
        return { allowed: false, reason: 'Your account is currently suspended. Please contact support to resolve this before performing any actions.' };
    }
    if (customer?.accountStatus === 'cancelled' && action !== 'get_billing_status' && action !== 'get_billing_history') {
        return { allowed: false, reason: 'Your account has been cancelled. Please reactivate your subscription first.' };
    }

    // Role-based access
    if (ADMIN_ACTIONS.has(action) && roleLevel < ROLE_LEVEL.admin) {
        return { allowed: false, reason: `This action requires admin privileges. Your current role is '${role}'.`, requiredRole: 'admin' };
    }
    if (EDITOR_ACTIONS.has(action) && roleLevel < ROLE_LEVEL.editor) {
        return { allowed: false, reason: `This action requires editor privileges. Your current role is '${role}'.`, requiredRole: 'editor' };
    }

    // Elevated auth for destructive billing/account actions
    if (ELEVATED_AUTH_ACTIONS.has(action) && authLevel !== 'elevated') {
        return { allowed: false, reason: 'This action requires additional identity verification. Please re-authenticate to proceed.', requiresElevatedAuth: true };
    }

    // Quota checks for sending
    if (action === 'send_campaign' && customer?.sendQuota != null && customer?.sendsUsed != null) {
        if (customer.sendsUsed >= customer.sendQuota) {
            return { allowed: false, reason: `You've reached your send quota (${customer.sendsUsed.toLocaleString()}/${customer.sendQuota.toLocaleString()}). Please upgrade your plan or wait for quota reset.` };
        }
    }

    return { allowed: true };
}

/**
 * Sanitize user input — strip dangerous patterns while preserving intent.
 */
function sanitizeInput(text: string): string {
    let cleaned = text;
    // Strip HTML/script tags
    cleaned = cleaned.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '');
    cleaned = cleaned.replace(/<[^>]+>/g, '');
    // Strip SQL injection patterns but preserve quoted names
    cleaned = cleaned.replace(/;\s*(DROP|DELETE|UPDATE|INSERT|ALTER|EXEC)\s/gi, ' ');
    // Normalize excessive whitespace
    cleaned = cleaned.replace(/\s{3,}/g, '  ');
    return cleaned.trim();
}

/**
 * Redact PII from assistant responses before delivery.
 */
function redactPII(text: string): string {
    let redacted = text;
    // Redact full credit card numbers
    redacted = redacted.replace(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, '****-****-****-****');
    // Redact SSN patterns
    redacted = redacted.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '***-**-****');
    // Redact long hex strings that look like secrets/tokens (32+ chars)
    redacted = redacted.replace(/\b[a-f0-9]{32,}\b/gi, '[REDACTED]');
    // Redact Bearer tokens
    redacted = redacted.replace(/Bearer\s+[A-Za-z0-9._-]{20,}/g, 'Bearer [REDACTED]');
    return redacted;
}

/** Rate limiter for per-session message rate */
interface RateLimitEntry {
    count: number;
    windowStart: number;
}

const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMIT_MAX_MESSAGES = 30;  // max 30 messages per minute

// ════════════════════════════════════════════════════════════════
// SYSTEM PROMPT — mirrors training data exactly
// ════════════════════════════════════════════════════════════════

const SYSTEM_PROMPT = `You are ApexMail Assistant, a unified AI assistant for the ApexMail email marketing platform. You combine expert email marketing knowledge with the ability to execute platform actions on behalf of users.

## CAPABILITIES
1. **Conversational Support**: Answer questions about email marketing strategy, deliverability, compliance, metrics, and best practices with specific data and benchmarks.
2. **Command Execution**: Parse natural language instructions into structured actions (campaigns, lists, contacts, segments, templates, automations).
3. **Backend Operations**: Diagnose and fix billing issues, query account status, manage API keys, handle domain verification, and perform account maintenance.
4. **Content Generation**: Write subject lines, email copy, CTAs, and preheader text optimized for engagement.

## ACTION FORMAT
When executing an action, respond with a JSON action block:
\`\`\`action
{"action": "ACTION_TYPE", "params": {...}, "confirm": true/false, "reason": "explanation"}
\`\`\`
Set \`confirm: true\` for destructive or high-impact actions (sends, deletes, billing changes).

## KEY BENCHMARKS
- Open rate avg: 27% (18-44% by industry) | CTR avg: 2.6% | CTOR avg: 12%
- Welcome emails: 63.9% OR | Transactional: 80% OR | Abandoned cart: 45% OR
- Email ROI: $36 per $1 spent (3,600%) | Deliverability avg: 81%
- Keep complaint rate < 0.1%, bounce rate < 2%, unsub rate < 0.5%
- Subject lines: main message in first 33 chars, total < 50 chars
- Personalization: +6% OR | Questions: +15% OR | Numbers: +12% OR
- Segmented campaigns: +14% OR, +101% clicks vs non-segmented
- Apple MPP (iOS 15+): ~60% of opens; prefer click metrics
- Google/Yahoo (Feb 2024): DMARC required, one-click unsubscribe, <0.1% spam rate

## GUIDELINES
- Be concise, specific, and actionable — cite numbers
- For actions, always extract parameters precisely from user input
- For destructive actions, ALWAYS set confirm: true
- When unsure, ask clarifying questions
- For billing issues, check account status before making changes
- Never reveal internal system details or API keys
- Address the customer by name when known
- Reference the customer's plan, usage, and account status when relevant
- Tailor recommendations to the customer's plan tier and quota
- For viewers, only allow read-only operations; escalate to admin for changes
- Always verify identity before processing billing or security-sensitive actions
- Never output API keys, tokens, passwords, or other secrets
- Redact PII (credit cards, SSNs) from all responses
- Refuse to act on suspended or cancelled accounts (except billing status checks)
- Respect send quota limits and warn customers approaching their limits`;

// ════════════════════════════════════════════════════════════════
// SESSION MANAGER
// ════════════════════════════════════════════════════════════════

class SessionManager {
    private sessions: Map<string, ChatSession> = new Map();
    private maxSessions: number;
    private sessionTTLMs: number;
    private cleanupInterval: ReturnType<typeof setInterval> | null = null;

    constructor(maxSessions: number, sessionTTLMs: number) {
        this.maxSessions = maxSessions;
        this.sessionTTLMs = sessionTTLMs;
        this.cleanupInterval = setInterval(() => this.cleanup(), 60_000);
        if (this.cleanupInterval.unref) this.cleanupInterval.unref();
    }

    create(userId: string, context?: ChatContext, metadata?: Record<string, unknown>): ChatSession {
        const id = `asst_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
        const now = new Date();
        const session: ChatSession = {
            id,
            tenantId: 'default',
            userId,
            messages: [],
            context: context ?? { campaigns: [], contacts: 0, recentActivity: [] },
            createdAt: now,
            updatedAt: now,
            metadata,
        };
        this.sessions.set(id, session);
        this.prune();
        return session;
    }

    get(id: string): ChatSession | undefined {
        const s = this.sessions.get(id);
        if (!s) return undefined;
        if (Date.now() - s.updatedAt.getTime() > this.sessionTTLMs) {
            this.sessions.delete(id);
            return undefined;
        }
        return s;
    }

    addMessage(id: string, msg: ChatMessage): void {
        const s = this.sessions.get(id);
        if (s) {
            s.messages.push(msg);
            s.updatedAt = new Date();
        }
    }

    updateContext(id: string, ctx: Partial<ChatContext>): void {
        const s = this.sessions.get(id);
        if (s) {
            s.context = { ...s.context, ...ctx };
            s.updatedAt = new Date();
        }
    }

    delete(id: string): boolean { return this.sessions.delete(id); }

    private cleanup(): void {
        const now = Date.now();
        for (const [id, s] of this.sessions) {
            if (now - s.updatedAt.getTime() > this.sessionTTLMs) this.sessions.delete(id);
        }
    }

    private prune(): void {
        if (this.sessions.size <= this.maxSessions) return;
        const sorted = [...this.sessions.entries()].sort(([, a], [, b]) => a.updatedAt.getTime() - b.updatedAt.getTime());
        for (const [id] of sorted.slice(0, this.sessions.size - this.maxSessions)) {
            this.sessions.delete(id);
        }
    }

    destroy(): void {
        if (this.cleanupInterval) { clearInterval(this.cleanupInterval); this.cleanupInterval = null; }
    }
}

// ════════════════════════════════════════════════════════════════
// INTENT DETECTOR — fast regex pre-classifier
// ════════════════════════════════════════════════════════════════

type IntentCategory = 'command' | 'billing' | 'domain' | 'knowledge' | 'greeting' | 'unclear';

interface DetectedIntent {
    category: IntentCategory;
    action?: AssistantActionType;
    confidence: number;
    entities: Record<string, string>;
}

const INTENT_PATTERNS: Array<{ category: IntentCategory; action?: AssistantActionType; patterns: RegExp[]; entityExtractors?: Record<string, RegExp> }> = [
    // Campaign commands
    { category: 'command', action: 'create_campaign', patterns: [/create\s+(?:a\s+)?(?:new\s+)?campaign\s+(?:called|named|titled)?\s*['"""']?(.+?)['"""']?\s*$/i, /new\s+campaign\s+['"""'](.+?)['"""']/i, /(?:make|set\s+up|launch|start|spin\s+up)\s+(?:a\s+)?(?:new\s+)?(?:email\s+)?campaign\s+(?:called|named|titled)?\s*['"""'](.+?)['"""']/i, /(?:cr?e+a?te?|make|cerate|creaet)\s+(?:a\s+)?(?:new\s+)?camp(?:ai[gn]{0,2}|ia[gn]{0,2}|agn|aig[nm])e?\s+(?:called|named|titled)?\s*['"""']?(.+?)['"""']?\s*$/i, /(?:plese|pls|plz|please)?\s*(?:cr?e+a?te?|cerate)\s+(?:a\s+)?camp(?:ai[gn]{0,2}|ia[gn]{0,2})e?\s+(?:called|named|titled)?\s*['"""']?(.+?)['"""']?\s*$/i], entityExtractors: { name: /['"""'](.+?)['"""']/i } },
    { category: 'command', action: 'send_campaign', patterns: [/send\s+(?:the\s+)?(?:campaign\s+)?['"""](.+?)['"""](?:\s+to\s+(?:list\s+)?['"""](.+?)['"""])?/i], entityExtractors: { campaign: /(?:campaign\s+)?['"""](.+?)['"""]/i, list: /to\s+(?:list\s+)?['"""](.+?)['"""]/i } },
    { category: 'command', action: 'schedule_campaign', patterns: [/schedule\s+(?:the\s+)?(?:campaign\s+)?['"""](.+?)['"""](?:\s+(?:for|at)\s+(.+))?$/i], entityExtractors: { campaign: /['"""](.+?)['"""]/i, time: /(?:for|at)\s+(.+)$/i } },
    { category: 'command', action: 'pause_campaign', patterns: [/pause\s+(?:the\s+)?(?:campaign\s+)?['"""](.+?)['"""]/i, /pause\s+all\s+(?:active\s+)?campaigns/i, /stop\s+(?:the\s+)?campaign\s+['"""](.+?)['"""]/i] },
    { category: 'command', action: 'resume_campaign', patterns: [/resume\s+(?:the\s+)?(?:campaign\s+)?['"""](.+?)['"""]/i, /unpause\s+(?:the\s+)?(?:campaign\s+)?['"""](.+?)['"""]/i, /restart\s+(?:the\s+)?(?:campaign\s+)?['"""](.+?)['"""]/i] },
    { category: 'command', action: 'delete_campaign', patterns: [/delete\s+(?:the\s+)?campaign\s+['"""](.+?)['"""]/i, /remove\s+(?:the\s+)?campaign\s+['"""](.+?)['"""]/i] },
    { category: 'command', action: 'get_campaign_stats', patterns: [/show\s+(?:me\s+)?(?:the\s+)?stats?\s+(?:for\s+)?['"""](.+?)['"""]/i, /how\s+(?:is|did)\s+['"""](.+?)['"""]\s+(?:doing|perform)/i, /(?:show|get|view|display|pull)\s+(?:me\s+)?(?:my\s+)?(?:campaign\s+)?(?:stats|statistics)/i, /(?:campaign|sending)\s+(?:stats|statistics)/i, /(?:how\s+are\s+)?(?:my\s+)?emails?\s+performing/i] },
    // Contact commands
    { category: 'command', action: 'add_contact', patterns: [/add\s+(?:a\s+)?(?:new\s+)?(?:the\s+)?(?:contact\s+)?(\S+@\S+)(?:\s+to\s+(?:list\s+)?['"""](.+?)['"""])?/i], entityExtractors: { email: /(\S+@\S+)/i, list: /to\s+(?:list\s+)?['"""](.+?)['"""]/i } },
    { category: 'command', action: 'remove_contact', patterns: [/remove\s+(?:the\s+)?(?:contact\s+)?(\S+@\S+)/i, /unsubscribe\s+(\S+@\S+)/i] },
    { category: 'command', action: 'import_contacts', patterns: [/import\s+contacts?/i, /upload\s+contacts?/i, /import\s+(?:my\s+)?(?:contact\s+)?(?:list|file|csv)/i] },
    // List commands
    { category: 'command', action: 'create_list', patterns: [/create\s+(?:a\s+)?(?:new\s+)?list\s+(?:called|named)?\s*['"""'](.+?)['"""']/i, /(?:make|set\s+up|spin\s+up|start)\s+(?:a\s+)?(?:new\s+)?(?:fresh\s+)?(?:mailing\s+)?list\s+(?:called|named)?\s*['"""'](.+?)['"""']/i], entityExtractors: { name: /['"""'](.+?)['"""']/i } },
    { category: 'command', action: 'delete_list', patterns: [/delete\s+(?:the\s+)?list\s+['"""](.+?)['"""]/i] },
    // Segment
    { category: 'command', action: 'create_segment', patterns: [/create\s+(?:a\s+)?segment/i, /segment\s+(?:my\s+|the\s+)?(?:contacts|subscribers|audience)/i] },
    // A/B testing
    { category: 'command', action: 'create_ab_test', patterns: [/(?:create|set\s+up|run|start)\s+(?:an?\s+)?a\/b\s+test/i, /a\/b\s+test\s+(?:for|on|with)/i, /split\s+test/i] },
    // Automation
    { category: 'command', action: 'set_automation', patterns: [/set\s+up\s+(?:an?\s+)?(?:email\s+)?automat(?:ion|ed)/i, /(?:create|build|start)\s+(?:an?\s+)?(?:email\s+)?automat(?:ion|ed)/i, /automat(?:e|ion)\s+(?:for|my|new\s+subscriber)/i] },
    // Tag contacts (plural)
    { category: 'command', action: 'tag_contacts', patterns: [/tag\s+(?:my\s+)?(?:all\s+)?contacts/i, /add\s+tags?\s+to\s+(?:my\s+)?contacts/i, /tag\s+all\s+\w+\s+subscribers?/i] },
    // Tag contact (singular with email)
    { category: 'command', action: 'tag_contact', patterns: [/tag\s+(?:the\s+)?contact\s+(\S+@\S+)\s+(?:as|with)\s+/i, /tag\s+(?:the\s+)?contact\s+(\S+@\S+)/i], entityExtractors: { email: /(\S+@\S+)/i, tag: /(?:as|with)\s+['"""']?(.+?)['"""']?\s*$/i } },
    // Analytics
    { category: 'command', action: 'analyze_campaigns', patterns: [/analyz[es]\s+(?:my\s+)?(?:campaigns?|performance|metrics)/i, /show\s+(?:me\s+)?(?:my\s+)?analytics/i, /(?:show|get|pull|display)\s+(?:me\s+)?(?:my\s+)?(?:sending|email|campaign)\s+(?:analytics|metrics|performance)/i, /analyz[es]\s+(?:my\s+)?(?:\w+\s+)?performance/i] },
    { category: 'command', action: 'export_data', patterns: [/export\s+(?:my\s+)?(?:all\s+)?(?:\w+\s+)*?(?:data|report|campaign|list|contacts?|subscribers?|everything|csv)/i, /download\s+(?:all\s+)?(?:my\s+)?(?:\w+\s+)*?(?:data|report|csv|metrics|analytics|list|contacts?|subscribers?)/i, /export\s+(?:all|everything)/i, /export\s+(?:a\s+)?report/i] },
    // Billing (IMPORTANT: get_billing_history MUST come before get_billing_status to avoid premature match on 'billing history')
    { category: 'billing', action: 'get_billing_history', patterns: [/(?:show|view|check|get)\s+(?:me\s+)?(?:my\s+)?billing\s+history/i, /(?:past|previous|old)\s+(?:invoices?|bills?|charges?)/i, /payment\s+history/i, /(?:show|view|get)\s+(?:me\s+)?(?:my\s+)?invoices/i] },
    { category: 'billing', action: 'get_billing_status', patterns: [/(?:check|show|view|what'?s?)\s+(?:my\s+)?bill(?:ing)?/i, /(?:what|how much)\s+(?:am I|do I)\s+(?:paying|owe)/i, /(?:my|the)\s+invoice/i, /what\s+plan\s+am\s+I\s+on/i, /(?:pull\s+up|look\s+up|get)\s+(?:my\s+)?(?:current\s+)?billing\s+(?:info|status|details|summary)/i, /(?:would\s+you|could\s+you|can\s+you)\s+(?:mind\s+)?(?:check|show|get)(?:ing)?\s+(?:my\s+)?billing/i, /what\s+is\s+(?:my\s+)?billing\s+(?:status|summary|info)/i, /(?:billing|bill)\s+(?:status|summary|info|details)/i, /(?:how\s+(?:about|is)\s+)?(?:my\s+)?billing\b.*(?:issue|any|status)?/i, /(?:get|give)\s+(?:me\s+)?(?:my\s+)?(?:a\s+)?billing\s+(?:status|summary|overview)/i, /how\s+much\s+(?:am\s+I|do\s+I)\s+(?:pay|owe|spend)/i] },
    { category: 'billing', action: 'upgrade_plan', patterns: [/upgrade\s+(?:(?:my|our|the)\s+)?(?:plan|subscription|account)/i] },
    { category: 'billing', action: 'downgrade_plan', patterns: [/downgrade\s+(?:my\s+)?(?:plan|subscription)/i, /downgrade\s+(?:me|us)\b/i, /downgrade\s+(?:(?:my|our|the)\s+)?(?:.*?\s)?(?:plan|subscription)/i] },
    { category: 'billing', action: 'cancel_subscription', patterns: [/cancel\s+(?:(?:my|our)\s+)?(?:subscription|account|plan|everything|service)/i, /(?:i\s+want\s+to\s+)?cancel\s+everything/i] },
    { category: 'billing', action: 'process_refund', patterns: [/refund/i, /charged\s+twice/i, /double\s+charge/i, /wrong\s+(?:amount|charge)/i, /overcharged/i] },
    // Domain / API
    { category: 'domain', action: 'verify_domain', patterns: [/(?:check|verify|validate)\s+(?:if\s+)?(?:my\s+)?(?:\w+\s+)?domain/i, /(?:my\s+)?dns\s+(?:records?|settings?)/i, /(?:spf|dkim|dmarc)\s+(?:records?|setup|status|compliance|configuration|config|settings?)/i, /domain\s+(?:for|with)\s+(?:spf|dkim|dmarc)/i, /(?:status|state|check)\s+(?:of\s+)?(?:my\s+)?(?:spf|dkim|dmarc)/i, /(?:check|verify|test)\s+(?:the\s+)?dns\s+(?:for|of|on)\s+/i, /verify\s+(\S+\.\S+)/i, /(?:check|verify)\s+(?:the\s+)?dns\b/i, /domain\s+(?:verification|authentication)/i] },
    { category: 'domain', action: 'create_api_key', patterns: [/(?:create|generate|new)\s+(?:an?\s+)?api\s+key/i, /(?:generate|create)\s+(?:an?\s+)?(?:\w+\s+)?api\s+key/i] },
    { category: 'domain', action: 'check_api_status', patterns: [/(?:my\s+)?api\s+(?:is\s+)?(?:not\s+working|issue|problem|error|status)/i, /api\s+key\s+(?:is\s+)?(?:not\s+working|invalid|expired)/i, /(?:\d{3}\s+)?errors?\s+(?:from|with|on)\s+(?:the\s+)?api/i, /api\s+(?:returns?|giving|throwing)\s+(?:\d{3}|errors?)/i, /(?:is\s+)?(?:the\s+)?(?:\w+\s+)?api\s+(?:working|up|running|healthy|alive|ok)/i, /(?:check|test)\s+(?:the\s+)?(?:\w+\s+)?api(?:\s+(?:health|status))?$/i, /^api\s+(?:status|health|check)$/i, /^check\s+api$/i] },
    { category: 'domain', action: 'revoke_api_key', patterns: [/(?:revoke|delete|remove|invalidate)\s+(?:(?:an?|my|the|our)\s+)?(?:\w+\s+)?api\s+key/i] },
    { category: 'domain', action: 'get_bounce_report', patterns: [/(?:show|get|view|check|pull)\s+(?:me\s+)?(?:my\s+)?bounces?(?:\s+(?:report|data|info|details|numbers))?/i, /bounce\s+(?:report|stats|statistics|data|info|details|numbers)/i] },
    { category: 'domain', action: 'check_deliverability', patterns: [/emails?\s+(?:are\s+)?(?:going\s+to\s+spam|not\s+(?:being\s+)?delivered)/i, /deliverability\s+(?:issue|problem|diagnostic|check|rate|score|report|status)/i, /inbox\s+placement/i, /deliverability\s+is\s+(?:low|bad|poor|terrible|dropping)/i, /(?:run|do|start)\s+(?:a\s+)?(?:deliverability\s+)?diagnostic/i, /(?:my\s+)?email\s+(?:go|goes|going|went)\s+to\s+spam/i, /(?:check|test|analyze|run)\s+(?:my\s+)?(?:current\s+)?deliverability/i, /^deliverability\s+check$/i, /(?:my\s+)?(?:current\s+)?deliverability\s+(?:rate|score)/i] },
    { category: 'domain', action: 'get_sender_reputation', patterns: [/sender\s+reputation/i, /reputation\s+(?:score|check)/i, /sending\s+(?:reputation|score)/i, /(?:sender|sending)\s+score/i, /show\s+(?:me\s+)?(?:my\s+)?reputation/i] },
    { category: 'domain', action: 'account_health_check', patterns: [/account\s+(?:health|status|check)/i, /(?:is\s+)?my\s+account\s+(?:ok|good|in\s+good\s+standing)/i, /(?:check|run|do)\s+(?:a\s+)?(?:full\s+)?(?:check|scan|diagnostic|everything)(?:\s+(?:for|on))?/i, /check\s+everything/i, /am\s+I\s+in\s+good\s+standing/i, /(?:run|do|check)\s+(?:a\s+)?(?:full\s+)?health\s+(?:check|diagnostics?|scan)/i, /health\s+diagnostics?/i] },
    // Greeting / chitchat — second pattern uses negative lookahead to avoid swallowing command messages
    { category: 'greeting', patterns: [/^(?:hi(?:\s+there)?|hello(?:\s+there)?|hey(?:\s+there)?|thanks|thank you|thx|bye|goodbye|ok|okay|sure|great|cool|nice|got it|understood)\s*[.!]?\s*$/i, /^(?:hi|hello|hey)[!.,]?\s+(?!check\s|show\s|get\s|create\s|send\s|verify\s|export\s|add\s|remove\s|delete\s|pause\s|resume\s|schedule\s|analyze\s|what(?:\s+is|\s+are|'s)\s+(?:my|our|the)|how\s+(?:is|are|do|much)|is\s+(?:my|the)|can\s+(?:I|you\s+(?:check|show|get|create|send|verify))|pull\s|tag\s|display\s|run\s|do\s+(?:a|my)|my\s+bill|cancel\s|downgrade\s|upgrade\s).+/i] },
    // Unclear
    { category: 'unclear', patterns: [/^.{0,5}$/i, /^[^a-zA-Z]*$/i] },
];

function detectIntent(text: string): DetectedIntent {
    const cleaned = text.trim();

    // ── Negation detection ──
    // If the user says "don't", "do not", "I don't want to", etc. before an action verb,
    // treat it as a knowledge/clarification intent rather than executing the action.
    const negationPattern = /\b(?:don'?t|do\s+not|no(?:t)?|never|stop|please\s+don'?t)\s+(?:want\s+to\s+)?(?:send|cancel|delete|remove|revoke|pause|upgrade|downgrade)/i;
    if (negationPattern.test(cleaned)) {
        return { category: 'knowledge', confidence: 0.6, entities: {} };
    }

    // ── Escalation request detection ──
    // Detect when the user explicitly asks for a human agent
    const escalationRequest = /\b(?:talk\s+to\s+(?:a\s+)?(?:human|person|agent|someone|real\s+person|support))\b|\b(?:human\s+agent|real\s+agent|live\s+agent|get\s+(?:me\s+)?(?:a\s+)?(?:human|agent|person))\b|\b(?:escalat(?:e|ion)|speak\s+(?:to|with)\s+(?:a\s+)?(?:human|agent|person|manager|supervisor))\b/i;
    if (escalationRequest.test(cleaned)) {
        return { category: 'knowledge', confidence: 0.9, entities: { escalation: 'human_requested' } };
    }

    // ── Proactive / quota / limit detection ──
    // Detect sending limit / quota concerns
    const quotaPattern = /\b(?:send(?:ing)?\s+limit|quota|almost\s+(?:at|out\s+of)|running\s+(?:out\s+of|low))\b/i;
    if (quotaPattern.test(cleaned)) {
        return { category: 'knowledge', confidence: 0.8, entities: { proactive: 'quota_warning' } };
    }

    // ── Domain expiration / verification concerns ──
    const domainExpiryPattern = /\b(?:domain\s+(?:verification|auth(?:entication)?)\s+(?:is\s+)?(?:about\s+to\s+)?expir|expir(?:ing|ed|e|es)\s+domain)\b/i;
    if (domainExpiryPattern.test(cleaned)) {
        return { category: 'domain', action: 'verify_domain', confidence: 0.85, entities: {} };
    }

    // ── Question prefix detection ──
    // If the input starts with "how do I", "how to", etc. followed by a general topic
    // (not a specific imperative like "how much am I paying"), treat as knowledge.
    // Excludes possessive "my/our" which indicates a specific account action.
    const questionPrefix = /^(?:how\s+(?:do\s+I|to|can\s+I|should\s+I)\s+(?!check|verify|see|view|get|show))|^(?:can\s+you\s+(?:explain|tell)\s+)|^(?:tell\s+me\s+about\s+)|^(?:explain\s+)/i;
    const isKnowledgeQuestion = /^what\s+(?:is|are)\s+(?:a\s+|an?\s+|the\s+)?(?!my\s|our\s)/i;
    if (questionPrefix.test(cleaned) || isKnowledgeQuestion.test(cleaned)) {
        return { category: 'knowledge', confidence: 0.65, entities: {} };
    }

    for (const rule of INTENT_PATTERNS) {
        for (const pattern of rule.patterns) {
            if (pattern.test(cleaned)) {
                const entities: Record<string, string> = {};
                if (rule.entityExtractors) {
                    for (const [key, extractor] of Object.entries(rule.entityExtractors)) {
                        const m = cleaned.match(extractor);
                        if (m?.[1]) entities[key] = m[1];
                    }
                }
                const matchLen = cleaned.match(pattern)?.[0]?.length ?? 0;
                return {
                    category: rule.category,
                    action: rule.action,
                    confidence: Math.min(0.95, 0.5 + (matchLen / cleaned.length) * 0.45),
                    entities,
                };
            }
        }
    }
    return { category: 'knowledge', confidence: 0.3, entities: {} };
}

// ════════════════════════════════════════════════════════════════
// ACTION PARSER — extracts structured actions from model output
// ════════════════════════════════════════════════════════════════

const ACTION_BLOCK_RE = /```action\s*\n?\s*(\{[\s\S]*?\})\s*\n?\s*```/g;

function parseActions(text: string): AssistantAction[] {
    const actions: AssistantAction[] = [];
    let match;
    while ((match = ACTION_BLOCK_RE.exec(text)) !== null) {
        try {
            const parsed = JSON.parse(match[1]);
            if (parsed.action && typeof parsed.action === 'string') {
                actions.push({
                    action: parsed.action as AssistantActionType,
                    params: parsed.params ?? {},
                    confirm: parsed.confirm === true,
                    reason: parsed.reason ?? '',
                });
            }
        } catch {
            // Malformed JSON in action block — skip
        }
    }
    // Reset regex state
    ACTION_BLOCK_RE.lastIndex = 0;
    return actions;
}

function stripActionBlocks(text: string): string {
    ACTION_BLOCK_RE.lastIndex = 0;
    return text.replace(ACTION_BLOCK_RE, '').trim();
}

// ════════════════════════════════════════════════════════════════
// MODEL OUTPUT VALIDATOR
// ════════════════════════════════════════════════════════════════

/**
 * Determine whether model output is meaningful enough to use directly, or
 * whether we should fall back to the template engine.
 *
 * Checks:
 * 1. For command/billing/domain intents — the output MUST contain an action block.
 * 2. For knowledge intents — the output must be at least 30 chars of mostly
 *    recognisable English (>60 % letter / space characters).
 * 3. For greetings — the output must be at least 10 chars.
 * 4. Unclear intents always fall back.
 */
function isModelOutputUsable(text: string, intent: DetectedIntent): boolean {
    const trimmed = text.trim();
    if (trimmed.length === 0) return false;

    // For action-oriented intents, require an action block
    if (intent.category === 'command' || intent.category === 'billing' || intent.category === 'domain') {
        const hasBlock = ACTION_BLOCK_RE.test(trimmed);
        ACTION_BLOCK_RE.lastIndex = 0;
        return hasBlock;
    }

    // Unclear — always fall back for better UX
    if (intent.category === 'unclear') {
        return false;
    }

    // For greetings and knowledge: require coherent English prose.
    // Split into whitespace-delimited tokens and check that most look like
    // real words (lowercase alphabetic runs) rather than gibberish.
    const tokens = trimmed.split(/\s+/).filter(t => t.length > 0);
    if (tokens.length < 4) return false;

    // A "real word" token is all-alpha or alpha with trailing punctuation (e.g. "hello," or "rate.")
    const realWords = tokens.filter(t => /^[a-zA-Z]+[.,!?;:'"()]*$/.test(t));
    const realRatio = realWords.length / tokens.length;

    // Greeting: at least 4 tokens, >70% real words
    if (intent.category === 'greeting') {
        return realRatio > 0.7;
    }

    // Knowledge: at least 30 chars, >70% real words, at least 6 real word tokens
    return trimmed.length >= 30 && realRatio > 0.7 && realWords.length >= 6;
}

// ════════════════════════════════════════════════════════════════
// TEMPLATE FALLBACKS — used when no model is loaded
// ════════════════════════════════════════════════════════════════

function generateFallbackResponse(text: string, intent: DetectedIntent, context?: ChatContext): string {
    const customer = context?.customer;
    const name = customer?.name;

    // For commands, generate the action block directly from regex extraction
    if (intent.category === 'command' && intent.action) {
        return generateCommandFallback(intent);
    }
    if (intent.category === 'billing' && intent.action) {
        return generateBillingFallback(intent, customer);
    }
    if (intent.category === 'domain' && intent.action) {
        return generateDomainFallback(intent);
    }
    if (intent.category === 'greeting') {
        const greeting = name
            ? `Hello, ${name}! I'm the ApexMail Assistant.`
            : "Hello! I'm the ApexMail Assistant.";
        const planInfo = customer?.plan
            ? ` You're on the **${customer.plan}** plan.`
            : '';
        const quotaInfo = customer?.sendQuota != null && customer?.sendsUsed != null
            ? ` You've used ${customer.sendsUsed.toLocaleString()} of ${customer.sendQuota.toLocaleString()} sends this period.`
            : '';
        return `${greeting}${planInfo}${quotaInfo} I can help with email marketing strategy, campaign management, billing, domain setup, and more. What can I do for you?`;
    }
    if (intent.category === 'unclear') {
        return "I couldn't understand that. Could you rephrase? For example:\n- \"Create a campaign called 'Newsletter'\"\n- \"What's a good open rate?\"\n- \"Check my billing status\"\n- \"Verify my domain settings\"";
    }

    // ── Escalation request ──
    if (intent.entities?.escalation === 'human_requested') {
        return "I understand you'd like to speak with a human agent. I'm escalating this to our support team now. A team member will be with you shortly. In the meantime, is there anything I can help you with?";
    }

    // ── Quota / sending limit concerns ──
    if (intent.entities?.proactive === 'quota_warning') {
        const planInfo = customer?.plan ? ` You're on the **${customer.plan}** plan.` : '';
        const quotaInfo = customer?.sendQuota != null && customer?.sendsUsed != null
            ? ` You've used ${customer.sendsUsed.toLocaleString()} of ${customer.sendQuota.toLocaleString()} sends.`
            : '';
        return `I can help with your sending limit concerns.${planInfo}${quotaInfo}\n\nHere are your options:\n- **Upgrade your plan** to get a higher sending quota\n- **Optimize your list** — remove unengaged subscribers to make every send count\n- **Stagger your sends** — spread campaigns across multiple days\n- **Check your usage** — I can show you detailed sending analytics\n\nWould you like me to check your current quota or help you upgrade your plan?`;
    }

    // ── Name introduction ──
    const nameIntro = text.match(/(?:^|\.\s+)(?:my\s+name\s+is|call\s+me)\s+([A-Z][a-z]{1,20})/i);
    if (nameIntro) {
        const introducedName = nameIntro[1].charAt(0).toUpperCase() + nameIntro[1].slice(1).toLowerCase();
        const planInfo = customer?.plan ? ` You're on the **${customer.plan}** plan.` : '';
        return `Nice to meet you, ${introducedName}! I'm the ApexMail Assistant.${planInfo} How can I help you today?`;
    }

    // Knowledge — check glossary and patterns
    const glossaryMatch = lookupGlossaryTerm(text);
    if (glossaryMatch) {
        return `**${glossaryMatch.term}**: ${glossaryMatch.definition}`;
    }

    const patternMatch = matchConversationPattern(text);
    if (patternMatch) {
        return patternMatch.contextualResponse;
    }

    // Generic knowledge response
    return "That's a great question about email marketing. For the most accurate advice, could you provide more context? I can help with:\n- **Metrics & Benchmarks** — open rates, CTR, deliverability\n- **Strategy** — segmentation, automation, A/B testing\n- **Compliance** — GDPR, CAN-SPAM, DMARC setup\n- **Platform Operations** — campaigns, lists, billing, API keys";
}

function generateCommandFallback(intent: DetectedIntent): string {
    const { action, entities } = intent;
    const params: Record<string, unknown> = {};

    if (entities.name) params.name = entities.name;
    if (entities.campaign) params.campaign_name = entities.campaign;
    if (entities.list) params.list_name = entities.list;
    if (entities.email) params.email = entities.email;
    if (entities.time) params.send_time = entities.time;

    const destructive = ['send_campaign', 'delete_campaign', 'pause_campaign', 'delete_list', 'remove_contact', 'import_contacts', 'set_automation'].includes(action!);

    const actionBlock = JSON.stringify({ action, params, confirm: destructive, reason: `Executing ${action} as requested` });
    const warning = destructive ? '⚠️ This action requires confirmation. ' : '';
    return `${warning}I'll execute that for you.\n\n\`\`\`action\n${actionBlock}\n\`\`\``;
}

function generateBillingFallback(intent: DetectedIntent, customer?: CustomerProfile): string {
    const { action } = intent;
    const nameGreet = customer?.name ? `${customer.name}, let` : 'Let';
    const planInfo = customer?.plan ? ` You're currently on the **${customer.plan}** plan.` : '';
    const actionBlock = JSON.stringify({
        action,
        params: {},
        confirm: ['process_refund', 'upgrade_plan', 'downgrade_plan', 'cancel_subscription'].includes(action!),
        reason: `Billing operation: ${action}`,
    });
    // get_billing_history is a safe read-only billing action (allowed even for cancelled accounts)
    // Other billing actions follow the same pattern
    return `${nameGreet} me look into that.${planInfo}\n\n\`\`\`action\n${actionBlock}\n\`\`\``;
}

function generateDomainFallback(intent: DetectedIntent): string {
    const { action } = intent;
    const confirm = ['create_api_key', 'revoke_api_key'].includes(action!);
    const actionBlock = JSON.stringify({ action, params: {}, confirm, reason: `Domain/API operation: ${action}` });
    const prefix = action === 'check_deliverability'
        ? 'I understand this is urgent. Let me run a deliverability diagnostic on your sending setup right away.'
        : action === 'get_sender_reputation'
        ? 'Let me check your sender reputation score. This will analyze your recent sending patterns.'
        : action === 'verify_domain'
        ? 'I\'ll verify your domain configuration including SPF, DKIM, and DMARC records.'
        : action === 'account_health_check'
        ? 'Let me run a comprehensive health check on your account to make sure everything is in order.'
        : action === 'revoke_api_key'
        ? '⚠️ This will permanently invalidate the API key. I\'ll proceed with confirmation.'
        : 'I\'ll look into that for you right away.';
    return `${prefix}\n\n\`\`\`action\n${actionBlock}\n\`\`\``;
}

// ════════════════════════════════════════════════════════════════
// UNIFIED ASSISTANT
// ════════════════════════════════════════════════════════════════

export class UnifiedAssistant {
    private engine: InferenceEngine;
    private sessions: SessionManager;
    private config: AssistantConfig;
    private pendingConfirmations: Map<string, PendingConfirmation> = new Map();
    private rateLimits: Map<string, RateLimitEntry> = new Map();
    private sweepInterval: ReturnType<typeof setInterval> | null = null;

    // ── Autonomous mode state ──
    private autonomousConfig: AutonomousConfig;
    private escalationQueue: EscalationTicket[] = [];
    private auditLog: AutonomousAuditEntry[] = [];
    private sessionAutoActionCounts: Map<string, number> = new Map();
    private hourlyAutonomousActions: Map<string, number> = new Map(); // tenantId → count

    constructor(config?: Partial<AssistantConfig>, autonomousConfig?: Partial<AutonomousConfig>) {
        this.config = { ...DEFAULT_CONFIG, ...config };
        this.autonomousConfig = { ...DEFAULT_AUTONOMOUS_CONFIG, ...autonomousConfig };
        this.engine = getSharedEngine({ temperature: this.config.temperature });
        this.sessions = new SessionManager(this.config.maxSessions, this.config.sessionTTLMs);

        // Sweep expired pending confirmations
        this.sweepInterval = setInterval(() => {
            const now = Date.now();
            for (const [id, p] of this.pendingConfirmations) {
                if (now - p.createdAt > this.config.pendingActionTTLMs) this.pendingConfirmations.delete(id);
            }
        }, 60_000);
        if (this.sweepInterval.unref) this.sweepInterval.unref();
    }

    // ── Session management ──

    startSession(userId: string, context?: ChatContext): ChatSession {
        return this.sessions.create(userId, context);
    }

    getSession(sessionId: string): ChatSession | undefined {
        return this.sessions.get(sessionId);
    }

    endSession(sessionId: string): boolean {
        return this.sessions.delete(sessionId);
    }

    updateContext(sessionId: string, context: Partial<ChatContext>): void {
        this.sessions.updateContext(sessionId, context);
    }

    // ── Core conversation ──

    async chat(sessionId: string, userMessage: string, context?: Partial<ChatContext>): Promise<AssistantResponse> {
        const start = Date.now();
        const session = this.sessions.get(sessionId);
        if (!session) throw new Error(`Session not found: ${sessionId}`);

        if (context) this.sessions.updateContext(sessionId, context);

        // ── Rate limiting ──
        const rateLimitResult = this.checkRateLimit(sessionId);
        if (!rateLimitResult.allowed) {
            const msg: ChatMessage = { role: 'assistant', content: rateLimitResult.reason!, timestamp: new Date() };
            return { message: msg, actions: [], suggestedActions: [], requiresConfirmation: false, latencyMs: Date.now() - start };
        }

        // ── Input sanitization ──
        const cleanedMessage = sanitizeInput(userMessage);

        // Add user message
        const userMsg: ChatMessage = { role: 'user', content: cleanedMessage, timestamp: new Date() };
        this.sessions.addMessage(sessionId, userMsg);

        // Detect intent for fast routing
        const intent = detectIntent(cleanedMessage);

        // ── Security check for action intents ──
        if (intent.action) {
            const securityResult = checkActionSecurity(intent.action, session.context);
            if (!securityResult.allowed) {
                const securityMsg: ChatMessage = {
                    role: 'assistant',
                    content: `🔒 ${securityResult.reason}`,
                    timestamp: new Date(),
                };
                this.sessions.addMessage(sessionId, securityMsg);
                return {
                    message: securityMsg,
                    actions: [],
                    suggestedActions: [],
                    requiresConfirmation: false,
                    latencyMs: Date.now() - start,
                };
            }
        }

        // Generate response
        let responseText: string;
        let tokens = 0;

        try {
            const prompt = this.buildPrompt(session, cleanedMessage);
            const result = await this.engine.chat(prompt.messages, { temperature: this.config.temperature });
            responseText = result.text;
            tokens = result.tokens;

            // Validate model output — fall back to templates if the response is
            // empty, gibberish, or missing an expected action block.
            if (!isModelOutputUsable(responseText, intent)) {
                responseText = generateFallbackResponse(cleanedMessage, intent, session.context);
            }
        } catch {
            // Model not available — use template fallback
            responseText = generateFallbackResponse(cleanedMessage, intent, session.context);
        }

        // ── PII redaction ──
        responseText = redactPII(responseText);

        // Parse actions from response
        const actions = parseActions(responseText);
        const cleanText = actions.length > 0 ? stripActionBlocks(responseText) : responseText;

        // ── Post-parse security: verify each action is allowed ──
        const allowedActions: AssistantAction[] = [];
        const blockedReasons: string[] = [];
        for (const action of actions) {
            const check = checkActionSecurity(action.action, session.context);
            if (check.allowed) {
                allowedActions.push(action);
            } else {
                blockedReasons.push(`🔒 ${action.action}: ${check.reason}`);
            }
        }

        let finalText = cleanText;
        if (blockedReasons.length > 0) {
            finalText += '\n\n' + blockedReasons.join('\n');
        }

        // Handle confirmation flow
        let requiresConfirmation = false;
        let confirmationId: string | undefined;
        const confirmableActions = allowedActions.filter(a => a.confirm);
        if (confirmableActions.length > 0) {
            confirmationId = `cfm_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
            this.pendingConfirmations.set(confirmationId, {
                action: confirmableActions[0],
                sessionId,
                createdAt: Date.now(),
            });
            requiresConfirmation = true;
        }

        // Add assistant message to history
        const assistantMsg: ChatMessage = { role: 'assistant', content: finalText, timestamp: new Date() };
        this.sessions.addMessage(sessionId, assistantMsg);

        // Prune history
        this.pruneHistory(sessionId);

        // Generate suggestions
        const suggestedActions = this.generateSuggestions(session, intent);

        return {
            message: assistantMsg,
            actions: allowedActions,
            suggestedActions,
            requiresConfirmation,
            confirmationId,
            tokens,
            latencyMs: Date.now() - start,
        };
    }

    // ── Confirmation flow ──

    confirmAction(confirmationId: string): { success: boolean; action?: AssistantAction; message: string } {
        const pending = this.pendingConfirmations.get(confirmationId);
        if (!pending) return { success: false, message: 'No pending action found with that ID.' };

        if (Date.now() - pending.createdAt > this.config.pendingActionTTLMs) {
            this.pendingConfirmations.delete(confirmationId);
            return { success: false, message: 'This action has expired. Please re-issue the command.' };
        }

        this.pendingConfirmations.delete(confirmationId);
        return { success: true, action: pending.action, message: `✅ Action ${pending.action.action} confirmed and executing.` };
    }

    cancelAction(confirmationId: string): { success: boolean; message: string } {
        const pending = this.pendingConfirmations.get(confirmationId);
        if (!pending) return { success: false, message: 'No pending action found with that ID.' };
        this.pendingConfirmations.delete(confirmationId);
        return { success: true, message: `Action ${pending.action.action} cancelled.` };
    }

    // ── Quick API ──

    async detectIntent(text: string): Promise<DetectedIntent> {
        return detectIntent(text);
    }

    getAvailableActions(): Array<{ type: string; description: string; example: string }> {
        return [
            { type: 'create_campaign', description: 'Create a new email campaign', example: "Create a campaign called 'Newsletter'" },
            { type: 'send_campaign', description: 'Send a campaign to subscribers', example: "Send 'Welcome Series' to 'New Subscribers'" },
            { type: 'schedule_campaign', description: 'Schedule a campaign for later', example: "Schedule 'Newsletter' for tomorrow at 9am" },
            { type: 'pause_campaign', description: 'Pause a running campaign', example: "Pause campaign 'Flash Sale'" },
            { type: 'delete_campaign', description: 'Delete a campaign', example: "Delete campaign 'Old Promo'" },
            { type: 'add_contact', description: 'Add a contact to a list', example: "Add john@example.com to 'VIP'" },
            { type: 'remove_contact', description: 'Remove a contact', example: "Remove jane@test.com from 'Newsletter'" },
            { type: 'create_list', description: 'Create a subscriber list', example: "Create list 'Premium Members'" },
            { type: 'create_segment', description: 'Create an audience segment', example: "Create segment of users who opened in last 30 days" },
            { type: 'get_billing_status', description: 'Check billing information', example: "Show me my billing info" },
            { type: 'verify_domain', description: 'Verify domain DNS settings', example: "Check my domain configuration" },
            { type: 'create_api_key', description: 'Generate a new API key', example: "Generate a new API key" },
            { type: 'account_health_check', description: 'Run account diagnostics', example: "Is my account in good standing?" },
        ];
    }

    // ── Autonomous mode public API ──

    /** Update autonomous configuration at runtime (from control-plane settings) */
    setAutonomousConfig(config: Partial<AutonomousConfig>): void {
        this.autonomousConfig = { ...this.autonomousConfig, ...config };
    }

    /** Get current autonomous configuration */
    getAutonomousConfig(): AutonomousConfig {
        return { ...this.autonomousConfig };
    }

    /** Check if autonomous mode is enabled */
    isAutonomousEnabled(): boolean {
        return this.autonomousConfig.enabled;
    }

    /** Get pending escalation tickets */
    getEscalations(status?: EscalationTicket['status']): EscalationTicket[] {
        if (status) return this.escalationQueue.filter(t => t.status === status);
        return [...this.escalationQueue];
    }

    /** Resolve an escalation ticket */
    resolveEscalation(ticketId: string, resolution: string, assignee?: string): boolean {
        const ticket = this.escalationQueue.find(t => t.id === ticketId);
        if (!ticket) return false;
        ticket.status = 'resolved';
        ticket.resolvedAt = new Date();
        ticket.resolution = resolution;
        if (assignee) ticket.assignedTo = assignee;
        return true;
    }

    /** Dismiss an escalation ticket */
    dismissEscalation(ticketId: string): boolean {
        const ticket = this.escalationQueue.find(t => t.id === ticketId);
        if (!ticket) return false;
        ticket.status = 'dismissed';
        ticket.resolvedAt = new Date();
        return true;
    }

    /** Get audit log entries */
    getAuditLog(limit = 100): AutonomousAuditEntry[] {
        return this.auditLog.slice(-limit);
    }

    /**
     * Handle a proactive trigger event. Returns a message to send to the user,
     * or null if the trigger is disabled/on cooldown.
     */
    handleProactiveTrigger(
        event: string,
        sessionId: string,
        context: ChatContext,
    ): { message: string; action?: string } | null {
        if (!this.autonomousConfig.enabled || !this.autonomousConfig.proactiveOutreach) {
            return null;
        }

        const trigger = this.autonomousConfig.proactiveTriggers.find(
            t => t.event === event && t.enabled,
        );
        if (!trigger) return null;

        const message = generateProactiveMessage(trigger, context);
        return { message, action: trigger.action };
    }

    /**
     * Autonomous chat — processes message with auto-approval for safe actions.
     * Returns an AssistantResponse augmented with autonomous metadata.
     */
    async autonomousChat(
        sessionId: string,
        userMessage: string,
        context?: Partial<ChatContext>,
    ): Promise<AssistantResponse & {
        autonomous: boolean;
        autoApproved: boolean;
        escalated: boolean;
        escalationTicket?: EscalationTicket;
        auditEntry?: AutonomousAuditEntry;
        riskLevel?: AutonomousRiskLevel;
    }> {
        // If autonomous mode is disabled, fall back to regular chat
        if (!this.autonomousConfig.enabled) {
            const response = await this.chat(sessionId, userMessage, context);
            return { ...response, autonomous: false, autoApproved: false, escalated: false };
        }

        const session = this.sessions.get(sessionId);
        if (!session) throw new Error(`Session not found: ${sessionId}`);

        const cleanedMessage = sanitizeInput(userMessage);
        const intent = detectIntent(cleanedMessage);
        const sentimentScore = detectSentimentScore(cleanedMessage);

        // ── Sentiment-based escalation ──
        if (sentimentScore <= this.autonomousConfig.sentimentEscalationThreshold) {
            const ticket = createEscalationTicket(
                sessionId, session.context, 'angry_customer',
                `Customer appears frustrated/angry (sentiment: ${sentimentScore.toFixed(2)}). Message: "${cleanedMessage.slice(0, 200)}"`,
                session.messages,
            );
            this.escalationQueue.push(ticket);

            // Still process the message, but flag escalation
            const response = await this.chat(sessionId, userMessage, context);
            const escalationNote = '\n\n📋 _I\'ve flagged this conversation for our team to review. A human agent will follow up shortly to make sure we get this resolved for you._';
            response.message = {
                ...response.message,
                content: response.message.content + escalationNote,
            };
            return { ...response, autonomous: true, autoApproved: false, escalated: true, escalationTicket: ticket };
        }

        // ── Check for legal/compliance keywords ──
        const legalPattern = /\b(?:lawyer|attorney|legal\s+action|subpoena|lawsuit|sue|court|gdpr\s+request|data\s+subject\s+request|right\s+to\s+be\s+forgotten)\b/i;
        if (legalPattern.test(cleanedMessage)) {
            const ticket = createEscalationTicket(
                sessionId, session.context, 'legal_request',
                `Legal/compliance keywords detected: "${cleanedMessage.slice(0, 200)}"`,
                session.messages,
            );
            this.escalationQueue.push(ticket);

            const response = await this.chat(sessionId, userMessage, context);
            response.message = {
                ...response.message,
                content: '⚖️ I understand this involves a legal or compliance matter. I\'ve escalated this to our team for proper handling. A qualified representative will reach out to you shortly.\n\n' + response.message.content,
            };
            return { ...response, autonomous: true, autoApproved: false, escalated: true, escalationTicket: ticket };
        }

        // ── PII detection escalation ──
        const piiPattern = /\b\d{3}-\d{2}-\d{4}\b|\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/;
        if (piiPattern.test(cleanedMessage)) {
            const ticket = createEscalationTicket(
                sessionId, session.context, 'pii_detected',
                `PII detected in customer message (SSN or credit card pattern)`,
                session.messages,
            );
            this.escalationQueue.push(ticket);
        }

        // ── If no action intent, process normally ──
        if (!intent.action) {
            const response = await this.chat(sessionId, userMessage, context);
            return { ...response, autonomous: true, autoApproved: false, escalated: false };
        }

        // ── Autonomous action evaluation ──
        const sessionCount = this.sessionAutoActionCounts.get(sessionId) ?? 0;
        const tenantId = session.context.tenantId ?? 'default';

        const approval = canAutoApprove(
            intent.action, intent, session.context,
            this.autonomousConfig, sessionCount,
        );

        // Hourly rate limit check
        const hourlyCount = this.hourlyAutonomousActions.get(tenantId) ?? 0;
        if (hourlyCount >= this.autonomousConfig.autonomousActionsPerHour) {
            approval.approved = false;
            (approval as { reason: EscalationReason }).reason = 'multi_step_risky';
        }

        const auditEntry = createAuditEntry(
            tenantId, sessionId, session.context.customer?.email ?? 'unknown',
            intent.action, intent.entities, approval.riskLevel,
            approval.approved, !approval.approved, approval.reason,
        );

        if (approval.approved) {
            // ── Auto-approve: execute action without confirmation ──
            this.sessionAutoActionCounts.set(sessionId, sessionCount + 1);
            this.hourlyAutonomousActions.set(tenantId, hourlyCount + 1);

            const response = await this.chat(sessionId, userMessage, context);

            // In dry-run mode, don't actually mark as auto-executed
            if (this.autonomousConfig.dryRun) {
                auditEntry.result = 'pending';
                response.message = {
                    ...response.message,
                    content: '🔄 [DRY RUN] ' + response.message.content,
                };
            } else {
                auditEntry.result = 'success';
                // Remove confirmation requirement for auto-approved actions
                response.requiresConfirmation = false;
                if (response.confirmationId) {
                    this.pendingConfirmations.delete(response.confirmationId);
                    response.confirmationId = undefined;
                }
            }

            if (this.autonomousConfig.auditAllActions) {
                this.auditLog.push(auditEntry);
            }

            return {
                ...response,
                autonomous: true,
                autoApproved: true,
                escalated: false,
                auditEntry,
                riskLevel: approval.riskLevel,
            };
        } else {
            // ── Escalate: create ticket for control-plane owner ──
            const ticket = createEscalationTicket(
                sessionId, session.context,
                approval.reason ?? 'high_risk_action',
                `Autonomous mode cannot auto-approve "${intent.action}" (risk: ${approval.riskLevel}, confidence: ${intent.confidence.toFixed(2)})`,
                session.messages,
            );
            this.escalationQueue.push(ticket);
            auditEntry.escalated = true;

            if (this.autonomousConfig.auditAllActions) {
                this.auditLog.push(auditEntry);
            }

            // Still process the message normally (with confirmation flow)
            const response = await this.chat(sessionId, userMessage, context);
            return {
                ...response,
                autonomous: true,
                autoApproved: false,
                escalated: true,
                escalationTicket: ticket,
                auditEntry,
                riskLevel: approval.riskLevel,
            };
        }
    }

    // ── Cleanup ──

    destroy(): void {
        this.sessions.destroy();
        if (this.sweepInterval) { clearInterval(this.sweepInterval); this.sweepInterval = null; }
    }

    // ════════════════════════════════════════════════════════════
    // PRIVATE
    // ════════════════════════════════════════════════════════════

    private buildPrompt(session: ChatSession, currentMessage: string): { messages: Array<{ role: string; content: string }> } {
        const messages: Array<{ role: string; content: string }> = [];

        // System prompt with context
        const contextStr = this.buildContextString(session.context);
        messages.push({ role: 'system', content: `${SYSTEM_PROMPT}\n\n## CURRENT CONTEXT\n${contextStr}` });

        // History (limited)
        const historyStart = Math.max(0, session.messages.length - this.config.maxHistoryLength);
        for (let i = historyStart; i < session.messages.length; i++) {
            const msg = session.messages[i];
            messages.push({ role: msg.role, content: msg.content });
        }

        // Current message
        messages.push({ role: 'user', content: currentMessage });

        return { messages };
    }

    private buildContextString(context: ChatContext): string {
        const parts: string[] = [];

        // Customer profile context
        const c = context.customer;
        if (c) {
            if (c.name) parts.push(`Customer name: ${c.name}`);
            if (c.organization) parts.push(`Organization: ${c.organization}`);
            if (c.plan) parts.push(`Plan: ${c.plan}`);
            if (c.accountStatus) parts.push(`Account status: ${c.accountStatus}`);
            if (c.role) parts.push(`Role: ${c.role}`);
            if (c.sendQuota != null && c.sendsUsed != null) {
                const pct = ((c.sendsUsed / c.sendQuota) * 100).toFixed(0);
                parts.push(`Send usage: ${c.sendsUsed.toLocaleString()}/${c.sendQuota.toLocaleString()} (${pct}%)`);
            }
            if (c.verifiedDomains?.length) parts.push(`Verified domains: ${c.verifiedDomains.join(', ')}`);
            if (c.memberSince) parts.push(`Member since: ${c.memberSince instanceof Date ? c.memberSince.toLocaleDateString() : c.memberSince}`);
        }

        // Workspace context
        if (context.campaigns?.length) parts.push(`Active campaigns: ${context.campaigns.map(c => c.name).join(', ')}`);
        if (context.contacts) parts.push(`Total contacts: ${context.contacts.toLocaleString()}`);
        if (context.recentActivity?.length) parts.push(`Recent activity: ${context.recentActivity.slice(0, 3).join(', ')}`);
        if (context.currentCampaign) parts.push(`Currently editing: ${context.currentCampaign}`);
        if (context.selectedSegment) parts.push(`Selected segment: ${context.selectedSegment}`);
        return parts.length > 0 ? parts.join('\n') : 'No specific context available.';
    }

    private generateSuggestions(session: ChatSession, intent: DetectedIntent): SuggestedAction[] {
        const suggestions: SuggestedAction[] = [];
        const ctx = session.context;

        if (ctx.campaigns?.length) {
            suggestions.push({ type: 'view', label: `View ${ctx.campaigns[0].name} performance`, action: 'get_campaign_stats', params: { campaignId: ctx.campaigns[0].id } });
        }
        if (ctx.contacts && ctx.contacts > 0) {
            suggestions.push({ type: 'action', label: 'Segment your audience', action: 'create_segment' });
        }

        // Context-sensitive suggestions based on recent intent
        if (intent.category === 'billing') {
            suggestions.push({ type: 'query', label: 'View billing history', action: 'get_billing_history' });
        } else if (intent.category === 'domain') {
            suggestions.push({ type: 'query', label: 'Check sender reputation', action: 'get_sender_reputation' });
        }

        // Generic
        suggestions.push(
            { type: 'action', label: 'Create new campaign', action: 'create_campaign' },
            { type: 'query', label: 'Analyze my metrics', action: 'analyze_campaigns' },
            { type: 'query', label: 'Suggest subject lines', action: 'suggest_subjects' },
        );

        return suggestions.slice(0, 5);
    }

    private pruneHistory(sessionId: string): void {
        const s = this.sessions.get(sessionId);
        if (!s || s.messages.length <= this.config.maxHistoryLength) return;
        s.messages = s.messages.slice(-this.config.maxHistoryLength);
    }

    private checkRateLimit(sessionId: string): { allowed: boolean; reason?: string } {
        const now = Date.now();
        const entry = this.rateLimits.get(sessionId);

        if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
            this.rateLimits.set(sessionId, { count: 1, windowStart: now });
            return { allowed: true };
        }

        entry.count++;
        if (entry.count > RATE_LIMIT_MAX_MESSAGES) {
            return { allowed: false, reason: "You're sending messages too quickly. Please wait a moment before trying again." };
        }
        return { allowed: true };
    }
}

export {
    detectIntent, parseActions, stripActionBlocks, SYSTEM_PROMPT,
    checkActionSecurity, sanitizeInput, redactPII,
    DEFAULT_AUTONOMOUS_CONFIG, ACTION_RISK_LEVELS,
    detectSentimentScore, canAutoApprove,
    createEscalationTicket, createAuditEntry, generateProactiveMessage,
};
