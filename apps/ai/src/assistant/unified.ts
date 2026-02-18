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
    | 'create_ab_test'
    // ── Diagnostics / message tracing ──
    | 'get_message_status'
    | 'get_smtp_transcript'
    | 'get_scheduled_send_status'
    | 'get_message_event_timeline'
    | 'trace_message'
    | 'validate_template'
    | 'get_content_scan_result'
    // ── DNS / authentication diagnostics ──
    | 'force_dns_recheck'
    | 'check_bimi_status'
    | 'check_rdns_ptr'
    // ── Deliverability / reputation ──
    | 'run_deliverability_audit'
    | 'get_geo_sending_report'
    | 'check_blocklist_status'
    // ── Bounces / suppressions ──
    | 'get_complaint_rate'
    | 'remove_from_suppression'
    | 'check_suppression_status'
    | 'get_suppression_scope'
    // ── Webhooks / events ──
    | 'get_webhook_config'
    | 'get_webhook_delivery_log'
    | 'resend_webhook_events'
    | 'enable_webhook_endpoint'
    | 'get_tracking_domain_config'
    | 'rotate_tracking_domain'
    | 'check_cert_provisioning_status'
    // ── API diagnostics ──
    | 'get_rate_limit_status'
    | 'get_api_error_log'
    | 'get_api_health_detailed'
    | 'enable_sdk_debug_mode'
    // ── Account / quota ──
    | 'get_quota_status'
    | 'get_usage_breakdown'
    | 'get_sending_status'
    | 'get_invoice_reconciliation'
    // ── Security ──
    | 'manage_ip_allowlist'
    | 'get_user_permissions'
    | 'resend_team_invite'
    | 'get_audit_log'
    | 'set_emergency_throttle'
    | 'get_api_access_log'
    | 'unlock_account'
    | 'freeze_account'
    | 'export_audit_log'
    // ── Compliance / privacy ──
    | 'execute_gdpr_erasure'
    | 'get_consent_record'
    | 'set_retention_policy'
    | 'request_dpa'
    | 'request_compliance_doc'
    | 'set_legal_hold'
    | 'get_compliance_risk_score'
    // ── Operations / infrastructure ──
    | 'request_dedicated_ip'
    | 'get_warmup_status'
    | 'get_ip_assignment'
    | 'get_throttle_status'
    | 'rollback_deployment'
    | 'get_system_health'
    | 'reconcile_analytics'
    | 'get_worker_status'
    // ── LLM self-diagnostics ──
    | 'get_llm_config'
    | 'get_llm_session_log'
    | 'get_intent_debug'
    | 'get_rag_debug';

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
        // Support diagnostic reads (safe)
        'get_message_status', 'get_smtp_transcript', 'get_scheduled_send_status',
        'get_message_event_timeline', 'check_bimi_status', 'check_rdns_ptr',
        'check_blocklist_status', 'get_complaint_rate', 'check_suppression_status',
        'get_suppression_scope', 'get_webhook_config', 'get_webhook_delivery_log',
        'get_tracking_domain_config', 'check_cert_provisioning_status',
        'get_rate_limit_status', 'get_api_error_log', 'get_api_health_detailed',
        'get_quota_status', 'get_usage_breakdown', 'get_sending_status',
        'get_user_permissions', 'get_consent_record', 'get_compliance_risk_score',
        'get_warmup_status', 'get_ip_assignment', 'get_throttle_status',
        'get_system_health', 'get_worker_status', 'get_geo_sending_report',
        'get_content_scan_result', 'get_invoice_reconciliation',
        'get_llm_config', 'get_llm_session_log', 'get_intent_debug', 'get_rag_debug',
    ],
    alwaysEscalateActions: [
        // NEVER auto-execute these — too risky
        'cancel_subscription', 'process_refund', 'delete_campaign',
        'delete_list', 'revoke_api_key', 'downgrade_plan',
        'send_campaign',           // Sending to real subscribers = irreversible
        'import_contacts',         // Bulk data changes
        'upgrade_plan',            // Financial commitment
        'execute_gdpr_erasure',    // Permanent data deletion
        'freeze_account',          // Account lockout
        'set_legal_hold',          // Compliance obligation
        'set_emergency_throttle',  // Emergency action
        'rollback_deployment',     // Infrastructure change
        'rotate_tracking_domain',  // Domain-level change
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
    // ── Support diagnostics (safe — read-only) ──
    get_message_status: 'safe',
    get_smtp_transcript: 'safe',
    get_scheduled_send_status: 'safe',
    get_message_event_timeline: 'safe',
    check_bimi_status: 'safe',
    check_rdns_ptr: 'safe',
    check_blocklist_status: 'safe',
    get_complaint_rate: 'safe',
    check_suppression_status: 'safe',
    get_suppression_scope: 'safe',
    get_webhook_config: 'safe',
    get_webhook_delivery_log: 'safe',
    get_tracking_domain_config: 'safe',
    check_cert_provisioning_status: 'safe',
    get_rate_limit_status: 'safe',
    get_api_error_log: 'safe',
    get_api_health_detailed: 'safe',
    get_quota_status: 'safe',
    get_usage_breakdown: 'safe',
    get_sending_status: 'safe',
    get_user_permissions: 'safe',
    get_consent_record: 'safe',
    get_compliance_risk_score: 'safe',
    get_warmup_status: 'safe',
    get_ip_assignment: 'safe',
    get_throttle_status: 'safe',
    get_system_health: 'safe',
    get_worker_status: 'safe',
    get_llm_config: 'safe',
    get_llm_session_log: 'safe',
    get_intent_debug: 'safe',
    get_rag_debug: 'safe',
    get_geo_sending_report: 'safe',
    get_content_scan_result: 'safe',
    get_invoice_reconciliation: 'safe',
    // Low — read-only but exposes data
    verify_domain: 'low',
    check_deliverability: 'low',
    export_data: 'low',
    export_report: 'low',
    get_audit_log: 'low',
    get_api_access_log: 'low',
    export_audit_log: 'low',
    trace_message: 'low',
    validate_template: 'low',
    run_deliverability_audit: 'low',
    // Medium — creates/modifies resources
    create_campaign: 'medium',
    create_list: 'medium',
    create_segment: 'medium',
    add_contact: 'medium',
    add_contacts: 'medium',
    tag_contacts: 'medium',
    tag_contact: 'medium',
    resume_campaign: 'medium',
    create_ab_test: 'medium',
    set_automation: 'medium',
    generate_content: 'medium',
    schedule_campaign: 'medium',
    pause_campaign: 'medium',
    create_api_key: 'medium',
    force_dns_recheck: 'medium',
    resend_webhook_events: 'medium',
    enable_webhook_endpoint: 'medium',
    enable_sdk_debug_mode: 'medium',
    resend_team_invite: 'medium',
    remove_from_suppression: 'medium',
    reconcile_analytics: 'medium',
    set_retention_policy: 'medium',
    request_dedicated_ip: 'medium',
    request_dpa: 'medium',
    request_compliance_doc: 'medium',
    manage_ip_allowlist: 'medium',
    // High — destructive or high-impact
    send_campaign: 'high',
    import_contacts: 'high',
    remove_contact: 'high',
    remove_contacts: 'high',
    upgrade_plan: 'high',
    rotate_tracking_domain: 'high',
    set_emergency_throttle: 'high',
    unlock_account: 'high',
    rollback_deployment: 'high',
    // Critical — irreversible or financial
    delete_campaign: 'critical',
    delete_list: 'critical',
    cancel_subscription: 'critical',
    process_refund: 'critical',
    downgrade_plan: 'critical',
    revoke_api_key: 'critical',
    execute_gdpr_erasure: 'critical',
    freeze_account: 'critical',
    set_legal_hold: 'critical',
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
        // ── New support/security/compliance/ops triggers ──
        complaint_rate_spike: `${name}, 🚨 your spam complaint rate has spiked above the 0.1% threshold. I've pulled your complaint report — this is urgent as it affects your sender reputation. Want me to investigate?`,
        blocklist_detected: `${name}, ⚠️ one of your sending IPs or domains has been detected on a blocklist. I can check the details and help you resolve it.`,
        suppression_anomaly: `${name}, 📋 I've detected an unusual pattern in your suppression list. Some addresses may be incorrectly suppressed. Want me to check?`,
        webhook_failures_spike: `${name}, 🔧 your webhook endpoint is seeing a high failure rate. I can check the delivery log and help troubleshoot.`,
        warmup_stalled: `${name}, 📈 your IP warmup appears to have stalled — volume hasn't increased for the expected period. Want me to check the status?`,
        security_alert: `${name}, 🔒 I detected unusual activity on your account (new IP/geo accessing the API). I can pull the access log for your review.`,
        certificate_expiring: `${name}, 🔐 the SSL certificate for your custom tracking domain is approaching expiration. I can check the provisioning status.`,
        worker_queue_backup: `${name}, ⏳ the email processing queue is backing up — scheduled sends may be delayed. I'm checking the worker status now.`,
        gdpr_retention_deadline: `${name}, ⚖️ a data retention deadline is approaching for some subscriber records. Want me to review your retention policy?`,
        ip_reputation_decline: `${name}, 📉 your dedicated IP's reputation score has been declining. I can run a full deliverability audit to identify the cause.`,
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
    // Support operations (editor+)
    'remove_from_suppression', 'resend_webhook_events', 'enable_webhook_endpoint',
    'validate_template', 'force_dns_recheck', 'enable_sdk_debug_mode',
    'resend_team_invite', 'trace_message', 'reconcile_analytics',
    'get_audit_log', 'get_api_access_log', 'export_audit_log',
    'run_deliverability_audit',
]);

/** Actions that require 'admin' or 'owner' role */
const ADMIN_ACTIONS: Set<AssistantActionType> = new Set([
    'create_api_key', 'revoke_api_key', 'upgrade_plan', 'downgrade_plan',
    'cancel_subscription', 'process_refund', 'verify_domain',
    // Security & compliance (admin+)
    'manage_ip_allowlist', 'set_emergency_throttle', 'unlock_account',
    'freeze_account', 'execute_gdpr_erasure', 'set_legal_hold',
    'set_retention_policy', 'request_dedicated_ip', 'rotate_tracking_domain',
    'rollback_deployment', 'request_dpa', 'request_compliance_doc',
]);

/** Actions that require elevated authentication (re-verification) */
const ELEVATED_AUTH_ACTIONS: Set<AssistantActionType> = new Set([
    'cancel_subscription', 'process_refund', 'revoke_api_key',
    'delete_campaign', 'delete_list',
    'execute_gdpr_erasure', 'freeze_account', 'set_legal_hold',
    'set_emergency_throttle', 'rollback_deployment',
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
5. **Support Diagnostics**: Trace messages, pull SMTP transcripts, check blocklists, investigate bounces, debug webhooks, validate templates, and diagnose delivery issues.
6. **Security Operations**: Manage IP allowlists, check audit logs, investigate suspicious activity, freeze compromised accounts, handle API key rotation, and unlock locked accounts.
7. **Compliance & Privacy**: Process GDPR erasure requests, retrieve consent records, manage data retention policies, request DPAs, set legal holds, and provide compliance documentation.
8. **Infrastructure & Ops**: Monitor system health, check IP warmup status, investigate throttling, check worker queues, and manage dedicated IPs.

## ACTION FORMAT
When executing an action, respond with a JSON action block:
\`\`\`action
{"action": "ACTION_TYPE", "params": {...}, "confirm": true/false, "reason": "explanation"}
\`\`\`
Set \`confirm: true\` for destructive or high-impact actions (sends, deletes, billing changes, GDPR erasure, account freeze, legal holds).

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

## SUPPORT DIAGNOSTIC GUIDELINES
- For delivery issues: check message status → SMTP transcript → blocklists → sender reputation
- For bounce spikes: get bounce report → check complaint rate → review suppression scope
- For webhook failures: check webhook config → get delivery log → resend failed events
- For DNS/auth issues: verify domain → force DNS recheck → check BIMI/rDNS
- For quota concerns: get quota status → get usage breakdown → check sending status
- For security incidents: freeze account immediately → get audit log → get API access log
- For compliance requests: always verify identity → process request → audit trail

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
- Respect send quota limits and warn customers approaching their limits
- For compliance actions (GDPR erasure, legal holds), always require elevated authentication
- For security incidents, prioritize account safety over conversation flow`;

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

type IntentCategory = 'command' | 'billing' | 'domain' | 'support' | 'compliance' | 'security' | 'ops' | 'knowledge' | 'greeting' | 'unclear';

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

    // ═══════════════════════════════════════════════════════════════
    // SUPPORT — diagnostics, message tracing, bounces, webhooks, suppressions
    // ═══════════════════════════════════════════════════════════════
    // Message diagnostics
    { category: 'support', action: 'get_message_status', patterns: [/(?:where|what\s+happened\s+to|status\s+of|track|find)\s+(?:my\s+)?(?:the\s+)?(?:message|email)\b/i, /message\s+(?:stuck|queued|pending|lost|missing|not\s+(?:sent|delivered))/i, /email\s+(?:stuck|queued|pending|lost|missing|not\s+(?:sent|delivered))/i, /(?:message|email)\s+(?:status|tracking)/i] },
    { category: 'support', action: 'get_smtp_transcript', patterns: [/smtp\s+(?:transcript|log|session|trace)/i, /(?:show|get)\s+(?:me\s+)?(?:the\s+)?smtp\s+(?:log|session|transcript)/i, /smtp\s+(?:session|conversation)\s+(?:for|of)/i] },
    { category: 'support', action: 'get_scheduled_send_status', patterns: [/scheduled\s+(?:email|send|campaign)\s+(?:never|not)\s+(?:sent|fired|triggered|delivered)/i, /scheduled\s+(?:email|send|campaign)\s+(?:sent\s+)?(?:early|late|wrong\s+time)/i, /(?:why\s+)?(?:was|did)\s+(?:my\s+)?scheduled\s+(?:email|send|campaign)/i] },
    { category: 'support', action: 'get_message_event_timeline', patterns: [/(?:event|activity)\s+(?:timeline|history|log)\s+(?:for|of)\s+(?:a\s+)?(?:message|email)/i, /(?:full|complete|all)\s+events?\s+(?:for|of)\s+(?:a\s+)?(?:message|email)/i, /(?:show|get)\s+(?:me\s+)?(?:the\s+)?(?:event|delivery)\s+timeline/i] },
    { category: 'support', action: 'trace_message', patterns: [/trace\s+(?:a\s+)?(?:message|email)\s+(?:through|across|in)/i, /(?:message|email)\s+trace\b/i, /(?:end[\s-]to[\s-]end|full)\s+(?:message|email)\s+trac/i] },
    { category: 'support', action: 'validate_template', patterns: [/(?:template|handlebars?)\s+(?:rendering|render)\s+(?:fail|error|broken|issue|problem|debug)/i, /(?:debug|fix|check|validate)\s+(?:my\s+)?template/i, /(?:variable|merge\s+tag)\s+(?:not\s+)?render/i, /\{\{.*\}\}\s+(?:not\s+)?(?:show|render|replac)/i] },
    { category: 'support', action: 'get_content_scan_result', patterns: [/content\s+scan\s+(?:block|reject|flag|result)/i, /(?:message|email)\s+(?:block|reject)(?:ed)?\s+(?:by\s+)?content\s+(?:scan|filter)/i, /(?:false\s+positive|incorrectly)\s+(?:block|flag|reject)/i] },
    // DNS / authentication diagnostics
    { category: 'support', action: 'force_dns_recheck', patterns: [/(?:force|trigger|refresh)\s+(?:a\s+)?dns\s+(?:recheck|refresh|re[\s-]?verif)/i, /domain\s+(?:says?\s+)?(?:not\s+verified|pending)\s+(?:but|still)/i, /dns\s+(?:cache|propagat)\s+(?:issue|problem|delay)/i] },
    { category: 'support', action: 'check_bimi_status', patterns: [/bimi\s+(?:logo|status|setup|not\s+showing|missing)/i, /(?:check|verify|debug)\s+(?:my\s+)?bimi/i] },
    { category: 'support', action: 'check_rdns_ptr', patterns: [/(?:rdns|ptr|reverse\s+dns)\s+(?:record|setup|mismatch|missing|check|status)/i, /(?:check|verify)\s+(?:my\s+)?(?:rdns|ptr|reverse\s+dns)/i] },
    // Deliverability
    { category: 'support', action: 'run_deliverability_audit', patterns: [/(?:run|do|start|perform)\s+(?:a\s+)?(?:full\s+)?deliverability\s+audit/i, /deliverability\s+audit/i, /(?:comprehensive|complete|full)\s+deliverability\s+(?:check|review|analysis)/i] },
    { category: 'support', action: 'get_geo_sending_report', patterns: [/(?:geo|geographic|region|country)\s+(?:sending|delivery)\s+(?:report|data|pattern|breakdown)/i, /(?:sudden|unexpected)\s+(?:geo|geographic)\s+(?:shift|change|pattern)/i] },
    { category: 'support', action: 'check_blocklist_status', patterns: [/(?:check|am\s+I\s+on|listed\s+on|remove\s+from)\s+(?:a\s+)?(?:block|black)list/i, /(?:spamhaus|barracuda|spamcop|sorbs|cloudmark|cisco\s+talos|senderbase)\b/i, /(?:block|black)list\s+(?:check|status|investigation|removal)/i] },
    // Bounces / suppressions
    { category: 'support', action: 'get_complaint_rate', patterns: [/complaint\s+rate\s+(?:spik|high|increas|above)/i, /(?:show|get|check)\s+(?:me\s+)?(?:my\s+)?complaint\s+(?:rate|report|data)/i, /(?:spam|abuse)\s+complaint\s+(?:rate|report|spik)/i] },
    { category: 'support', action: 'remove_from_suppression', patterns: [/(?:remove|delete|clear|unsuppress)\s+(?:\S+@\S+\s+)?(?:from\s+)?(?:the\s+)?suppress(?:ion)?(?:\s+list)?/i, /(?:unsuppress|un[\s-]?suppress)\s+(\S+@\S+)/i] },
    { category: 'support', action: 'check_suppression_status', patterns: [/(?:is|check\s+if)\s+(\S+@\S+)\s+(?:suppressed|on\s+(?:the\s+)?suppress)/i, /(?:suppression|suppress(?:ed)?)\s+(?:status|check)\s+(?:for\s+)?/i, /(?:unsubscribe|complaint)\s+(?:suppress(?:ion)?|not\s+applied)/i] },
    { category: 'support', action: 'get_suppression_scope', patterns: [/suppress(?:ion)?\s+scope\s+(?:per|by|confusion)/i, /(?:per[\s-]?campaign|global|tenant|domain)\s+suppress(?:ion)?\s+(?:scope|difference)/i, /suppress(?:ion)?\s+(?:applied\s+)?too\s+(?:broadly|narrowly)/i] },
    // Webhooks / events
    { category: 'support', action: 'get_webhook_config', patterns: [/(?:show|get|check|view)\s+(?:me\s+)?(?:my\s+)?webhook\s+(?:config|configuration|settings|setup|filters?)/i, /webhook\s+(?:event\s+)?(?:types?|filters?)\s+(?:not\s+)?(?:enabled|configured|selected)/i] },
    { category: 'support', action: 'get_webhook_delivery_log', patterns: [/webhook\s+(?:delivery|event)\s+(?:log|history|failures?)/i, /(?:show|get|check)\s+(?:me\s+)?(?:my\s+)?webhook\s+(?:delivery|event)\s+(?:log|history)/i, /(?:missed|failed|missing)\s+webhook\s+(?:event|deliver)/i] },
    { category: 'support', action: 'resend_webhook_events', patterns: [/(?:resend|replay|retry|re[\s-]?deliver)\s+(?:a\s+)?(?:failed\s+)?webhook\s+(?:event|deliver|payload)/i, /webhook\s+(?:event\s+)?(?:resend|replay|retry)/i] },
    { category: 'support', action: 'enable_webhook_endpoint', patterns: [/(?:re[\s-]?enable|reactivate|turn\s+(?:back\s+)?on)\s+(?:my\s+)?(?:disabled\s+)?webhook\s+(?:endpoint|url)/i, /webhook\s+endpoint\s+(?:disabled|deactivated|off)/i] },
    { category: 'support', action: 'get_tracking_domain_config', patterns: [/(?:show|get|check)\s+(?:my\s+)?(?:link\s+)?(?:branding|tracking)\s+(?:domain\s+)?(?:config|configuration|settings|status)/i, /(?:link\s+)?branding\s+(?:not\s+)?(?:working|applied|used)/i] },
    { category: 'support', action: 'rotate_tracking_domain', patterns: [/(?:rotate|change|switch)\s+(?:my\s+)?tracking\s+domain/i, /tracking\s+domain\s+(?:flagged|blocked|compromised)/i] },
    { category: 'support', action: 'check_cert_provisioning_status', patterns: [/(?:ssl|tls|cert(?:ificate)?)\s+(?:provisioning|issuanc)\s+(?:status|stuck|pending|failed)/i, /(?:custom|tracking)\s+domain\s+(?:ssl|cert)\s+(?:stuck|pending|not\s+ready)/i] },
    // API diagnostics
    { category: 'support', action: 'get_rate_limit_status', patterns: [/(?:rate\s+limit|429)\s+(?:status|details?|info|why|hit|exceeded)/i, /(?:show|get|check)\s+(?:me\s+)?(?:my\s+)?rate\s+limit\s+(?:status|usage|remaining)/i, /(?:how\s+many|when\s+do)\s+(?:my\s+)?rate\s+limits?\s+(?:remain|reset)/i] },
    { category: 'support', action: 'get_api_error_log', patterns: [/(?:api|server)\s+(?:error|500)\s+(?:log|history|details?)/i, /(?:show|get|check)\s+(?:me\s+)?(?:my\s+)?(?:api\s+)?error\s+(?:log|history)/i, /(?:internal\s+server\s+error|500\s+error)\s+(?:log|detail|diagnos)/i] },
    { category: 'support', action: 'get_api_health_detailed', patterns: [/(?:api|gateway)\s+(?:502|503|504|timeout|unhealthy|degraded)/i, /(?:detailed|comprehensive)\s+api\s+(?:health|status|diagnostic)/i] },
    { category: 'support', action: 'enable_sdk_debug_mode', patterns: [/(?:enable|turn\s+on|activate)\s+(?:sdk\s+)?debug\s+(?:mode|logging|verbose)/i, /sdk\s+(?:debug|verbose)\s+(?:mode|logging)/i] },
    // Quota / account
    { category: 'support', action: 'get_quota_status', patterns: [/(?:daily|monthly)\s+quota\s+(?:exceeded|status|usage|left|remaining|reset)/i, /(?:show|get|check)\s+(?:me\s+)?(?:my\s+)?(?:send(?:ing)?\s+)?quota\s+(?:status|usage|details?)/i, /(?:when\s+does?\s+)?(?:my\s+)?quota\s+reset/i, /quota\s+(?:exceeded|used\s+up|maxed\s+out|ran\s+out|running\s+low)/i] },
    { category: 'support', action: 'get_usage_breakdown', patterns: [/(?:usage|send(?:ing)?)\s+(?:breakdown|details?|itemized|counters?)\s+(?:don'?t|do\s+not)\s+match/i, /(?:show|get)\s+(?:me\s+)?(?:my\s+)?(?:detailed\s+)?usage\s+breakdown/i, /(?:what\s+counts?\s+as|how\s+(?:are|is)\s+(?:send|usage))\s+/i] },
    { category: 'support', action: 'get_sending_status', patterns: [/(?:sending|send)\s+(?:paused|stopped|suspended|blocked)\s+(?:unexpect|automat|sudden)/i, /(?:why\s+(?:is|was|did)\s+)?(?:my\s+)?sending\s+(?:paused|stopped|suspended)/i, /(?:automatic|auto)\s+(?:protection|throttle|pause)\s+(?:trigger|kick)/i] },
    { category: 'support', action: 'get_invoice_reconciliation', patterns: [/invoice\s+(?:mismatch|reconcil|doesn'?t\s+match)/i, /(?:invoice|bill)\s+(?:vs|versus|compared\s+to)\s+(?:usage|sending)/i, /reconcil(?:e|iation)\s+(?:my\s+)?(?:invoice|billing|usage)/i] },

    // ═══════════════════════════════════════════════════════════════
    // SECURITY — access control, incidents, audit
    // ═══════════════════════════════════════════════════════════════
    { category: 'security', action: 'manage_ip_allowlist', patterns: [/(?:ip\s+)?(?:allowlist|whitelist)\s+(?:add|remove|manage|update|configure|recovery|locked\s+out)/i, /(?:add|remove)\s+(?:an?\s+)?ip\s+(?:to|from)\s+(?:the\s+)?(?:allow|white)list/i, /(?:locked\s+out|blocked)\s+(?:by|after)\s+(?:ip\s+)?allowlist/i] },
    { category: 'security', action: 'get_user_permissions', patterns: [/(?:show|get|check|view)\s+(?:me\s+)?(?:my\s+)?(?:user\s+)?(?:permission|access|role)/i, /(?:can'?t|cannot|unable\s+to)\s+(?:see|view|access)\s+(?:logs?|analytics|dashboard)/i, /(?:what\s+)?(?:permissions?|access)\s+(?:do\s+I\s+have|am\s+I\s+missing)/i] },
    { category: 'security', action: 'resend_team_invite', patterns: [/(?:resend|re[\s-]?send)\s+(?:the\s+)?(?:team\s+)?invit(?:e|ation)/i, /(?:invit(?:e|ation))\s+(?:email\s+)?(?:never|not)\s+(?:received|arrived|came)/i] },
    { category: 'security', action: 'get_audit_log', patterns: [/(?:show|get|view|check)\s+(?:me\s+)?(?:my\s+)?(?:the\s+)?audit\s+log/i, /(?:who|what)\s+(?:changed|modified|deleted|updated)\s+(?:my\s+)?(?:settings?|config|domain|api)/i, /audit\s+(?:log|trail|history)\s+(?:for|of)/i] },
    { category: 'security', action: 'set_emergency_throttle', patterns: [/(?:emergency|immediate)\s+(?:throttle|rate[\s-]?limit|stop|pause\s+all)/i, /(?:sudden|suspicious)\s+(?:spike|surge|increase)\s+(?:in\s+)?(?:sending|api\s+call)/i, /(?:possible|suspected|potential)\s+(?:compromise|breach|hack|attack)/i] },
    { category: 'security', action: 'get_api_access_log', patterns: [/(?:api\s+)?access\s+log\s+(?:from|show|suspicious)/i, /(?:suspicious|unknown|unexpected)\s+(?:api\s+)?(?:usage|access|request)\s+(?:from|by)/i, /(?:who|what\s+ip)\s+(?:is|has\s+been)\s+(?:using|accessing)\s+(?:my\s+)?api/i] },
    { category: 'security', action: 'unlock_account', patterns: [/(?:unlock|unblock|unfreeze)\s+(?:my\s+)?account/i, /account\s+(?:locked|blocked)\s+(?:after|too\s+many)\s+(?:failed\s+)?(?:login|attempt)/i, /(?:too\s+many)\s+(?:failed\s+)?(?:login|password)\s+attempts?/i] },
    { category: 'security', action: 'freeze_account', patterns: [/(?:freeze|lock|disable)\s+(?:my\s+)?account\s+(?:immediately|now|emergency)/i, /(?:account\s+)?(?:takeover|compromised|hacked|stolen)/i, /(?:someone\s+(?:else|unauthorized)\s+(?:is\s+)?(?:using|accessing|in))\s+(?:my\s+)?account/i] },
    { category: 'security', action: 'export_audit_log', patterns: [/(?:export|download)\s+(?:my\s+)?(?:the\s+)?audit\s+log/i, /audit\s+log\s+(?:export|download)\s+(?:for\s+)?(?:soc|compliance|evidence)/i] },

    // ═══════════════════════════════════════════════════════════════
    // COMPLIANCE — GDPR, DPA, retention, legal holds
    // ═══════════════════════════════════════════════════════════════
    { category: 'compliance', action: 'execute_gdpr_erasure', patterns: [/(?:gdpr|data)\s+(?:erasure|deletion|right\s+to\s+(?:be\s+)?forgot)/i, /(?:delete|erase|remove)\s+(?:all\s+)?(?:my|their|subscriber'?s?)\s+(?:personal\s+)?data/i, /(?:right\s+to\s+(?:be\s+)?forgotten|data\s+subject\s+(?:erasure|deletion))/i] },
    { category: 'compliance', action: 'get_consent_record', patterns: [/(?:show|get|prove|find)\s+(?:the\s+)?consent\s+(?:record|proof|evidence)/i, /(?:when|how)\s+did\s+(?:\S+@\S+|this\s+(?:person|subscriber|contact))\s+(?:consent|opt[\s-]?in)/i, /consent\s+(?:proof|record|evidence|documentation)\s+(?:for|of)/i] },
    { category: 'compliance', action: 'set_retention_policy', patterns: [/(?:set|change|update|configure)\s+(?:my\s+)?(?:data\s+)?retention\s+(?:policy|period|setting)/i, /(?:zero[\s-]?retention|no\s+data\s+stor)/i, /(?:data\s+)?retention\s+(?:policy|period)\s+(?:change|update|configure)/i] },
    { category: 'compliance', action: 'request_dpa', patterns: [/(?:need|request|send|sign|get)\s+(?:a\s+)?(?:data\s+processing\s+agreement|dpa)/i, /dpa\s+(?:request|signature|needed|required)/i] },
    { category: 'compliance', action: 'request_compliance_doc', patterns: [/(?:need|request|get|send)\s+(?:a\s+)?(?:soc[\s-]?2|hipaa|baa|compliance)\s+(?:report|evidence|certificate|doc)/i, /soc[\s-]?2\s+(?:type\s+(?:i{1,2}|1|2)\s+)?(?:report|evidence|audit)/i, /(?:hipaa|baa)\s+(?:compliance|agreement|request)/i] },
    { category: 'compliance', action: 'set_legal_hold', patterns: [/(?:set|place|enable|initiate)\s+(?:a\s+)?(?:legal|litigation)\s+(?:hold|preservation)/i, /(?:legal|litigation)\s+hold\s+(?:on|for)/i, /(?:preserve|retain)\s+(?:all\s+)?data\s+(?:for\s+)?(?:legal|litigation|lawsuit)/i] },
    { category: 'compliance', action: 'get_compliance_risk_score', patterns: [/(?:compliance\s+)?risk\s+score\s+(?:too\s+high|flagged|elevated)/i, /(?:show|get|check)\s+(?:me\s+)?(?:my\s+)?compliance\s+(?:risk\s+)?(?:score|status|rating)/i, /(?:account|sending)\s+(?:flagged|flagging)\s+(?:for\s+)?compliance/i] },

    // ═══════════════════════════════════════════════════════════════
    // OPS — infrastructure, IP warmup, workers, system health
    // ═══════════════════════════════════════════════════════════════
    { category: 'ops', action: 'request_dedicated_ip', patterns: [/(?:request|get|add|need)\s+(?:a\s+)?dedicated\s+(?:sending\s+)?ip/i, /dedicated\s+ip\s+(?:request|setup|add)/i] },
    { category: 'ops', action: 'get_warmup_status', patterns: [/(?:ip\s+)?warmup\s+(?:status|progress|stalled|stuck|schedule)/i, /(?:show|get|check)\s+(?:me\s+)?(?:my\s+)?(?:ip\s+)?warmup\s+(?:status|progress)/i, /warmup\s+(?:not\s+)?(?:increasing|progressing|advancing)/i] },
    { category: 'ops', action: 'get_ip_assignment', patterns: [/(?:my\s+)?(?:sending\s+)?ip\s+(?:changed|assignment|switched|different)/i, /(?:what|which)\s+ip\s+(?:am\s+I\s+|are\s+we\s+)?(?:sending|using)\s+(?:from|on)/i] },
    { category: 'ops', action: 'get_throttle_status', patterns: [/(?:throttle|throttling)\s+(?:status|triggered|active|why)/i, /(?:volume|sending)\s+(?:spike|spike)\s+(?:trigger|caused)\s+(?:throttl|auto)/i, /(?:why\s+(?:am\s+I|are\s+we)\s+(?:being\s+)?)?throttled/i] },
    { category: 'ops', action: 'rollback_deployment', patterns: [/(?:rollback|roll\s+back|revert)\s+(?:a\s+)?(?:bad\s+)?(?:deploy|release|update)/i, /(?:last|recent)\s+deploy(?:ment)?\s+(?:broke|broken|bad|cause)/i] },
    { category: 'ops', action: 'get_system_health', patterns: [/(?:system|platform|service)\s+(?:health|status|degraded|down|outage|incident)/i, /(?:is\s+)?(?:the\s+)?(?:system|platform|api|service)\s+(?:down|degraded|experiencing)/i, /(?:performance|latency)\s+(?:degrad|issue|problem|slow)/i, /(?:check|show)\s+(?:me\s+)?(?:the\s+)?(?:system|infrastructure|platform)\s+(?:health|status)/i] },
    { category: 'ops', action: 'reconcile_analytics', patterns: [/analytics?\s+(?:numbers?|counts?|data)\s+(?:don'?t|do\s+not)\s+match/i, /(?:reconcile|fix|investigate)\s+(?:my\s+)?analytics\s+(?:discrepanc|mismatch)/i, /(?:event\s+counts?\s+(?:vs|versus|don'?t\s+match)\s+analytics)/i] },
    { category: 'ops', action: 'get_worker_status', patterns: [/(?:worker|job\s+queue|background\s+(?:job|process))\s+(?:status|health|disabled|down|stuck)/i, /(?:scheduled\s+)?(?:sends?|emails?)\s+(?:not\s+)?(?:process|stuck)\s+(?:in\s+)?(?:queue|worker)/i, /(?:show|get|check)\s+(?:me\s+)?(?:the\s+)?worker\s+(?:status|health|queue)/i] },

    // ═══════════════════════════════════════════════════════════════
    // LLM — self-diagnostics for AI/chatbot runtime
    // ═══════════════════════════════════════════════════════════════
    { category: 'support', action: 'get_llm_config', patterns: [/(?:llm|model|ai|chatbot)\s+(?:config|configuration|settings|context\s+(?:window|length|limit))/i, /(?:response|output)\s+(?:cut\s+off|truncated|incomplete|too\s+short)/i, /(?:context|input)\s+(?:too\s+long|exceeds?|overflow)/i, /(?:max|maximum)\s+(?:token|output|context)\s+(?:limit|length|size)/i] },
    { category: 'support', action: 'get_llm_session_log', patterns: [/(?:llm|ai|chatbot)\s+(?:session|conversation)\s+(?:log|history|debug)/i, /(?:streaming|stream)\s+(?:response|output)\s+(?:stopped|interrupted|cut\s+off|dropped)/i, /(?:verifier|validator)\s+(?:rejected|failed|regenerat)/i] },
    { category: 'support', action: 'get_intent_debug', patterns: [/(?:intent|classification)\s+(?:confidence|wrong|incorrect|misclassif|debug)/i, /(?:wrong|incorrect|bad)\s+(?:intent|action|classification)/i, /(?:ai|bot|chatbot)\s+(?:tried|called|invoked)\s+(?:wrong|invalid)\s+(?:tool|action|function)/i, /(?:tool\s+call|function\s+call)\s+(?:failed|invalid|wrong)\s+(?:arg|param)/i] },
    { category: 'support', action: 'get_rag_debug', patterns: [/(?:rag|retrieval|retrieved)\s+(?:context|chunks?)\s+(?:irrelevant|wrong|bad|not\s+relevant)/i, /(?:ai|bot|chatbot)\s+(?:gave|returned|answered)\s+(?:wrong|incorrect|irrelevant|unrelated)/i, /(?:knowledge|context)\s+(?:retrieval|chunks?)\s+(?:debug|quality|issue)/i] },
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

    // ── SMTP / delivery failure detection ──
    const smtpIssuePattern = /\bsmtp\s+(?:timeout|connection\s+reset|greeting|etimedout|data\s+timeout|pipelining|error|issue|problem|fail)\b/i;
    if (smtpIssuePattern.test(cleaned)) {
        return { category: 'support', action: 'get_smtp_transcript', confidence: 0.8, entities: {} };
    }

    // ── Bounce code / classification detection ──
    const bounceCodePattern = /\b(?:550|551|552|553|554|421|450|451|452)\s+(?:\d\.\d\.\d)?\b|\bbounce\s+code\b|\bwhat\s+does\s+(?:this\s+)?bounce\s+(?:code|mean)/i;
    if (bounceCodePattern.test(cleaned)) {
        return { category: 'knowledge', confidence: 0.85, entities: { topic: 'bounce_codes' } };
    }

    // ── Security incident detection ──
    const securityIncidentPattern = /\b(?:account\s+(?:compromised|hacked|takeover|stolen)|unauthorized\s+(?:access|sending|login)|suspicious\s+(?:activity|login|api\s+usage))\b/i;
    if (securityIncidentPattern.test(cleaned)) {
        return { category: 'security', action: 'freeze_account', confidence: 0.9, entities: { escalation: 'security_incident' } };
    }

    // ── GDPR / compliance request detection ──
    const complianceRequestPattern = /\b(?:gdpr\s+(?:erasure|deletion|export|request)|data\s+subject\s+(?:request|access)|right\s+to\s+(?:be\s+)?forgotten|dpa\s+(?:request|needed|required)|soc[\s-]?2\s+(?:report|evidence)|hipaa\s+(?:baa|compliance)|legal\s+hold)\b/i;
    if (complianceRequestPattern.test(cleaned)) {
        return { category: 'compliance', confidence: 0.85, entities: {} };
    }

    // ── Webhook troubleshooting detection ──
    const webhookIssuePattern = /\bwebhook\s+(?:not\s+(?:working|receiving|firing|delivering)|fail(?:ing|ed|ure)?|broken|issue|problem|error|miss(?:ing|ed)|timeout|signature\s+(?:fail|invalid|wrong))\b/i;
    if (webhookIssuePattern.test(cleaned)) {
        return { category: 'support', action: 'get_webhook_delivery_log', confidence: 0.8, entities: {} };
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
    if (intent.category === 'command' || intent.category === 'billing' || intent.category === 'domain'
        || intent.category === 'support' || intent.category === 'compliance'
        || intent.category === 'security' || intent.category === 'ops') {
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
    if (intent.category === 'support' && intent.action) {
        return generateSupportFallback(intent, customer);
    }
    if (intent.category === 'security' && intent.action) {
        return generateSecurityFallback(intent);
    }
    if (intent.category === 'compliance' && intent.action) {
        return generateComplianceFallback(intent);
    }
    if (intent.category === 'ops' && intent.action) {
        return generateOpsFallback(intent);
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
    const descriptions: Record<string, string> = {
        check_deliverability: 'I understand this is urgent. Let me run a deliverability diagnostic on your sending setup right away.',
        get_sender_reputation: 'Let me check your sender reputation score. This will analyze your recent sending patterns.',
        verify_domain: 'I\'ll verify your domain configuration including SPF, DKIM, and DMARC records.',
        account_health_check: 'Let me run a comprehensive health check on your account to make sure everything is in order.',
        revoke_api_key: '⚠️ This will permanently invalidate the API key. I\'ll proceed with confirmation.',
        create_api_key: 'I\'ll create a new API key for you. You\'ll need to store the key securely — it won\'t be shown again.',
        check_api_status: 'Let me check the current API status and health across all endpoints.',
        get_bounce_report: 'I\'ll pull your bounce report with a breakdown by type, reason, and recipient domain.',
    };
    const prefix = descriptions[action!] ?? 'I\'ll look into that for you right away.';
    return `${prefix}\n\n\`\`\`action\n${actionBlock}\n\`\`\``;
}

function generateSupportFallback(intent: DetectedIntent, customer?: CustomerProfile): string {
    const { action } = intent;
    const riskLevel = ACTION_RISK_LEVELS[action!] ?? 'medium';
    const confirm = riskLevel === 'high' || riskLevel === 'critical';
    const actionBlock = JSON.stringify({ action, params: {}, confirm, reason: `Support diagnostic: ${action}` });

    const descriptions: Record<string, string> = {
        get_message_status: 'Let me check the delivery status of that message right away.',
        get_smtp_transcript: 'I\'ll pull the SMTP session transcript so we can see exactly what happened during delivery.',
        get_scheduled_send_status: 'Let me check the status of your scheduled send to see what happened.',
        get_message_event_timeline: 'I\'ll get the full event timeline for that message — from acceptance through delivery.',
        trace_message: 'Let me trace that message through our entire pipeline to find where it is.',
        validate_template: 'I\'ll validate your template and check for rendering issues with your variables.',
        get_content_scan_result: 'Let me check the content scan results to see if there was a false positive block.',
        force_dns_recheck: 'I\'ll force a fresh DNS check to clear any cached verification state.',
        check_bimi_status: 'Let me check your BIMI configuration — logo, VMC certificate, and DMARC alignment.',
        check_rdns_ptr: 'I\'ll check your reverse DNS (PTR) record to make sure it matches your sending IP.',
        run_deliverability_audit: 'I\'ll run a comprehensive deliverability audit covering authentication, reputation, content, and list health.',
        get_geo_sending_report: 'Let me pull your geographic sending report to check for unusual pattern shifts.',
        check_blocklist_status: 'I\'ll check major blocklists (Spamhaus, Barracuda, SpamCop, Cloudmark, Cisco Talos) for your IPs and domains.',
        get_complaint_rate: 'Let me check your complaint rate and identify the source of any spikes.',
        remove_from_suppression: '⚠️ I\'ll remove the address from the suppression list. Please ensure you have valid re-consent before re-sending.',
        check_suppression_status: 'Let me check the suppression status for that address.',
        get_suppression_scope: 'I\'ll show you the suppression scope — whether it\'s per-campaign, per-domain, or tenant-wide.',
        get_webhook_config: 'Let me check your webhook configuration including endpoints, event types, and filters.',
        get_webhook_delivery_log: 'I\'ll pull the webhook delivery logs so we can see any failures or missed events.',
        resend_webhook_events: '⚠️ I\'ll replay the missed webhook events. Make sure your endpoint handles idempotency.',
        enable_webhook_endpoint: 'I\'ll re-enable your disabled webhook endpoint.',
        get_tracking_domain_config: 'Let me check your link branding / tracking domain configuration.',
        rotate_tracking_domain: '⚠️ This will rotate your tracking domain. Any links in previously sent emails will need the old domain to remain active.',
        check_cert_provisioning_status: 'Let me check the SSL certificate provisioning status for your custom tracking domain.',
        get_rate_limit_status: 'I\'ll check your current rate limit status including remaining quota and reset time.',
        get_api_error_log: 'Let me pull your recent API error log to diagnose the issue.',
        get_api_health_detailed: 'I\'ll run a detailed API health check across all endpoints.',
        enable_sdk_debug_mode: 'I\'ll enable debug/verbose logging for your SDK to help diagnose the issue.',
        get_quota_status: `Let me check your quota status.${customer?.plan ? ` You're on the **${customer.plan}** plan.` : ''}`,
        get_usage_breakdown: 'I\'ll pull a detailed usage breakdown showing what counts toward your quota.',
        get_sending_status: 'Let me check why your sending was paused and what triggered the automatic protection.',
        get_invoice_reconciliation: 'I\'ll run a reconciliation between your invoice and actual usage data.',
        // LLM self-diagnostic actions
        get_llm_config: 'Let me check the AI assistant configuration — model, context window, token limits, and active settings.',
        get_llm_session_log: 'I\'ll pull the session log so we can see what happened during that conversation — prompts, completions, verifier results, and any errors.',
        get_intent_debug: 'Let me run an intent classification diagnostic — I\'ll show what intent was detected, the confidence score, and which patterns matched.',
        get_rag_debug: 'I\'ll check the RAG retrieval pipeline — showing which knowledge chunks were retrieved, relevance scores, and what context was fed to the model.',
    };

    const prefix = descriptions[action!] ?? 'Let me investigate that for you right away.';
    return `${prefix}\n\n\`\`\`action\n${actionBlock}\n\`\`\``;
}

function generateSecurityFallback(intent: DetectedIntent): string {
    const { action } = intent;
    const riskLevel = ACTION_RISK_LEVELS[action!] ?? 'high';
    const confirm = riskLevel === 'high' || riskLevel === 'critical';
    const actionBlock = JSON.stringify({ action, params: {}, confirm, reason: `Security operation: ${action}` });

    const descriptions: Record<string, string> = {
        manage_ip_allowlist: '🔐 I\'ll help you manage your IP allowlist. Please provide the IP address or CIDR range.',
        get_user_permissions: 'Let me check your current permissions and role assignments.',
        resend_team_invite: 'I\'ll resend the team invitation email.',
        get_audit_log: 'Let me pull up the audit log to see who made changes and when.',
        set_emergency_throttle: '🚨 I\'ll set an emergency throttle on your account immediately to stop the suspicious activity.',
        get_api_access_log: 'I\'ll check the API access log for any suspicious activity from unknown IPs.',
        unlock_account: 'I\'ll unlock the account after verifying your identity.',
        freeze_account: '🚨 ⚠️ I\'m initiating an emergency account freeze. This will immediately halt all sending and API access.',
        export_audit_log: 'I\'ll export your audit log for compliance evidence.',
    };

    const prefix = descriptions[action!] ?? '🔐 I\'ll handle that security request.';
    return `${prefix}\n\n\`\`\`action\n${actionBlock}\n\`\`\``;
}

function generateComplianceFallback(intent: DetectedIntent): string {
    const { action } = intent;
    const riskLevel = ACTION_RISK_LEVELS[action!] ?? 'high';
    const confirm = riskLevel === 'high' || riskLevel === 'critical';
    const actionBlock = JSON.stringify({ action, params: {}, confirm, reason: `Compliance operation: ${action}` });

    const descriptions: Record<string, string> = {
        execute_gdpr_erasure: '⚠️ ⚖️ This will permanently delete all personal data for the specified data subject. This action is irreversible and requires confirmation.',
        get_consent_record: 'I\'ll look up the consent record to verify when and how opt-in consent was obtained.',
        set_retention_policy: '⚖️ I\'ll update your data retention policy. This affects how long message content and activity data is stored.',
        request_dpa: '⚖️ I\'ll initiate a Data Processing Agreement (DPA) request. Our legal team will prepare the document for review and signature.',
        request_compliance_doc: '⚖️ I\'ll request the compliance documentation (SOC 2, HIPAA BAA, etc.) from our compliance team.',
        set_legal_hold: '⚠️ ⚖️ I\'ll place a legal/litigation hold on the specified data. This prevents any automated deletion until the hold is lifted.',
        get_compliance_risk_score: 'Let me check your compliance risk score and identify any flagged areas.',
    };

    const prefix = descriptions[action!] ?? '⚖️ I\'ll handle that compliance request.';
    return `${prefix}\n\n\`\`\`action\n${actionBlock}\n\`\`\``;
}

function generateOpsFallback(intent: DetectedIntent): string {
    const { action } = intent;
    const riskLevel = ACTION_RISK_LEVELS[action!] ?? 'medium';
    const confirm = riskLevel === 'high' || riskLevel === 'critical';
    const actionBlock = JSON.stringify({ action, params: {}, confirm, reason: `Operations: ${action}` });

    const descriptions: Record<string, string> = {
        request_dedicated_ip: 'I\'ll submit a request for a dedicated sending IP. Our team will provision it and set up the warmup schedule.',
        get_warmup_status: 'Let me check your IP warmup progress and current volume schedule.',
        get_ip_assignment: 'I\'ll check your current IP assignment and verify which IPs you\'re sending from.',
        get_throttle_status: 'Let me check why throttling was triggered and what the current limits are.',
        rollback_deployment: '⚠️ I\'ll initiate a rollback to the previous stable deployment. This requires confirmation.',
        get_system_health: 'Let me run a system health check across all services (API, MTA, workers, database, Redis).',
        reconcile_analytics: 'I\'ll investigate the analytics discrepancy and reconcile the numbers.',
        get_worker_status: 'Let me check the worker/job queue status and see if there are any stuck or disabled workers.',
    };

    const prefix = descriptions[action!] ?? '🔧 Let me investigate that infrastructure concern.';
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
            // Campaign management
            { type: 'create_campaign', description: 'Create a new email campaign', example: "Create a campaign called 'Newsletter'" },
            { type: 'send_campaign', description: 'Send a campaign to subscribers', example: "Send 'Welcome Series' to 'New Subscribers'" },
            { type: 'schedule_campaign', description: 'Schedule a campaign for later', example: "Schedule 'Newsletter' for tomorrow at 9am" },
            { type: 'pause_campaign', description: 'Pause a running campaign', example: "Pause campaign 'Flash Sale'" },
            { type: 'delete_campaign', description: 'Delete a campaign', example: "Delete campaign 'Old Promo'" },
            // Contacts & lists
            { type: 'add_contact', description: 'Add a contact to a list', example: "Add john@example.com to 'VIP'" },
            { type: 'remove_contact', description: 'Remove a contact', example: "Remove jane@test.com from 'Newsletter'" },
            { type: 'create_list', description: 'Create a subscriber list', example: "Create list 'Premium Members'" },
            { type: 'create_segment', description: 'Create an audience segment', example: "Create segment of users who opened in last 30 days" },
            // Billing & account
            { type: 'get_billing_status', description: 'Check billing information', example: "Show me my billing info" },
            { type: 'get_quota_status', description: 'Check sending quota usage', example: "How much of my quota have I used?" },
            { type: 'get_invoice_reconciliation', description: 'Reconcile invoice vs usage', example: "My invoice doesn't match my usage" },
            // Domain & authentication
            { type: 'verify_domain', description: 'Verify domain DNS settings', example: "Check my domain configuration" },
            { type: 'force_dns_recheck', description: 'Force DNS re-verification', example: "Force a DNS recheck for my domain" },
            { type: 'check_bimi_status', description: 'Check BIMI verification', example: "Why isn't my BIMI logo showing?" },
            // API & webhooks
            { type: 'create_api_key', description: 'Generate a new API key', example: "Generate a new API key" },
            { type: 'check_api_status', description: 'Check API health', example: "Is the API working?" },
            { type: 'get_webhook_config', description: 'View webhook settings', example: "Show my webhook configuration" },
            { type: 'get_webhook_delivery_log', description: 'Check webhook delivery', example: "Why are my webhooks failing?" },
            { type: 'resend_webhook_events', description: 'Replay missed webhook events', example: "Resend the failed webhook events" },
            // Diagnostics
            { type: 'get_message_status', description: 'Check message delivery status', example: "Where is my email? It hasn't been delivered" },
            { type: 'get_smtp_transcript', description: 'View SMTP session log', example: "Show the SMTP transcript for my last send" },
            { type: 'trace_message', description: 'End-to-end message trace', example: "Trace this message through the system" },
            { type: 'validate_template', description: 'Debug template rendering', example: "My template variables aren't rendering" },
            { type: 'account_health_check', description: 'Run account diagnostics', example: "Is my account in good standing?" },
            // Deliverability
            { type: 'check_deliverability', description: 'Run deliverability diagnostic', example: "My emails are going to spam" },
            { type: 'check_blocklist_status', description: 'Check blocklist status', example: "Am I on any blocklists?" },
            { type: 'run_deliverability_audit', description: 'Full deliverability audit', example: "Run a deliverability audit" },
            // Bounces & suppressions
            { type: 'get_bounce_report', description: 'View bounce details', example: "Show my bounce report" },
            { type: 'get_complaint_rate', description: 'Check complaint rates', example: "What's my complaint rate?" },
            { type: 'check_suppression_status', description: 'Check if address is suppressed', example: "Is user@example.com suppressed?" },
            { type: 'remove_from_suppression', description: 'Remove from suppression list', example: "Remove user@example.com from suppression" },
            // Security
            { type: 'get_audit_log', description: 'View audit log', example: "Who changed my domain settings?" },
            { type: 'manage_ip_allowlist', description: 'Manage IP allowlist', example: "Add 203.0.113.0/24 to my IP allowlist" },
            { type: 'freeze_account', description: 'Emergency account freeze', example: "My account has been compromised, freeze it!" },
            { type: 'unlock_account', description: 'Unlock locked account', example: "My account is locked from failed logins" },
            // Compliance
            { type: 'execute_gdpr_erasure', description: 'GDPR data erasure', example: "Process a GDPR deletion request" },
            { type: 'get_consent_record', description: 'Look up consent proof', example: "Show consent record for user@example.com" },
            { type: 'request_dpa', description: 'Request a DPA', example: "We need a Data Processing Agreement" },
            { type: 'request_compliance_doc', description: 'Request compliance docs', example: "We need your SOC 2 report" },
            // Infrastructure
            { type: 'get_system_health', description: 'Check platform health', example: "Is the platform experiencing issues?" },
            { type: 'get_warmup_status', description: 'Check IP warmup progress', example: "How is my IP warmup going?" },
            { type: 'get_worker_status', description: 'Check worker queue health', example: "Are the email workers running?" },
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

        // Context-sensitive suggestions based on recent intent category
        switch (intent.category) {
            case 'billing':
                suggestions.push(
                    { type: 'query', label: 'View billing history', action: 'get_billing_history' },
                    { type: 'query', label: 'Check quota usage', action: 'get_quota_status' },
                );
                break;
            case 'domain':
                suggestions.push(
                    { type: 'query', label: 'Check sender reputation', action: 'get_sender_reputation' },
                    { type: 'query', label: 'Run deliverability check', action: 'check_deliverability' },
                );
                break;
            case 'support': {
                const a = intent.action;
                if (a?.includes('message') || a?.includes('smtp') || a?.includes('trace')) {
                    suggestions.push(
                        { type: 'query', label: 'Check bounce report', action: 'get_bounce_report' },
                        { type: 'query', label: 'View event timeline', action: 'get_message_event_timeline' },
                    );
                } else if (a?.includes('webhook')) {
                    suggestions.push(
                        { type: 'query', label: 'View webhook logs', action: 'get_webhook_delivery_log' },
                        { type: 'action', label: 'Resend failed events', action: 'resend_webhook_events' },
                    );
                } else if (a?.includes('blocklist') || a?.includes('deliverability') || a?.includes('complaint')) {
                    suggestions.push(
                        { type: 'query', label: 'Full deliverability audit', action: 'run_deliverability_audit' },
                        { type: 'query', label: 'Check blocklist status', action: 'check_blocklist_status' },
                    );
                } else if (a?.includes('suppression')) {
                    suggestions.push(
                        { type: 'query', label: 'Check suppression scope', action: 'get_suppression_scope' },
                        { type: 'query', label: 'View bounce report', action: 'get_bounce_report' },
                    );
                } else if (a?.includes('quota') || a?.includes('usage') || a?.includes('sending_status')) {
                    suggestions.push(
                        { type: 'query', label: 'Usage breakdown', action: 'get_usage_breakdown' },
                        { type: 'query', label: 'Billing details', action: 'get_billing_status' },
                    );
                } else if (a?.includes('llm') || a?.includes('intent') || a?.includes('rag')) {
                    suggestions.push(
                        { type: 'query', label: 'Check LLM config', action: 'get_llm_config' },
                        { type: 'query', label: 'View session log', action: 'get_llm_session_log' },
                    );
                } else {
                    suggestions.push(
                        { type: 'query', label: 'Account health check', action: 'account_health_check' },
                        { type: 'query', label: 'System health', action: 'get_system_health' },
                    );
                }
                break;
            }
            case 'security':
                suggestions.push(
                    { type: 'query', label: 'View audit log', action: 'get_audit_log' },
                    { type: 'query', label: 'Check API access log', action: 'get_api_access_log' },
                    { type: 'query', label: 'Account health check', action: 'account_health_check' },
                );
                break;
            case 'compliance':
                suggestions.push(
                    { type: 'query', label: 'Request DPA', action: 'request_dpa' },
                    { type: 'query', label: 'Compliance risk score', action: 'get_compliance_risk_score' },
                    { type: 'query', label: 'View audit log', action: 'get_audit_log' },
                );
                break;
            case 'ops':
                suggestions.push(
                    { type: 'query', label: 'System health check', action: 'get_system_health' },
                    { type: 'query', label: 'Worker queue status', action: 'get_worker_status' },
                    { type: 'query', label: 'IP warmup progress', action: 'get_warmup_status' },
                );
                break;
            default:
                break;
        }

        // Generic fallbacks if no category-specific suggestions were added
        if (suggestions.length < 2) {
            suggestions.push(
                { type: 'action', label: 'Create new campaign', action: 'create_campaign' },
                { type: 'query', label: 'Analyze my metrics', action: 'analyze_campaigns' },
                { type: 'query', label: 'Account health check', action: 'account_health_check' },
            );
        }

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
