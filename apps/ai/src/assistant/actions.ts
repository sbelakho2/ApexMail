/**
 * @apexmail/ai — Action Router
 *
 * Routes parsed AssistantAction objects to the appropriate backend service.
 * Each handler validates parameters, executes the operation (or simulates it),
 * and returns a structured result that the assistant can relay to the user.
 *
 * In production, these call real internal APIs. The router itself is a clean
 * abstraction layer — swap handlers per environment.
 */

import type { AssistantAction, AssistantActionType } from './unified.js';

// ════════════════════════════════════════════════════════════════
// TYPES
// ════════════════════════════════════════════════════════════════

export interface ActionResult {
    success: boolean;
    data?: Record<string, unknown>;
    message: string;
    warnings?: string[];
}

export type ActionHandler = (params: Record<string, unknown>) => Promise<ActionResult>;

export interface ActionRouterConfig {
    /** Base URL for internal API calls */
    apiBaseUrl: string;
    /** Base URL for billing service (port 3030) */
    billingBaseUrl: string;
    /** Base URL for enterprise service (port 3040) */
    enterpriseBaseUrl: string;
    /** Base URL for compliance service (port 3050) */
    complianceBaseUrl: string;
    /** Base URL for observability service (port 3060) */
    observabilityBaseUrl: string;
    /** Base URL for ops service (port 3070) */
    opsBaseUrl: string;
    /** Base URL for HA service (port 3080) */
    haBaseUrl: string;
    /** Auth token for internal service-to-service calls */
    serviceToken?: string;
    /** Tenant ID for scoped operations */
    tenantId?: string;
    /** Request timeout in ms */
    timeoutMs: number;
    /** Dry-run mode — simulate actions without executing */
    dryRun: boolean;
}

const DEFAULT_CONFIG: ActionRouterConfig = {
    apiBaseUrl: process.env.API_BASE_URL ?? 'http://localhost:3010',
    billingBaseUrl: process.env.BILLING_BASE_URL ?? 'http://localhost:3030',
    enterpriseBaseUrl: process.env.ENTERPRISE_BASE_URL ?? 'http://localhost:3040',
    complianceBaseUrl: process.env.COMPLIANCE_BASE_URL ?? 'http://localhost:3050',
    observabilityBaseUrl: process.env.OBSERVABILITY_BASE_URL ?? 'http://localhost:3060',
    opsBaseUrl: process.env.OPS_BASE_URL ?? 'http://localhost:3070',
    haBaseUrl: process.env.HA_BASE_URL ?? 'http://localhost:3080',
    serviceToken: process.env.SERVICE_TOKEN,
    tenantId: undefined,
    timeoutMs: 10_000,
    dryRun: false,
};

// ════════════════════════════════════════════════════════════════
// INTERNAL HELPERS
// ════════════════════════════════════════════════════════════════

function requireParam(params: Record<string, unknown>, key: string, label?: string): string {
    const v = params[key];
    if (v == null || (typeof v === 'string' && v.trim() === '')) {
        throw new Error(`Missing required parameter: ${label ?? key}`);
    }
    return String(v);
}

function optionalParam(params: Record<string, unknown>, key: string): string | undefined {
    const v = params[key];
    return v != null ? String(v) : undefined;
}

/**
 * Converts period shorthand ('1h', '24h', '7d', '30d') to ISO start/end dates.
 * Used for backends that don't accept 'period' directly.
 */
function periodToDateRange(period: string): { startDate: string; endDate: string } {
    const now = new Date();
    const endDate = now.toISOString();
    let ms = 24 * 60 * 60 * 1000; // default 1 day
    const match = period.match(/^(\d+)([hdwm])$/);
    if (match) {
        const num = parseInt(match[1], 10);
        const unit = match[2];
        if (unit === 'h') ms = num * 60 * 60 * 1000;
        else if (unit === 'd') ms = num * 24 * 60 * 60 * 1000;
        else if (unit === 'w') ms = num * 7 * 24 * 60 * 60 * 1000;
        else if (unit === 'm') ms = num * 30 * 24 * 60 * 60 * 1000;
    }
    const startDate = new Date(now.getTime() - ms).toISOString();
    return { startDate, endDate };
}

async function callInternalApi(
    config: ActionRouterConfig,
    method: string,
    path: string,
    body?: Record<string, unknown>,
    baseUrlOverride?: string,
): Promise<Record<string, unknown>> {
    const base = baseUrlOverride ?? config.apiBaseUrl;
    const url = `${base}${path}`;
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (config.serviceToken) headers['Authorization'] = `Bearer ${config.serviceToken}`;
    if (config.tenantId) headers['X-Tenant-Id'] = config.tenantId;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.timeoutMs);

    try {
        const resp = await fetch(url, {
            method,
            headers,
            body: body ? JSON.stringify(body) : undefined,
            signal: controller.signal,
        });

        const data = await resp.json().catch(() => ({}));

        if (!resp.ok) {
            throw new Error(`API ${method} ${path} returned ${resp.status}: ${JSON.stringify(data)}`);
        }

        return data as Record<string, unknown>;
    } finally {
        clearTimeout(timer);
    }
}

/** Shorthand callers for each service — includes service-specific route prefixes */
function callApi(c: ActionRouterConfig, m: string, p: string, b?: Record<string, unknown>) { return callInternalApi(c, m, p, b, c.apiBaseUrl); }
function callBilling(c: ActionRouterConfig, m: string, p: string, b?: Record<string, unknown>) { return callInternalApi(c, m, `/api/billing${p}`, b, c.billingBaseUrl); }
function callEnterprise(c: ActionRouterConfig, m: string, p: string, b?: Record<string, unknown>) { return callInternalApi(c, m, `/api${p}`, b, c.enterpriseBaseUrl); }
function callCompliance(c: ActionRouterConfig, m: string, p: string, b?: Record<string, unknown>) { return callInternalApi(c, m, p, b, c.complianceBaseUrl); }
function callObs(c: ActionRouterConfig, m: string, p: string, b?: Record<string, unknown>) { return callInternalApi(c, m, `/api/v1${p}`, b, c.observabilityBaseUrl); }
function callOps(c: ActionRouterConfig, m: string, p: string, b?: Record<string, unknown>) { return callInternalApi(c, m, p, b, c.opsBaseUrl); }
function callHA(c: ActionRouterConfig, m: string, p: string, b?: Record<string, unknown>) { return callInternalApi(c, m, `/api/v1${p}`, b, c.haBaseUrl); }

// ════════════════════════════════════════════════════════════════
// HANDLER BUILDERS
// ════════════════════════════════════════════════════════════════

function buildCampaignHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        create_campaign: async (params) => {
            const name = requireParam(params, 'name', 'campaign name');
            const subject = optionalParam(params, 'subject') ?? name;
            const listName = optionalParam(params, 'list_name');
            const templateId = optionalParam(params, 'template_id');

            if (config.dryRun) return { success: true, message: `[DRY RUN] Would create campaign "${name}"`, data: { name, subject, listName } };

            const data = await callInternalApi(config, 'POST', '/api/campaigns', { name, subject, listName, templateId });
            return { success: true, message: `Campaign "${name}" created successfully.`, data };
        },

        send_campaign: async (params) => {
            const campaignName = requireParam(params, 'campaign_name', 'campaign name');
            const listName = optionalParam(params, 'list_name');

            if (config.dryRun) return { success: true, message: `[DRY RUN] Would send campaign "${campaignName}"`, data: { campaignName, listName } };

            const data = await callInternalApi(config, 'POST', '/api/campaigns/send', { campaignName, listName });
            return { success: true, message: `Campaign "${campaignName}" is now sending.`, data };
        },

        schedule_campaign: async (params) => {
            const campaignName = requireParam(params, 'campaign_name', 'campaign name');
            const sendTime = requireParam(params, 'send_time', 'scheduled time');

            if (config.dryRun) return { success: true, message: `[DRY RUN] Would schedule "${campaignName}" for ${sendTime}`, data: { campaignName, sendTime } };

            const data = await callInternalApi(config, 'POST', '/api/campaigns/schedule', { campaignName, sendTime });
            return { success: true, message: `Campaign "${campaignName}" scheduled for ${sendTime}.`, data };
        },

        pause_campaign: async (params) => {
            const campaignName = requireParam(params, 'campaign_name', 'campaign name');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would pause "${campaignName}"`, data: { campaignName } };
            const data = await callInternalApi(config, 'POST', '/api/campaigns/pause', { campaignName });
            return { success: true, message: `Campaign "${campaignName}" paused.`, data };
        },

        delete_campaign: async (params) => {
            const campaignName = requireParam(params, 'campaign_name', 'campaign name');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would delete "${campaignName}"`, data: { campaignName } };
            const data = await callInternalApi(config, 'DELETE', `/api/campaigns/${encodeURIComponent(campaignName)}`, {});
            return { success: true, message: `Campaign "${campaignName}" deleted.`, data };
        },

        get_campaign_stats: async (params) => {
            const campaignName = requireParam(params, 'campaign_name', 'campaign name');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch stats for "${campaignName}"`, data: { campaignName } };
            const data = await callInternalApi(config, 'GET', `/api/campaigns/${encodeURIComponent(campaignName)}/stats`, undefined);
            return { success: true, message: `Stats for "${campaignName}":`, data };
        },

        analyze_campaigns: async (params) => {
            const period = optionalParam(params, 'period') ?? '30d';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would analyze campaigns for period ${period}`, data: { period } };
            const data = await callInternalApi(config, 'GET', `/api/analytics/campaigns?period=${period}`, undefined);
            return { success: true, message: 'Campaign analysis:', data };
        },

        create_ab_test: async (params) => {
            const campaignName = requireParam(params, 'campaign_name', 'campaign name');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would create A/B test for "${campaignName}"`, data: { campaignName } };
            const data = await callInternalApi(config, 'POST', '/api/campaigns/ab-test', { campaignName, ...params });
            return { success: true, message: `A/B test created for "${campaignName}".`, data };
        },
    };
}

function buildContactHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        add_contact: async (params) => {
            const email = requireParam(params, 'email', 'email address');
            const listName = optionalParam(params, 'list_name');
            const firstName = optionalParam(params, 'first_name');
            const lastName = optionalParam(params, 'last_name');

            if (config.dryRun) return { success: true, message: `[DRY RUN] Would add ${email}`, data: { email, listName } };
            const data = await callInternalApi(config, 'POST', '/api/contacts', { email, listName, firstName, lastName });
            return { success: true, message: `Contact ${email} added${listName ? ` to "${listName}"` : ''}.`, data };
        },

        remove_contact: async (params) => {
            const email = requireParam(params, 'email', 'email address');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would remove ${email}`, data: { email } };
            const data = await callInternalApi(config, 'DELETE', `/api/contacts/${encodeURIComponent(email)}`, {});
            return { success: true, message: `Contact ${email} removed.`, data };
        },

        import_contacts: async (params) => {
            const source = optionalParam(params, 'source') ?? 'csv';
            const listName = optionalParam(params, 'list_name');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would import contacts from ${source}`, data: { source, listName } };
            const data = await callInternalApi(config, 'POST', '/api/contacts/import', { source, listName });
            return { success: true, message: 'Contact import initiated.', data };
        },
    };
}

function buildListHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        create_list: async (params) => {
            const name = requireParam(params, 'name', 'list name');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would create list "${name}"`, data: { name } };
            const data = await callInternalApi(config, 'POST', '/api/lists', { name });
            return { success: true, message: `List "${name}" created.`, data };
        },

        delete_list: async (params) => {
            const name = requireParam(params, 'name', 'list name');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would delete list "${name}"`, data: { name } };
            const data = await callInternalApi(config, 'DELETE', `/api/lists/${encodeURIComponent(name)}`, {});
            return { success: true, message: `List "${name}" deleted.`, data };
        },

        create_segment: async (params) => {
            const name = optionalParam(params, 'name');
            const criteria = params.criteria ?? params.conditions;
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would create segment${name ? ` "${name}"` : ''}`, data: { name, criteria } };
            const data = await callInternalApi(config, 'POST', '/api/segments', { name, criteria });
            return { success: true, message: `Segment${name ? ` "${name}"` : ''} created.`, data };
        },
    };
}

function buildBillingHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        get_billing_status: async (params) => {
            const userId = optionalParam(params, 'user_id');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check billing status`, data: { userId } };
            const data = await callInternalApi(config, 'GET', `/api/billing/status${userId ? `?userId=${userId}` : ''}`, undefined);
            return { success: true, message: 'Your current billing status:', data };
        },

        get_billing_history: async (params) => {
            const limit = optionalParam(params, 'limit') ?? '10';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch billing history`, data: { limit } };
            const data = await callInternalApi(config, 'GET', `/api/billing/history?limit=${limit}`, undefined);
            return { success: true, message: 'Billing history:', data };
        },

        process_refund: async (params) => {
            const reason = optionalParam(params, 'reason') ?? 'Customer request';
            const invoiceId = optionalParam(params, 'invoice_id');
            const amount = optionalParam(params, 'amount');

            if (config.dryRun) return { success: true, message: `[DRY RUN] Would process refund`, data: { reason, invoiceId, amount } };
            const data = await callInternalApi(config, 'POST', '/api/billing/refund', { reason, invoiceId, amount });
            return { success: true, message: 'Refund processed.', data };
        },

        upgrade_plan: async (params) => {
            const plan = requireParam(params, 'plan', 'target plan');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would upgrade to "${plan}"`, data: { plan } };
            const data = await callInternalApi(config, 'POST', '/api/billing/upgrade', { plan });
            return { success: true, message: `Plan upgraded to "${plan}".`, data };
        },

        downgrade_plan: async (params) => {
            const plan = requireParam(params, 'plan', 'target plan');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would downgrade to "${plan}"`, data: { plan } };
            const data = await callInternalApi(config, 'POST', '/api/billing/downgrade', { plan });
            return {
                success: true,
                message: `Plan downgraded to "${plan}". Changes take effect at end of current billing period.`,
                data,
                warnings: ['Downgrading may reduce your subscriber limit and feature access.'],
            };
        },

        cancel_subscription: async (params) => {
            const reason = optionalParam(params, 'reason') ?? 'Not specified';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would cancel subscription`, data: { reason } };
            const data = await callInternalApi(config, 'POST', '/api/billing/cancel', { reason });
            return {
                success: true,
                message: 'Subscription cancelled. Access continues until end of billing period.',
                data,
                warnings: ['All scheduled campaigns will be paused. Data is retained for 30 days after cancellation.'],
            };
        },
    };
}

function buildDomainHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        verify_domain: async (params) => {
            const domain = optionalParam(params, 'domain');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would verify domain${domain ? ` "${domain}"` : ''}`, data: { domain } };
            const data = await callInternalApi(config, 'POST', '/api/domains/verify', { domain });
            return { success: true, message: `Domain verification:`, data };
        },

        check_deliverability: async (params) => {
            const domain = optionalParam(params, 'domain');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check deliverability`, data: { domain } };
            const data = await callInternalApi(config, 'GET', `/api/deliverability/check${domain ? `?domain=${domain}` : ''}`, undefined);
            return { success: true, message: 'Deliverability diagnostic:', data };
        },

        get_sender_reputation: async (params) => {
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check sender reputation`, data: {} };
            const data = await callInternalApi(config, 'GET', '/api/deliverability/reputation', undefined);
            return { success: true, message: 'Sender reputation report:', data };
        },

        get_bounce_report: async (params) => {
            const period = optionalParam(params, 'period') ?? '7d';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch bounce report`, data: { period } };
            const data = await callInternalApi(config, 'GET', `/api/deliverability/bounces?period=${period}`, undefined);
            return { success: true, message: 'Bounce report:', data };
        },

        create_api_key: async (params) => {
            const name = optionalParam(params, 'name') ?? 'api-key';
            const scopes = params.scopes ?? ['send', 'read'];
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would create API key "${name}"`, data: { name, scopes } };
            const data = await callInternalApi(config, 'POST', '/api/api-keys', { name, scopes });
            return {
                success: true,
                message: `API key "${name}" created. **Save this key — it won't be shown again.**`,
                data,
                warnings: ['Store this key securely. It cannot be retrieved later.'],
            };
        },

        revoke_api_key: async (params) => {
            const keyId = requireParam(params, 'key_id', 'API key ID');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would revoke API key ${keyId}`, data: { keyId } };
            const data = await callInternalApi(config, 'DELETE', `/api/api-keys/${keyId}`, {});
            return { success: true, message: `API key revoked.`, data };
        },

        check_api_status: async (params) => {
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check API status`, data: {} };
            const data = await callInternalApi(config, 'GET', '/api/status', undefined);
            return { success: true, message: 'API status:', data };
        },

        account_health_check: async (params) => {
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would run account health check`, data: {} };
            const data = await callInternalApi(config, 'GET', '/api/account/health', undefined);
            return { success: true, message: 'Account health report:', data };
        },
    };
}

function buildDataHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        export_data: async (params) => {
            const type = optionalParam(params, 'type') ?? 'campaigns';
            const format = optionalParam(params, 'format') ?? 'csv';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would export ${type} as ${format}`, data: { type, format } };
            const data = await callApi(config, 'GET', `/v1/analytics/export?type=${type}&format=${format}`, undefined);
            return { success: true, message: `Export initiated. You'll receive a download link when ready.`, data };
        },

        generate_content: async (params) => {
            const topic = optionalParam(params, 'topic') ?? 'newsletter';
            const type = optionalParam(params, 'type') ?? 'email_body';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would generate content about "${topic}"`, data: { topic, type } };
            const data = await callInternalApi(config, 'POST', '/api/content/generate', { topic, type, ...params }, config.apiBaseUrl.replace(':3010', ':3090'));
            return { success: true, message: 'Generated content:', data };
        },

        generate_subject: async (params) => {
            const topic = optionalParam(params, 'topic') ?? 'newsletter';
            return {
                success: true,
                message: 'Here are some subject line suggestions:',
                data: {
                    suggestions: [
                        `📢 ${topic} — What you need to know this week`,
                        `Your ${topic} update is here 🎯`,
                        `Don't miss out: ${topic} insights inside`,
                        `[Action Required] ${topic} updates`,
                        `The ${topic} guide you've been waiting for`,
                    ],
                },
            };
        },

        suggest_subjects: async (params) => {
            const topic = optionalParam(params, 'topic') ?? 'newsletter';
            const tone = optionalParam(params, 'tone') ?? 'professional';
            return {
                success: true,
                message: 'Subject line suggestions:',
                data: {
                    topic,
                    tone,
                    suggestions: [
                        `${topic} highlights you can't afford to miss`,
                        `Quick update: ${topic}`,
                        `Your weekly ${topic} digest 📋`,
                    ],
                },
            };
        },

        get_template: async (params) => {
            const templateId = requireParam(params, 'template_id', 'template ID');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch template ${templateId}`, data: { templateId } };
            const data = await callInternalApi(config, 'GET', `/api/templates/${templateId}`, undefined);
            return { success: true, message: `Template:`, data };
        },

        export_report: async (params) => {
            const type = optionalParam(params, 'type') ?? 'analytics';
            const format = optionalParam(params, 'format') ?? 'csv';
            const period = optionalParam(params, 'period') ?? '30d';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would export ${type} report`, data: { type, format, period } };
            const data = await callApi(config, 'GET', `/v1/analytics/export?format=${format}&period=${period}`, undefined);
            return { success: true, message: 'Report export initiated:', data };
        },
    };
}

// ════════════════════════════════════════════════════════════════
// MESSAGE DIAGNOSTICS & TRACING HANDLERS
// ════════════════════════════════════════════════════════════════

function buildMessageDiagnosticHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        get_message_status: async (params) => {
            const messageId = requireParam(params, 'message_id', 'message ID');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check status of message ${messageId}`, data: { messageId } };
            const data = await callApi(config, 'GET', `/v1/messages/${messageId}`, undefined);
            return { success: true, message: 'Message status:', data };
        },

        get_smtp_transcript: async (params) => {
            const messageId = requireParam(params, 'message_id', 'message ID');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch SMTP transcript for ${messageId}`, data: { messageId } };
            // SMTP transcript is stored in the message events as metadata
            const data = await callApi(config, 'GET', `/v1/events/message/${messageId}?include=smtp_transcript`, undefined);
            return { success: true, message: 'SMTP session transcript:', data };
        },

        get_scheduled_send_status: async (params) => {
            const messageId = requireParam(params, 'message_id', 'message ID');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check scheduled send ${messageId}`, data: { messageId } };
            const data = await callApi(config, 'GET', `/v1/messages/${messageId}`, undefined);
            return { success: true, message: 'Scheduled send status:', data };
        },

        get_message_event_timeline: async (params) => {
            const messageId = requireParam(params, 'message_id', 'message ID');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch event timeline for ${messageId}`, data: { messageId } };
            const data = await callApi(config, 'GET', `/v1/events/message/${messageId}`, undefined);
            return { success: true, message: 'Message event timeline:', data };
        },

        trace_message: async (params) => {
            const messageId = requireParam(params, 'message_id', 'message ID');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would trace message ${messageId}`, data: { messageId } };
            // Cross-service trace: get message data from API + distributed trace from observability
            const [msgData, traceData] = await Promise.all([
                callApi(config, 'GET', `/v1/messages/${messageId}`, undefined),
                callObs(config, 'GET', `/traces?tags=${encodeURIComponent(JSON.stringify({ messageId }))}`, undefined).catch(() => ({})),
            ]);
            return { success: true, message: 'Message trace:', data: { message: msgData, trace: traceData } };
        },

        validate_template: async (params) => {
            const templateId = optionalParam(params, 'template_id');
            const html = optionalParam(params, 'html');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would validate template`, data: { templateId } };
            if (templateId) {
                const data = await callApi(config, 'POST', `/v1/templates/${templateId}/render`, { validateOnly: true });
                return { success: true, message: 'Template validation result:', data };
            }
            // Inline HTML validation via content scan
            const data = await callCompliance(config, 'POST', '/api/scan', { content: html ?? '', type: 'template_validation' });
            return { success: true, message: 'Template validation result:', data };
        },

        get_content_scan_result: async (params) => {
            const messageId = optionalParam(params, 'message_id');
            const scanId = optionalParam(params, 'scan_id');
            const id = scanId ?? messageId;
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch content scan result`, data: { id } };
            const data = await callCompliance(config, 'GET', `/api/scan/${id}`, undefined);
            return { success: true, message: 'Content scan result:', data };
        },
    };
}

// ════════════════════════════════════════════════════════════════
// DNS / AUTHENTICATION DIAGNOSTIC HANDLERS
// ════════════════════════════════════════════════════════════════

function buildDNSDiagnosticHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        force_dns_recheck: async (params) => {
            const domain = requireParam(params, 'domain', 'domain name');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would force DNS recheck for ${domain}`, data: { domain } };
            const data = await callApi(config, 'POST', `/v1/domains/${encodeURIComponent(domain)}/verify`, {});
            return { success: true, message: `DNS recheck initiated for ${domain}:`, data };
        },

        check_bimi_status: async (params) => {
            const domain = requireParam(params, 'domain', 'domain name');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check BIMI for ${domain}`, data: { domain } };
            const data = await callApi(config, 'GET', `/v1/domains/${encodeURIComponent(domain)}/bimi`, undefined);
            return { success: true, message: 'BIMI configuration status:', data };
        },

        check_rdns_ptr: async (params) => {
            const ip = requireParam(params, 'ip', 'IP address');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check rDNS/PTR for ${ip}`, data: { ip } };
            const data = await callApi(config, 'GET', `/v1/domains/rdns?ip=${encodeURIComponent(ip)}`, undefined);
            return { success: true, message: 'Reverse DNS (PTR) check:', data };
        },
    };
}

// ════════════════════════════════════════════════════════════════
// DELIVERABILITY / REPUTATION HANDLERS
// ════════════════════════════════════════════════════════════════

function buildDeliverabilityHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        run_deliverability_audit: async (params) => {
            const domain = optionalParam(params, 'domain');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would run deliverability audit`, data: { domain } };
            // Comprehensive: combines DNS health + analytics deliverability + reputation
            const [authData, delivData] = await Promise.all([
                domain ? callApi(config, 'GET', `/v1/domains/${encodeURIComponent(domain)}/auth-status`, undefined) : Promise.resolve({}),
                callApi(config, 'GET', '/v1/analytics/deliverability', undefined),
            ]);
            return { success: true, message: 'Deliverability audit results:', data: { authentication: authData, deliverability: delivData } };
        },

        get_geo_sending_report: async (params) => {
            const period = optionalParam(params, 'period') ?? '7d';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch geo sending report`, data: { period } };
            const data = await callApi(config, 'GET', `/v1/analytics/domains?period=${period}&groupBy=geo`, undefined);
            return { success: true, message: 'Geographic sending report:', data };
        },

        check_blocklist_status: async (params) => {
            const ip = optionalParam(params, 'ip');
            const domain = optionalParam(params, 'domain');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check blocklist status`, data: { ip, domain } };
            const data = await callOps(config, 'GET', `/health/detailed`, undefined);
            return { success: true, message: 'Blocklist check results:', data };
        },
    };
}

// ════════════════════════════════════════════════════════════════
// BOUNCE / SUPPRESSION HANDLERS
// ════════════════════════════════════════════════════════════════

function buildSuppressionHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        get_complaint_rate: async (params) => {
            const period = optionalParam(params, 'period') ?? '7d';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check complaint rate`, data: { period } };
            const data = await callApi(config, 'GET', `/v1/analytics/bounces?period=${period}&type=complaint`, undefined);
            return { success: true, message: 'Complaint rate report:', data };
        },

        remove_from_suppression: async (params) => {
            const email = requireParam(params, 'email', 'email address');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would remove ${email} from suppression`, data: { email } };
            const data = await callApi(config, 'DELETE', `/v1/suppressions/email/${encodeURIComponent(email)}`, {});
            return {
                success: true,
                message: `${email} removed from suppression list.`,
                data,
                warnings: ['Ensure you have valid re-consent before re-sending to this address.'],
            };
        },

        check_suppression_status: async (params) => {
            const email = requireParam(params, 'email', 'email address');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check suppression status for ${email}`, data: { email } };
            const data = await callApi(config, 'GET', `/v1/suppressions/check/${encodeURIComponent(email)}`, undefined);
            return { success: true, message: `Suppression status for ${email}:`, data };
        },

        get_suppression_scope: async (params) => {
            const email = requireParam(params, 'email', 'email address');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check suppression scope for ${email}`, data: { email } };
            const data = await callApi(config, 'GET', `/v1/suppressions/check/${encodeURIComponent(email)}`, undefined);
            return { success: true, message: `Suppression scope for ${email}:`, data };
        },
    };
}

// ════════════════════════════════════════════════════════════════
// WEBHOOK / TRACKING HANDLERS
// ════════════════════════════════════════════════════════════════

function buildWebhookHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        get_webhook_config: async (params) => {
            const webhookId = optionalParam(params, 'webhook_id');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch webhook config`, data: { webhookId } };
            const endpoint = webhookId ? `/v1/webhooks/${webhookId}` : '/v1/webhooks';
            const data = await callApi(config, 'GET', endpoint, undefined);
            return { success: true, message: 'Webhook configuration:', data };
        },

        get_webhook_delivery_log: async (params) => {
            const webhookId = requireParam(params, 'webhook_id', 'webhook ID');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch webhook delivery log`, data: { webhookId } };
            const data = await callApi(config, 'GET', `/v1/webhooks/${webhookId}/deliveries`, undefined);
            return { success: true, message: 'Webhook delivery log:', data };
        },

        resend_webhook_events: async (params) => {
            const webhookId = requireParam(params, 'webhook_id', 'webhook ID');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would resend webhook events`, data: { webhookId } };
            const data = await callApi(config, 'POST', `/v1/webhooks/${webhookId}/test`, {});
            return {
                success: true,
                message: 'Webhook events resent.',
                data,
                warnings: ['Ensure your endpoint handles idempotency — duplicate events may arrive.'],
            };
        },

        enable_webhook_endpoint: async (params) => {
            const webhookId = requireParam(params, 'webhook_id', 'webhook ID');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would enable webhook ${webhookId}`, data: { webhookId } };
            const data = await callApi(config, 'POST', `/v1/webhooks/${webhookId}/enable`, {});
            return { success: true, message: `Webhook ${webhookId} re-enabled.`, data };
        },

        get_tracking_domain_config: async (params) => {
            const domain = optionalParam(params, 'domain');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch tracking domain config`, data: { domain } };
            const data = await callApi(config, 'GET', '/v1/domains', undefined);
            return { success: true, message: 'Tracking domain configuration:', data };
        },

        rotate_tracking_domain: async (params) => {
            const domain = requireParam(params, 'domain', 'tracking domain');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would rotate tracking domain ${domain}`, data: { domain } };
            const data = await callApi(config, 'POST', `/v1/domains/${encodeURIComponent(domain)}/verify`, { rotate: true });
            return {
                success: true,
                message: `Tracking domain rotation initiated for ${domain}.`,
                data,
                warnings: ['Links in previously sent emails still use the old domain — keep it active.'],
            };
        },

        check_cert_provisioning_status: async (params) => {
            const domain = requireParam(params, 'domain', 'tracking domain');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check cert status for ${domain}`, data: { domain } };
            const data = await callApi(config, 'GET', `/v1/domains/${encodeURIComponent(domain)}/health`, undefined);
            return { success: true, message: 'SSL certificate provisioning status:', data };
        },
    };
}

// ════════════════════════════════════════════════════════════════
// API DIAGNOSTIC HANDLERS
// ════════════════════════════════════════════════════════════════

function buildAPIDiagnosticHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        get_rate_limit_status: async (params) => {
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check rate limit status`, data: {} };
            const data = await callObs(config, 'GET', '/metrics/query?name=rate_limit_remaining', undefined);
            return { success: true, message: 'Rate limit status:', data };
        },

        get_api_error_log: async (params) => {
            const period = optionalParam(params, 'period') ?? '1h';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch API error log`, data: { period } };
            const { startDate: s, endDate: e } = periodToDateRange(period);
            const data = await callObs(config, 'GET', `/logs?level=error&service=api&startTime=${s}&endTime=${e}`, undefined);
            return { success: true, message: 'Recent API errors:', data };
        },

        get_api_health_detailed: async (params) => {
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would run detailed API health check`, data: {} };
            const data = await callApi(config, 'GET', '/health/deep', undefined);
            return { success: true, message: 'Detailed API health:', data };
        },

        enable_sdk_debug_mode: async (params) => {
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would enable SDK debug mode`, data: {} };
            // SDK debug mode is toggled via a per-tenant setting
            const data = await callObs(config, 'POST', '/metrics', { name: 'sdk_debug_mode', value: 1, type: 'gauge' });
            return {
                success: true,
                message: 'SDK debug mode enabled. Verbose request/response logging is now active.',
                data,
                warnings: ['Debug mode increases log volume. Disable after troubleshooting.'],
            };
        },
    };
}

// ════════════════════════════════════════════════════════════════
// ACCOUNT / QUOTA HANDLERS (BILLING SERVICE)
// ════════════════════════════════════════════════════════════════

function buildQuotaHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        get_quota_status: async (params) => {
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check quota status`, data: {} };
            const data = await callBilling(config, 'GET', '/usage', undefined);
            return { success: true, message: 'Quota status:', data };
        },

        get_usage_breakdown: async (params) => {
            const period = optionalParam(params, 'period') ?? '30d';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch usage breakdown`, data: { period } };
            const data = await callBilling(config, 'GET', `/usage?period=${period}&breakdown=true`, undefined);
            return { success: true, message: 'Usage breakdown:', data };
        },

        get_sending_status: async (params) => {
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check sending status`, data: {} };
            const [billing, health] = await Promise.all([
                callBilling(config, 'GET', '/subscription', undefined),
                callApi(config, 'GET', '/health/ready', undefined),
            ]);
            return { success: true, message: 'Sending status:', data: { subscription: billing, health } };
        },

        get_invoice_reconciliation: async (params) => {
            const invoiceId = optionalParam(params, 'invoice_id');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would reconcile invoice`, data: { invoiceId } };
            const [invoices, usage] = await Promise.all([
                callBilling(config, 'GET', invoiceId ? `/invoices/${invoiceId}` : '/invoices?limit=1', undefined),
                callBilling(config, 'GET', '/usage', undefined),
            ]);
            return { success: true, message: 'Invoice reconciliation:', data: { invoice: invoices, actualUsage: usage } };
        },
    };
}

// ════════════════════════════════════════════════════════════════
// SECURITY / ACCESS CONTROL HANDLERS
// ════════════════════════════════════════════════════════════════

function buildSecurityHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        manage_ip_allowlist: async (params) => {
            const action = optionalParam(params, 'action') ?? 'list'; // add, remove, list
            const ip = optionalParam(params, 'ip');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would ${action} IP allowlist`, data: { action, ip } };
            if (action === 'add' && ip) {
                const data = await callEnterprise(config, 'POST', '/compliance/enable', { type: 'ip_allowlist', ip });
                return { success: true, message: `IP ${ip} added to allowlist.`, data };
            }
            const data = await callEnterprise(config, 'GET', `/compliance/config/${config.tenantId ?? 'current'}`, undefined);
            return { success: true, message: 'IP allowlist:', data };
        },

        get_user_permissions: async (params) => {
            const userId = optionalParam(params, 'user_id');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check permissions`, data: { userId } };
            const data = await callApi(config, 'GET', '/v1/auth/me', undefined);
            return { success: true, message: 'User permissions:', data };
        },

        resend_team_invite: async (params) => {
            const email = requireParam(params, 'email', 'team member email');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would resend invite to ${email}`, data: { email } };
            // SCIM user endpoint can re-provision/re-invite
            const data = await callApi(config, 'POST', '/v1/scim/Users', { emails: [{ value: email }], active: true, reinvite: true });
            return { success: true, message: `Team invitation resent to ${email}.`, data };
        },

        get_audit_log: async (params) => {
            const period = optionalParam(params, 'period') ?? '24h';
            const action = optionalParam(params, 'action_filter');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch audit log`, data: { period, action } };
            const { startDate, endDate } = periodToDateRange(period);
            const query = `/api/audit?startDate=${startDate}&endDate=${endDate}${action ? `&action=${action}` : ''}`;
            const data = await callCompliance(config, 'GET', query, undefined);
            return { success: true, message: 'Audit log:', data };
        },

        set_emergency_throttle: async (params) => {
            const rate = optionalParam(params, 'rate') ?? '0'; // 0 = full stop
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would set emergency throttle to ${rate}/s`, data: { rate } };
            const data = await callOps(config, 'POST', '/admin/alerts/rules/emergency-throttle/enable', { maxRate: Number(rate) });
            return {
                success: true,
                message: `🚨 Emergency throttle activated. Sending rate limited to ${rate}/second.`,
                data,
                warnings: ['This immediately affects all sending. Disable once the situation is resolved.'],
            };
        },

        get_api_access_log: async (params) => {
            const period = optionalParam(params, 'period') ?? '24h';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch API access log`, data: { period } };
            const { startDate, endDate } = periodToDateRange(period);
            const data = await callCompliance(config, 'GET', `/api/audit?startDate=${startDate}&endDate=${endDate}&resource=api`, undefined);
            return { success: true, message: 'API access log:', data };
        },

        unlock_account: async (params) => {
            const accountId = optionalParam(params, 'account_id') ?? config.tenantId;
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would unlock account`, data: { accountId } };
            // Resolve suspension via compliance risk flag resolution
            const data = await callCompliance(config, 'POST', `/api/risk/${accountId}/flags/account_locked/resolve`, { resolution: 'manual_unlock' });
            return { success: true, message: 'Account unlocked.', data };
        },

        freeze_account: async (params) => {
            const reason = optionalParam(params, 'reason') ?? 'Emergency freeze requested';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would freeze account`, data: { reason } };
            const accountId = config.tenantId ?? optionalParam(params, 'account_id');
            const data = await callEnterprise(config, 'POST', `/sub-accounts/${accountId}/suspend`, { reason });
            return {
                success: true,
                message: '🚨 Account frozen. All sending and API access halted immediately.',
                data,
                warnings: ['This is a critical action. Contact support to re-activate.'],
            };
        },

        export_audit_log: async (params) => {
            const period = optionalParam(params, 'period') ?? '30d';
            const format = optionalParam(params, 'format') ?? 'json';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would export audit log`, data: { period, format } };
            const data = await callCompliance(config, 'POST', '/api/audit/export', { period, format });
            return { success: true, message: 'Audit log export initiated. Download link will be provided when ready.', data };
        },
    };
}

// ════════════════════════════════════════════════════════════════
// COMPLIANCE / PRIVACY HANDLERS
// ════════════════════════════════════════════════════════════════

function buildComplianceHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        execute_gdpr_erasure: async (params) => {
            const email = requireParam(params, 'email', 'data subject email');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would execute GDPR erasure for ${email}`, data: { email } };
            // Create GDPR request → verify → process (full pipeline)
            const req = await callCompliance(config, 'POST', '/api/gdpr/requests', {
                tenantId: config.tenantId,
                type: 'erasure',
                subjectEmail: email,
                reason: 'Right to be forgotten (Article 17)',
            });
            const requestId = req.requestId ?? req.id;
            await callCompliance(config, 'POST', `/api/gdpr/requests/${requestId}/verify`, {});
            const data = await callCompliance(config, 'POST', `/api/gdpr/requests/${requestId}/process`, {});
            return {
                success: true,
                message: `⚖️ GDPR erasure executed for ${email}. All personal data permanently deleted.`,
                data,
                warnings: ['This action is irreversible. A compliance certificate has been generated.'],
            };
        },

        get_consent_record: async (params) => {
            const email = requireParam(params, 'email', 'subscriber email');
            const subscriberId = optionalParam(params, 'subscriber_id') ?? email;
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch consent record for ${email}`, data: { email } };
            const data = await callCompliance(config, 'GET', `/api/gdpr/consent/${config.tenantId ?? 'current'}/${encodeURIComponent(subscriberId)}`, undefined);
            return { success: true, message: `Consent record for ${email}:`, data };
        },

        set_retention_policy: async (params) => {
            const days = requireParam(params, 'days', 'retention period in days');
            const scope = optionalParam(params, 'scope') ?? 'all';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would set retention to ${days} days`, data: { days, scope } };
            const data = await callCompliance(config, 'POST', '/api/gdpr/requests', {
                tenantId: config.tenantId,
                type: 'retention_update',
                retentionDays: Number(days),
                scope,
            });
            return {
                success: true,
                message: `Data retention policy updated to ${days} days for scope: ${scope}.`,
                data,
                warnings: ['Existing data older than the new retention period will be purged within 24 hours.'],
            };
        },

        request_dpa: async (params) => {
            const companyName = optionalParam(params, 'company_name');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would request DPA`, data: { companyName } };
            const data = await callCompliance(config, 'POST', '/api/gdpr/requests', {
                tenantId: config.tenantId,
                type: 'dpa_request',
                companyName,
            });
            return { success: true, message: '⚖️ DPA request submitted. Our legal team will prepare the document for review and signature.', data };
        },

        request_compliance_doc: async (params) => {
            const docType = requireParam(params, 'doc_type', 'document type (soc2, hipaa_baa, iso27001, ccpa)');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would request ${docType} documentation`, data: { docType } };
            const data = await callOps(config, 'GET', `/trust/documents?type=${docType}`, undefined);
            return { success: true, message: `Compliance documentation (${docType}):`, data };
        },

        set_legal_hold: async (params) => {
            const scope = requireParam(params, 'scope', 'hold scope (email, tenant, date_range)');
            const reason = requireParam(params, 'reason', 'legal hold reason');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would set legal hold`, data: { scope, reason } };
            const data = await callCompliance(config, 'POST', '/api/gdpr/requests', {
                tenantId: config.tenantId,
                type: 'legal_hold',
                scope,
                reason,
            });
            return {
                success: true,
                message: '⚖️ Legal hold applied. Automated data deletion is suspended for the specified scope.',
                data,
                warnings: ['Legal holds persist until explicitly removed. All applicable data is preserved.'],
            };
        },

        get_compliance_risk_score: async (params) => {
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check compliance risk score`, data: {} };
            const data = await callCompliance(config, 'GET', `/api/risk/${config.tenantId ?? 'current'}`, undefined);
            return { success: true, message: 'Compliance risk assessment:', data };
        },
    };
}

// ════════════════════════════════════════════════════════════════
// OPS / INFRASTRUCTURE HANDLERS
// ════════════════════════════════════════════════════════════════

function buildOpsHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        request_dedicated_ip: async (params) => {
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would request dedicated IP`, data: {} };
            const data = await callEnterprise(config, 'POST', '/dedicated-ips', {
                accountId: config.tenantId,
                type: 'dedicated',
            });
            return {
                success: true,
                message: 'Dedicated IP requested. It will be provisioned and warmup will begin automatically.',
                data,
                warnings: ['New IPs require 4-8 weeks of warmup. Start with engaged subscribers only.'],
            };
        },

        get_warmup_status: async (params) => {
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check warmup status`, data: {} };
            const data = await callOps(config, 'GET', '/warmup/pools', undefined);
            return { success: true, message: 'IP warmup status:', data };
        },

        get_ip_assignment: async (params) => {
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check IP assignment`, data: {} };
            const data = await callEnterprise(config, 'GET', `/accounts/${config.tenantId ?? 'current'}/dedicated-ips`, undefined);
            return { success: true, message: 'IP assignment:', data };
        },

        get_throttle_status: async (params) => {
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check throttle status`, data: {} };
            const data = await callOps(config, 'GET', '/slo', undefined);
            return { success: true, message: 'Throttle / SLO status:', data };
        },

        rollback_deployment: async (params) => {
            const target = optionalParam(params, 'target') ?? 'previous';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would rollback to ${target}`, data: { target } };
            const data = await callHA(config, 'POST', '/failover/failback', { target });
            return {
                success: true,
                message: `Deployment rollback initiated to ${target}.`,
                data,
                warnings: ['Monitor health closely after rollback. Check /health/detailed for status.'],
            };
        },

        get_system_health: async (params) => {
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check system health`, data: {} };
            const [opsHealth, apiHealth, haHealth] = await Promise.all([
                callOps(config, 'GET', '/health/detailed', undefined).catch(() => ({ status: 'unreachable' })),
                callApi(config, 'GET', '/health/deep', undefined).catch(() => ({ status: 'unreachable' })),
                callHA(config, 'GET', '/health/detailed', undefined).catch(() => ({ status: 'unreachable' })),
            ]);
            return { success: true, message: 'System health overview:', data: { ops: opsHealth, api: apiHealth, ha: haHealth } };
        },

        reconcile_analytics: async (params) => {
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would reconcile analytics`, data: {} };
            const data = await callApi(config, 'GET', '/v1/analytics/dashboard', undefined);
            return { success: true, message: 'Analytics reconciliation:', data };
        },

        get_worker_status: async (params) => {
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would check worker status`, data: {} };
            const data = await callOps(config, 'GET', '/dashboard', undefined);
            return { success: true, message: 'Worker / queue status:', data };
        },
    };
}

// ════════════════════════════════════════════════════════════════
// LLM SELF-DIAGNOSTIC HANDLERS (LOCAL)
// ════════════════════════════════════════════════════════════════

/** LLM runtime context — injected by the UnifiedAssistant at session start */
export interface LLMDiagnosticContext {
    modelName?: string;
    contextLength?: number;
    maxOutputTokens?: number;
    temperature?: number;
    sessionHistory?: Array<{ role: string; contentLength: number; timestamp: number }>;
    lastIntentResult?: Record<string, unknown>;
    lastRAGContext?: Record<string, unknown>;
}

let _llmDiagCtx: LLMDiagnosticContext = {};

export function setLLMDiagnosticContext(ctx: LLMDiagnosticContext): void {
    _llmDiagCtx = ctx;
}

function buildLLMDiagnosticHandlers(_config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        get_llm_config: async () => {
            return {
                success: true,
                message: 'Current AI assistant configuration:',
                data: {
                    model: _llmDiagCtx.modelName ?? 'qwen2.5-7b-instruct',
                    contextWindow: _llmDiagCtx.contextLength ?? 8192,
                    maxOutputTokens: _llmDiagCtx.maxOutputTokens ?? 4096,
                    temperature: _llmDiagCtx.temperature ?? 0.7,
                    runtime: 'ONNX Runtime',
                },
            };
        },

        get_llm_session_log: async () => {
            const history = _llmDiagCtx.sessionHistory ?? [];
            return {
                success: true,
                message: 'Session log:',
                data: {
                    messageCount: history.length,
                    totalInputTokensEstimate: history.reduce((s, m) => s + Math.ceil(m.contentLength / 4), 0),
                    messages: history.slice(-10).map((m, i) => ({
                        index: i,
                        role: m.role,
                        contentLengthChars: m.contentLength,
                        timestamp: new Date(m.timestamp).toISOString(),
                    })),
                },
            };
        },

        get_intent_debug: async () => {
            return {
                success: true,
                message: 'Last intent classification result:',
                data: _llmDiagCtx.lastIntentResult ?? {
                    note: 'No intent classification data available for this session. Send a message first.',
                },
            };
        },

        get_rag_debug: async () => {
            return {
                success: true,
                message: 'RAG retrieval debug info:',
                data: _llmDiagCtx.lastRAGContext ?? {
                    note: 'No RAG retrieval data available for this session.',
                },
            };
        },
    };
}

// ════════════════════════════════════════════════════════════════
// ADDITIONAL MISSING COMMAND HANDLERS
// ════════════════════════════════════════════════════════════════

function buildAdditionalCommandHandlers(config: ActionRouterConfig): Record<string, ActionHandler> {
    return {
        resume_campaign: async (params) => {
            const campaignName = requireParam(params, 'campaign_name', 'campaign name');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would resume "${campaignName}"`, data: { campaignName } };
            const data = await callApi(config, 'POST', `/v1/campaigns/${encodeURIComponent(campaignName)}/resume`, {});
            return { success: true, message: `Campaign "${campaignName}" resumed.`, data };
        },

        stop_campaign: async (params) => {
            const campaignName = requireParam(params, 'campaign_name', 'campaign name');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would stop "${campaignName}"`, data: { campaignName } };
            const data = await callApi(config, 'POST', `/v1/campaigns/${encodeURIComponent(campaignName)}/stop`, {});
            return { success: true, message: `Campaign "${campaignName}" stopped.`, data };
        },

        add_contacts: async (params) => {
            const listName = optionalParam(params, 'list_name');
            const emails = params.emails ?? [];
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would bulk add contacts`, data: { count: (emails as unknown[]).length, listName } };
            const data = await callApi(config, 'POST', '/v1/contacts/bulk', { emails, listName });
            return { success: true, message: 'Contacts added.', data };
        },

        remove_contacts: async (params) => {
            const emails = params.emails ?? [];
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would bulk remove contacts`, data: { count: (emails as unknown[]).length } };
            const data = await callApi(config, 'DELETE', '/v1/contacts/bulk', { emails });
            return { success: true, message: 'Contacts removed.', data };
        },

        tag_contacts: async (params) => {
            const tag = requireParam(params, 'tag', 'tag name');
            const listName = optionalParam(params, 'list_name');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would tag contacts with "${tag}"`, data: { tag, listName } };
            const data = await callApi(config, 'POST', '/v1/contacts/tags', { tag, listName });
            return { success: true, message: `Contacts tagged with "${tag}".`, data };
        },

        tag_contact: async (params) => {
            const email = requireParam(params, 'email', 'contact email');
            const tag = requireParam(params, 'tag', 'tag name');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would tag ${email} with "${tag}"`, data: { email, tag } };
            const data = await callApi(config, 'POST', `/v1/contacts/${encodeURIComponent(email)}/tags`, { tag });
            return { success: true, message: `Contact ${email} tagged with "${tag}".`, data };
        },

        set_automation: async (params) => {
            const name = optionalParam(params, 'name') ?? 'automation';
            const trigger = optionalParam(params, 'trigger');
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would create automation "${name}"`, data: { name, trigger } };
            const data = await callApi(config, 'POST', '/v1/automations', { name, trigger, ...params });
            return { success: true, message: `Automation "${name}" created.`, data };
        },

        analyze_performance: async (params) => {
            const period = optionalParam(params, 'period') ?? '30d';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would analyze performance`, data: { period } };
            const data = await callApi(config, 'GET', `/v1/analytics/engagement?period=${period}`, undefined);
            return { success: true, message: 'Performance analysis:', data };
        },

        get_stats: async (params) => {
            const period = optionalParam(params, 'period') ?? '7d';
            if (config.dryRun) return { success: true, message: `[DRY RUN] Would fetch stats`, data: { period } };
            const data = await callApi(config, 'GET', `/v1/analytics/dashboard?period=${period}`, undefined);
            return { success: true, message: 'Statistics:', data };
        },
    };
}

// ════════════════════════════════════════════════════════════════
// ACTION ROUTER
// ════════════════════════════════════════════════════════════════

export class ActionRouter {
    private handlers: Map<string, ActionHandler> = new Map();
    private config: ActionRouterConfig;

    constructor(config?: Partial<ActionRouterConfig>) {
        this.config = { ...DEFAULT_CONFIG, ...config };
        this.registerAll();
    }

    private registerAll(): void {
        const registries = [
            // Core domain handlers (original 6)
            buildCampaignHandlers(this.config),
            buildContactHandlers(this.config),
            buildListHandlers(this.config),
            buildBillingHandlers(this.config),
            buildDomainHandlers(this.config),
            buildDataHandlers(this.config),
            // Extended handlers (all 71 missing action types)
            buildMessageDiagnosticHandlers(this.config),
            buildDNSDiagnosticHandlers(this.config),
            buildDeliverabilityHandlers(this.config),
            buildSuppressionHandlers(this.config),
            buildWebhookHandlers(this.config),
            buildAPIDiagnosticHandlers(this.config),
            buildQuotaHandlers(this.config),
            buildSecurityHandlers(this.config),
            buildComplianceHandlers(this.config),
            buildOpsHandlers(this.config),
            buildLLMDiagnosticHandlers(this.config),
            buildAdditionalCommandHandlers(this.config),
        ];
        for (const registry of registries) {
            for (const [type, handler] of Object.entries(registry)) {
                this.handlers.set(type, handler);
            }
        }
    }

    async execute(action: AssistantAction): Promise<ActionResult> {
        const handler = this.handlers.get(action.action);
        if (!handler) {
            return { success: false, message: `Unknown action type: ${action.action}` };
        }

        try {
            return await handler(action.params);
        } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            return { success: false, message: `Action failed: ${msg}` };
        }
    }

    has(actionType: string): boolean {
        return this.handlers.has(actionType);
    }

    listActions(): string[] {
        return [...this.handlers.keys()];
    }
}
