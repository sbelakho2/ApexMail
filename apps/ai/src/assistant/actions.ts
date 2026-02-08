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
    /** Auth token for internal service-to-service calls */
    serviceToken?: string;
    /** Request timeout in ms */
    timeoutMs: number;
    /** Dry-run mode — simulate actions without executing */
    dryRun: boolean;
}

const DEFAULT_CONFIG: ActionRouterConfig = {
    apiBaseUrl: process.env.API_BASE_URL ?? 'http://localhost:3010',
    serviceToken: process.env.SERVICE_TOKEN,
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

async function callInternalApi(
    config: ActionRouterConfig,
    method: string,
    path: string,
    body?: Record<string, unknown>,
): Promise<Record<string, unknown>> {
    const url = `${config.apiBaseUrl}${path}`;
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (config.serviceToken) headers['Authorization'] = `Bearer ${config.serviceToken}`;

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
            const data = await callInternalApi(config, 'POST', '/api/export', { type, format });
            return { success: true, message: `Export initiated. You'll receive a download link when ready.`, data };
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
            buildCampaignHandlers(this.config),
            buildContactHandlers(this.config),
            buildListHandlers(this.config),
            buildBillingHandlers(this.config),
            buildDomainHandlers(this.config),
            buildDataHandlers(this.config),
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
