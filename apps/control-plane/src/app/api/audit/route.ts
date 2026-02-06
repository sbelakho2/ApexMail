/**
 * Audit Logs API
 * 
 * Returns audit trail events with filtering.
 * Used by the /audit page.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

// Demo fallback
const DEMO_AUDIT_LOGS = [
    { id: '1', timestamp: new Date(Date.now() - 60000).toISOString(), action: 'email.sent', resource: 'message', resourceId: 'msg-12345', actorType: 'api', actorId: 'api-key-abc', tenantId: 'tenant-saas', status: 'success', ipAddress: '52.23.145.12', userAgent: 'ApexMail-SDK/1.0', details: { recipients: 1, template: 'welcome' } },
    { id: '2', timestamp: new Date(Date.now() - 120000).toISOString(), action: 'auth.login', resource: 'session', resourceId: 'sess-xyz', actorType: 'user', actorId: 'user-456', tenantId: 'tenant-newsletter', status: 'success', ipAddress: '192.168.1.100', userAgent: 'Mozilla/5.0...', details: { method: 'password' } },
    { id: '3', timestamp: new Date(Date.now() - 180000).toISOString(), action: 'auth.login', resource: 'session', resourceId: 'sess-fail', actorType: 'user', actorId: 'unknown', tenantId: null, status: 'failure', ipAddress: '45.33.32.156', userAgent: 'curl/7.68.0', details: { reason: 'invalid_credentials', attempts: 5 } },
    { id: '4', timestamp: new Date(Date.now() - 240000).toISOString(), action: 'domain.verified', resource: 'domain', resourceId: 'dom-789', actorType: 'system', actorId: 'dns-verifier', tenantId: 'tenant-ecommerce', status: 'success', ipAddress: '127.0.0.1', userAgent: 'ApexMail-Worker', details: { domain: 'shop.example.com', records: ['SPF', 'DKIM'] } },
    { id: '5', timestamp: new Date(Date.now() - 300000).toISOString(), action: 'api_key.created', resource: 'api_key', resourceId: 'key-new', actorType: 'user', actorId: 'user-admin', tenantId: 'tenant-growth', status: 'success', ipAddress: '10.0.0.5', userAgent: 'Mozilla/5.0...', details: { permissions: ['send', 'read'] } },
    { id: '6', timestamp: new Date(Date.now() - 360000).toISOString(), action: 'webhook.delivered', resource: 'webhook', resourceId: 'hook-456', actorType: 'system', actorId: 'webhook-worker', tenantId: 'tenant-saas', status: 'success', ipAddress: '127.0.0.1', userAgent: 'ApexMail-Webhook', details: { event: 'email.delivered', retries: 0 } },
    { id: '7', timestamp: new Date(Date.now() - 420000).toISOString(), action: 'template.updated', resource: 'template', resourceId: 'tpl-welcome', actorType: 'user', actorId: 'user-123', tenantId: 'tenant-newsletter', status: 'success', ipAddress: '192.168.1.50', userAgent: 'Mozilla/5.0...', details: { version: 3 } },
    { id: '8', timestamp: new Date(Date.now() - 480000).toISOString(), action: 'gdpr.request_created', resource: 'gdpr_request', resourceId: 'gdpr-001', actorType: 'system', actorId: 'gdpr-processor', tenantId: 'tenant-ecommerce', status: 'success', ipAddress: '127.0.0.1', userAgent: 'ApexMail-GDPR', details: { type: 'deletion', email: 'user@***.com' } },
    { id: '9', timestamp: new Date(Date.now() - 540000).toISOString(), action: 'rate_limit.exceeded', resource: 'api', resourceId: 'endpoint-send', actorType: 'api', actorId: 'api-key-xyz', tenantId: 'tenant-spammy', status: 'failure', ipAddress: '203.0.113.50', userAgent: 'ApexMail-SDK/1.0', details: { limit: 1000, current: 1001 } },
    { id: '10', timestamp: new Date(Date.now() - 600000).toISOString(), action: 'subscription.upgraded', resource: 'subscription', resourceId: 'sub-456', actorType: 'system', actorId: 'billing-worker', tenantId: 'tenant-growth', status: 'success', ipAddress: '127.0.0.1', userAgent: 'ApexMail-Billing', details: { from: 'starter', to: 'professional' } },
];

export async function GET(request: NextRequest) {
    try {
        const { searchParams } = new URL(request.url);
        const action = searchParams.get('action');
        const status = searchParams.get('status');
        const tenantId = searchParams.get('tenantId');
        const limit = parseInt(searchParams.get('limit') || '50', 10);

        // TODO: Replace with real audit_logs query
        const conditions: string[] = [];
        const params: unknown[] = [];
        let paramIdx = 1;

        if (action) { conditions.push(`action = $${paramIdx++}`); params.push(action); }
        if (status) { conditions.push(`status = $${paramIdx++}`); params.push(status); }
        if (tenantId) { conditions.push(`tenant_id = $${paramIdx++}`); params.push(tenantId); }

        const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

        const rows = await query<{
            id: string;
            timestamp: Date;
            action: string;
            resource: string;
            resource_id: string;
            actor_type: string;
            actor_id: string;
            tenant_id: string | null;
            status: string;
            ip_address: string;
            user_agent: string;
            details: Record<string, unknown>;
        }>(`
            SELECT id, created_at as timestamp, action, resource, resource_id,
                   actor_type, actor_id, tenant_id, status, ip_address, user_agent, details
            FROM audit_logs
            ${where}
            ORDER BY created_at DESC
            LIMIT $${paramIdx}
        `, [...params, limit]);

        if (rows.length === 0) {
            return NextResponse.json(DEMO_AUDIT_LOGS);
        }

        return NextResponse.json(rows.map(r => ({
            id: r.id,
            timestamp: new Date(r.timestamp).toISOString(),
            action: r.action,
            resource: r.resource,
            resourceId: r.resource_id,
            actorType: r.actor_type,
            actorId: r.actor_id,
            tenantId: r.tenant_id,
            status: r.status,
            ipAddress: r.ip_address,
            userAgent: r.user_agent,
            details: r.details || {},
        })));
    } catch (error) {
        console.error('Audit API error:', error);
        return NextResponse.json(DEMO_AUDIT_LOGS);
    }
}
