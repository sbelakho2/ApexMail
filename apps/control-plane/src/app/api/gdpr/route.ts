/**
 * GDPR Requests API
 * 
 * Returns GDPR data subject requests with status tracking.
 * Used by the /gdpr page.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

// Demo fallback
const DEMO_REQUESTS = [
    { id: 'gdpr-001', type: 'deletion', status: 'pending', email: 'user1@example.com', tenantId: 'tenant-saas', tenantName: 'SaaS Notifications', createdAt: new Date(Date.now() - 172800000).toISOString(), verifiedAt: null, completedAt: null, slaDeadline: new Date(Date.now() + 2419200000).toISOString(), notes: null },
    { id: 'gdpr-002', type: 'access', status: 'verified', email: 'user2@corp.com', tenantId: 'tenant-newsletter', tenantName: 'Newsletter Pro', createdAt: new Date(Date.now() - 259200000).toISOString(), verifiedAt: new Date(Date.now() - 86400000).toISOString(), completedAt: null, slaDeadline: new Date(Date.now() + 2160000000).toISOString(), notes: 'User verified via double opt-in' },
    { id: 'gdpr-003', type: 'deletion', status: 'processing', email: 'john.doe@test.com', tenantId: 'tenant-ecommerce', tenantName: 'E-Commerce Store', createdAt: new Date(Date.now() - 604800000).toISOString(), verifiedAt: new Date(Date.now() - 518400000).toISOString(), completedAt: null, slaDeadline: new Date(Date.now() + 1814400000).toISOString(), notes: 'Deleting from all systems' },
    { id: 'gdpr-004', type: 'portability', status: 'completed', email: 'jane@startup.io', tenantId: 'tenant-growth', tenantName: 'GrowthHack Inc', createdAt: new Date(Date.now() - 1209600000).toISOString(), verifiedAt: new Date(Date.now() - 1123200000).toISOString(), completedAt: new Date(Date.now() - 864000000).toISOString(), slaDeadline: new Date(Date.now() + 1209600000).toISOString(), notes: 'Data export sent to user' },
    { id: 'gdpr-005', type: 'rectification', status: 'completed', email: 'mike@company.com', tenantId: 'tenant-saas', tenantName: 'SaaS Notifications', createdAt: new Date(Date.now() - 2592000000).toISOString(), verifiedAt: new Date(Date.now() - 2505600000).toISOString(), completedAt: new Date(Date.now() - 2419200000).toISOString(), slaDeadline: new Date(Date.now() - 172800000).toISOString(), notes: 'Updated email address per request' },
];

export async function GET(request: Request) {
    try {
        // FIX-500-302: Add pagination support
        const url = new URL(request.url);
        const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 1), 200);
        const offset = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);

        const rows = await query<{
            id: string;
            type: string;
            status: string;
            email: string;
            tenant_id: string;
            tenant_name: string;
            created_at: Date;
            verified_at: Date | null;
            completed_at: Date | null;
            sla_deadline: Date;
            notes: string | null;
        }>(`
            SELECT g.id, g.type, g.status, g.email, g.tenant_id,
                   COALESCE(t.name, g.tenant_id) as tenant_name,
                   g.created_at, g.verified_at, g.completed_at,
                   g.sla_deadline, g.notes
            FROM gdpr_requests g
            LEFT JOIN tenants t ON t.id = g.tenant_id
            ORDER BY g.created_at DESC
            LIMIT $1 OFFSET $2
        `, [limit, offset]);

        if (rows.length === 0) {
            return NextResponse.json(DEMO_REQUESTS);
        }

        return NextResponse.json(rows.map(r => ({
            id: r.id,
            type: r.type,
            status: r.status,
            email: r.email,
            tenantId: r.tenant_id,
            tenantName: r.tenant_name,
            createdAt: new Date(r.created_at).toISOString(),
            verifiedAt: r.verified_at ? new Date(r.verified_at).toISOString() : null,
            completedAt: r.completed_at ? new Date(r.completed_at).toISOString() : null,
            slaDeadline: new Date(r.sla_deadline).toISOString(),
            notes: r.notes,
        })));
    } catch (error) {
        console.error('GDPR API error:', error);
        // FIX-018: Return a proper error response instead of silently
        // falling back to demo data. Serving fake GDPR compliance data
        // in production masks real failures and misleads operators.
        return NextResponse.json(
            { error: 'Failed to fetch GDPR requests' },
            { status: 500 }
        );
    }
}
