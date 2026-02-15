/**
 * GDPR Requests API
 * 
 * Returns GDPR data subject requests with status tracking.
 * Used by the /gdpr page.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

async function tableExists(tableName: string): Promise<boolean> {
    const rows = await query<{ exists: boolean }>(
        `SELECT to_regclass($1) IS NOT NULL as exists`,
        [`public.${tableName}`]
    );
    return rows[0]?.exists ?? false;
}

export async function GET(request: Request) {
    try {
        const hasGdprRequests = await tableExists('gdpr_requests');
        if (!hasGdprRequests) {
            return NextResponse.json([]);
        }

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
