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

type AuditMetadata = Record<string, unknown>;

export async function GET(request: NextRequest) {
    try {
        const { searchParams } = new URL(request.url);
        const action = searchParams.get('action');
        const status = searchParams.get('status');
        const tenantId = searchParams.get('tenantId');
        const userId = searchParams.get('userId');
        const resourceType = searchParams.get('resourceType');
        const limit = Math.max(1, Math.min(parseInt(searchParams.get('limit') || '50', 10) || 50, 200));
        const offset = Math.max(0, parseInt(searchParams.get('offset') || '0', 10) || 0);

        const conditions: string[] = [];
        const params: unknown[] = [];
        let paramIdx = 1;

        if (action) { conditions.push(`action = $${paramIdx++}`); params.push(action); }
        if (tenantId) { conditions.push(`tenant_id = $${paramIdx++}`); params.push(tenantId); }
        if (userId) { conditions.push(`user_id = $${paramIdx++}`); params.push(userId); }
        if (resourceType) { conditions.push(`resource_type = $${paramIdx++}`); params.push(resourceType); }
        if (status) {
            conditions.push(`COALESCE(metadata->>'status', 'success') = $${paramIdx++}`);
            params.push(status);
        }

        const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

        const rows = await query<{
            id: string;
            timestamp: Date;
            action: string;
            resource_type: string;
            resource_id: string;
            user_id: string | null;
            tenant_id: string | null;
            ip_address: string | null;
            user_agent: string | null;
            metadata: AuditMetadata | null;
        }>(`
            SELECT id, timestamp, action, resource_type, resource_id,
                   user_id, tenant_id, ip_address, user_agent, metadata
            FROM audit_logs
            ${where}
            ORDER BY timestamp DESC, id DESC
            LIMIT $${paramIdx} OFFSET $${paramIdx + 1}
        `, [...params, limit, offset]);

        return NextResponse.json(rows.map(r => ({
            id: r.id,
            timestamp: new Date(r.timestamp).toISOString(),
            action: r.action,
            resource: r.resource_type,
            resourceId: r.resource_id,
            actorType: r.user_id ? 'user' : 'system',
            actorId: r.user_id ?? 'system',
            tenantId: r.tenant_id,
            status: typeof r.metadata?.['status'] === 'string' ? r.metadata['status'] : 'success',
            ipAddress: r.ip_address,
            userAgent: r.user_agent,
            details: (r.metadata && typeof r.metadata['details'] === 'object' && r.metadata['details'] !== null)
                ? (r.metadata['details'] as Record<string, unknown>)
                : (r.metadata ?? {}),
        })));
    } catch (error) {
        console.error('Audit API error:', error);
        // FIX-500-298: Return 500 instead of masking errors with demo data
        return NextResponse.json({ error: 'Failed to fetch audit logs' }, { status: 500 });
    }
}
