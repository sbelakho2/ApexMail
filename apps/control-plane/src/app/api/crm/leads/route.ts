/**
 * CRM Pipeline API
 * 
 * Returns leads for the Kanban pipeline view.
 * Used by the /crm page.
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
        const hasSalesLeads = await tableExists('sales_leads');
        if (!hasSalesLeads) {
            return NextResponse.json([]);
        }

        // FIX-500-302: Add pagination support
        const url = new URL(request.url);
        const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 1), 200);
        const offset = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);

        const rows = await query<{
            id: string;
            company_name: string;
            domain: string;
            contact_email: string | null;
            contact_name: string | null;
            status: string;
            score: number;
            source: string | null;
            tags: unknown;
            created_at: Date;
            updated_at: Date;
        }>(`
            SELECT id, company_name, domain, contact_email, contact_name,
                   status, score, source, COALESCE(tags, '[]'::jsonb) as tags,
                   created_at, updated_at
            FROM sales_leads
            ORDER BY score DESC, created_at DESC
            LIMIT $1 OFFSET $2
        `, [limit, offset]);

        return NextResponse.json(rows.map(r => ({
            id: r.id,
            companyName: r.company_name,
            domain: r.domain,
            contactEmail: r.contact_email,
            contactName: r.contact_name,
            stage: r.status,
            score: r.score,
            source: r.source ?? 'unknown',
            lastActivity: new Date(r.updated_at).toISOString(),
            createdAt: new Date(r.created_at).toISOString(),
            tags: Array.isArray(r.tags) ? r.tags : [],
        })));
    } catch (error) {
        console.error('CRM API error:', error);
        // FIX-500-018: Return 500 instead of masking errors with demo data
        return NextResponse.json({ error: 'Failed to fetch leads' }, { status: 500 });
    }
}
