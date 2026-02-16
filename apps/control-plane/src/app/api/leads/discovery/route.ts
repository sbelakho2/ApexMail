/**
 * Lead Discovery API
 * 
 * Returns discovery sources and discovered leads.
 * Used by the /leads page.
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

export async function GET() {
    try {
        const hasSalesLeads = await tableExists('sales_leads');
        if (!hasSalesLeads) {
            return NextResponse.json({ sources: [], leads: [] });
        }

        const [sourceRows, leadRows] = await Promise.all([
            query<{ source: string; leads_found: string; last_run: Date | null }>(`
                SELECT
                    COALESCE(source, 'unknown') as source,
                    COUNT(*)::text as leads_found,
                    MAX(created_at) as last_run
                FROM sales_leads
                GROUP BY COALESCE(source, 'unknown')
                ORDER BY leads_found::int DESC
            `),
            query<{
                id: string;
                company_name: string;
                domain: string;
                source: string | null;
                industry: string | null;
                notes: string | null;
                status: string;
                created_at: Date;
            }>(`
                SELECT id, company_name, domain, source, industry, notes, status, created_at
                FROM sales_leads
                ORDER BY created_at DESC
                LIMIT 100
            `),
        ]);

        const sources = sourceRows.map((row) => ({
            id: row.source,
            name: row.source,
            icon: 'Source',
            enabled: true,
            lastRun: row.last_run ? new Date(row.last_run).toISOString() : null,
            leadsFound: parseInt(row.leads_found, 10),
            status: 'idle',
        }));

        const leads = leadRows.map((row) => ({
            id: row.id,
            companyName: row.company_name,
            domain: row.domain,
            source: row.source ?? 'unknown',
            category: row.industry ?? 'General',
            description: row.notes ?? '',
            foundAt: new Date(row.created_at).toISOString(),
            imported: row.status !== 'new',
        }));

        return NextResponse.json({
            sources,
            leads,
        });
    } catch (error) {
        console.error('Leads discovery API error:', error);
        // FIX-500-018: Return 500 instead of masking errors with demo data
        return NextResponse.json({ error: 'Failed to fetch lead discovery data' }, { status: 500 });
    }
}
