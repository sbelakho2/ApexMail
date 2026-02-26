/**
 * Sales Leads API Route
 * 
 * Returns discovered leads with email provider detection.
 * Used by the automated sales system page.
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
            return NextResponse.json({ leads: [], stats: null });
        }

        const url = new URL(request.url);
        const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '100', 10) || 100, 1), 500);
        const offset = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);

        const leadRows = await query<{
            id: string;
            company_name: string;
            domain: string;
            source: string | null;
            industry: string | null;
            notes: string | null;
            status: string;
            email_provider: string | null;
            mx_records: string | null;
            score: number | null;
            tags: string | null;
            created_at: Date;
        }>(`
            SELECT 
                id, 
                company_name, 
                domain, 
                source, 
                industry, 
                notes, 
                status, 
                email_provider,
                mx_records,
                score,
                tags,
                created_at
            FROM sales_leads
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
        `, [limit, offset]);

        // Aggregate stats
        const statsRows = await query<{
            total: string;
            with_mx: string;
        }>(`
            SELECT 
                COUNT(*)::text as total,
                COUNT(*) FILTER (WHERE mx_records IS NOT NULL AND mx_records != '[]')::text as with_mx
            FROM sales_leads
        `);

        const providerCountRows = await query<{
            provider: string;
            count: string;
        }>(`
            SELECT 
                COALESCE(email_provider, 'Unknown') as provider,
                COUNT(*)::text as count
            FROM sales_leads
            GROUP BY COALESCE(email_provider, 'Unknown')
            ORDER BY count DESC
        `);

        const sourceCountRows = await query<{
            source: string;
            count: string;
        }>(`
            SELECT 
                COALESCE(source, 'unknown') as source,
                COUNT(*)::text as count
            FROM sales_leads
            GROUP BY COALESCE(source, 'unknown')
            ORDER BY count DESC
        `);

        const leads = leadRows.map((row) => ({
            id: row.id,
            companyName: row.company_name,
            domain: row.domain,
            source: row.source ?? 'unknown',
            category: row.industry ?? 'General',
            description: row.notes ?? '',
            foundAt: new Date(row.created_at).toISOString(),
            emailProvider: row.email_provider,
            mxRecords: row.mx_records ? JSON.parse(row.mx_records) : [],
            score: row.score ?? 50,
            status: row.status as 'new' | 'contacted' | 'qualified' | 'nurturing',
            tags: row.tags ? JSON.parse(row.tags) : [],
        }));

        const stats = {
            totalScraped: parseInt(statsRows[0]?.total ?? '0', 10),
            totalWithMx: parseInt(statsRows[0]?.with_mx ?? '0', 10),
            byProvider: Object.fromEntries(
                providerCountRows.map(r => [r.provider, parseInt(r.count, 10)])
            ),
            bySource: Object.fromEntries(
                sourceCountRows.map(r => [r.source, parseInt(r.count, 10)])
            ),
        };

        return NextResponse.json({ leads, stats });
    } catch (error) {
        console.error('Sales leads API error:', error);
        return NextResponse.json({ error: 'Failed to fetch sales leads' }, { status: 500 });
    }
}
