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
            contact_email: string | null;
            contact_name: string | null;
            contact_title: string | null;
            company_size: string | null;
            estimated_deal_value: number | null;
            last_contacted_at: Date | null;
            next_follow_up_at: Date | null;
            assigned_to: string | null;
            icp_fit: string | null;
            linkedin_url: string | null;
            website_traffic: string | null;
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
                contact_email,
                contact_name,
                contact_title,
                company_size,
                estimated_deal_value,
                last_contacted_at,
                next_follow_up_at,
                assigned_to,
                icp_fit,
                linkedin_url,
                website_traffic,
                created_at
            FROM sales_leads
            ORDER BY score DESC NULLS LAST, created_at DESC
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
            status: row.status ?? 'new',
            tags: row.tags ? JSON.parse(row.tags) : [],
            contactEmail: row.contact_email ?? null,
            contactName: row.contact_name ?? null,
            contactTitle: row.contact_title ?? null,
            companySize: row.company_size ?? null,
            estimatedDealValue: row.estimated_deal_value ?? null,
            lastContactedAt: row.last_contacted_at ? new Date(row.last_contacted_at).toISOString() : null,
            nextFollowUpAt: row.next_follow_up_at ? new Date(row.next_follow_up_at).toISOString() : null,
            engagementHistory: [],
            notes: row.notes ?? '',
            assignedTo: row.assigned_to ?? null,
            icpFit: row.icp_fit ?? 'unscored',
            linkedinUrl: row.linkedin_url ?? null,
            websiteTraffic: row.website_traffic ?? null,
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
