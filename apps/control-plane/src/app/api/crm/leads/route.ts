/**
 * CRM Pipeline API
 * 
 * Returns leads for the Kanban pipeline view.
 * Used by the /crm page.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

// Demo fallback
const DEMO_LEADS = [
    { id: '1', companyName: 'TechCorp Inc', domain: 'techcorp.io', contactEmail: 'ceo@techcorp.io', contactName: 'John Smith', stage: 'prospect', score: 85, source: 'Product Hunt', lastActivity: new Date(Date.now() - 3600000).toISOString(), createdAt: new Date(Date.now() - 86400000 * 3).toISOString(), tags: ['SaaS', 'Series A'] },
    { id: '2', companyName: 'StartupXYZ', domain: 'startupxyz.com', contactEmail: 'founder@startupxyz.com', contactName: 'Jane Doe', stage: 'outreach', score: 72, source: 'G2', lastActivity: new Date(Date.now() - 7200000).toISOString(), createdAt: new Date(Date.now() - 86400000 * 5).toISOString(), tags: ['MarTech'] },
    { id: '3', companyName: 'GrowthCo', domain: 'growthco.io', contactEmail: 'sales@growthco.io', contactName: 'Mike Johnson', stage: 'engaged', score: 91, source: 'Capterra', lastActivity: new Date(Date.now() - 1800000).toISOString(), createdAt: new Date(Date.now() - 86400000 * 7).toISOString(), tags: ['Enterprise', 'High Value'] },
    { id: '4', companyName: 'DataDriven Ltd', domain: 'datadriven.co', contactEmail: 'cto@datadriven.co', contactName: 'Sarah Williams', stage: 'demo_scheduled', score: 88, source: 'Crunchbase', lastActivity: new Date(Date.now() - 900000).toISOString(), createdAt: new Date(Date.now() - 86400000 * 10).toISOString(), tags: ['Data', 'Analytics'] },
    { id: '5', companyName: 'CloudFirst', domain: 'cloudfirst.dev', contactEmail: 'hello@cloudfirst.dev', contactName: 'Alex Chen', stage: 'proposal', score: 94, source: 'G2', lastActivity: new Date(Date.now() - 3600000).toISOString(), createdAt: new Date(Date.now() - 86400000 * 14).toISOString(), tags: ['Cloud', 'DevOps'] },
    { id: '6', companyName: 'ScaleUp Hub', domain: 'scaleup.io', contactEmail: null, contactName: null, stage: 'prospect', score: 65, source: 'Product Hunt', lastActivity: new Date(Date.now() - 86400000).toISOString(), createdAt: new Date(Date.now() - 86400000 * 2).toISOString(), tags: ['SMB'] },
    { id: '7', companyName: 'MailPro Systems', domain: 'mailpro.net', contactEmail: 'team@mailpro.net', contactName: 'Lisa Brown', stage: 'negotiation', score: 96, source: 'Referral', lastActivity: new Date(Date.now() - 1800000).toISOString(), createdAt: new Date(Date.now() - 86400000 * 20).toISOString(), tags: ['Enterprise', 'Priority'] },
    { id: '8', companyName: 'FastGrow Inc', domain: 'fastgrow.com', contactEmail: 'sales@fastgrow.com', contactName: 'Tom Harris', stage: 'closed_won', score: 98, source: 'Demo Request', lastActivity: new Date(Date.now() - 86400000 * 2).toISOString(), createdAt: new Date(Date.now() - 86400000 * 30).toISOString(), tags: ['Converted'] },
    { id: '9', companyName: 'OldSchool Ltd', domain: 'oldschool.biz', contactEmail: 'info@oldschool.biz', contactName: 'Bob Wilson', stage: 'closed_lost', score: 45, source: 'Cold Outreach', lastActivity: new Date(Date.now() - 86400000 * 5).toISOString(), createdAt: new Date(Date.now() - 86400000 * 25).toISOString(), tags: ['Lost - Pricing'] },
];

export async function GET() {
    try {
        // TODO: Replace with real leads table query
        const rows = await query<{
            id: string;
            company_name: string;
            domain: string;
            email: string | null;
            contact_name: string | null;
            stage: string;
            score: number;
            source: string;
            tags: string[];
            created_at: Date;
            updated_at: Date;
        }>(`
            SELECT id, company_name, domain, email, contact_name,
                   stage, score, source, COALESCE(tags, '{}') as tags,
                   created_at, updated_at
            FROM leads
            ORDER BY score DESC, created_at DESC
        `);

        if (rows.length === 0) {
            return NextResponse.json(DEMO_LEADS);
        }

        return NextResponse.json(rows.map(r => ({
            id: r.id,
            companyName: r.company_name,
            domain: r.domain,
            contactEmail: r.email,
            contactName: r.contact_name,
            stage: r.stage,
            score: r.score,
            source: r.source,
            lastActivity: new Date(r.updated_at).toISOString(),
            createdAt: new Date(r.created_at).toISOString(),
            tags: r.tags || [],
        })));
    } catch (error) {
        console.error('CRM API error:', error);
        return NextResponse.json(DEMO_LEADS);
    }
}
