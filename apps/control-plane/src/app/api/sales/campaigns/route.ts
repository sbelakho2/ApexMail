/**
 * Sales Campaigns API Route
 *
 * GET: List all campaigns with status, metrics, and lead counts
 * POST: Create a new campaign
 * PATCH: Update campaign (pause, resume, archive)
 *
 * Improvement #44: Campaign listing and management
 * Improvement #45: Campaign status tracking
 * Improvement #46: Campaign analytics (opens, clicks, replies)
 */

import { NextRequest, NextResponse } from 'next/server';
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
        const hasCampaigns = await tableExists('sales_campaigns');
        if (!hasCampaigns) {
            return NextResponse.json({ campaigns: [], total: 0 });
        }

        const campaignRows = await query<{
            id: string;
            name: string;
            offer_id: string;
            template_id: string;
            status: string;
            lead_count: string;
            sent_count: string;
            open_count: string;
            click_count: string;
            reply_count: string;
            bounce_count: string;
            created_at: Date;
            started_at: Date | null;
            completed_at: Date | null;
        }>(`
            SELECT 
                c.id,
                c.name,
                c.offer_id,
                c.template_id,
                c.status,
                COUNT(cl.lead_id)::text as lead_count,
                COALESCE(SUM(CASE WHEN cl.sent_at IS NOT NULL THEN 1 ELSE 0 END), 0)::text as sent_count,
                COALESCE(SUM(CASE WHEN cl.opened_at IS NOT NULL THEN 1 ELSE 0 END), 0)::text as open_count,
                COALESCE(SUM(CASE WHEN cl.clicked_at IS NOT NULL THEN 1 ELSE 0 END), 0)::text as click_count,
                COALESCE(SUM(CASE WHEN cl.replied_at IS NOT NULL THEN 1 ELSE 0 END), 0)::text as reply_count,
                COALESCE(SUM(CASE WHEN cl.bounced_at IS NOT NULL THEN 1 ELSE 0 END), 0)::text as bounce_count,
                c.created_at,
                c.started_at,
                c.completed_at
            FROM sales_campaigns c
            LEFT JOIN sales_campaign_leads cl ON cl.campaign_id = c.id
            GROUP BY c.id
            ORDER BY c.created_at DESC
        `);

        const campaigns = campaignRows.map(row => ({
            id: row.id,
            name: row.name,
            offerId: row.offer_id,
            templateId: row.template_id,
            status: row.status,
            leads: parseInt(row.lead_count, 10),
            metrics: {
                sent: parseInt(row.sent_count, 10),
                opened: parseInt(row.open_count, 10),
                clicked: parseInt(row.click_count, 10),
                replied: parseInt(row.reply_count, 10),
                bounced: parseInt(row.bounce_count, 10),
            },
            createdAt: new Date(row.created_at).toISOString(),
            startedAt: row.started_at ? new Date(row.started_at).toISOString() : null,
            completedAt: row.completed_at ? new Date(row.completed_at).toISOString() : null,
        }));

        return NextResponse.json({
            campaigns,
            total: campaigns.length,
        });
    } catch (error) {
        console.error('Campaigns API error:', error);
        return NextResponse.json({ error: 'Failed to fetch campaigns' }, { status: 500 });
    }
}

export async function PATCH(request: NextRequest) {
    try {
        const body = await request.json();
        const { campaignId, action } = body;

        if (!campaignId) {
            return NextResponse.json({ error: 'Campaign ID required' }, { status: 400 });
        }

        const validActions = ['pause', 'resume', 'archive', 'cancel'];
        if (!action || !validActions.includes(action)) {
            return NextResponse.json(
                { error: `Invalid action. Must be one of: ${validActions.join(', ')}` },
                { status: 400 }
            );
        }

        const statusMap: Record<string, string> = {
            pause: 'paused',
            resume: 'active',
            archive: 'archived',
            cancel: 'cancelled',
        };

        const hasCampaigns = await tableExists('sales_campaigns');
        if (!hasCampaigns) {
            return NextResponse.json({ error: 'Campaigns table not found' }, { status: 404 });
        }

        await query(
            `UPDATE sales_campaigns SET status = $1, updated_at = NOW() WHERE id = $2`,
            [statusMap[action], campaignId]
        );

        return NextResponse.json({
            success: true,
            campaignId,
            newStatus: statusMap[action],
        });
    } catch (error) {
        console.error('Campaign update API error:', error);
        return NextResponse.json({ error: 'Failed to update campaign' }, { status: 500 });
    }
}
