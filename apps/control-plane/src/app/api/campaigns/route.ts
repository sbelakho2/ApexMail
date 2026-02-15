/**
 * Campaigns API
 * 
 * Returns campaign list with performance stats.
 * Used by the /campaigns page.
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
        const hasCampaigns = await tableExists('drip_campaigns');
        if (!hasCampaigns) {
            return NextResponse.json([]);
        }

        // FIX-500-302: Add pagination support
        const url = new URL(request.url);
        const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 1), 200);
        const offset = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);

        const rows = await query<{
            id: string;
            name: string;
            description: string | null;
            status: string;
            from_email: string;
            from_name: string;
            sequence_steps: unknown[];
            stats: {
                totalEnrolled?: number;
                emailsSent?: number;
                emailsOpened?: number;
                emailsClicked?: number;
                repliesReceived?: number;
                unsubscribed?: number;
            } | null;
            created_at: Date;
            started_at: Date | null;
        }>(`
            SELECT id, name, description, status, from_email, from_name, sequence_steps, stats, created_at, started_at
            FROM drip_campaigns
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
        `, [limit, offset]);

        return NextResponse.json(rows.map(r => ({
            id: r.id,
            name: r.name,
            status: r.status,
            description: r.description ?? '',
            fromEmail: r.from_email,
            fromName: r.from_name,
            sequence: Array.isArray(r.sequence_steps) ? r.sequence_steps : [],
            stats: {
                enrolled: r.stats?.totalEnrolled ?? 0,
                emailsSent: r.stats?.emailsSent ?? 0,
                opened: r.stats?.emailsOpened ?? 0,
                clicked: r.stats?.emailsClicked ?? 0,
                replied: r.stats?.repliesReceived ?? 0,
                unsubscribed: r.stats?.unsubscribed ?? 0,
            },
            createdAt: new Date(r.created_at).toISOString(),
            startedAt: r.started_at ? new Date(r.started_at).toISOString() : null,
        })));
    } catch (error) {
        console.error('Campaigns API error:', error);
        // FIX-500-018: Return 500 instead of masking errors with demo data
        return NextResponse.json({ error: 'Failed to fetch campaigns' }, { status: 500 });
    }
}
