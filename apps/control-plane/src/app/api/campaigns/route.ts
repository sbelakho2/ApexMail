/**
 * Campaigns API
 * 
 * Returns campaign list with performance stats.
 * Used by the /campaigns page.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

// Demo fallback
const DEMO_CAMPAIGNS = [
    {
        id: '1', name: 'SaaS Founders Outreach', description: 'Cold outreach to newly funded SaaS startups', status: 'active',
        fromEmail: 'alex@apexmail.eu', fromName: 'Alex from ApexMail',
        sequence: [
            { id: '1a', type: 'email', subject: 'Quick question about your email infrastructure', sent: 450, opened: 180 },
            { id: '1b', type: 'delay', delayDays: 3 },
            { id: '1c', type: 'email', subject: 'Following up on email deliverability', sent: 380, opened: 152 },
            { id: '1d', type: 'delay', delayDays: 5 },
            { id: '1e', type: 'email', subject: 'Last chance: Free email audit offer', sent: 290, opened: 87 },
        ],
        stats: { enrolled: 500, emailsSent: 1120, opened: 419, clicked: 87, replied: 32, unsubscribed: 12 },
        createdAt: new Date(Date.now() - 86400000 * 30).toISOString(),
        startedAt: new Date(Date.now() - 86400000 * 25).toISOString(),
    },
    {
        id: '2', name: 'Product Hunt Launch Follow-up', description: 'Follow-up sequence for Product Hunt visitors', status: 'active',
        fromEmail: 'team@apexmail.eu', fromName: 'ApexMail Team',
        sequence: [
            { id: '2a', type: 'email', subject: 'Thanks for checking out ApexMail!', sent: 890, opened: 534 },
            { id: '2b', type: 'delay', delayDays: 1 },
            { id: '2c', type: 'email', subject: 'Your exclusive 30% discount code', sent: 720, opened: 360 },
        ],
        stats: { enrolled: 920, emailsSent: 1610, opened: 894, clicked: 234, replied: 67, unsubscribed: 8 },
        createdAt: new Date(Date.now() - 86400000 * 14).toISOString(),
        startedAt: new Date(Date.now() - 86400000 * 12).toISOString(),
    },
    {
        id: '3', name: 'Enterprise Nurture Sequence', description: 'Long-term nurture for enterprise prospects', status: 'paused',
        fromEmail: 'enterprise@apexmail.eu', fromName: 'Enterprise Team',
        sequence: [
            { id: '3a', type: 'email', subject: 'Enterprise email at scale', sent: 120, opened: 48 },
            { id: '3b', type: 'delay', delayDays: 7 },
            { id: '3c', type: 'email', subject: 'Case study: How TechCorp scaled', sent: 85, opened: 34 },
        ],
        stats: { enrolled: 150, emailsSent: 205, opened: 82, clicked: 18, replied: 5, unsubscribed: 2 },
        createdAt: new Date(Date.now() - 86400000 * 45).toISOString(),
        startedAt: new Date(Date.now() - 86400000 * 40).toISOString(),
    },
    {
        id: '4', name: 'New Feature Announcement', description: 'Announce new AI features to existing leads', status: 'draft',
        fromEmail: 'updates@apexmail.eu', fromName: 'ApexMail Updates',
        sequence: [
            { id: '4a', type: 'email', subject: 'Introducing AI-powered email insights', sent: 0, opened: 0 },
        ],
        stats: { enrolled: 0, emailsSent: 0, opened: 0, clicked: 0, replied: 0, unsubscribed: 0 },
        createdAt: new Date(Date.now() - 86400000 * 2).toISOString(),
        startedAt: null,
    },
];

export async function GET() {
    try {
        // TODO: Replace with DB query when campaigns table is available
        const rows = await query<{
            id: string;
            name: string;
            status: string;
            stats: Record<string, unknown>;
            created_at: Date;
            started_at: Date | null;
        }>(`
            SELECT id, name, status, stats, created_at, started_at
            FROM campaigns
            ORDER BY created_at DESC
        `);

        if (rows.length === 0) {
            return NextResponse.json(DEMO_CAMPAIGNS);
        }

        return NextResponse.json(rows.map(r => ({
            id: r.id,
            name: r.name,
            status: r.status,
            description: '',
            fromEmail: '',
            fromName: '',
            sequence: [],
            stats: r.stats || { enrolled: 0, emailsSent: 0, opened: 0, clicked: 0, replied: 0, unsubscribed: 0 },
            createdAt: new Date(r.created_at).toISOString(),
            startedAt: r.started_at ? new Date(r.started_at).toISOString() : null,
        })));
    } catch (error) {
        console.error('Campaigns API error:', error);
        return NextResponse.json(DEMO_CAMPAIGNS);
    }
}
