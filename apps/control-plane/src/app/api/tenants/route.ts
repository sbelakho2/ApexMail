/**
 * Tenants List API
 * 
 * Returns all tenants with their status, plan, risk level, and metrics.
 * Used by the /tenants page.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

// Demo fallback data used when the database is unavailable
const DEMO_TENANTS = [
    { id: 'tenant-1', name: 'TechCorp Solutions', domain: 'techcorp.io', email: 'admin@techcorp.io', plan: 'enterprise', status: 'active', riskLevel: 'low', metrics: { emailsSentMonth: 2500000, emailsSentTotal: 45000000, domainsVerified: 5, apiKeys: 8, teamMembers: 12 }, billing: { mrr: 1299, nextBillingDate: new Date(Date.now() + 1209600000).toISOString(), paymentMethod: 'Visa •••• 4242' }, createdAt: new Date(Date.now() - 31536000000).toISOString(), lastActiveAt: new Date(Date.now() - 300000).toISOString() },
    { id: 'tenant-2', name: 'Newsletter Pro', domain: 'newsletter.pro', email: 'team@newsletter.pro', plan: 'professional', status: 'active', riskLevel: 'medium', metrics: { emailsSentMonth: 320000, emailsSentTotal: 8900000, domainsVerified: 2, apiKeys: 3, teamMembers: 4 }, billing: { mrr: 129, nextBillingDate: new Date(Date.now() + 604800000).toISOString(), paymentMethod: 'Mastercard •••• 5555' }, createdAt: new Date(Date.now() - 15768000000).toISOString(), lastActiveAt: new Date(Date.now() - 3600000).toISOString() },
    { id: 'tenant-3', name: 'StartupXYZ', domain: 'startupxyz.com', email: 'founder@startupxyz.com', plan: 'professional', status: 'active', riskLevel: 'low', metrics: { emailsSentMonth: 45000, emailsSentTotal: 890000, domainsVerified: 1, apiKeys: 2, teamMembers: 2 }, billing: { mrr: 59, nextBillingDate: new Date(Date.now() + 1814400000).toISOString(), paymentMethod: 'PayPal' }, createdAt: new Date(Date.now() - 7884000000).toISOString(), lastActiveAt: new Date(Date.now() - 7200000).toISOString() },
    { id: 'tenant-4', name: 'E-Commerce Store', domain: 'shop.example.com', email: 'admin@shop.example.com', plan: 'enterprise', status: 'active', riskLevel: 'low', metrics: { emailsSentMonth: 650000, emailsSentTotal: 12500000, domainsVerified: 3, apiKeys: 4, teamMembers: 6 }, billing: { mrr: 399, nextBillingDate: new Date(Date.now() + 2419200000).toISOString(), paymentMethod: 'Visa •••• 1234' }, createdAt: new Date(Date.now() - 23652000000).toISOString(), lastActiveAt: new Date(Date.now() - 1800000).toISOString() },
    { id: 'tenant-5', name: 'Spammy Marketing', domain: 'spammy.io', email: 'marketing@spammy.io', plan: 'starter', status: 'suspended', riskLevel: 'critical', metrics: { emailsSentMonth: 0, emailsSentTotal: 890000, domainsVerified: 1, apiKeys: 1, teamMembers: 1 }, billing: { mrr: 0, nextBillingDate: null, paymentMethod: 'Visa •••• 9999' }, createdAt: new Date(Date.now() - 5256000000).toISOString(), lastActiveAt: new Date(Date.now() - 604800000).toISOString() },
    { id: 'tenant-6', name: 'GrowthHack Inc', domain: 'growthhack.co', email: 'team@growthhack.co', plan: 'professional', status: 'active', riskLevel: 'high', metrics: { emailsSentMonth: 1200000, emailsSentTotal: 15600000, domainsVerified: 2, apiKeys: 5, teamMembers: 3 }, billing: { mrr: 129, nextBillingDate: new Date(Date.now() + 1209600000).toISOString(), paymentMethod: 'Amex •••• 8888' }, createdAt: new Date(Date.now() - 10512000000).toISOString(), lastActiveAt: new Date(Date.now() - 600000).toISOString() },
    { id: 'tenant-7', name: 'New Startup', domain: 'newstartup.dev', email: 'hello@newstartup.dev', plan: 'free', status: 'trialing', riskLevel: 'low', metrics: { emailsSentMonth: 1200, emailsSentTotal: 1200, domainsVerified: 1, apiKeys: 1, teamMembers: 1 }, billing: { mrr: 0, nextBillingDate: new Date(Date.now() + 604800000).toISOString(), paymentMethod: null }, createdAt: new Date(Date.now() - 604800000).toISOString(), lastActiveAt: new Date(Date.now() - 43200000).toISOString() },
    { id: 'tenant-8', name: 'Old Company', domain: 'oldcompany.biz', email: 'info@oldcompany.biz', plan: 'starter', status: 'churned', riskLevel: 'low', metrics: { emailsSentMonth: 0, emailsSentTotal: 234000, domainsVerified: 1, apiKeys: 0, teamMembers: 1 }, billing: { mrr: 0, nextBillingDate: null, paymentMethod: null }, createdAt: new Date(Date.now() - 31536000000).toISOString(), lastActiveAt: new Date(Date.now() - 7776000000).toISOString() },
];

export async function GET() {
    try {
        // TODO: Replace with DB query once tenants table schema is finalized
        const rows = await query<{
            id: string;
            name: string;
            domain: string;
            email: string;
            plan: string;
            status: string;
            risk_score: number;
            suspended: boolean;
            created_at: Date;
            last_active_at: Date;
        }>(`
            SELECT 
                t.id, t.name, t.domain, t.email, t.plan, t.status,
                COALESCE(t.risk_score, 0) as risk_score,
                COALESCE(t.suspended, false) as suspended,
                t.created_at,
                COALESCE(t.last_active_at, t.created_at) as last_active_at
            FROM tenants t
            ORDER BY t.created_at DESC
        `);

        if (rows.length === 0) {
            // Return demo data when DB is empty (development)
            return NextResponse.json(DEMO_TENANTS);
        }

        const tenants = rows.map(row => {
            const riskScore = Number(row.risk_score);
            let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
            if (riskScore >= 90) riskLevel = 'critical';
            else if (riskScore >= 70) riskLevel = 'high';
            else if (riskScore >= 40) riskLevel = 'medium';

            return {
                id: row.id,
                name: row.name,
                domain: row.domain,
                email: row.email,
                plan: row.plan || 'free',
                status: row.suspended ? 'suspended' : (row.status || 'active'),
                riskLevel,
                metrics: {
                    emailsSentMonth: 0,   // TODO: join with messages table
                    emailsSentTotal: 0,
                    domainsVerified: 0,
                    apiKeys: 0,
                    teamMembers: 0,
                },
                billing: {
                    mrr: 0,   // TODO: join with subscriptions table
                    nextBillingDate: null,
                    paymentMethod: null,
                },
                createdAt: new Date(row.created_at).toISOString(),
                lastActiveAt: new Date(row.last_active_at).toISOString(),
            };
        });

        return NextResponse.json(tenants);
    } catch (error) {
        console.error('Tenants API error:', error);
        // Graceful fallback to demo data
        return NextResponse.json(DEMO_TENANTS);
    }
}

/**
 * PATCH /api/tenants — Update tenant (suspend/unsuspend, change plan, etc.)
 */
export async function PATCH(request: Request) {
    try {
        const body = await request.json();
        const { id, action, ...updates } = body as { id: string; action?: string; [key: string]: unknown };

        if (!id) {
            return NextResponse.json({ error: 'Tenant ID is required' }, { status: 400 });
        }

        if (action === 'suspend') {
            await query('UPDATE tenants SET suspended = true, status = $1 WHERE id = $2', ['suspended', id]);
            return NextResponse.json({ success: true, message: `Tenant ${id} suspended` });
        }

        if (action === 'unsuspend') {
            await query('UPDATE tenants SET suspended = false, status = $1 WHERE id = $2', ['active', id]);
            return NextResponse.json({ success: true, message: `Tenant ${id} unsuspended` });
        }

        // General field updates (plan, name, etc.)
        const allowedFields = ['name', 'plan', 'status', 'domain', 'email'];
        const setClauses: string[] = [];
        const values: unknown[] = [];
        let paramIdx = 1;

        for (const field of allowedFields) {
            if (updates[field] !== undefined) {
                setClauses.push(`${field} = $${paramIdx}`);
                values.push(updates[field]);
                paramIdx++;
            }
        }

        if (setClauses.length === 0) {
            return NextResponse.json({ error: 'No valid fields to update' }, { status: 400 });
        }

        values.push(id);
        await query(`UPDATE tenants SET ${setClauses.join(', ')} WHERE id = $${paramIdx}`, values);

        return NextResponse.json({ success: true, message: `Tenant ${id} updated` });
    } catch (error) {
        console.error('Tenants PATCH error:', error);
        return NextResponse.json({ error: 'Failed to update tenant' }, { status: 500 });
    }
}

/**
 * DELETE /api/tenants — Delete a tenant
 */
export async function DELETE(request: Request) {
    try {
        const { searchParams } = new URL(request.url);
        const id = searchParams.get('id');

        if (!id) {
            return NextResponse.json({ error: 'Tenant ID is required' }, { status: 400 });
        }

        await query('DELETE FROM tenants WHERE id = $1', [id]);
        return NextResponse.json({ success: true, message: `Tenant ${id} deleted` });
    } catch (error) {
        console.error('Tenants DELETE error:', error);
        return NextResponse.json({ error: 'Failed to delete tenant' }, { status: 500 });
    }
}
