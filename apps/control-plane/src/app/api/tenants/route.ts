/**
 * Tenants List API
 * 
 * Returns all tenants with their status, plan, risk level, and metrics.
 * Used by the /tenants page.
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
        // FIX-500-302: Add pagination support
        const url = new URL(request.url);
        const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 1), 200);
        const offset = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);

        const [hasDomains, hasApiKeys, hasStripeSubscriptions] = await Promise.all([
            tableExists('domains'),
            tableExists('api_keys'),
            tableExists('stripe_subscriptions'),
        ]);

        const rows = await query<{
            id: string;
            name: string;
            slug: string;
            plan: string;
            status: string;
            created_at: Date;
            updated_at: Date;
            emails_sent_month: string;
            emails_sent_total: string;
            domains_verified: string;
            api_keys: string;
            team_members: string;
            mrr: string;
            next_billing_date: Date | null;
        }>(`
            SELECT 
                t.id, t.name, t.slug, t.plan, t.status,
                t.created_at,
                t.updated_at,
                (SELECT COUNT(*)::text FROM messages m WHERE m.tenant_id = t.id AND m.created_at >= NOW() - INTERVAL '30 days') as emails_sent_month,
                (SELECT COUNT(*)::text FROM messages m WHERE m.tenant_id = t.id) as emails_sent_total,
                ${hasDomains
                    ? `(SELECT COUNT(*)::text FROM domains d WHERE d.tenant_id = t.id AND d.is_verified = true) as domains_verified,`
                    : `'0'::text as domains_verified,`}
                ${hasApiKeys
                    ? `(SELECT COUNT(*)::text FROM api_keys ak WHERE ak.tenant_id = t.id AND ak.is_active = true) as api_keys,`
                    : `'0'::text as api_keys,`}
                (SELECT COUNT(*)::text FROM users u WHERE u.tenant_id = t.id AND u.status = 'active') as team_members,
                ${hasStripeSubscriptions
                    ? `(SELECT COALESCE(SUM(CASE WHEN s.billing_interval = 'year' THEN s.amount / 12.0 ELSE s.amount END) / 100.0, 0)::text
                        FROM stripe_subscriptions s
                        WHERE s.tenant_id = t.id AND s.status IN ('active', 'trialing', 'past_due') AND s.canceled_at IS NULL) as mrr,
                       (SELECT MIN(s.current_period_end)
                        FROM stripe_subscriptions s
                        WHERE s.tenant_id = t.id AND s.status IN ('active', 'trialing', 'past_due') AND s.canceled_at IS NULL) as next_billing_date`
                    : `'0'::text as mrr, NULL::timestamptz as next_billing_date`}
            FROM tenants t
            ORDER BY t.created_at DESC
            LIMIT $1 OFFSET $2
        `, [limit, offset]);

        const tenants = rows.map(row => {
            const mrr = parseFloat(row.mrr || '0');
            const emailsSentMonth = parseInt(row.emails_sent_month || '0', 10);
            const emailsSentTotal = parseInt(row.emails_sent_total || '0', 10);
            const domainsVerified = parseInt(row.domains_verified || '0', 10);
            const apiKeys = parseInt(row.api_keys || '0', 10);
            const teamMembers = parseInt(row.team_members || '0', 10);

            const inferredRiskScore = Math.min(100,
                (emailsSentMonth > 500000 ? 30 : 0) +
                (domainsVerified === 0 ? 40 : 0) +
                (apiKeys > 20 ? 20 : 0)
            );

            let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
            if (inferredRiskScore >= 90) riskLevel = 'critical';
            else if (inferredRiskScore >= 70) riskLevel = 'high';
            else if (inferredRiskScore >= 40) riskLevel = 'medium';

            return {
                id: row.id,
                name: row.name,
                domain: row.slug,
                email: null,
                plan: row.plan || 'free',
                status: row.status || 'active',
                riskLevel,
                metrics: {
                    emailsSentMonth,
                    emailsSentTotal,
                    domainsVerified,
                    apiKeys,
                    teamMembers,
                },
                billing: {
                    mrr,
                    nextBillingDate: row.next_billing_date ? new Date(row.next_billing_date).toISOString() : null,
                    paymentMethod: null,
                },
                createdAt: new Date(row.created_at).toISOString(),
                lastActiveAt: new Date(row.updated_at).toISOString(),
            };
        });

        return NextResponse.json(tenants);
    } catch (error) {
        console.error('Tenants API error:', error);
        // FIX-018: Return a proper error response instead of silently
        // falling back to demo data. Production operators need to know
        // when the DB is down, not see fake tenant data.
        return NextResponse.json(
            { error: 'Failed to fetch tenants' },
            { status: 500 }
        );
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
            await query('UPDATE tenants SET status = $1, updated_at = NOW() WHERE id = $2', ['suspended', id]);
            return NextResponse.json({ success: true, message: `Tenant ${id} suspended` });
        }

        if (action === 'unsuspend') {
            await query('UPDATE tenants SET status = $1, updated_at = NOW() WHERE id = $2', ['active', id]);
            return NextResponse.json({ success: true, message: `Tenant ${id} unsuspended` });
        }

        // General field updates (plan, name, etc.)
        const allowedFields = ['name', 'plan', 'status', 'slug'];
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
 * DELETE /api/tenants — Soft-delete a tenant
 * 
 * FIX-500-014: Hard-deleting a tenant orphans messages, subscriptions,
 * GDPR requests, and other foreign-keyed data. Use soft-delete instead.
 */
export async function DELETE(request: Request) {
    try {
        const { searchParams } = new URL(request.url);
        const id = searchParams.get('id');

        if (!id) {
            return NextResponse.json({ error: 'Tenant ID is required' }, { status: 400 });
        }

        // Soft-delete: mark as deleted instead of removing the row
        const result = await query(
            `UPDATE tenants
             SET status = 'deleted', updated_at = NOW()
             WHERE id = $1 AND status != 'deleted'
             RETURNING id`,
            [id]
        );

        if (!result || result.length === 0) {
            return NextResponse.json({ error: 'Tenant not found or already deleted' }, { status: 404 });
        }

        return NextResponse.json({ success: true, message: `Tenant ${id} soft-deleted` });
    } catch (error) {
        console.error('Tenants DELETE error:', error);
        return NextResponse.json({ error: 'Failed to delete tenant' }, { status: 500 });
    }
}
