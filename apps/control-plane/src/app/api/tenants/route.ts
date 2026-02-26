/**
 * Tenants List API
 * 
 * Returns all tenants with their status, plan, risk level, and metrics.
 * Used by the /tenants page.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';
import { columnExists } from '@/lib/schema';

export const dynamic = 'force-dynamic';

type TenantAction = 'suspend' | 'unsuspend';

interface TenantPatchBody {
    id?: string;
    action?: TenantAction;
    name?: string;
    plan?: string;
    status?: string;
}

async function logTenantAudit(action: string, tenantId: string, metadata?: Record<string, unknown>) {
    try {
        await query(
            `INSERT INTO audit_logs (
                timestamp,
                action,
                resource_type,
                resource_id,
                tenant_id,
                metadata
            ) VALUES (
                NOW(),
                $1,
                'tenant',
                $2,
                $2,
                $3::jsonb
            )`,
            [action, tenantId, JSON.stringify(metadata ?? {})]
        );
    } catch (error) {
        console.error('Tenant audit log error:', error);
    }
}

export async function GET(request: Request) {
    try {
        // FIX-500-302: Add pagination support
        const url = new URL(request.url);
        const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 1), 200);
        const offset = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);

        const rows = await query<{
            id: string;
            name: string;
            slug: string;
            plan: string;
            status: string;
            created_at: Date;
            updated_at: Date;
            owner_email: string | null;
            emails_sent_month: string;
            emails_sent_total: string;
            domains_verified: string;
            api_keys: string;
            team_members: string;
            mrr: string;
            next_billing_date: Date | null;
        }>(`
            WITH tenant_page AS (
                SELECT
                    t.id,
                    t.name,
                    t.slug,
                    t.plan,
                    t.status,
                    t.created_at,
                    t.updated_at
                FROM tenants t
                ORDER BY t.created_at DESC
                LIMIT $1 OFFSET $2
            ),
            message_counts AS (
                SELECT
                    m.tenant_id,
                    COUNT(*) FILTER (WHERE m.created_at >= NOW() - INTERVAL '30 days')::text AS emails_sent_month,
                    COUNT(*)::text AS emails_sent_total
                FROM messages m
                INNER JOIN tenant_page tp ON tp.id = m.tenant_id
                GROUP BY m.tenant_id
            ),
            user_counts AS (
                SELECT
                    u.tenant_id,
                    COUNT(*)::text AS team_members
                FROM users u
                INNER JOIN tenant_page tp ON tp.id = u.tenant_id
                WHERE u.status = 'active'
                GROUP BY u.tenant_id
            ),
            owner_contacts AS (
                SELECT tenant_id, email
                FROM (
                    SELECT
                        u.tenant_id,
                        u.email,
                        ROW_NUMBER() OVER (
                            PARTITION BY u.tenant_id
                            ORDER BY
                                CASE
                                    WHEN u.role = 'owner' THEN 1
                                    WHEN u.role = 'admin' THEN 2
                                    ELSE 3
                                END,
                                u.created_at ASC
                        ) AS rank
                    FROM users u
                    INNER JOIN tenant_page tp ON tp.id = u.tenant_id
                    WHERE u.status = 'active' AND u.email IS NOT NULL
                ) ranked_users
                WHERE rank = 1
            ),
            domain_counts AS (
                SELECT
                    d.tenant_id,
                    COUNT(*)::text AS domains_verified
                FROM domains d
                INNER JOIN tenant_page tp ON tp.id = d.tenant_id
                WHERE d.is_verified = true
                GROUP BY d.tenant_id
            ),
            api_key_counts AS (
                SELECT
                    ak.tenant_id,
                    COUNT(*)::text AS api_keys
                FROM api_keys ak
                INNER JOIN tenant_page tp ON tp.id = ak.tenant_id
                WHERE ak.is_active = true
                GROUP BY ak.tenant_id
            ),
            subscription_metrics AS (
                SELECT
                    s.tenant_id,
                    COALESCE(SUM(CASE WHEN s.billing_interval = 'year' THEN s.amount / 12.0 ELSE s.amount END) / 100.0, 0)::text AS mrr,
                    MIN(s.current_period_end) AS next_billing_date
                FROM stripe_subscriptions s
                INNER JOIN tenant_page tp ON tp.id = s.tenant_id
                WHERE s.status IN ('active', 'trialing', 'past_due')
                  AND s.canceled_at IS NULL
                GROUP BY s.tenant_id
            )
            SELECT
                tp.id,
                tp.name,
                tp.slug,
                tp.plan,
                tp.status,
                tp.created_at,
                tp.updated_at,
                oc.email AS owner_email,
                COALESCE(mc.emails_sent_month, '0') AS emails_sent_month,
                COALESCE(mc.emails_sent_total, '0') AS emails_sent_total,
                COALESCE(dc.domains_verified, '0') AS domains_verified,
                COALESCE(akc.api_keys, '0') AS api_keys,
                COALESCE(uc.team_members, '0') AS team_members,
                COALESCE(sm.mrr, '0') AS mrr,
                sm.next_billing_date
            FROM tenant_page tp
            LEFT JOIN message_counts mc ON mc.tenant_id = tp.id
            LEFT JOIN user_counts uc ON uc.tenant_id = tp.id
            LEFT JOIN owner_contacts oc ON oc.tenant_id = tp.id
            LEFT JOIN domain_counts dc ON dc.tenant_id = tp.id
            LEFT JOIN api_key_counts akc ON akc.tenant_id = tp.id
            LEFT JOIN subscription_metrics sm ON sm.tenant_id = tp.id
            ORDER BY tp.created_at DESC
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
                email: row.owner_email,
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
        const body = await request.json() as TenantPatchBody;
        const { id, action } = body;

        if (!id) {
            return NextResponse.json({ error: 'Tenant ID is required' }, { status: 400 });
        }

        if (action === 'suspend') {
            await query('UPDATE tenants SET status = $1, updated_at = NOW() WHERE id = $2', ['suspended', id]);
            await logTenantAudit('control_plane.tenant.suspended', id, { status: 'suspended' });
            return NextResponse.json({ success: true, message: `Tenant ${id} suspended` });
        }

        if (action === 'unsuspend') {
            await query('UPDATE tenants SET status = $1, updated_at = NOW() WHERE id = $2', ['active', id]);
            await logTenantAudit('control_plane.tenant.unsuspended', id, { status: 'active' });
            return NextResponse.json({ success: true, message: `Tenant ${id} unsuspended` });
        }

        // General field updates (plan, name, etc.)
        const allowedFieldValues = {
            name: body.name,
            plan: body.plan,
            status: body.status,
        };
        const setClauses: string[] = [];
        const values: string[] = [];
        let paramIdx = 1;

        for (const [field, value] of Object.entries(allowedFieldValues) as Array<[keyof typeof allowedFieldValues, string | undefined]>) {
            if (value !== undefined) {
                setClauses.push(`${field} = $${paramIdx}`);
                values.push(value);
                paramIdx++;
            }
        }

        if (setClauses.length === 0) {
            return NextResponse.json({ error: 'No valid fields to update' }, { status: 400 });
        }

        // Always set updated_at server-side so it is never skipped or user-supplied.
        setClauses.push('updated_at = NOW()');
        values.push(id);
        await query(`UPDATE tenants SET ${setClauses.join(', ')} WHERE id = $${paramIdx}`, values);
        await logTenantAudit('control_plane.tenant.updated', id, {
            fields: Object.entries(allowedFieldValues)
                .filter(([, value]) => value !== undefined)
                .map(([field]) => field),
        });

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

        const [hasSuspendedColumn, hasMetadataColumn] = await Promise.all([
            columnExists('tenants', 'suspended'),
            columnExists('tenants', 'metadata'),
        ]);

        const setClauses = [
            "status = 'deleted'",
            'updated_at = NOW()',
        ];

        if (hasSuspendedColumn) {
            setClauses.push('suspended = true');
        }

        if (hasMetadataColumn) {
            setClauses.push("metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('deletedAt', NOW())");
        }

        // Soft-delete: mark as deleted instead of removing the row.
        // Canonical statement shape: UPDATE tenants SET status = 'deleted' ...
        const result = await query(
            `UPDATE tenants
             SET ${setClauses.join(', ')}
             WHERE id = $1 AND status != 'deleted'
             RETURNING id`,
            [id]
        );

        if (!result || result.length === 0) {
            return NextResponse.json({ error: 'Tenant not found or already deleted' }, { status: 404 });
        }

        await logTenantAudit('control_plane.tenant.deleted', id, { softDeleted: true });

        return NextResponse.json({ success: true, message: `Tenant ${id} soft-deleted` });
    } catch (error) {
        console.error('Tenants DELETE error:', error);
        return NextResponse.json({ error: 'Failed to delete tenant' }, { status: 500 });
    }
}
