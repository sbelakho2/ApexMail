/**
 * Control Plane Dashboard Stats API
 *
 * Provides dashboard metrics by querying canonical database tables.
 * This endpoint is only accessible to authenticated control plane users.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

interface ActivityRow {
    id: string;
    type: string;
    message: string;
    timestamp: Date;
}

export interface DashboardStats {
    sales: {
        activeLeads: number;
        leadsThisWeek: number;
        campaignsRunning: number;
        demosScheduled: number;
        conversionRate: number;
    };
    compliance: {
        riskAlerts: number;
        criticalTenants: number;
        gdprPending: number;
        auditEventsToday: number;
    };
    platform: {
        activeTenants: number;
        totalEmails: number;
        mrr: number;
        healthStatus: 'healthy' | 'degraded' | 'down';
    };
    recentActivity: Array<{
        id: string;
        type: string;
        message: string;
        timestamp: string;
    }>;
    pipeline: {
        prospect: number;
        outreach: number;
        engaged: number;
        demo: number;
        closed: number;
    };
}

async function tableExists(tableName: string): Promise<boolean> {
    const rows = await query<{ exists: boolean }>(
        `SELECT to_regclass($1) IS NOT NULL as exists`,
        [`public.${tableName}`]
    );
    return rows[0]?.exists ?? false;
}

function parseCount(value: string | undefined): number {
    return parseInt(value || '0', 10);
}

function toIsoTimestamp(value: Date | string): string {
    return new Date(value).toISOString();
}

export async function GET(): Promise<NextResponse<DashboardStats | { error: string }>> {
    try {
        const [
            hasSalesLeads,
            hasDripCampaigns,
            hasGdprRequests,
            hasSystemAlerts,
            hasStripeSubscriptions,
        ] = await Promise.all([
            tableExists('sales_leads'),
            tableExists('drip_campaigns'),
            tableExists('gdpr_requests'),
            tableExists('system_alerts'),
            tableExists('stripe_subscriptions'),
        ]);

        const [
            activeLeadsRows,
            leadsThisWeekRows,
            campaignsRunningRows,
            demosScheduledRows,
            pipelineRows,
            conversionRows,
            auditEventsTodayRows,
            activeTenantsRows,
            totalEmailsRows,
            mrrRows,
            alertsRows,
        ] = await Promise.all([
            hasSalesLeads
                ? query<{ count: string }>(`
                    SELECT COUNT(*)::text as count
                    FROM sales_leads
                    WHERE status NOT IN ('converted', 'lost', 'unqualified')
                `)
                : Promise.resolve([]),
            hasSalesLeads
                ? query<{ count: string }>(`
                    SELECT COUNT(*)::text as count
                    FROM sales_leads
                    WHERE created_at >= NOW() - INTERVAL '7 days'
                `)
                : Promise.resolve([]),
            hasDripCampaigns
                ? query<{ count: string }>(`
                    SELECT COUNT(*)::text as count
                    FROM drip_campaigns
                    WHERE status = 'active'
                `)
                : Promise.resolve([]),
            hasSalesLeads
                ? query<{ count: string }>(`
                    SELECT COUNT(*)::text as count
                    FROM sales_leads
                    WHERE status IN ('demo_scheduled', 'demo_booked', 'demo')
                `)
                : Promise.resolve([]),
            hasSalesLeads
                ? query<{ status: string; count: string }>(`
                    SELECT status, COUNT(*)::text as count
                    FROM sales_leads
                    GROUP BY status
                `)
                : Promise.resolve([]),
            hasSalesLeads
                ? query<{ conversion_rate: string }>(`
                    SELECT CASE
                        WHEN COUNT(*) FILTER (WHERE status IN ('contacted', 'qualified', 'converted')) = 0 THEN 0
                        ELSE (
                            COUNT(*) FILTER (WHERE status = 'converted')::float /
                            COUNT(*) FILTER (WHERE status IN ('contacted', 'qualified', 'converted'))
                        )
                    END::text as conversion_rate
                    FROM sales_leads
                `)
                : Promise.resolve([]),
            query<{ count: string }>(`
                SELECT COUNT(*)::text as count
                FROM audit_logs
                WHERE timestamp >= CURRENT_DATE
            `),
            query<{ count: string }>(`
                SELECT COUNT(*)::text as count
                FROM tenants
                WHERE status = 'active'
            `),
            query<{ count: string }>(`
                SELECT COUNT(*)::text as count
                FROM messages
                WHERE status IN ('sent', 'delivered')
            `),
            hasStripeSubscriptions
                ? query<{ mrr: string }>(`
                    SELECT COALESCE(SUM(
                        CASE
                            WHEN billing_interval = 'year' THEN amount / 12.0
                            WHEN billing_interval = 'month' THEN amount
                            ELSE 0
                        END
                    ) / 100.0, 0)::text as mrr
                    FROM stripe_subscriptions
                    WHERE status IN ('active', 'trialing', 'past_due')
                      AND canceled_at IS NULL
                `)
                : Promise.resolve([]),
            hasSystemAlerts
                ? query<{ severity: string; total: string; tenant_count: string }>(`
                    SELECT
                        severity,
                        COUNT(*)::text as total,
                        COUNT(DISTINCT tenant_id)::text as tenant_count
                    FROM system_alerts
                    WHERE acknowledged = false
                      AND severity IN ('high', 'critical')
                    GROUP BY severity
                `)
                : Promise.resolve([]),
        ]);

        const [leadActivityRows, alertActivityRows, campaignActivityRows, gdprActivityRows, gdprPendingRows] = await Promise.all([
            hasSalesLeads
                ? query<{
                    id: string;
                    company_name: string;
                    created_at: Date;
                }>(`
                    SELECT id, company_name, created_at
                    FROM sales_leads
                    ORDER BY created_at DESC
                    LIMIT 4
                `)
                : Promise.resolve([]),
            hasSystemAlerts
                ? query<{
                    id: string;
                    alert_type: string;
                    message: string | null;
                    created_at: Date;
                }>(`
                    SELECT id, alert_type, message, created_at
                    FROM system_alerts
                    ORDER BY created_at DESC
                    LIMIT 3
                `)
                : Promise.resolve([]),
            hasDripCampaigns
                ? query<{
                    id: string;
                    name: string;
                    status: string;
                    created_at: Date;
                }>(`
                    SELECT id, name, status, created_at
                    FROM drip_campaigns
                    ORDER BY created_at DESC
                    LIMIT 3
                `)
                : Promise.resolve([]),
            hasGdprRequests
                ? query<{
                    id: string;
                    email: string;
                    status: string;
                    created_at: Date;
                }>(`
                    SELECT id, email, status, created_at
                    FROM gdpr_requests
                    ORDER BY created_at DESC
                    LIMIT 3
                `)
                : Promise.resolve([]),
            hasGdprRequests
                ? query<{ count: string }>(`
                    SELECT COUNT(*)::text as count
                    FROM gdpr_requests
                    WHERE status = 'pending'
                `)
                : Promise.resolve([]),
        ]);

        const pipeline = {
            prospect: 0,
            outreach: 0,
            engaged: 0,
            demo: 0,
            closed: 0,
        };

        for (const row of pipelineRows) {
            const status = row.status;
            const count = parseCount(row.count);

            if (['new', 'prospect', 'identified'].includes(status)) {
                pipeline.prospect += count;
            } else if (['contacted', 'outreach', 'attempted'].includes(status)) {
                pipeline.outreach += count;
            } else if (['engaged', 'qualified', 'responded'].includes(status)) {
                pipeline.engaged += count;
            } else if (['demo_scheduled', 'demo_booked', 'demo'].includes(status)) {
                pipeline.demo += count;
            } else if (['converted', 'closed_won'].includes(status)) {
                pipeline.closed += count;
            }
        }

        let riskAlerts = 0;
        let criticalTenants = 0;
        let criticalAlertCount = 0;
        let highAlertCount = 0;

        for (const row of alertsRows) {
            const alertCount = parseCount(row.total);
            riskAlerts += alertCount;

            if (row.severity === 'critical') {
                criticalAlertCount += alertCount;
                criticalTenants += parseCount(row.tenant_count);
            }
            if (row.severity === 'high') {
                highAlertCount += alertCount;
            }
        }

        const healthStatus: 'healthy' | 'degraded' | 'down' = criticalAlertCount > 0
            ? 'down'
            : highAlertCount > 0
                ? 'degraded'
                : 'healthy';

        const recentActivity: ActivityRow[] = [
            ...leadActivityRows.map((row) => ({
                id: row.id,
                type: 'lead',
                message: `New lead: ${row.company_name}`,
                timestamp: row.created_at,
            })),
            ...alertActivityRows.map((row) => ({
                id: row.id,
                type: 'risk',
                message: row.message || `System alert: ${row.alert_type}`,
                timestamp: row.created_at,
            })),
            ...campaignActivityRows.map((row) => ({
                id: row.id,
                type: 'campaign',
                message: `Campaign ${row.name} is ${row.status}`,
                timestamp: row.created_at,
            })),
            ...gdprActivityRows.map((row) => ({
                id: row.id,
                type: 'gdpr',
                message: `GDPR request from ${row.email} (${row.status})`,
                timestamp: row.created_at,
            })),
        ]
            .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
            .slice(0, 10);

        const stats: DashboardStats = {
            sales: {
                activeLeads: parseCount(activeLeadsRows[0]?.count),
                leadsThisWeek: parseCount(leadsThisWeekRows[0]?.count),
                campaignsRunning: parseCount(campaignsRunningRows[0]?.count),
                demosScheduled: parseCount(demosScheduledRows[0]?.count),
                conversionRate: parseFloat(conversionRows[0]?.conversion_rate || '0'),
            },
            compliance: {
                riskAlerts,
                criticalTenants,
                gdprPending: parseCount(gdprPendingRows[0]?.count),
                auditEventsToday: parseCount(auditEventsTodayRows[0]?.count),
            },
            platform: {
                activeTenants: parseCount(activeTenantsRows[0]?.count),
                totalEmails: parseCount(totalEmailsRows[0]?.count),
                mrr: parseFloat(mrrRows[0]?.mrr || '0'),
                healthStatus,
            },
            recentActivity: recentActivity.map((row) => ({
                id: row.id,
                type: row.type,
                message: row.message,
                timestamp: toIsoTimestamp(row.timestamp),
            })),
            pipeline,
        };

        return NextResponse.json(stats);
    } catch (error) {
        console.error('Dashboard stats error:', error);
        return NextResponse.json(
            { error: 'Failed to fetch dashboard stats' },
            { status: 500 }
        );
    }
}
