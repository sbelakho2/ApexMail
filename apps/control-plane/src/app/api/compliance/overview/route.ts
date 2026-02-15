/**
 * Compliance Overview API
 * 
 * Returns compliance metrics: risk summary, GDPR queue, audit stats, 
 * policy compliance, and recent alerts.
 * Used by the /compliance page.
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

export async function GET() {
    try {
        const [hasGdprRequests, hasSystemAlerts, hasDomains] = await Promise.all([
            tableExists('gdpr_requests'),
            tableExists('system_alerts'),
            tableExists('domains'),
        ]);

        const [riskRows, auditRows, alertsTodayRows] = await Promise.all([
            hasSystemAlerts
                ? query<{ risk_level: string; count: string }>(`
                    SELECT
                        CASE
                            WHEN severity = 'critical' THEN 'critical'
                            WHEN severity = 'high' THEN 'high'
                            WHEN severity = 'medium' THEN 'medium'
                            ELSE 'low'
                        END as risk_level,
                        COUNT(*)::text as count
                    FROM system_alerts
                    WHERE acknowledged = false
                    GROUP BY risk_level
                `)
                : Promise.resolve([]),
            query<{ today_events: string; week_events: string }>(`
                SELECT
                    COUNT(*) FILTER (WHERE timestamp >= CURRENT_DATE)::text as today_events,
                    COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '7 days')::text as week_events
                FROM audit_logs
            `),
            hasSystemAlerts
                ? query<{ count: string }>(`
                    SELECT COUNT(*)::text as count
                    FROM system_alerts
                    WHERE created_at >= NOW() - INTERVAL '24 hours'
                      AND severity IN ('high', 'critical')
                `)
                : Promise.resolve([]),
        ]);

        const gdprRows = hasGdprRequests
            ? await query<{ status: string; count: string }>(`
                SELECT status, COUNT(*)::text as count
                FROM gdpr_requests
                GROUP BY status
            `)
            : [];

        const policyRows = hasDomains
            ? await query<{ total: string; spf: string; dkim: string; dmarc: string; verified: string }>(`
                SELECT
                    COUNT(*)::text as total,
                    COUNT(*) FILTER (WHERE spf_configured = true)::text as spf,
                    COUNT(*) FILTER (WHERE dkim_selector IS NOT NULL AND dkim_selector <> '')::text as dkim,
                    COUNT(*) FILTER (WHERE dmarc_configured = true)::text as dmarc,
                    COUNT(*) FILTER (WHERE is_verified = true)::text as verified
                FROM domains
            `)
            : [];

        const recentAlerts = hasSystemAlerts
            ? await query<{
                id: string;
                alert_type: string;
                message: string | null;
                severity: string;
                metadata: Record<string, unknown> | null;
                created_at: Date;
            }>(`
                SELECT id, alert_type, message, severity, metadata, created_at
                FROM system_alerts
                ORDER BY created_at DESC
                LIMIT 10
            `)
            : [];

        const riskSummary = { low: 0, medium: 0, high: 0, critical: 0 };
        for (const row of riskRows) {
            const level = row.risk_level as keyof typeof riskSummary;
            if (level in riskSummary) {
                riskSummary[level] = parseInt(row.count, 10);
            }
        }

        const gdprRequests = { pending: 0, processing: 0, completed: 0, overdue: 0 };
        for (const row of gdprRows) {
            const status = row.status as keyof typeof gdprRequests;
            if (status in gdprRequests) {
                gdprRequests[status] = parseInt(row.count, 10);
            }
        }

        const domainMetrics = policyRows[0];
        const domainsTotal = parseInt(domainMetrics?.total ?? '0', 10);
        const policyCompliance = [
            { name: 'SPF Records', compliant: parseInt(domainMetrics?.spf ?? '0', 10), total: domainsTotal },
            { name: 'DKIM Signing', compliant: parseInt(domainMetrics?.dkim ?? '0', 10), total: domainsTotal },
            { name: 'DMARC Policy', compliant: parseInt(domainMetrics?.dmarc ?? '0', 10), total: domainsTotal },
            { name: 'Domain Verification', compliant: parseInt(domainMetrics?.verified ?? '0', 10), total: domainsTotal },
        ];

        return NextResponse.json({
            riskSummary,
            gdprRequests,
            auditStats: {
                todayEvents: parseInt(auditRows[0]?.today_events || '0', 10),
                weekEvents: parseInt(auditRows[0]?.week_events || '0', 10),
                alertsTriggered: parseInt(alertsTodayRows[0]?.count || '0', 10),
            },
            policyCompliance,
            recentAlerts: recentAlerts.map((alert) => ({
                id: alert.id,
                type: alert.alert_type,
                message: alert.message ?? '',
                severity: alert.severity,
                tenantId: typeof alert.metadata?.['tenantId'] === 'string' ? alert.metadata['tenantId'] : null,
                timestamp: new Date(alert.created_at).toISOString(),
            })),
        });
    } catch (error) {
        console.error('Compliance API error:', error);
        // FIX-500-298: Return 500 instead of masking errors with demo data
        return NextResponse.json({ error: 'Failed to fetch compliance data' }, { status: 500 });
    }
}
