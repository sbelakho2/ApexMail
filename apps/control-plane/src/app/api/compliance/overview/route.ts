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

// Demo fallback data
const DEMO_OVERVIEW = {
    riskSummary: { low: 128, medium: 23, high: 4, critical: 1 },
    gdprRequests: { pending: 3, processing: 2, completed: 156, overdue: 0 },
    auditStats: { todayEvents: 1847, weekEvents: 12450, alertsTriggered: 7 },
    policyCompliance: [
        { name: 'SPF Records', compliant: 152, total: 156 },
        { name: 'DKIM Signing', compliant: 156, total: 156 },
        { name: 'DMARC Policy', compliant: 145, total: 156 },
        { name: 'Bounce Rate < 5%', compliant: 148, total: 156 },
        { name: 'Complaint Rate < 0.1%', compliant: 151, total: 156 },
        { name: 'Unsubscribe Link', compliant: 156, total: 156 },
    ],
    recentAlerts: [
        { id: '1', type: 'high_bounce', message: 'Tenant "spammy.io" exceeded 10% bounce rate', severity: 'high', tenantId: 'tenant-123', timestamp: new Date(Date.now() - 1800000).toISOString() },
        { id: '2', type: 'spam_report', message: 'Spike in spam complaints for "newsletter.co"', severity: 'medium', tenantId: 'tenant-456', timestamp: new Date(Date.now() - 3600000).toISOString() },
        { id: '3', type: 'auth_failure', message: 'Multiple failed auth attempts from IP 192.168.1.1', severity: 'medium', tenantId: 'system', timestamp: new Date(Date.now() - 7200000).toISOString() },
        { id: '4', type: 'gdpr_deadline', message: 'GDPR request #42 approaching SLA deadline', severity: 'high', tenantId: 'tenant-789', timestamp: new Date(Date.now() - 14400000).toISOString() },
        { id: '5', type: 'volume_spike', message: 'Unusual volume spike detected for "marketing.io"', severity: 'low', tenantId: 'tenant-321', timestamp: new Date(Date.now() - 21600000).toISOString() },
    ],
};

export async function GET() {
    try {
        // Try to get real data from DB
        const [riskRows, gdprRows, auditTodayRows] = await Promise.all([
            // Risk summary by level
            query<{ risk_level: string; count: string }>(`
                SELECT 
                    CASE 
                        WHEN risk_score >= 90 THEN 'critical'
                        WHEN risk_score >= 70 THEN 'high'
                        WHEN risk_score >= 40 THEN 'medium'
                        ELSE 'low'
                    END as risk_level,
                    COUNT(*) as count
                FROM tenants
                GROUP BY risk_level
            `),
            // GDPR request counts by status
            query<{ status: string; count: string }>(`
                SELECT status, COUNT(*) as count
                FROM gdpr_requests
                GROUP BY status
            `),
            // Audit events today
            query<{ count: string }>(`
                SELECT COUNT(*) as count
                FROM audit_logs
                WHERE created_at >= CURRENT_DATE
            `),
        ]);

        // If we got real data, build the response
        if (riskRows.length > 0 || gdprRows.length > 0) {
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

            return NextResponse.json({
                riskSummary,
                gdprRequests,
                auditStats: {
                    todayEvents: parseInt(auditTodayRows[0]?.count || '0', 10),
                    weekEvents: 0,   // TODO: add weekly query
                    alertsTriggered: 0,
                },
                policyCompliance: DEMO_OVERVIEW.policyCompliance, // TODO: Replace with real policy checks
                recentAlerts: DEMO_OVERVIEW.recentAlerts, // TODO: Replace with real alert queries
            });
        }

        // No data in DB — return demo
        return NextResponse.json(DEMO_OVERVIEW);
    } catch (error) {
        console.error('Compliance API error:', error);
        // FIX-500-298: Return 500 instead of masking errors with demo data
        return NextResponse.json({ error: 'Failed to fetch compliance data' }, { status: 500 });
    }
}
