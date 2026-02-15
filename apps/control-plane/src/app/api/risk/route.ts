/**
 * Risk Monitoring API
 * 
 * Returns tenants with risk profiles, flags, and metrics.
 * Used by the /risk page.
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
        const [hasReputationStats, hasReputationAlerts] = await Promise.all([
            tableExists('reputation_stats'),
            tableExists('reputation_alerts'),
        ]);

        // FIX-500-302: Add pagination support
        const url = new URL(request.url);
        const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 1), 200);
        const offset = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);

        const rows = await query<{
            id: string;
            name: string;
            slug: string;
            critical_alerts: string;
            high_alerts: string;
            recent_bounces: string;
            recent_complaints: string;
            recent_sent: string;
        }>(`
            SELECT
                t.id,
                t.name,
                t.slug,
                ${hasReputationAlerts ? `
                COALESCE(SUM(CASE WHEN ra.alert_type = 'critical' THEN 1 ELSE 0 END), 0)::text as critical_alerts,
                COALESCE(SUM(CASE WHEN ra.alert_type <> 'critical' THEN 1 ELSE 0 END), 0)::text as high_alerts,
                ` : `
                '0'::text as critical_alerts,
                '0'::text as high_alerts,
                `}
                ${hasReputationStats ? `
                COALESCE(SUM(rs.bounces), 0)::text as recent_bounces,
                COALESCE(SUM(rs.complaints), 0)::text as recent_complaints,
                COALESCE(SUM(rs.sent), 0)::text as recent_sent
                ` : `
                '0'::text as recent_bounces,
                '0'::text as recent_complaints,
                '0'::text as recent_sent
                `}
            FROM tenants t
            ${hasReputationAlerts ? `LEFT JOIN reputation_alerts ra ON ra.tenant_id = t.id AND ra.acknowledged = false` : ''}
            ${hasReputationStats ? `LEFT JOIN reputation_stats rs ON rs.tenant_id = t.id AND rs.date >= CURRENT_DATE - INTERVAL '30 days'` : ''}
            GROUP BY t.id, t.name, t.slug
            ORDER BY t.created_at DESC
            LIMIT $1 OFFSET $2
        `, [limit, offset]);

        const tenants = rows.map(row => {
            const criticalAlerts = parseInt(row.critical_alerts || '0', 10);
            const highAlerts = parseInt(row.high_alerts || '0', 10);
            const bounces = parseInt(row.recent_bounces || '0', 10);
            const complaints = parseInt(row.recent_complaints || '0', 10);
            const sent = parseInt(row.recent_sent || '0', 10);

            const bounceRate = sent > 0 ? bounces / sent : 0;
            const complaintRate = sent > 0 ? complaints / sent : 0;
            const riskScore = Math.min(100,
                (criticalAlerts * 35) +
                (highAlerts * 12) +
                Math.round(bounceRate * 200) +
                Math.round(complaintRate * 2000)
            );

            let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
            if (riskScore >= 90) riskLevel = 'critical';
            else if (riskScore >= 70) riskLevel = 'high';
            else if (riskScore >= 40) riskLevel = 'medium';

            return {
                tenantId: row.id,
                tenantName: row.name,
                domain: row.slug,
                riskScore,
                riskLevel,
                flags: [],
                metrics: {
                    bounceRate,
                    complaintRate,
                    dailyVolume: 0,
                    monthlyVolume: sent,
                },
                limits: { daily: null, hourly: null },
                lastAssessed: new Date().toISOString(),
            };
        });

        return NextResponse.json(tenants);
    } catch (error) {
        console.error('Risk API error:', error);
        // FIX-500-298: Return 500 instead of masking errors with demo data
        return NextResponse.json({ error: 'Failed to fetch risk data' }, { status: 500 });
    }
}
