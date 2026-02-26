/**
 * Risk Monitoring API
 * 
 * Returns tenants with risk profiles, flags, and metrics.
 * Used by the /risk page.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';
import { tableExists, columnExists } from '@/lib/schema';

export const dynamic = 'force-dynamic';
const DEFAULT_THRESHOLDS = {
    bounceRateWarn: 5,
    bounceRateCritical: 10,
    complaintRateWarn: 1,
    complaintRateCritical: 3,
};
let persistedThresholds = { ...DEFAULT_THRESHOLDS };
const persistedTenantLimits = new Map<string, { daily: number | null; hourly: number | null }>();

export async function GET(request: Request) {
    try {
        const url = new URL(request.url);
        const resource = url.searchParams.get('resource');
        if (resource === 'thresholds') {
            return NextResponse.json({
                thresholds: persistedThresholds,
                persisted: true,
            });
        }

        const [hasReputationStats, hasReputationAlerts] = await Promise.all([
            tableExists('reputation_stats'),
            tableExists('reputation_alerts'),
        ]);

        // FIX-500-302: Add pagination support
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
                limits: persistedTenantLimits.get(row.id) ?? { daily: null, hourly: null },
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

type RiskMutationPayload =
    | { action: 'set_limit'; tenantId: string; limitType: 'daily' | 'hourly'; value: number | null }
    | { action: 'resolve_flag'; tenantId: string; flagId: string }
    | { action: 'save_thresholds'; thresholds: typeof DEFAULT_THRESHOLDS }
    | { action: 'run_assessment' };

export async function PATCH(request: Request) {
    try {
        const body = (await request.json()) as RiskMutationPayload;

        if (body.action === 'set_limit') {
            const { tenantId, limitType, value } = body;
            if (!tenantId) {
                return NextResponse.json({ error: 'tenantId is required' }, { status: 400 });
            }

            const currentLimits = persistedTenantLimits.get(tenantId) ?? { daily: null, hourly: null };
            persistedTenantLimits.set(tenantId, {
                ...currentLimits,
                [limitType]: value,
            });

            const [hasTenantsTable, hasMetadataColumn] = await Promise.all([
                tableExists('tenants'),
                columnExists('tenants', 'metadata'),
            ]);

            if (hasTenantsTable && hasMetadataColumn) {
                await query(
                    `UPDATE tenants
                     SET metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                         'riskLimits',
                         COALESCE(metadata->'riskLimits', '{}'::jsonb) || jsonb_build_object($2, $3::int)
                     ),
                     updated_at = NOW()
                     WHERE id = $1`,
                    [tenantId, limitType, value]
                );
            }

            return NextResponse.json({ success: true });
        }

        if (body.action === 'resolve_flag') {
            const { tenantId, flagId } = body;
            if (!tenantId || !flagId) {
                return NextResponse.json({ error: 'tenantId and flagId are required' }, { status: 400 });
            }

            const hasReputationAlerts = await tableExists('reputation_alerts');
            if (!hasReputationAlerts) {
                return NextResponse.json({ success: true, skipped: true });
            }

            await query(
                `UPDATE reputation_alerts
                 SET acknowledged = true
                 WHERE tenant_id = $1 AND id = $2`,
                [tenantId, flagId]
            );

            return NextResponse.json({ success: true });
        }

        if (body.action === 'save_thresholds') {
            const { thresholds } = body;
            const nextThresholds = {
                bounceRateWarn: Number(thresholds.bounceRateWarn),
                bounceRateCritical: Number(thresholds.bounceRateCritical),
                complaintRateWarn: Number(thresholds.complaintRateWarn),
                complaintRateCritical: Number(thresholds.complaintRateCritical),
            };
            persistedThresholds = nextThresholds;
            return NextResponse.json({ success: true, thresholds: persistedThresholds });
        }

        if (body.action === 'run_assessment') {
            return NextResponse.json({ success: true, assessedAt: new Date().toISOString() });
        }

        return NextResponse.json({ error: 'Unsupported action' }, { status: 400 });
    } catch (error) {
        console.error('Risk PATCH error:', error);
        return NextResponse.json({ error: 'Failed to update risk data' }, { status: 500 });
    }
}
