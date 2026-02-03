/**
 * Control Plane Dashboard Stats API
 * 
 * Provides real-time business metrics by querying the database directly.
 * This endpoint is only accessible to authenticated control plane users.
 */

import { NextResponse } from 'next/server';

// Use dynamic import for pg to avoid build issues
type Pool = import('pg').Pool;
type PoolClient = import('pg').PoolClient;

let pool: Pool | null = null;

async function getPool(): Promise<Pool> {
    if (!pool) {
        const { Pool: PgPool } = await import('pg');
        pool = new PgPool({
            host: process.env.DB_HOST || 'localhost',
            port: parseInt(process.env.DB_PORT || '5432', 10),
            database: process.env.DB_NAME || 'apexmail',
            user: process.env.DB_USER || 'postgres',
            password: process.env.DB_PASSWORD || '',
            max: 5,
            idleTimeoutMillis: 30000,
            connectionTimeoutMillis: 5000,
        });
    }
    return pool;
}

// Database configuration types
interface DbConfig {
    host: string;
    port: number;
    database: string;
    user: string;
    password: string;
    max: number;
    idleTimeoutMillis: number;
    connectionTimeoutMillis: number;
}

// Activity row interface
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

export async function GET(): Promise<NextResponse<DashboardStats | { error: string }>> {
    try {
        const dbPool = await getPool();
        const client = await dbPool.connect();
        
        try {
            // Sales metrics
            const [
                activeLeadsResult,
                leadsThisWeekResult,
                campaignsRunningResult,
                demosScheduledResult,
                pipelineResult,
                conversionResult,
            ] = await Promise.all([
                // Active leads count
                client.query<{ count: string }>(
                    `SELECT COUNT(*) as count FROM leads 
                     WHERE status NOT IN ('converted', 'lost', 'unqualified')`
                ),
                // Leads this week
                client.query<{ count: string }>(
                    `SELECT COUNT(*) as count FROM leads 
                     WHERE created_at >= NOW() - INTERVAL '7 days'`
                ),
                // Running campaigns
                client.query<{ count: string }>(
                    `SELECT COUNT(*) as count FROM campaigns WHERE status = 'active'`
                ),
                // Demos scheduled
                client.query<{ count: string }>(
                    `SELECT COUNT(*) as count FROM leads WHERE stage = 'demo_scheduled'`
                ),
                // Pipeline stages
                client.query<{ stage: string; count: string }>(
                    `SELECT stage, COUNT(*) as count FROM leads 
                     WHERE status NOT IN ('converted', 'lost')
                     GROUP BY stage`
                ),
                // Conversion rate (converted / total contacted)
                client.query<{ conversion_rate: string }>(
                    `SELECT 
                        CASE 
                            WHEN COUNT(*) FILTER (WHERE status IN ('contacted', 'qualified', 'converted')) = 0 
                            THEN 0
                            ELSE COUNT(*) FILTER (WHERE status = 'converted')::float / 
                                 COUNT(*) FILTER (WHERE status IN ('contacted', 'qualified', 'converted'))
                        END as conversion_rate
                     FROM leads`
                ),
            ]);

            // Compliance metrics
            const [
                riskAlertsResult,
                criticalTenantsResult,
                gdprPendingResult,
                auditEventsTodayResult,
            ] = await Promise.all([
                // Risk alerts (high/critical tenants)
                client.query<{ count: string }>(
                    `SELECT COUNT(*) as count FROM tenants 
                     WHERE risk_score >= 70`
                ),
                // Critical tenants
                client.query<{ count: string }>(
                    `SELECT COUNT(*) as count FROM tenants 
                     WHERE risk_score >= 90 OR suspended = true`
                ),
                // Pending GDPR requests
                client.query<{ count: string }>(
                    `SELECT COUNT(*) as count FROM gdpr_requests 
                     WHERE status = 'pending'`
                ),
                // Audit events today
                client.query<{ count: string }>(
                    `SELECT COUNT(*) as count FROM audit_logs 
                     WHERE created_at >= CURRENT_DATE`
                ),
            ]);

            // Platform metrics
            const [
                activeTenantsResult,
                totalEmailsResult,
                mrrResult,
                healthResult,
            ] = await Promise.all([
                // Active tenants
                client.query<{ count: string }>(
                    `SELECT COUNT(*) as count FROM tenants 
                     WHERE status = 'active'`
                ),
                // Total emails sent
                client.query<{ count: string }>(
                    `SELECT COUNT(*) as count FROM messages 
                     WHERE status IN ('sent', 'delivered')`
                ),
                // MRR (Monthly Recurring Revenue)
                client.query<{ mrr: string }>(
                    `SELECT COALESCE(SUM(
                        CASE 
                            WHEN billing_period = 'monthly' THEN price_cents
                            WHEN billing_period = 'yearly' THEN price_cents / 12
                            ELSE 0 
                        END
                    ) / 100.0, 0) as mrr
                     FROM subscriptions 
                     WHERE status = 'active'`
                ),
                // System health
                client.query<{ status: string; last_check: Date }>(
                    `SELECT status, last_check FROM system_health 
                     ORDER BY last_check DESC LIMIT 1`
                ),
            ]);

            // Recent activity (combine from multiple sources)
            const recentActivityResult = await client.query<{
                id: string;
                type: string;
                message: string;
                timestamp: Date;
            }>(`
                (
                    SELECT 
                        id::text,
                        'lead' as type,
                        'New lead: ' || company_name as message,
                        created_at as timestamp
                    FROM leads 
                    WHERE score >= 70
                    ORDER BY created_at DESC 
                    LIMIT 3
                )
                UNION ALL
                (
                    SELECT 
                        id::text,
                        'risk' as type,
                        'Tenant "' || name || '" flagged: risk score ' || risk_score as message,
                        updated_at as timestamp
                    FROM tenants 
                    WHERE risk_score >= 70
                    ORDER BY updated_at DESC 
                    LIMIT 2
                )
                UNION ALL
                (
                    SELECT 
                        id::text,
                        'campaign' as type,
                        'Campaign "' || name || '" - ' || 
                            COALESCE((stats->>'emailsSent')::int, 0)::text || ' emails sent' as message,
                        updated_at as timestamp
                    FROM campaigns 
                    WHERE status = 'active'
                    ORDER BY updated_at DESC 
                    LIMIT 2
                )
                UNION ALL
                (
                    SELECT 
                        id::text,
                        'gdpr' as type,
                        'GDPR request from ' || email as message,
                        created_at as timestamp
                    FROM gdpr_requests 
                    WHERE status = 'pending'
                    ORDER BY created_at DESC 
                    LIMIT 2
                )
                ORDER BY timestamp DESC
                LIMIT 10
            `);

            // Build pipeline object
            const pipelineMap: Record<string, number> = {
                prospect: 0,
                outreach: 0,
                engaged: 0,
                demo_scheduled: 0,
                closed_won: 0,
            };
            for (const row of pipelineResult.rows) {
                pipelineMap[row.stage] = parseInt(row.count, 10);
            }

            // Determine health status
            let healthStatus: 'healthy' | 'degraded' | 'down' = 'healthy';
            if (healthResult.rows[0]) {
                const { status, last_check } = healthResult.rows[0];
                const checkAge = Date.now() - new Date(last_check).getTime();
                if (status === 'down' || checkAge > 5 * 60 * 1000) {
                    healthStatus = 'down';
                } else if (status === 'degraded') {
                    healthStatus = 'degraded';
                }
            }

            const stats: DashboardStats = {
                sales: {
                    activeLeads: parseInt(activeLeadsResult.rows[0]?.count || '0', 10),
                    leadsThisWeek: parseInt(leadsThisWeekResult.rows[0]?.count || '0', 10),
                    campaignsRunning: parseInt(campaignsRunningResult.rows[0]?.count || '0', 10),
                    demosScheduled: parseInt(demosScheduledResult.rows[0]?.count || '0', 10),
                    conversionRate: parseFloat(conversionResult.rows[0]?.conversion_rate || '0'),
                },
                compliance: {
                    riskAlerts: parseInt(riskAlertsResult.rows[0]?.count || '0', 10),
                    criticalTenants: parseInt(criticalTenantsResult.rows[0]?.count || '0', 10),
                    gdprPending: parseInt(gdprPendingResult.rows[0]?.count || '0', 10),
                    auditEventsToday: parseInt(auditEventsTodayResult.rows[0]?.count || '0', 10),
                },
                platform: {
                    activeTenants: parseInt(activeTenantsResult.rows[0]?.count || '0', 10),
                    totalEmails: parseInt(totalEmailsResult.rows[0]?.count || '0', 10),
                    mrr: parseFloat(mrrResult.rows[0]?.mrr || '0'),
                    healthStatus,
                },
                recentActivity: recentActivityResult.rows.map((row: ActivityRow) => ({
                    id: row.id,
                    type: row.type,
                    message: row.message,
                    timestamp: row.timestamp.toISOString(),
                })),
                pipeline: {
                    prospect: pipelineMap.prospect || 0,
                    outreach: pipelineMap.outreach || 0,
                    engaged: pipelineMap.engaged || 0,
                    demo: pipelineMap.demo_scheduled || 0,
                    closed: pipelineMap.closed_won || 0,
                },
            };

            return NextResponse.json(stats);
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Dashboard stats error:', error);
        
        // Return fallback data on error (graceful degradation)
        return NextResponse.json({
            sales: {
                activeLeads: 0,
                leadsThisWeek: 0,
                campaignsRunning: 0,
                demosScheduled: 0,
                conversionRate: 0,
            },
            compliance: {
                riskAlerts: 0,
                criticalTenants: 0,
                gdprPending: 0,
                auditEventsToday: 0,
            },
            platform: {
                activeTenants: 0,
                totalEmails: 0,
                mrr: 0,
                healthStatus: 'down' as const,
            },
            recentActivity: [],
            pipeline: {
                prospect: 0,
                outreach: 0,
                engaged: 0,
                demo: 0,
                closed: 0,
            },
        }, { status: 200 }); // Return 200 with empty data for graceful degradation
    }
}
