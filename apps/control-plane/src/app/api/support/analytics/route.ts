/**
 * Support Ticket Analytics API
 *
 * Returns aggregated ticket analytics for the control plane dashboard.
 */

import { NextRequest, NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
    try {
        const rawDays = parseInt(request.nextUrl.searchParams.get('days') ?? '30', 10);
        const days = Number.isFinite(rawDays) ? Math.min(Math.max(rawDays, 1), 365) : 30;
        const since = new Date();
        since.setDate(since.getDate() - days);

        const [
            statusCounts,
            categoryCounts,
            priorityCounts,
            timeline,
            topTenants,
            avgResolution,
            recentTickets,
            responseTimeBuckets,
        ] = await Promise.all([
            query<{ status: string; count: string }>(
                `SELECT status, COUNT(*)::text AS count FROM support_tickets GROUP BY status`
            ),
            query<{ category: string; count: string }>(
                `SELECT COALESCE(category, 'general') AS category, COUNT(*)::text AS count
                 FROM support_tickets GROUP BY category`
            ),
            query<{ priority: string; count: string }>(
                `SELECT priority, COUNT(*)::text AS count FROM support_tickets GROUP BY priority`
            ),
            query<{ date: string; count: string }>(
                `SELECT DATE(created_at)::text AS date, COUNT(*)::text AS count
                 FROM support_tickets WHERE created_at >= $1
                 GROUP BY DATE(created_at) ORDER BY date`,
                [since]
            ),
            query<{ tenant_name: string; count: string }>(
                `SELECT COALESCE(tenant_name, 'Unknown') AS tenant_name, COUNT(*)::text AS count
                 FROM support_tickets GROUP BY tenant_name ORDER BY COUNT(*) DESC LIMIT 10`
            ),
            query<{ avg_hours: string }>(
                `SELECT COALESCE(
                   AVG(EXTRACT(EPOCH FROM (updated_at - created_at)) / 3600), 0
                 )::text AS avg_hours
                 FROM support_tickets WHERE status IN ('resolved', 'closed')`
            ),
            query<{ id: string; subject: string; tenant_name: string; status: string; priority: string; category: string; created_at: string }>(
                `SELECT id, subject, COALESCE(tenant_name, 'Unknown') AS tenant_name,
                        status, priority, COALESCE(category, 'general') AS category, created_at
                 FROM support_tickets
                 ORDER BY created_at DESC LIMIT 10`
            ),
            query<{ bucket: string; count: string }>(
                `SELECT
                   CASE
                     WHEN EXTRACT(EPOCH FROM (updated_at - created_at)) / 3600 < 1 THEN '< 1h'
                     WHEN EXTRACT(EPOCH FROM (updated_at - created_at)) / 3600 < 4 THEN '1-4h'
                     WHEN EXTRACT(EPOCH FROM (updated_at - created_at)) / 3600 < 24 THEN '4-24h'
                     WHEN EXTRACT(EPOCH FROM (updated_at - created_at)) / 3600 < 72 THEN '1-3d'
                     ELSE '> 3d'
                   END AS bucket,
                   COUNT(*)::text AS count
                 FROM support_tickets
                 WHERE status IN ('resolved', 'closed')
                 GROUP BY bucket`
            ),
        ]);

        const toMap = (rows: { [key: string]: string }[], keyField: string) => {
            const map: Record<string, number> = {};
            for (const row of rows) map[row[keyField]] = parseInt(row.count, 10);
            return map;
        };

        const statusMap = toMap(statusCounts, 'status');
        const totalTickets = Object.values(statusMap).reduce((a, b) => a + b, 0);

        return NextResponse.json({
            totalTickets,
            openTickets: statusMap['open'] ?? 0,
            inProgressTickets: statusMap['in_progress'] ?? 0,
            waitingTickets: statusMap['waiting_on_customer'] ?? 0,
            resolvedTickets: statusMap['resolved'] ?? 0,
            closedTickets: statusMap['closed'] ?? 0,
            urgentTickets: toMap(priorityCounts, 'priority')['urgent'] ?? 0,
            avgResolutionHours: parseFloat(avgResolution[0]?.avg_hours ?? '0'),
            ticketsByCategory: toMap(categoryCounts, 'category'),
            ticketsByPriority: toMap(priorityCounts, 'priority'),
            ticketsOverTime: timeline.map(r => ({ date: r.date, count: parseInt(r.count, 10) })),
            topTenants: topTenants.map(r => ({ tenantName: r.tenant_name, count: parseInt(r.count, 10) })),
            recentTickets: recentTickets.map(r => ({
                id: r.id,
                subject: r.subject,
                tenantName: r.tenant_name,
                status: r.status,
                priority: r.priority,
                category: r.category,
                createdAt: r.created_at,
            })),
            responseTimeBuckets: toMap(responseTimeBuckets, 'bucket'),
        });
    } catch (error) {
        console.error('Support analytics error:', error);
        return NextResponse.json({ error: 'Failed to fetch analytics' }, { status: 500 });
    }
}
