/**
 * Analytics Export API
 *
 * FIX-500-142: Real CSV export of analytics data.
 */

import { NextRequest, NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

interface ExportRow {
    date: string;
    sent: string;
    delivered: string;
    opened: string;
    clicked: string;
    bounced: string;
    complaints: string;
}

export async function GET(request: NextRequest) {
    const { searchParams } = new URL(request.url);
    const range = searchParams.get('range') || '30d';
    const format = searchParams.get('format') || 'csv';
    
    // Convert range to interval
    const intervalMap: Record<string, string> = {
        '24h': '24 hours',
        '7d': '7 days',
        '30d': '30 days',
        '90d': '90 days',
        '12m': '12 months',
    };
    const interval = intervalMap[range] || '30 days';
    
    try {
        const rows = await query<ExportRow>(
            `SELECT 
                DATE(created_at)::text AS date,
                SUM(CASE WHEN event_type = 'sent' THEN 1 ELSE 0 END)::text AS sent,
                SUM(CASE WHEN event_type = 'delivered' THEN 1 ELSE 0 END)::text AS delivered,
                SUM(CASE WHEN event_type = 'opened' THEN 1 ELSE 0 END)::text AS opened,
                SUM(CASE WHEN event_type = 'clicked' THEN 1 ELSE 0 END)::text AS clicked,
                SUM(CASE WHEN event_type = 'bounced' THEN 1 ELSE 0 END)::text AS bounced,
                SUM(CASE WHEN event_type = 'complained' THEN 1 ELSE 0 END)::text AS complaints
            FROM events
            WHERE created_at >= NOW() - $1::interval
            GROUP BY DATE(created_at)
            ORDER BY DATE(created_at) ASC`,
            [interval]
        );
        
        if (format === 'json') {
            return NextResponse.json({
                exportedAt: new Date().toISOString(),
                range,
                data: rows.map(row => ({
                    date: row.date,
                    sent: parseInt(row.sent, 10),
                    delivered: parseInt(row.delivered, 10),
                    opened: parseInt(row.opened, 10),
                    clicked: parseInt(row.clicked, 10),
                    bounced: parseInt(row.bounced, 10),
                    complaints: parseInt(row.complaints, 10),
                })),
            });
        }
        
        // CSV format
        const headers = ['Date', 'Sent', 'Delivered', 'Opened', 'Clicked', 'Bounced', 'Complaints'];
        const csvLines = [
            headers.join(','),
            ...rows.map(row => [
                row.date,
                row.sent,
                row.delivered,
                row.opened,
                row.clicked,
                row.bounced,
                row.complaints,
            ].join(',')),
        ];
        const csv = csvLines.join('\n');
        
        const timestamp = new Date().toISOString().slice(0, 10);
        const filename = `analytics-export-${range}-${timestamp}.csv`;
        
        return new NextResponse(csv, {
            headers: {
                'Content-Type': 'text/csv; charset=utf-8',
                'Content-Disposition': `attachment; filename="${filename}"`,
            },
        });
    } catch (error) {
        console.error('Analytics export error:', error);
        return NextResponse.json({ error: 'Failed to export analytics' }, { status: 500 });
    }
}
