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

interface ColumnRow {
    column_name: string;
}

interface EventSchema {
    eventColumn: 'event_type' | 'type';
    timeColumn: 'created_at' | 'timestamp';
}

async function resolveEventSchema(): Promise<EventSchema | null> {
    const rows = await query<ColumnRow>(
        `SELECT column_name
         FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'events'
           AND column_name IN ('event_type', 'type', 'created_at', 'timestamp')`
    );

    if (rows.length === 0) {
        return null;
    }

    const columns = new Set(rows.map(row => row.column_name));
    const eventColumn = columns.has('event_type') ? 'event_type' : columns.has('type') ? 'type' : null;
    const timeColumn = columns.has('created_at') ? 'created_at' : columns.has('timestamp') ? 'timestamp' : null;

    if (!eventColumn || !timeColumn) {
        return null;
    }

    return {
        eventColumn,
        timeColumn,
    };
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
        const schema = await resolveEventSchema();
        if (!schema) {
            return NextResponse.json({
                exportedAt: new Date().toISOString(),
                range,
                data: [],
                warning: 'events table schema unavailable',
            });
        }

        const { eventColumn, timeColumn } = schema;

        const rows = await query<ExportRow>(
            `SELECT 
                DATE(${timeColumn})::text AS date,
                SUM(CASE WHEN ${eventColumn} = 'sent' THEN 1 ELSE 0 END)::text AS sent,
                SUM(CASE WHEN ${eventColumn} = 'delivered' THEN 1 ELSE 0 END)::text AS delivered,
                SUM(CASE WHEN ${eventColumn} = 'opened' THEN 1 ELSE 0 END)::text AS opened,
                SUM(CASE WHEN ${eventColumn} = 'clicked' THEN 1 ELSE 0 END)::text AS clicked,
                SUM(CASE WHEN ${eventColumn} = 'bounced' THEN 1 ELSE 0 END)::text AS bounced,
                SUM(CASE WHEN ${eventColumn} = 'complained' THEN 1 ELSE 0 END)::text AS complaints
            FROM events
            WHERE ${timeColumn} >= NOW() - $1::interval
            GROUP BY DATE(${timeColumn})
            ORDER BY DATE(${timeColumn}) ASC`,
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
