/**
 * Analytics API
 *
 * FIX-500-142: DB-backed analytics — no demo data.
 * Queries events and messages tables for real metrics.
 */

import { NextRequest, NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

interface StatsRow {
    total_sent: string;
    total_delivered: string;
    total_opened: string;
    total_clicked: string;
    total_bounced: string;
    total_complaints: string;
}

interface TimeSeriesRow {
    date: string;
    sent: string;
    delivered: string;
    opened: string;
    clicked: string;
}

interface ProviderRow {
    provider: string;
    count: string;
}

interface ColumnRow {
    column_name: string;
}

interface EventSchema {
    eventColumn: 'event_type' | 'type';
    timeColumn: 'created_at' | 'timestamp';
    recipientColumn: 'recipient' | 'recipient_email' | null;
}

async function resolveEventSchema(): Promise<EventSchema | null> {
    const rows = await query<ColumnRow>(
        `SELECT column_name
         FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'events'
           AND column_name IN ('event_type', 'type', 'created_at', 'timestamp', 'recipient', 'recipient_email')`
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

    const recipientColumn = columns.has('recipient')
        ? 'recipient'
        : columns.has('recipient_email')
            ? 'recipient_email'
            : null;

    return {
        eventColumn,
        timeColumn,
        recipientColumn,
    };
}

export async function GET(request: NextRequest) {
    const { searchParams } = new URL(request.url);
    const range = searchParams.get('range') || '30d';
    
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
                stats: {
                    totalSent: 0,
                    totalDelivered: 0,
                    totalOpened: 0,
                    totalClicked: 0,
                    totalBounced: 0,
                    totalComplaints: 0,
                    deliveryRate: '0',
                    openRate: '0',
                    clickRate: '0',
                    bounceRate: '0',
                    complaintRate: '0',
                },
                timeSeries: [],
                providers: [],
                warning: 'events table schema unavailable',
            });
        }

        const { eventColumn, timeColumn, recipientColumn } = schema;

        const providerQuery = recipientColumn
            ? query<ProviderRow>(
                `SELECT 
                    CASE 
                        WHEN ${recipientColumn} LIKE '%@gmail.com' THEN 'Gmail'
                        WHEN ${recipientColumn} LIKE '%@yahoo.%' THEN 'Yahoo'
                        WHEN ${recipientColumn} LIKE '%@outlook.%' OR ${recipientColumn} LIKE '%@hotmail.%' THEN 'Microsoft'
                        WHEN ${recipientColumn} LIKE '%@icloud.%' OR ${recipientColumn} LIKE '%@me.com' THEN 'iCloud'
                        ELSE 'Other'
                    END AS provider,
                    COUNT(*)::text AS count
                FROM events
                WHERE ${eventColumn} = 'sent' AND ${timeColumn} >= NOW() - $1::interval
                GROUP BY provider
                ORDER BY COUNT(*) DESC`,
                [interval]
            )
            : Promise.resolve([] as ProviderRow[]);

        const [statsResult, timeSeriesResult, providerResult] = await Promise.all([
            // Aggregate stats
            query<StatsRow>(
                `SELECT 
                    COALESCE(SUM(CASE WHEN ${eventColumn} = 'sent' THEN 1 ELSE 0 END), 0)::text AS total_sent,
                    COALESCE(SUM(CASE WHEN ${eventColumn} = 'delivered' THEN 1 ELSE 0 END), 0)::text AS total_delivered,
                    COALESCE(SUM(CASE WHEN ${eventColumn} = 'opened' THEN 1 ELSE 0 END), 0)::text AS total_opened,
                    COALESCE(SUM(CASE WHEN ${eventColumn} = 'clicked' THEN 1 ELSE 0 END), 0)::text AS total_clicked,
                    COALESCE(SUM(CASE WHEN ${eventColumn} = 'bounced' THEN 1 ELSE 0 END), 0)::text AS total_bounced,
                    COALESCE(SUM(CASE WHEN ${eventColumn} = 'complained' THEN 1 ELSE 0 END), 0)::text AS total_complaints
                FROM events
                WHERE ${timeColumn} >= NOW() - $1::interval`,
                [interval]
            ),
            
            // Time series data
            query<TimeSeriesRow>(
                `SELECT 
                    DATE(${timeColumn})::text AS date,
                    SUM(CASE WHEN ${eventColumn} = 'sent' THEN 1 ELSE 0 END)::text AS sent,
                    SUM(CASE WHEN ${eventColumn} = 'delivered' THEN 1 ELSE 0 END)::text AS delivered,
                    SUM(CASE WHEN ${eventColumn} = 'opened' THEN 1 ELSE 0 END)::text AS opened,
                    SUM(CASE WHEN ${eventColumn} = 'clicked' THEN 1 ELSE 0 END)::text AS clicked
                FROM events
                WHERE ${timeColumn} >= NOW() - $1::interval
                GROUP BY DATE(${timeColumn})
                ORDER BY DATE(${timeColumn}) ASC`,
                [interval]
            ),
            providerQuery,
        ]);
        
        const stats = statsResult[0] || {
            total_sent: '0',
            total_delivered: '0',
            total_opened: '0',
            total_clicked: '0',
            total_bounced: '0',
            total_complaints: '0',
        };
        
        const totalSent = parseInt(stats.total_sent, 10);
        const totalDelivered = parseInt(stats.total_delivered, 10);
        const totalOpened = parseInt(stats.total_opened, 10);
        const totalClicked = parseInt(stats.total_clicked, 10);
        const totalBounced = parseInt(stats.total_bounced, 10);
        const totalComplaints = parseInt(stats.total_complaints, 10);
        
        return NextResponse.json({
            stats: {
                totalSent,
                totalDelivered,
                totalOpened,
                totalClicked,
                totalBounced,
                totalComplaints,
                deliveryRate: totalSent > 0 ? ((totalDelivered / totalSent) * 100).toFixed(2) : '0',
                openRate: totalDelivered > 0 ? ((totalOpened / totalDelivered) * 100).toFixed(2) : '0',
                clickRate: totalOpened > 0 ? ((totalClicked / totalOpened) * 100).toFixed(2) : '0',
                bounceRate: totalSent > 0 ? ((totalBounced / totalSent) * 100).toFixed(2) : '0',
                complaintRate: totalDelivered > 0 ? ((totalComplaints / totalDelivered) * 100).toFixed(4) : '0',
            },
            timeSeries: timeSeriesResult.map(row => ({
                date: row.date,
                sent: parseInt(row.sent, 10),
                delivered: parseInt(row.delivered, 10),
                opened: parseInt(row.opened, 10),
                clicked: parseInt(row.clicked, 10),
            })),
            providers: providerResult.map(row => ({
                provider: row.provider,
                count: parseInt(row.count, 10),
            })),
        });
    } catch (error) {
        console.error('Analytics API error:', error);
        return NextResponse.json({ error: 'Failed to fetch analytics' }, { status: 500 });
    }
}
