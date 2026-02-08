/**
 * Calendar API
 *
 * FIX-500-141: DB-backed calendar events — no demo data.
 * Queries calendar_events + availability_slots tables.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

interface EventRow {
    id: string;
    title: string;
    lead_name: string | null;
    lead_email: string | null;
    lead_company: string | null;
    type: string;
    status: string;
    start_time: string;
    end_time: string;
    notes: string | null;
    outcome: string | null;
    meeting_link: string | null;
}

interface AvailRow {
    id: string;
    day_of_week: number;
    start_time: string;
    end_time: string;
    enabled: boolean;
}

export async function GET() {
    try {
        const [events, availability] = await Promise.all([
            query<EventRow>(
                `SELECT id, title, lead_name, lead_email, lead_company, type,
                        status, start_time, end_time, notes, outcome, meeting_link
                 FROM calendar_events
                 ORDER BY start_time DESC
                 LIMIT 100`
            ),
            query<AvailRow>(
                `SELECT id, day_of_week, start_time, end_time, enabled
                 FROM availability_slots
                 ORDER BY day_of_week, start_time`
            ),
        ]);

        return NextResponse.json({
            events: events.map((e) => ({
                id: e.id,
                title: e.title,
                leadName: e.lead_name,
                leadEmail: e.lead_email,
                leadCompany: e.lead_company,
                type: e.type,
                status: e.status,
                startTime: e.start_time,
                endTime: e.end_time,
                notes: e.notes,
                outcome: e.outcome,
                meetingLink: e.meeting_link,
            })),
            availability: availability.map((a) => ({
                id: a.id,
                dayOfWeek: a.day_of_week,
                startTime: a.start_time,
                endTime: a.end_time,
                enabled: a.enabled,
            })),
        });
    } catch (error) {
        console.error('Calendar API error:', error);
        return NextResponse.json({ error: 'Failed to fetch calendar data' }, { status: 500 });
    }
}
