import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

// TODO: Replace with DB query against calendar_events table
const DEMO_EVENTS = [
    { id: '1', title: 'Discovery Call - TechCorp', leadName: 'John Smith', leadEmail: 'john@techcorp.io', leadCompany: 'TechCorp', type: 'discovery', status: 'scheduled', startTime: new Date(1737000000000 + 86400000).toISOString(), endTime: new Date(1737000000000 + 86400000 + 1800000).toISOString(), notes: 'Interested in enterprise features', meetingLink: 'https://meet.apexmail.io/demo/abc123' },
    { id: '2', title: 'Product Demo - Growth.io', leadName: 'Sarah Williams', leadEmail: 'sarah@growth.io', leadCompany: 'Growth.io', type: 'demo', status: 'scheduled', startTime: new Date(1737000000000 + 172800000).toISOString(), endTime: new Date(1737000000000 + 172800000 + 3600000).toISOString(), notes: '50 users, 100k emails/month', meetingLink: 'https://meet.apexmail.io/demo/def456' },
    { id: '3', title: 'Follow-up - StartupXYZ', leadName: 'Mike Johnson', leadEmail: 'mike@startupxyz.com', leadCompany: 'StartupXYZ', type: 'follow_up', status: 'completed', startTime: new Date(1737000000000 - 86400000).toISOString(), endTime: new Date(1737000000000 - 86400000 + 1800000).toISOString(), notes: 'Discussing pricing options', outcome: 'needs_follow_up', meetingLink: 'https://meet.apexmail.io/demo/ghi789' },
    { id: '4', title: 'Demo - Enterprise Co', leadName: 'Alice Brown', leadEmail: 'alice@enterprise.co', leadCompany: 'Enterprise Co', type: 'demo', status: 'no_show', startTime: new Date(1737000000000 - 172800000).toISOString(), endTime: new Date(1737000000000 - 172800000 + 3600000).toISOString(), notes: 'Large enterprise deal', meetingLink: 'https://meet.apexmail.io/demo/jkl012' },
];

const DEFAULT_AVAILABILITY = [
    { id: '1', dayOfWeek: 1, startTime: '09:00', endTime: '12:00', enabled: true },
    { id: '2', dayOfWeek: 1, startTime: '14:00', endTime: '17:00', enabled: true },
    { id: '3', dayOfWeek: 2, startTime: '09:00', endTime: '12:00', enabled: true },
    { id: '4', dayOfWeek: 2, startTime: '14:00', endTime: '17:00', enabled: true },
    { id: '5', dayOfWeek: 3, startTime: '09:00', endTime: '12:00', enabled: true },
    { id: '6', dayOfWeek: 3, startTime: '14:00', endTime: '17:00', enabled: true },
    { id: '7', dayOfWeek: 4, startTime: '09:00', endTime: '12:00', enabled: true },
    { id: '8', dayOfWeek: 4, startTime: '14:00', endTime: '17:00', enabled: true },
    { id: '9', dayOfWeek: 5, startTime: '09:00', endTime: '12:00', enabled: true },
    { id: '10', dayOfWeek: 5, startTime: '14:00', endTime: '16:00', enabled: true },
];

export async function GET() {
    try {
        // TODO: Query calendar_events and availability_slots tables
        return NextResponse.json({
            events: DEMO_EVENTS,
            availability: DEFAULT_AVAILABILITY,
        });
    } catch {
        return NextResponse.json({
            events: DEMO_EVENTS,
            availability: DEFAULT_AVAILABILITY,
        });
    }
}
