/**
 * Calendar event status update
 */
import { NextResponse } from 'next/server';
import { proxyToRust } from '@/lib/rust-api';

const SAFE_ID = /^[a-zA-Z0-9._:-]+$/;

export const PATCH = (r: Request, { params }: { params: { eventId: string } }) => {
    if (!SAFE_ID.test(params.eventId)) return NextResponse.json({ error: 'Invalid eventId' }, { status: 400 });
    return proxyToRust(r, `/v1/admin/calendar/events/${params.eventId}/status`);
};
