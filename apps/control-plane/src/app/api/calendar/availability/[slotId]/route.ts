/**
 * Calendar availability slot by ID - toggle/update/delete
 */
import { NextResponse } from 'next/server';
import { proxyToRust } from '@/lib/rust-api';

const SAFE_ID = /^[a-zA-Z0-9._:-]+$/;

function validateId(id: string) {
    if (!SAFE_ID.test(id)) return NextResponse.json({ error: 'Invalid slotId' }, { status: 400 });
    return null;
}

export const PATCH = (r: Request, { params }: { params: { slotId: string } }) =>
    validateId(params.slotId) ?? proxyToRust(r, `/v1/admin/calendar/availability/${params.slotId}`);

export const DELETE = (r: Request, { params }: { params: { slotId: string } }) =>
    validateId(params.slotId) ?? proxyToRust(r, `/v1/admin/calendar/availability/${params.slotId}`);
