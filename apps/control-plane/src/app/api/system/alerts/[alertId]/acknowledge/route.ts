/** 
 * System Alert Acknowledgment - Acknowledge a system alert
 */
import { NextResponse } from 'next/server';
import { proxyToRust } from '@/lib/rust-api';

const SAFE_ID = /^[a-zA-Z0-9._:-]+$/;

function validateId(id: string) {
    if (!SAFE_ID.test(id)) return NextResponse.json({ error: 'Invalid alertId' }, { status: 400 });
    return null;
}

export const PATCH = (r: Request, { params }: { params: { alertId: string } }) => 
    validateId(params.alertId) ?? proxyToRust(r, `/v1/admin/system/alerts/${params.alertId}/acknowledge`);

// Frontend sends POST; keep both methods for compatibility
export const POST = (r: Request, { params }: { params: { alertId: string } }) => 
    validateId(params.alertId) ?? proxyToRust(r, `/v1/admin/system/alerts/${params.alertId}/acknowledge`);
