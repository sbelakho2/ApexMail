/**
 * System worker restart
 */
import { NextResponse } from 'next/server';
import { proxyToRust } from '@/lib/rust-api';

const SAFE_ID = /^[a-zA-Z0-9._:-]+$/;

export const POST = (r: Request, { params }: { params: { workerId: string } }) => {
    if (!SAFE_ID.test(params.workerId)) return NextResponse.json({ error: 'Invalid workerId' }, { status: 400 });
    return proxyToRust(r, `/v1/admin/system/workers/${params.workerId}/restart`);
};
