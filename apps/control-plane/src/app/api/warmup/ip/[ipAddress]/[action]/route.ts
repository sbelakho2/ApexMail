/**
 * IP Warmup per-IP actions (start/pause/resume/reset/day)
 */
import { NextResponse } from 'next/server';
import { proxyToRust } from '@/lib/rust-api';

const SAFE_IP = /^[0-9a-fA-F.:]+$/;
const SAFE_ACTION = /^(start|pause|resume|reset|day)$/;

export const POST = (r: Request, { params }: { params: { ipAddress: string; action: string } }) => {
    if (!SAFE_IP.test(params.ipAddress)) return NextResponse.json({ error: 'Invalid IP address' }, { status: 400 });
    if (!SAFE_ACTION.test(params.action)) return NextResponse.json({ error: 'Invalid action' }, { status: 400 });
    return proxyToRust(r, `/v1/admin/warmup/ip/${params.ipAddress}/${params.action}`);
};
