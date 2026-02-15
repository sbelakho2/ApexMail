/**
 * Autopilot Console API
 *
 * Proxies to the Sales Autopilot operator/loop endpoints (port 3010).
 */

import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const AUTOPILOT_BASE = process.env.AUTOPILOT_API_URL || 'http://localhost:3010';

async function autopilotFetch(path: string, init?: RequestInit): Promise<{ ok: boolean; status: number; data: unknown }> {
    try {
        const res = await fetch(`${AUTOPILOT_BASE}${path}`, {
            ...init,
            headers: { 'Content-Type': 'application/json', ...init?.headers },
            signal: AbortSignal.timeout(5000),
        });

        const payload = await res.json().catch(() => ({}));
        return { ok: res.ok, status: res.status, data: payload };
    } catch {
        return { ok: false, status: 502, data: { error: 'Autopilot backend unavailable' } };
    }
}

// ── GET handler — returns combined dashboard data ──

export async function GET(request: NextRequest) {
    const section = request.nextUrl.searchParams.get('section') || 'overview';

    const resolveResponse = (result: { ok: boolean; status: number; data: unknown }) => {
        if (!result.ok) {
            return NextResponse.json(
                { error: 'Failed to fetch autopilot data', details: result.data },
                { status: result.status || 502 }
            );
        }

        const envelope = result.data as { data?: unknown };
        if (envelope && typeof envelope === 'object' && 'data' in envelope) {
            return NextResponse.json(envelope.data);
        }

        return NextResponse.json(result.data);
    };

    switch (section) {
        case 'overview': {
            return resolveResponse(await autopilotFetch('/api/v1/operator/overview'));
        }
        case 'metrics': {
            return resolveResponse(await autopilotFetch('/api/v1/operator/metrics'));
        }
        case 'baseline': {
            return resolveResponse(await autopilotFetch('/api/v1/operator/baseline'));
        }
        case 'candidates': {
            return resolveResponse(await autopilotFetch('/api/v1/operator/candidates'));
        }
        case 'outcomes': {
            return resolveResponse(await autopilotFetch('/api/v1/operator/outcomes'));
        }
        case 'pending': {
            return resolveResponse(await autopilotFetch('/api/v1/operator/approvals/pending'));
        }
        case 'actions': {
            return resolveResponse(await autopilotFetch('/api/v1/operator/actions'));
        }
        case 'safety': {
            return resolveResponse(await autopilotFetch('/api/v1/operator/safety'));
        }
        default:
            return NextResponse.json({ error: 'Unknown section' }, { status: 400 });
    }
}

// ── POST handler — start/stop, approve/reject ──

export async function POST(request: NextRequest) {
    const body = await request.json();
    const action = body.action as string;

    const resolveMutation = (result: { ok: boolean; status: number; data: unknown }) => {
        if (!result.ok) {
            return NextResponse.json(
                { error: 'Failed to execute autopilot action', details: result.data },
                { status: result.status || 502 }
            );
        }
        return NextResponse.json(result.data);
    };

    switch (action) {
        case 'start': {
            return resolveMutation(await autopilotFetch('/api/v1/operator/start', { method: 'POST' }));
        }
        case 'stop': {
            return resolveMutation(await autopilotFetch('/api/v1/operator/stop', { method: 'POST' }));
        }
        case 'approve': {
            const id = body.id as string;
            return resolveMutation(await autopilotFetch(`/api/v1/operator/approvals/${id}/approve`, { method: 'POST' }));
        }
        case 'reject': {
            const id = body.id as string;
            return resolveMutation(await autopilotFetch(`/api/v1/operator/approvals/${id}/reject`, { method: 'POST' }));
        }
        case 'approve-all': {
            return resolveMutation(await autopilotFetch('/api/v1/operator/approvals/approve-all', { method: 'POST' }));
        }
        case 'exit-safe-mode': {
            return resolveMutation(await autopilotFetch('/api/v1/operator/safe-mode/exit', { method: 'POST' }));
        }
        default:
            return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
    }
}
