/**
 * Sales Lead Enrichment API Route
 *
 * POST: Trigger enrichment for a list of lead IDs
 * Enriches with contact info, company size, LinkedIn, traffic estimates
 *
 * Improvement #50: On-demand lead enrichment
 */

import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const AUTOPILOT_BASE = process.env.AUTOPILOT_API_URL || 'http://localhost:3010';
const OWNER_TENANT_ID = process.env.CONTROL_PLANE_OWNER_TENANT_ID || 'apexmail-owner';

export async function POST(request: NextRequest) {
    try {
        const body = await request.json();
        const { leadIds } = body;

        if (!leadIds || !Array.isArray(leadIds) || leadIds.length === 0) {
            return NextResponse.json(
                { error: 'At least one lead ID is required' },
                { status: 400 }
            );
        }

        if (leadIds.length > 50) {
            return NextResponse.json(
                { error: 'Maximum 50 leads per enrichment batch' },
                { status: 400 }
            );
        }

        const response = await fetch(`${AUTOPILOT_BASE}/api/v1/enrichment/run`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                tenantId: OWNER_TENANT_ID,
                leadIds,
            }),
            signal: AbortSignal.timeout(60000),
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            return NextResponse.json(
                { error: 'Enrichment job failed', details: error },
                { status: response.status }
            );
        }

        const result = await response.json();
        return NextResponse.json({
            success: true,
            enriched: result.data?.enrichedCount ?? leadIds.length,
            results: result.data?.results ?? [],
        });
    } catch (error) {
        console.error('Enrichment API error:', error);
        if (error instanceof Error && error.name === 'TimeoutError') {
            return NextResponse.json(
                { error: 'Enrichment job timed out' },
                { status: 504 }
            );
        }
        return NextResponse.json(
            { error: 'Failed to run enrichment' },
            { status: 500 }
        );
    }
}
