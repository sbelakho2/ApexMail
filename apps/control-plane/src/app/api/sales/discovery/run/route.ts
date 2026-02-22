/**
 * Sales Discovery Run API Route
 * 
 * Triggers a discovery job via the Sales Autopilot backend.
 * Scrapes SaaS directories and enriches with MX records.
 */

import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const AUTOPILOT_BASE = process.env.AUTOPILOT_API_URL || 'http://localhost:3010';

export async function POST(request: NextRequest) {
    try {
        const body = await request.json();
        const { sources, categories, maxPagesPerSource } = body;

        if (!sources || !Array.isArray(sources) || sources.length === 0) {
            return NextResponse.json(
                { error: 'At least one source must be selected' },
                { status: 400 }
            );
        }

        if (!categories || !Array.isArray(categories) || categories.length === 0) {
            return NextResponse.json(
                { error: 'At least one category must be selected' },
                { status: 400 }
            );
        }

        // Proxy to Sales Autopilot backend
        const response = await fetch(`${AUTOPILOT_BASE}/api/v1/discovery/run`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                tenantId: 'apexmail-owner', // Owner tenant ID
                sources,
                categories,
                maxPagesPerSource: Math.min(maxPagesPerSource || 3, 10),
            }),
            signal: AbortSignal.timeout(120000), // 2 minute timeout for discovery
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            return NextResponse.json(
                { error: 'Discovery job failed', details: error },
                { status: response.status }
            );
        }

        const result = await response.json();
        return NextResponse.json(result.data || result);
    } catch (error) {
        console.error('Discovery run API error:', error);
        if (error instanceof Error && error.name === 'TimeoutError') {
            return NextResponse.json(
                { error: 'Discovery job timed out' },
                { status: 504 }
            );
        }
        return NextResponse.json(
            { error: 'Failed to run discovery job' },
            { status: 500 }
        );
    }
}
