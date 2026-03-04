/**
 * Billing API proxy route
 *
 * Thin translation layer between the frontend's legacy `/api/billing` format
 * and the billing service's RESTful endpoints.
 *
 * The billing microservice (apps/billing) exposes:
 *   GET  /api/billing/subscription
 *   POST /api/billing/switch-plan    { planName, billingInterval? }
 *   POST /api/billing/checkout       { priceId, successUrl, cancelUrl }
 *   POST /api/billing/portal         { returnUrl }
 *
 * The frontend calls:
 *   GET  /api/billing                → subscription info
 *   POST /api/billing  { action: 'checkout', planName }  → plan change / Stripe checkout
 *   POST /api/billing  { action: 'portal' }              → Stripe customer portal
 */

import { NextRequest, NextResponse } from 'next/server';

const BILLING_URL = process.env.BILLING_URL || 'http://localhost:4100';

async function proxyToBilling(
    path: string,
    req: NextRequest,
    method: string = 'GET',
    body?: unknown,
): Promise<NextResponse> {
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
    };

    // Forward authentication cookies so the billing service can verify the session.
    const cookie = req.headers.get('cookie');
    if (cookie) headers['cookie'] = cookie;

    // Forward CSRF token
    const csrf = req.headers.get('x-csrf-token');
    if (csrf) headers['x-csrf-token'] = csrf;

    // Forward authorization header if present
    const authorization = req.headers.get('authorization');
    if (authorization) headers['authorization'] = authorization;

    const resp = await fetch(`${BILLING_URL}${path}`, {
        method,
        headers,
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });

    const data = await resp.json().catch(() => ({}));

    // Pass through Set-Cookie headers from the billing service
    const response = NextResponse.json(data, { status: resp.status });
    const setCookie = resp.headers.get('set-cookie');
    if (setCookie) {
        response.headers.set('set-cookie', setCookie);
    }

    return response;
}

export async function GET(req: NextRequest) {
    return proxyToBilling('/api/billing/subscription', req);
}

export async function POST(req: NextRequest) {
    const body = await req.json().catch(() => ({}));

    if (body.action === 'checkout') {
        // Use the switch-plan endpoint which accepts planName directly and
        // handles both proration for existing subscribers and new checkout sessions.
        const result = await proxyToBilling('/api/billing/switch-plan', req, 'POST', {
            planName: body.planName,
            billingInterval: body.billingInterval || 'monthly',
        });

        // Normalise the response so the frontend can check for `checkoutUrl`.
        const data = await result.json();
        if (data.checkoutUrl || data.url) {
            return NextResponse.json({ checkoutUrl: data.checkoutUrl || data.url }, { status: result.status });
        }
        return NextResponse.json(data, { status: result.status });
    }

    if (body.action === 'portal') {
        const origin = req.headers.get('origin') || req.nextUrl.origin;
        const result = await proxyToBilling('/api/billing/portal', req, 'POST', {
            returnUrl: `${origin}/settings/billing`,
        });

        // Normalise: the frontend expects { url } for portal redirects.
        const data = await result.json();
        if (data.url || data.portalUrl) {
            return NextResponse.json({ url: data.url || data.portalUrl }, { status: result.status });
        }
        return NextResponse.json(data, { status: result.status });
    }

    return NextResponse.json({ error: 'Unknown billing action' }, { status: 400 });
}
