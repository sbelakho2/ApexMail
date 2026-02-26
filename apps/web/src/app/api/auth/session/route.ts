/**
 * Session Info API
 * 
 * Returns current session information including impersonation status.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { verifySignedToken, constantTimeEqual } from '@/lib/signatures';

const IMPERSONATION_SESSION_COOKIE = 'impersonation_session';
const USER_SESSION_COOKIE = 'am_session';
const E2E_BYPASS_HEADER = 'x-e2e-bypass-key';

interface SessionPayload {
    exp?: number;
    type?: string;
    tenantId?: string;
    operatorId?: string;
    operatorName?: string;
}

interface SessionResponse {
    authenticated: boolean;
    impersonation: null | {
        tenantId: string;
        operatorId: string;
        operatorName: string;
        exp?: number;
        expiresAt?: number;
    };
    sessionType?: 'e2e' | 'impersonation' | 'user';
    user?: unknown;
}

function hasValidE2EBypass(request: NextRequest): boolean {
    const e2eEnabled = process.env.NODE_ENV !== 'production' && process.env.E2E_TEST_MODE === 'true';
    const expectedKey = process.env.E2E_BYPASS_KEY;
    const providedKey = request.headers.get(E2E_BYPASS_HEADER);

    if (!e2eEnabled || !expectedKey || !providedKey) {
        return false;
    }

    const expectedBuffer = Buffer.from(expectedKey);
    const providedBuffer = Buffer.from(providedKey);

    if (expectedBuffer.length !== providedBuffer.length) {
        return false;
    }

    return constantTimeEqual(expectedKey, providedKey);
}

async function validateSession(sessionToken: string, secret: string): Promise<{ valid: boolean; payload?: SessionPayload }> {
    try {
        const validation = await verifySignedToken<SessionPayload>(sessionToken, secret);
        if (!validation.valid || !validation.payload) {
            return { valid: false };
        }

        const payload = validation.payload;
        
        if (payload.exp && Date.now() > payload.exp) {
            return { valid: false };
        }
        
        return { valid: true, payload };
    } catch {
        return { valid: false };
    }
}

export async function GET(request: NextRequest) {
    if (hasValidE2EBypass(request)) {
        return NextResponse.json({
            authenticated: true,
            impersonation: null,
            sessionType: 'e2e',
        });
    }

    const impersonationToken = request.cookies.get(IMPERSONATION_SESSION_COOKIE)?.value;
    const userSessionToken = request.cookies.get(USER_SESSION_COOKIE)?.value;
    
    const response: SessionResponse = {
        authenticated: false,
        impersonation: null,
    };
    
    // Check for impersonation session
    if (impersonationToken) {
        const secret = process.env.SESSION_SECRET;
        if (!secret) {
            return NextResponse.json(
                { authenticated: false, impersonation: null },
                { status: 500 }
            );
        }
        const validation = await validateSession(impersonationToken, secret);
        
        if (validation.valid && validation.payload?.type === 'impersonation') {
            response.authenticated = true;
            response.impersonation = {
                tenantId: validation.payload.tenantId ?? '',
                operatorId: validation.payload.operatorId ?? '',
                operatorName: validation.payload.operatorName ?? 'Operator',
                exp: validation.payload.exp,
                expiresAt: validation.payload.exp,
            };
            response.sessionType = 'impersonation';
        }
    }
    
    // Check regular user session when impersonation is not active
    if (!response.authenticated && userSessionToken) {
        const apiBaseUrl = process.env.API_URL || 'http://localhost:3001';

        try {
            const authResponse = await fetch(`${apiBaseUrl}/v1/auth/me`, {
                headers: {
                    Authorization: `Bearer ${userSessionToken}`,
                    'Content-Type': 'application/json',
                },
                cache: 'no-store',
                signal: AbortSignal.timeout(5000),
            });

            if (authResponse.ok) {
                const data = await authResponse.json().catch(() => ({}));
                response.authenticated = true;
                response.user = data.user ?? null;
                response.sessionType = 'user';
            }
        } catch {
            // Keep unauthenticated response on upstream connectivity errors
        }
    }
    
    return NextResponse.json(response);
}
