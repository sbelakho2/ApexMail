/**
 * Session Info API
 * 
 * Returns current session information including impersonation status.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import * as crypto from 'crypto';

const IMPERSONATION_SESSION_COOKIE = 'impersonation_session';
const USER_SESSION_COOKIE = 'am_session';

function validateSession(sessionToken: string, secret: string): { valid: boolean; payload?: Record<string, unknown> } {
    try {
        const [payloadB64, signature] = sessionToken.split('.');
        if (!payloadB64 || !signature) {
            return { valid: false };
        }
        
        const expectedSignature = crypto
            .createHmac('sha256', secret)
            .update(payloadB64)
            .digest('base64url');
        
        const sigBuffer = Buffer.from(signature);
        const expectedBuffer = Buffer.from(expectedSignature);
        
        if (sigBuffer.length !== expectedBuffer.length) {
            return { valid: false };
        }
        
        if (!crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
            return { valid: false };
        }
        
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
        
        if (payload.exp && Date.now() > payload.exp) {
            return { valid: false };
        }
        
        return { valid: true, payload };
    } catch {
        return { valid: false };
    }
}

export async function GET(request: NextRequest) {
    if (process.env.E2E_TEST_MODE === 'true') {
        return NextResponse.json({
            authenticated: true,
            impersonation: null,
            sessionType: 'e2e',
        });
    }

    const impersonationToken = request.cookies.get(IMPERSONATION_SESSION_COOKIE)?.value;
    const userSessionToken = request.cookies.get(USER_SESSION_COOKIE)?.value;
    
    const response: Record<string, unknown> = {
        authenticated: false,
        impersonation: null,
    };
    
    // Check for impersonation session
    if (impersonationToken) {
        const secret = process.env.SESSION_SECRET;
        if (!secret) {
            console.error('[SECURITY] SESSION_SECRET not configured');
            return NextResponse.json(
                { authenticated: false, impersonation: null },
                { status: 500 }
            );
        }
        const validation = validateSession(impersonationToken, secret);
        
        if (validation.valid && validation.payload?.type === 'impersonation') {
            response.authenticated = true;
            response.impersonation = {
                tenantId: validation.payload.tenantId,
                operatorId: validation.payload.operatorId,
                operatorName: validation.payload.operatorName,
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
