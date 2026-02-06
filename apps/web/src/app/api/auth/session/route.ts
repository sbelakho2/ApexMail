/**
 * Session Info API
 * 
 * Returns current session information including impersonation status.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import * as crypto from 'crypto';

const IMPERSONATION_SESSION_COOKIE = 'impersonation_session';

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
    const impersonationToken = request.cookies.get(IMPERSONATION_SESSION_COOKIE)?.value;
    
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
                { authenticated: false, impersonation: null, error: 'Server configuration error' },
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
            };
        }
    }
    
    // TODO: Also check for regular user session
    // const userSession = request.cookies.get('session')?.value;
    // ...
    
    return NextResponse.json(response);
}
