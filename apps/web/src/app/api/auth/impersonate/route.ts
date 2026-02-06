/**
 * Impersonation Handler API
 * 
 * Handles impersonation tokens from Control Plane to allow
 * platform operators to access the customer console as a specific tenant.
 * 
 * SECURITY:
 * - Validates token signature
 * - Checks token expiration
 * - Sets impersonation session with visible indicator
 * - All actions are logged
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import * as crypto from 'crypto';

const IMPERSONATION_SESSION_COOKIE = 'impersonation_session';

/**
 * Validates an impersonation token
 */
function validateImpersonationToken(token: string): {
    valid: boolean;
    payload?: {
        tenantId: string;
        operatorId: string;
        operatorName: string;
        exp: number;
        jti: string;
    };
} {
    try {
        const [payloadB64, signature] = token.split('.');
        if (!payloadB64 || !signature) {
            return { valid: false };
        }
        
        // Verify signature
        const secret = process.env.IMPERSONATION_SECRET;
        if (!secret) {
            console.error('[SECURITY CRITICAL] IMPERSONATION_SECRET not configured');
            return { valid: false };
        }
        const expectedSignature = crypto
            .createHmac('sha256', secret)
            .update(payloadB64)
            .digest('base64url');
        
        // Timing-safe comparison
        const sigBuffer = Buffer.from(signature);
        const expectedBuffer = Buffer.from(expectedSignature);
        
        if (sigBuffer.length !== expectedBuffer.length) {
            return { valid: false };
        }
        
        if (!crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
            console.warn('[SECURITY] Invalid impersonation token signature');
            return { valid: false };
        }
        
        // Decode payload
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
        
        // Check expiration
        if (payload.exp && Date.now() > payload.exp) {
            console.warn('[SECURITY] Expired impersonation token');
            return { valid: false };
        }
        
        // Verify token type
        if (payload.type !== 'impersonation') {
            return { valid: false };
        }
        
        return {
            valid: true,
            payload: {
                tenantId: payload.tenantId,
                operatorId: payload.operatorId,
                operatorName: payload.operatorName,
                exp: payload.exp,
                jti: payload.jti,
            },
        };
    } catch (error) {
        console.error('[IMPERSONATION] Token validation error:', error);
        return { valid: false };
    }
}

export async function GET(request: NextRequest) {
    const token = request.nextUrl.searchParams.get('token');
    
    if (!token) {
        return NextResponse.redirect(new URL('/login?error=missing_token', request.url));
    }
    
    const validation = validateImpersonationToken(token);
    
    if (!validation.valid || !validation.payload) {
        console.warn('[SECURITY] Invalid or expired impersonation token attempt');
        return NextResponse.redirect(new URL('/login?error=invalid_token', request.url));
    }
    
    const { tenantId, operatorId, operatorName, exp, jti } = validation.payload;
    
    // Log the impersonation session start
    console.log(`[AUDIT] Impersonation session started`, {
        operatorId,
        operatorName,
        tenantId,
        tokenId: jti,
        timestamp: new Date().toISOString(),
    });
    
    // Create impersonation session payload
    const sessionPayload = {
        type: 'impersonation',
        tenantId,
        operatorId,
        operatorName,
        tokenId: jti,
        exp,
    };
    
    const sessionPayloadB64 = Buffer.from(JSON.stringify(sessionPayload)).toString('base64url');
    const secret = process.env.SESSION_SECRET;
    if (!secret) {
        console.error('[SECURITY] SESSION_SECRET not configured');
        return NextResponse.json(
            { error: 'Server configuration error' },
            { status: 500 }
        );
    }
    const sessionSignature = crypto
        .createHmac('sha256', secret)
        .update(sessionPayloadB64)
        .digest('base64url');
    
    const sessionToken = `${sessionPayloadB64}.${sessionSignature}`;
    
    // Set the impersonation session cookie and redirect to dashboard
    const response = NextResponse.redirect(new URL('/dashboard', request.url));
    
    response.cookies.set(IMPERSONATION_SESSION_COOKIE, sessionToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: Math.floor((exp - Date.now()) / 1000),
        path: '/',
    });
    
    return response;
}
