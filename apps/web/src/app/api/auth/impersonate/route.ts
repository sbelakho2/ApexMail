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
import { createSignedToken, verifySignedToken } from '@/lib/signatures';
import { logAuditEvent, logErrorEvent, logSecurityEvent } from '@/lib/server-logger';

const IMPERSONATION_SESSION_COOKIE = 'impersonation_session';

/**
 * Validates an impersonation token
 */
async function validateImpersonationToken(token: string): Promise<{
    valid: boolean;
    payload?: {
        tenantId: string;
        operatorId: string;
        operatorName: string;
        exp: number;
        jti: string;
    };
}> {
    try {
        const secret = process.env.IMPERSONATION_SECRET;
        if (!secret) {
            logErrorEvent('impersonation_secret_missing', {});
            return { valid: false };
        }

        const validation = await verifySignedToken<{
            type?: string;
            tenantId?: string;
            operatorId?: string;
            operatorName?: string;
            exp?: number;
            jti?: string;
        }>(token, secret);

        if (!validation.valid || !validation.payload) {
            logSecurityEvent('impersonation_invalid_signature', {});
            return { valid: false };
        }

        const payload = validation.payload;
        if (payload.exp && Date.now() > payload.exp) {
            logSecurityEvent('impersonation_expired_token', {});
            return { valid: false };
        }

        if (payload.type !== 'impersonation') {
            return { valid: false };
        }

        if (
            typeof payload.tenantId !== 'string' ||
            typeof payload.operatorId !== 'string' ||
            typeof payload.operatorName !== 'string' ||
            typeof payload.exp !== 'number' ||
            typeof payload.jti !== 'string'
        ) {
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
        logErrorEvent('impersonation_token_validation_error', {
            message: error instanceof Error ? error.message : 'unknown_error',
        });
        return { valid: false };
    }
}

export async function GET(request: NextRequest) {
    return NextResponse.redirect(new URL('/login?error=invalid_method', request.url));
}

async function getImpersonationTokenFromRequest(request: NextRequest): Promise<string | null> {
    const contentType = request.headers.get('content-type') || '';

    if (contentType.includes('application/json')) {
        const body = await request.json().catch(() => null) as { token?: unknown } | null;
        return typeof body?.token === 'string' ? body.token : null;
    }

    if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
        const form = await request.formData().catch(() => null);
        const token = form?.get('token');
        return typeof token === 'string' ? token : null;
    }

    return null;
}

export async function POST(request: NextRequest) {
    const token = await getImpersonationTokenFromRequest(request);

    if (!token) {
        return NextResponse.redirect(new URL('/login?error=missing_token', request.url));
    }

    const validation = await validateImpersonationToken(token);

    if (!validation.valid || !validation.payload) {
        logSecurityEvent('impersonation_invalid_or_expired_attempt', {});
        return NextResponse.redirect(new URL('/login?error=invalid_token', request.url));
    }

    const { tenantId, operatorId, operatorName, exp, jti } = validation.payload;

    logAuditEvent('impersonation_session_started', {
        operatorId,
        operatorName,
        tenantId,
        tokenId: jti,
    });

    const sessionPayload = {
        type: 'impersonation',
        tenantId,
        operatorId,
        operatorName,
        tokenId: jti,
        exp,
    };

    const secret = process.env.SESSION_SECRET;
    if (!secret) {
        logErrorEvent('session_secret_missing', {});
        return NextResponse.json(
            { error: 'Server configuration error' },
            { status: 500 }
        );
    }
    const sessionToken = await createSignedToken(sessionPayload, secret);
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
