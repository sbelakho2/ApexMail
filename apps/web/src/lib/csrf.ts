/**
 * CSRF protection utilities
 */

import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import {
    generateRandomBase64Url,
    hmacSha256Base64Url,
    constantTimeEqual,
} from '@/lib/signatures';

export const CSRF_COOKIE = 'csrf_token';
export const CSRF_SIG_COOKIE = 'csrf_token_sig';

function getCsrfSecret(): string | null {
    if (process.env.CSRF_SECRET) {
        return process.env.CSRF_SECRET;
    }

    if (process.env.NODE_ENV !== 'production' && process.env.SESSION_SECRET) {
        return process.env.SESSION_SECRET;
    }

    return null;
}

export async function createCsrfToken(secret: string, sessionBinding?: string): Promise<{ token: string; signature: string }> {
    const token = generateRandomBase64Url(32);
    // Bind CSRF token to the current session to prevent token fixation attacks
    const signPayload = sessionBinding ? `${token}.${sessionBinding}` : token;
    const signature = await hmacSha256Base64Url(secret, signPayload);
    return { token, signature };
}

export async function validateCsrf(request: NextRequest): Promise<{ ok: boolean; response?: NextResponse }> {
    const secret = getCsrfSecret();
    if (!secret) {
        return {
            ok: false,
            response: NextResponse.json(
                { error: 'Server configuration error' },
                { status: 500 }
            ),
        };
    }

    const headerToken = request.headers.get('x-csrf-token');
    const cookieToken = request.cookies.get(CSRF_COOKIE)?.value;
    const cookieSig = request.cookies.get(CSRF_SIG_COOKIE)?.value;

    if (!headerToken || !cookieToken || !cookieSig) {
        return {
            ok: false,
            response: NextResponse.json(
                { error: 'CSRF token missing' },
                { status: 403 }
            ),
        };
    }

    if (headerToken !== cookieToken) {
        return {
            ok: false,
            response: NextResponse.json(
                { error: 'CSRF token mismatch' },
                { status: 403 }
            ),
        };
    }

    // Bind verification to session cookie (if present) to prevent token fixation
    const sessionCookie = request.cookies.get('am_session')?.value;
    const signPayload = sessionCookie ? `${cookieToken}.${sessionCookie}` : cookieToken;
    const expectedSig = await hmacSha256Base64Url(secret, signPayload);
    if (!constantTimeEqual(expectedSig, cookieSig)) {
        return {
            ok: false,
            response: NextResponse.json(
                { error: 'CSRF token invalid' },
                { status: 403 }
            ),
        };
    }

    return { ok: true };
}

export async function buildCsrfResponse(request?: NextRequest): Promise<NextResponse> {
    const secret = getCsrfSecret();
    if (!secret) {
        return NextResponse.json(
            { error: 'Server configuration error' },
            { status: 500 }
        );
    }

    // Bind CSRF token to current session (if authenticated)
    const sessionBinding = request?.cookies.get('am_session')?.value;
    const { token, signature } = await createCsrfToken(secret, sessionBinding);

    // SEC-007 FIX: Omit `domain` attribute so cookies are scoped to the exact
    // hostname ("host-only" cookie).  Setting `domain: 'apexmail.ee'` would
    // *enable* access from every subdomain — the opposite of what we want.

    const response = NextResponse.json({ token });
    response.cookies.set(CSRF_COOKIE, token, {
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/',
        maxAge: 60 * 60 * 2,
    });
    response.cookies.set(CSRF_SIG_COOKIE, signature, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/',
        maxAge: 60 * 60 * 2,
    });

    return response;
}
