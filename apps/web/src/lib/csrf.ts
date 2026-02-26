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

export async function createCsrfToken(secret: string): Promise<{ token: string; signature: string }> {
    const token = generateRandomBase64Url(32);
    const signature = await hmacSha256Base64Url(secret, token);
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

    const expectedSig = await hmacSha256Base64Url(secret, cookieToken);
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

export async function buildCsrfResponse(): Promise<NextResponse> {
    const secret = getCsrfSecret();
    if (!secret) {
        return NextResponse.json(
            { error: 'Server configuration error' },
            { status: 500 }
        );
    }

    const { token, signature } = await createCsrfToken(secret);

    // SEC-007 FIX: Add explicit domain to prevent subdomain cookie access
    const cookieDomain = process.env.NODE_ENV === 'production' ? 'apexmail.ee' : undefined;

    const response = NextResponse.json({ token });
    response.cookies.set(CSRF_COOKIE, token, {
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/',
        maxAge: 60 * 60 * 2,
        domain: cookieDomain,
    });
    response.cookies.set(CSRF_SIG_COOKIE, signature, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/',
        maxAge: 60 * 60 * 2,
        domain: cookieDomain,
    });

    return response;
}
