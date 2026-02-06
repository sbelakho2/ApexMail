/**
 * CSRF protection utilities
 */

import * as crypto from 'crypto';
import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

export const CSRF_COOKIE = 'csrf_token';
export const CSRF_SIG_COOKIE = 'csrf_token_sig';

function getCsrfSecret(): string | null {
    return process.env.CSRF_SECRET || process.env.CONTROL_PLANE_JWT_SECRET || null;
}

export function createCsrfToken(secret: string): { token: string; signature: string } {
    const token = crypto.randomBytes(32).toString('base64url');
    const signature = crypto.createHmac('sha256', secret).update(token).digest('base64url');
    return { token, signature };
}

function safeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export function validateCsrf(request: NextRequest): { ok: boolean; response?: NextResponse } {
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

    const expectedSig = crypto.createHmac('sha256', secret).update(cookieToken).digest('base64url');
    if (!safeEqual(expectedSig, cookieSig)) {
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

export function buildCsrfResponse(): NextResponse {
    const secret = getCsrfSecret();
    if (!secret) {
        return NextResponse.json(
            { error: 'Server configuration error' },
            { status: 500 }
        );
    }

    const { token, signature } = createCsrfToken(secret);

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
