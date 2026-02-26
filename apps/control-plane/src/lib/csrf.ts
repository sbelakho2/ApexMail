/**
 * CSRF protection utilities
 */

import * as crypto from 'crypto';
import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

export const CSRF_COOKIE = 'csrf_token';
export const CSRF_SIG_COOKIE = 'csrf_token_sig';
const SESSION_COOKIE = 'cp_session';

function getCsrfSecret(): string | null {
    return process.env.CSRF_SECRET || null;
}

function getSessionBinding(request: NextRequest): string {
    return request.cookies.get(SESSION_COOKIE)?.value || 'anonymous';
}

function signCsrfToken(secret: string, token: string, sessionBinding: string): string {
    return crypto.createHmac('sha256', secret).update(`${token}.${sessionBinding}`).digest('base64url');
}

export function createCsrfToken(secret: string, sessionBinding: string): { token: string; signature: string } {
    const token = crypto.randomBytes(32).toString('base64url');
    const signature = signCsrfToken(secret, token, sessionBinding);
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
    const sessionBinding = getSessionBinding(request);

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

    const expectedSig = signCsrfToken(secret, cookieToken, sessionBinding);
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

export function buildCsrfResponse(request: NextRequest): NextResponse {
    const secret = getCsrfSecret();
    if (!secret) {
        return NextResponse.json(
            { error: 'Server configuration error' },
            { status: 500 }
        );
    }

    const sessionBinding = getSessionBinding(request);
    const { token, signature } = createCsrfToken(secret, sessionBinding);

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
