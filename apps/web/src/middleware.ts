/**
 * Web App Authentication Middleware
 *
 * Ensures authenticated access to the customer dashboard.
 * Supports both user JWT sessions and control-plane impersonation sessions.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import * as crypto from 'crypto';

const PUBLIC_PATHS = [
    '/login',
    '/api/auth/login',
    '/api/auth/impersonate',
    '/api/auth/session',
    '/api/csrf',
    '/api/health',
    '/_next',
    '/favicon.ico',
];

const IMPERSONATION_SESSION_COOKIE = 'impersonation_session';
const USER_SESSION_COOKIE = 'am_session';

function isPublicPath(pathname: string): boolean {
    return PUBLIC_PATHS.some((path) => pathname === path || pathname.startsWith(path));
}

function validateImpersonationSession(sessionToken: string, secret: string): boolean {
    try {
        const [payloadB64, signature] = sessionToken.split('.');
        if (!payloadB64 || !signature) return false;

        const expectedSignature = crypto
            .createHmac('sha256', secret)
            .update(payloadB64)
            .digest('base64url');

        const sigBuffer = Buffer.from(signature);
        const expectedBuffer = Buffer.from(expectedSignature);

        if (sigBuffer.length !== expectedBuffer.length) return false;
        if (!crypto.timingSafeEqual(sigBuffer, expectedBuffer)) return false;

        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
        if (payload.exp && Date.now() > payload.exp) return false;
        if (payload.type !== 'impersonation') return false;

        return true;
    } catch {
        return false;
    }
}

async function validateJwtSession(token: string, apiBaseUrl: string): Promise<boolean> {
    try {
        const response = await fetch(`${apiBaseUrl}/v1/auth/me`, {
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json',
            },
        });

        return response.ok;
    } catch {
        return false;
    }
}

export async function middleware(request: NextRequest) {
    const { pathname } = request.nextUrl;

    if (isPublicPath(pathname)) {
        return NextResponse.next();
    }

    const impersonationToken = request.cookies.get(IMPERSONATION_SESSION_COOKIE)?.value;
    const sessionToken = request.cookies.get(USER_SESSION_COOKIE)?.value;

    const sessionSecret = process.env.SESSION_SECRET;
    if (!sessionSecret && process.env.NODE_ENV !== 'development') {
        console.error('[SECURITY] SESSION_SECRET is not configured');
        return NextResponse.redirect(new URL('/login', request.url));
    }

    if (impersonationToken && sessionSecret) {
        const isValidImpersonation = validateImpersonationSession(impersonationToken, sessionSecret);
        if (isValidImpersonation) {
            return NextResponse.next();
        }
    }

    if (!sessionToken) {
        return NextResponse.redirect(new URL('/login', request.url));
    }

    const apiBaseUrl = process.env.API_URL || 'http://localhost:3001';
    const isValidSession = await validateJwtSession(sessionToken, apiBaseUrl);

    if (!isValidSession) {
        const response = NextResponse.redirect(new URL('/login', request.url));
        response.cookies.delete(USER_SESSION_COOKIE);
        return response;
    }

    return NextResponse.next();
}

export const config = {
    matcher: [
        '/((?!_next/static|_next/image|favicon.ico).*)',
    ],
};
