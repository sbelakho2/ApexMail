/**
 * Web App Authentication Middleware
 *
 * Ensures authenticated access to the customer dashboard.
 * Supports both user JWT sessions and control-plane impersonation sessions.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { constantTimeEqual, verifySignedToken } from '@/lib/signatures';
import { logSecurityEvent } from '@/lib/server-logger';

let hasLoggedMissingSessionSecret = false;

// ─── Security headers applied to every response ───────────────

function addSecurityHeaders(response: NextResponse, pathname: string): NextResponse {
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('X-Content-Type-Options', 'nosniff');
    response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    response.headers.set(
        'Strict-Transport-Security',
        'max-age=63072000; includeSubDomains; preload'
    );
    response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    // Prevent caching of API responses (may contain sensitive data)
    if (pathname.startsWith('/api/')) {
        response.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate');
        response.headers.set('Pragma', 'no-cache');
    }

    return response;
}

const PUBLIC_PATHS = [
    '/login',
    '/signup',
    '/forgot-password',
    '/api/auth/login',
    '/api/auth/register',
    '/api/auth/forgot-password',
    '/api/auth/session',
    '/api/auth/sso/github',
    '/api/auth/sso/google',
    '/api/csrf',
    '/api/health',
    '/favicon.ico',
];

const PUBLIC_PREFIXES = ['/_next'];

const IMPERSONATION_SESSION_COOKIE = 'impersonation_session';
const USER_SESSION_COOKIE = 'am_session';
const E2E_BYPASS_HEADER = 'x-e2e-bypass-key';

function isNonProductionE2EModeEnabled(): boolean {
    return process.env.NODE_ENV !== 'production' && process.env.E2E_TEST_MODE === 'true';
}

function hasValidE2EBypass(request: NextRequest): boolean {
    const enabled = isNonProductionE2EModeEnabled();
    const expectedKey = process.env.E2E_BYPASS_KEY;
    const providedKey = request.headers.get(E2E_BYPASS_HEADER);

    if (!enabled || !expectedKey || !providedKey) {
        return false;
    }

    return constantTimeEqual(expectedKey, providedKey);
}

async function validateImpersonationBootstrapToken(token: string, secret: string): Promise<boolean> {
    try {
        const validation = await verifySignedToken<{
            type?: string;
            tenantId?: string;
            operatorId?: string;
            exp?: number;
        }>(token, secret);
        if (!validation.valid || !validation.payload) return false;

        const payload = validation.payload;
        if (payload.type !== 'impersonation') return false;
        if (typeof payload.tenantId !== 'string' || !payload.tenantId) return false;
        if (typeof payload.operatorId !== 'string' || !payload.operatorId) return false;
        if (!payload.exp || typeof payload.exp !== 'number') return false;
        if (Date.now() > payload.exp) return false;

        return true;
    } catch {
        return false;
    }
}

async function isPublicPath(request: NextRequest): Promise<boolean> {
    const pathname = request.nextUrl.pathname;
    const method = request.method.toUpperCase();

    if (PUBLIC_PATHS.includes(pathname)) {
        return true;
    }

    if (pathname === '/api/auth/impersonate') {
        if (method === 'POST') {
            return true;
        }

        const token = request.nextUrl.searchParams.get('token');
        const secret = process.env.IMPERSONATION_SECRET;
        if (!token || !secret) {
            return false;
        }

        return validateImpersonationBootstrapToken(token, secret);
    }

    return PUBLIC_PREFIXES.some((prefix) => pathname.startsWith(prefix));
}

async function validateImpersonationSession(sessionToken: string, secret: string): Promise<boolean> {
    try {
        const validation = await verifySignedToken<{ exp?: number; type?: string }>(sessionToken, secret);
        if (!validation.valid || !validation.payload) return false;

        const payload = validation.payload;
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
            signal: AbortSignal.timeout(5000),
        });

        return response.ok;
    } catch {
        return false;
    }
}

export async function middleware(request: NextRequest) {
    const { pathname } = request.nextUrl;

    if (await isPublicPath(request)) {
        return addSecurityHeaders(NextResponse.next(), pathname);
    }

    if (hasValidE2EBypass(request)) {
        const response = NextResponse.next();
        response.headers.set('X-E2E-Bypass', '1');
        return addSecurityHeaders(response, pathname);
    }

    const impersonationToken = request.cookies.get(IMPERSONATION_SESSION_COOKIE)?.value;
    const sessionToken = request.cookies.get(USER_SESSION_COOKIE)?.value;

    const sessionSecret = process.env.SESSION_SECRET;
    if (!sessionSecret && process.env.NODE_ENV !== 'development') {
        if (!hasLoggedMissingSessionSecret) {
            hasLoggedMissingSessionSecret = true;
            logSecurityEvent('missing_session_secret', { path: pathname });
        }
        return addSecurityHeaders(NextResponse.redirect(new URL('/login', request.url)), pathname);
    }

    if (impersonationToken && sessionSecret) {
        const isValidImpersonation = await validateImpersonationSession(impersonationToken, sessionSecret);
        if (isValidImpersonation) {
            return addSecurityHeaders(NextResponse.next(), pathname);
        }
    }

    if (!sessionToken) {
        return addSecurityHeaders(NextResponse.redirect(new URL('/login', request.url)), pathname);
    }

    const apiBaseUrl = process.env.API_URL || 'http://localhost:3001';
    const isValidSession = await validateJwtSession(sessionToken, apiBaseUrl);

    if (!isValidSession) {
        const response = NextResponse.redirect(new URL('/login', request.url));
        response.cookies.delete(USER_SESSION_COOKIE);
        return addSecurityHeaders(response, pathname);
    }

    return addSecurityHeaders(NextResponse.next(), pathname);
}

export const config = {
    matcher: [
        '/((?!_next/static|_next/image|favicon.ico).*)',
    ],
};
