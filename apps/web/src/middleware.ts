/**
 * Web App Authentication Middleware
 *
 * Ensures authenticated access to the customer dashboard.
 * Supports both user JWT sessions and control-plane impersonation sessions.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const _enc = new TextEncoder();

function _b64url(buf: Uint8Array): string {
    let bin = '';
    for (let i = 0; i < buf.length; i++) bin += String.fromCharCode(buf[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function _b64urlDecode(s: string): string {
    const base64 = s.replace(/-/g, '+').replace(/_/g, '/');
    return atob(base64);
}

async function _hmacSign(secret: string, data: string): Promise<string> {
    const key = await crypto.subtle.importKey(
        'raw', _enc.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    );
    const sig = await crypto.subtle.sign('HMAC', key, _enc.encode(data));
    return _b64url(new Uint8Array(sig));
}

function _constTimeEq(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let r = 0;
    for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return r === 0;
}

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

const PUBLIC_PREFIXES = ['/_next'];

const IMPERSONATION_SESSION_COOKIE = 'impersonation_session';
const USER_SESSION_COOKIE = 'am_session';
const E2E_BYPASS_HEADER = 'x-e2e-bypass-key';

function hasValidE2EBypass(request: NextRequest): boolean {
    const enabled = process.env.E2E_TEST_MODE === 'true';
    const expectedKey = process.env.E2E_BYPASS_KEY;
    const providedKey = request.headers.get(E2E_BYPASS_HEADER);

    if (!enabled || !expectedKey || !providedKey) {
        return false;
    }

    return _constTimeEq(expectedKey, providedKey);
}

function isPublicPath(pathname: string): boolean {
    if (PUBLIC_PATHS.includes(pathname)) {
        return true;
    }

    return PUBLIC_PREFIXES.some((prefix) => pathname.startsWith(prefix));
}

async function validateImpersonationSession(sessionToken: string, secret: string): Promise<boolean> {
    try {
        const [payloadB64, signature] = sessionToken.split('.');
        if (!payloadB64 || !signature) return false;

        const expectedSignature = await _hmacSign(secret, payloadB64);

        if (!_constTimeEq(signature, expectedSignature)) return false;

        const payload = JSON.parse(_b64urlDecode(payloadB64));
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

    if (hasValidE2EBypass(request)) {
        const response = NextResponse.next();
        response.headers.set('X-E2E-Bypass', '1');
        return response;
    }

    const impersonationToken = request.cookies.get(IMPERSONATION_SESSION_COOKIE)?.value;
    const sessionToken = request.cookies.get(USER_SESSION_COOKIE)?.value;

    const sessionSecret = process.env.SESSION_SECRET;
    if (!sessionSecret && process.env.NODE_ENV !== 'development') {
        console.error('[SECURITY] SESSION_SECRET is not configured');
        return NextResponse.redirect(new URL('/login', request.url));
    }

    if (impersonationToken && sessionSecret) {
        const isValidImpersonation = await validateImpersonationSession(impersonationToken, sessionSecret);
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
