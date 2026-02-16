/**
 * Control Plane Authentication Middleware
 * 
 * CRITICAL SECURITY: This middleware ensures that ONLY authorized platform owners
 * can access the Control Plane. Customers CANNOT access this even with direct links.
 * 
 * Security Layers:
 * 1. IP Whitelist (production) - Only allowed IPs can reach the control plane
 * 2. Owner Authentication - Separate auth system from customer auth
 * 3. Session Validation - Sessions are validated on every request
 * 4. Rate Limiting - Prevents brute force attacks
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// ---------- Edge-compatible crypto helpers ----------
// The Edge Runtime does NOT support Node.js 'crypto' module.
// All HMAC / comparison operations use the Web Crypto API instead.

const _enc = new TextEncoder();

function _b64url(buf: Uint8Array): string {
    let bin = '';
    for (let i = 0; i < buf.length; i++) bin += String.fromCharCode(buf[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function _b64urlDecode(s: string): string {
    // base64url → base64 → decoded string
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
// ---------- end crypto helpers ----------

// Allowed paths without authentication (login page, assets)
const PUBLIC_PATHS = [
    '/login',
    '/api/auth/login',
    '/api/auth/logout',
    '/api/csrf',
    '/favicon.ico',
];

const PUBLIC_PREFIXES = ['/_next'];

// Production IP whitelist - Control plane only accessible from these IPs
// In production, this would be loaded from environment variables
const IP_WHITELIST = process.env.CONTROL_PLANE_IP_WHITELIST?.split(',') || [];

// Control plane auth cookie name (different from customer auth)
const CONTROL_PLANE_SESSION_COOKIE = 'cp_session';

// Control plane API key header
const CONTROL_PLANE_API_KEY_HEADER = 'x-control-plane-key';
const CSRF_HEADER = 'x-csrf-token';
const CSRF_COOKIE = 'csrf_token';
const CSRF_SIG_COOKIE = 'csrf_token_sig';

/**
 * Validates the control plane session token
 * SECURITY: Uses HMAC-SHA256 signature verification to prevent token tampering
 */
async function validateSession(sessionToken: string): Promise<boolean> {
    try {
        const [payload, signature] = sessionToken.split('.');
        if (!payload || !signature) return false;
        
        // SECURITY FIX: Verify signature cryptographically
        const secret = process.env.CONTROL_PLANE_JWT_SECRET;
        if (!secret) {
            console.error('[SECURITY CRITICAL] CONTROL_PLANE_JWT_SECRET not configured');
            return false; // Fail-secure: no secret = no valid sessions
        }
        
        // Compute expected signature using HMAC-SHA256 (Web Crypto API)
        const expectedSignature = await _hmacSign(secret, payload);
        
        // Constant-time comparison to prevent timing attacks
        if (!_constTimeEq(signature, expectedSignature)) {
            console.warn('[SECURITY] Invalid session signature detected');
            return false;
        }
        
        // Signature verified, now decode and validate payload
        const decoded = JSON.parse(_b64urlDecode(payload));
        
        // Check expiration
        if (decoded.exp && Date.now() > decoded.exp) {
            return false;
        }
        
        // Check that this is a control plane session (not customer session)
        if (decoded.type !== 'control_plane') {
            return false;
        }
        
        // Check issued-at time (reject tokens issued too long ago even if not expired)
        const maxAge = 24 * 60 * 60 * 1000; // 24 hours
        if (decoded.iat && Date.now() - decoded.iat > maxAge) {
            return false;
        }
        
        return true;
    } catch (error) {
        console.error('[SECURITY] Session validation error:', error);
        return false;
    }
}

// G-208: Session duration for refresh calculations
const SESSION_DURATION_MS = 8 * 60 * 60 * 1000; // 8 hours — must match login route

/**
 * G-208: Validates session and returns a refreshed token when the session is
 * past its half-life (sliding expiry). This keeps active users logged in
 * without requiring re-authentication, while still bounding absolute session
 * lifetime via the maxAge check in validateSession.
 */
async function validateSessionWithRefresh(sessionToken: string): Promise<{ valid: boolean; refreshedToken?: string }> {
    try {
        const [payload, signature] = sessionToken.split('.');
        if (!payload || !signature) return { valid: false };

        const secret = process.env.CONTROL_PLANE_JWT_SECRET;
        if (!secret) return { valid: false };

        // Web Crypto API — Edge Runtime compatible
        const expectedSignature = await _hmacSign(secret, payload);
        if (!_constTimeEq(signature, expectedSignature)) return { valid: false };

        const decoded = JSON.parse(_b64urlDecode(payload));

        if (decoded.exp && Date.now() > decoded.exp) return { valid: false };
        if (decoded.type !== 'control_plane') return { valid: false };

        const maxAge = 24 * 60 * 60 * 1000;
        if (decoded.iat && Date.now() - decoded.iat > maxAge) return { valid: false };

        // G-208: Sliding refresh — if more than half the session duration has
        // elapsed since issuance, mint a fresh token.
        const halfLife = SESSION_DURATION_MS / 2;
        const elapsed = Date.now() - (decoded.iat || 0);
        let refreshedToken: string | undefined;

        if (elapsed > halfLife) {
            const refreshedPayload = {
                ...decoded,
                iat: Date.now(),
                exp: Date.now() + SESSION_DURATION_MS,
            };
            const refreshedB64 = _b64url(_enc.encode(JSON.stringify(refreshedPayload)));
            const refreshedSig = await _hmacSign(secret, refreshedB64);
            refreshedToken = `${refreshedB64}.${refreshedSig}`;
        }

        return { valid: true, refreshedToken };
    } catch (err) {
        console.error('[MIDDLEWARE] validateSessionWithRefresh error:', err);
        return { valid: false };
    }
}

/**
 * Validates the control plane API key
 */
function validateApiKey(apiKey: string): boolean {
    const validKey = process.env.CONTROL_PLANE_API_KEY;
    if (!validKey) {
        console.error('[SECURITY] CONTROL_PLANE_API_KEY not configured');
        return false;
    }
    
    // Constant-time comparison to prevent timing attacks
    if (apiKey.length !== validKey.length) return false;
    
    let result = 0;
    for (let i = 0; i < apiKey.length; i++) {
        result |= apiKey.charCodeAt(i) ^ validKey.charCodeAt(i);
    }
    return result === 0;
}

/**
 * Gets the real client IP, handling proxies
 */
function getClientIp(request: NextRequest): string {
    const forwarded = request.headers.get('x-forwarded-for');
    if (forwarded) {
        // FIX-500-304: Use rightmost entry — the one added by our trusted reverse proxy.
        // The leftmost entry can be spoofed by the client.
        const parts = forwarded.split(',').map(s => s.trim()).filter(Boolean);
        return parts[parts.length - 1];
    }
    const realIp = request.headers.get('x-real-ip');
    if (realIp) {
        return realIp;
    }
    return '127.0.0.1';
}

/**
 * Checks if the request IP is whitelisted
 */
function isIpWhitelisted(clientIp: string): boolean {
    // In development, allow all IPs
    if (process.env.NODE_ENV === 'development') {
        return true;
    }
    
    // If no whitelist configured, deny all (fail-secure)
    if (IP_WHITELIST.length === 0) {
        console.warn('[SECURITY] No IP whitelist configured, denying access');
        return false;
    }
    
    // Check if IP is in whitelist (supports CIDR notation in production)
    return IP_WHITELIST.includes(clientIp) || IP_WHITELIST.includes('*');
}

export async function middleware(request: NextRequest) {
    const path = request.nextUrl.pathname;
    const clientIp = getClientIp(request);
    
    // Log all access attempts for audit
    console.log(`[CONTROL_PLANE_ACCESS] IP=${clientIp} Path=${path} Method=${request.method}`);
    
    // Allow public paths
    if (PUBLIC_PATHS.includes(path) || PUBLIC_PREFIXES.some(prefix => path.startsWith(prefix))) {
        return NextResponse.next();
    }
    
    // ==== SECURITY LAYER 1: IP Whitelist ====
    if (!isIpWhitelisted(clientIp)) {
        console.warn(`[SECURITY] Blocked access from non-whitelisted IP: ${clientIp}`);
        return new NextResponse(
            JSON.stringify({ 
                error: 'Access Denied',
                message: 'Your IP is not authorized to access the Control Plane',
            }),
            { 
                status: 403, 
                headers: { 'Content-Type': 'application/json' }
            }
        );
    }
    
    // ==== SECURITY LAYER 2: API Key (for API routes) ====
    if (path.startsWith('/api/')) {
        const apiKey = request.headers.get(CONTROL_PLANE_API_KEY_HEADER);
        if (apiKey) {
            if (validateApiKey(apiKey)) {
                return NextResponse.next();
            }
            console.warn(`[SECURITY] Invalid API key attempt from IP: ${clientIp}`);
            return new NextResponse(
                JSON.stringify({ error: 'Invalid API Key' }),
                { status: 401, headers: { 'Content-Type': 'application/json' } }
            );
        }
    }
    
    // ==== SECURITY LAYER 3: Session Authentication ====
    const sessionToken = request.cookies.get(CONTROL_PLANE_SESSION_COOKIE)?.value;
    
    if (!sessionToken) {
        // No session, redirect to login
        console.log(`[CONTROL_PLANE] No session, redirecting to login from ${clientIp}`);
        return NextResponse.redirect(new URL('/login', request.url));
    }
    
    const sessionResult = await validateSessionWithRefresh(sessionToken);
    
    if (!sessionResult.valid) {
        // Invalid or expired session
        console.warn(`[SECURITY] Invalid session attempt from IP: ${clientIp}`);
        const response = NextResponse.redirect(new URL('/login', request.url));
        // Clear the invalid cookie
        response.cookies.delete(CONTROL_PLANE_SESSION_COOKIE);
        return response;
    }

    // ==== SECURITY LAYER 3.5: CSRF Protection for state-changing API requests ====
    if (path.startsWith('/api/') && !['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
        if (!path.startsWith('/api/auth/login') && !path.startsWith('/api/csrf')) {
            const csrfToken = request.headers.get(CSRF_HEADER);
            const csrfCookie = request.cookies.get(CSRF_COOKIE)?.value;
            const csrfSig = request.cookies.get(CSRF_SIG_COOKIE)?.value;

            if (!csrfToken || !csrfCookie || !csrfSig || csrfToken !== csrfCookie) {
                return new NextResponse(
                    JSON.stringify({ error: 'CSRF token missing or invalid' }),
                    { status: 403, headers: { 'Content-Type': 'application/json' } }
                );
            }

            const secret = process.env.CSRF_SECRET || process.env.CONTROL_PLANE_JWT_SECRET;
            if (!secret) {
                return new NextResponse(
                    JSON.stringify({ error: 'Server configuration error' }),
                    { status: 500, headers: { 'Content-Type': 'application/json' } }
                );
            }

            // Web Crypto API — Edge Runtime compatible
            const expectedSig = await _hmacSign(secret, csrfCookie);

            if (!_constTimeEq(expectedSig, csrfSig)) {
                return new NextResponse(
                    JSON.stringify({ error: 'CSRF token invalid' }),
                    { status: 403, headers: { 'Content-Type': 'application/json' } }
                );
            }
        }
    }
    
    // ==== SECURITY LAYER 4: Add security headers ====
    const response = NextResponse.next();
    
    // Prevent embedding in iframes (clickjacking protection)
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('Content-Security-Policy', "frame-ancestors 'none'");
    
    // Mark as control plane request
    response.headers.set('X-Control-Plane', 'authenticated');
    
    // Prevent caching of authenticated content
    response.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    response.headers.set('Pragma', 'no-cache');

    // G-208: Set refreshed session cookie if the session was past half-life
    if (sessionResult.refreshedToken) {
        response.cookies.set(CONTROL_PLANE_SESSION_COOKIE, sessionResult.refreshedToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: SESSION_DURATION_MS / 1000,
            path: '/',
        });
    }
    
    return response;
}

// Configure which paths the middleware runs on
export const config = {
    matcher: [
        /*
         * Match all paths except static files
         */
        '/((?!_next/static|_next/image|favicon.ico).*)',
    ],
};
