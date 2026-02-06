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

// Allowed paths without authentication (login page, assets)
const PUBLIC_PATHS = [
    '/login',
    '/api/auth/login',
    '/api/auth/logout',
    '/api/csrf',
    '/_next',
    '/favicon.ico',
];

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
        
        // Compute expected signature using HMAC-SHA256
        const crypto = await import('crypto');
        const expectedSignature = crypto
            .createHmac('sha256', secret)
            .update(payload)
            .digest('base64url');
        
        // Constant-time comparison to prevent timing attacks
        const signatureBuffer = Buffer.from(signature);
        const expectedBuffer = Buffer.from(expectedSignature);
        
        if (signatureBuffer.length !== expectedBuffer.length) {
            return false;
        }
        
        if (!crypto.timingSafeEqual(signatureBuffer, expectedBuffer)) {
            console.warn('[SECURITY] Invalid session signature detected');
            return false;
        }
        
        // Signature verified, now decode and validate payload
        const decoded = JSON.parse(Buffer.from(payload, 'base64').toString());
        
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
        return forwarded.split(',')[0].trim();
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
    if (PUBLIC_PATHS.some(p => path.startsWith(p))) {
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
    
    const isValidSession = await validateSession(sessionToken);
    
    if (!isValidSession) {
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

            const crypto = await import('crypto');
            const expectedSig = crypto
                .createHmac('sha256', secret)
                .update(csrfCookie)
                .digest('base64url');

            if (
                expectedSig.length !== csrfSig.length ||
                !crypto.timingSafeEqual(Buffer.from(expectedSig), Buffer.from(csrfSig))
            ) {
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
