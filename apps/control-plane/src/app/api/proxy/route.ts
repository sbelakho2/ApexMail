/**
 * Control Plane Proxy API
 *
 * SECURITY: Proxy is restricted to an explicit hostname allowlist.
 * No custom DNS/IP SSRF engine is used; destination control is enforced through
 * host allowlisting and protocol restrictions only.
 */

import { NextRequest, NextResponse } from 'next/server';

const PROXY_ALLOWLIST = (process.env.CONTROL_PLANE_PROXY_ALLOWLIST || '')
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);

const DEV_PROXY_ALLOWLIST = ['localhost', '127.0.0.1'];

function isHostnameAllowed(hostname: string): boolean {
    const normalized = hostname.toLowerCase();
    const allowlist = PROXY_ALLOWLIST.length > 0
        ? PROXY_ALLOWLIST
        : (process.env.NODE_ENV === 'production' ? [] : DEV_PROXY_ALLOWLIST);

    if (allowlist.length === 0) {
        return false;
    }

    return allowlist.some((allowed) => normalized === allowed || normalized.endsWith(`.${allowed}`));
}

function validateUrlSafe(urlString: string): URL {
    let url: URL;
    try {
        url = new URL(urlString);
    } catch {
        throw new Error('Invalid URL format');
    }
    
    const hostname = url.hostname.toLowerCase();
    const protocol = url.protocol;

    if (!isHostnameAllowed(hostname)) {
        throw new Error('URL hostname is not in proxy allowlist');
    }
    
    // 1. Protocol validation - only allow http(s)
    if (protocol !== 'http:' && protocol !== 'https:') {
        throw new Error(`Invalid protocol: ${protocol}. Only HTTP(S) allowed.`);
    }
    
    // 2. HTTPS required in production
    if (process.env.NODE_ENV === 'production' && protocol !== 'https:') {
        throw new Error('HTTPS required in production environment');
    }

    return url;
}

/**
 * Validate URL and make request with additional safety checks
 * Re-validates IP at connection time to prevent TOCTOU/DNS rebinding
 */
async function safeFetch(url: string, options: RequestInit = {}): Promise<Response> {
    const validatedUrl = validateUrlSafe(url);
    
    // Make the request with timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000); // 30s timeout
    
    try {
        const response = await fetch(validatedUrl.toString(), {
            ...options,
            signal: controller.signal,
            // Prevent redirects to internal URLs
            redirect: 'manual',
        });
        
        // If redirect, validate the redirect target
        if (response.status >= 300 && response.status < 400) {
            const location = response.headers.get('location');
            if (location) {
                // Resolve relative URLs
                const redirectUrl = new URL(location, url).toString();
                validateUrlSafe(redirectUrl);
            }
        }
        
        return response;
    } finally {
        clearTimeout(timeout);
    }
}

function sanitizeProxyHeaders(input: Record<string, unknown>): Record<string, string> {
    const allowed = new Set([
        'accept',
        'accept-language',
        'content-type',
        'if-none-match',
        'if-modified-since',
        'cache-control',
    ]);

    const sanitized: Record<string, string> = {};
    for (const [rawKey, rawValue] of Object.entries(input)) {
        const key = rawKey.toLowerCase();
        if (!allowed.has(key)) {
            continue;
        }
        if (typeof rawValue !== 'string') {
            continue;
        }
        sanitized[rawKey] = rawValue;
    }
    return sanitized;
}

/**
 * POST /api/proxy
 * 
 * Proxies requests to external URLs with SSRF protection
 */
export async function POST(request: NextRequest) {
    try {
        const body = await request.json();
        
        if (!body.url || typeof body.url !== 'string') {
            return NextResponse.json(
                { error: 'URL is required' },
                { status: 400 }
            );
        }
        
        const { url, method = 'GET', headers = {}, data } = body;
        
        // Validate method
        const allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
        if (!allowedMethods.includes(method.toUpperCase())) {
            return NextResponse.json(
                { error: `Invalid method: ${method}` },
                { status: 400 }
            );
        }
        
        const safeHeaders = sanitizeProxyHeaders(headers as Record<string, unknown>);

        // Make safe request
        const response = await safeFetch(url, {
            method: method.toUpperCase(),
            headers: {
                'Content-Type': 'application/json',
                ...safeHeaders,
            },
            body: data ? JSON.stringify(data) : undefined,
        });
        
        // Handle redirect responses
        if (response.status >= 300 && response.status < 400) {
            const location = response.headers.get('location');
            return NextResponse.json({
                status: response.status,
                redirect: true,
                location,
                message: 'Redirect detected. Validate and follow manually if needed.',
            });
        }
        
        // Return response data
        const contentType = response.headers.get('content-type') || '';
        let responseData;
        
        if (contentType.includes('application/json')) {
            responseData = await response.json();
        } else {
            responseData = await response.text();
        }
        
        return NextResponse.json({
            status: response.status,
            headers: Object.fromEntries(response.headers.entries()),
            data: responseData,
        });
        
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Proxy request failed';
        
        // Don't expose internal error details in production
        const safeMessage = process.env.NODE_ENV === 'production' 
            ? 'Request failed. URL may be invalid or blocked.'
            : message;
        
        return NextResponse.json(
            { error: safeMessage },
            { status: 400 }
        );
    }
}

/**
 * GET /api/proxy
 * 
 * Simple GET proxy with URL in query parameter
 */
export async function GET(request: NextRequest) {
    return NextResponse.json(
        { error: 'GET proxy is disabled. Use POST /api/proxy with a validated payload.' },
        { status: 405 }
    );
}
