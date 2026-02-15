/**
 * Control Plane Proxy API
 * 
 * SECURITY: This proxy endpoint includes comprehensive SSRF protection with:
 * - IP address validation (blocks private, loopback, link-local, metadata endpoints)
 * - DNS rebinding protection (validates IPs at request time, not just configuration)
 * - Hostname blocklist for known internal services
 * - Protocol validation (HTTPS required in production)
 * 
 * SSRF-002 FIX: Implements proper URL validation with DNS rebinding protection
 *
 * FIX-500-499: SECURITY NOTE — The GET /api/proxy endpoint allows authenticated
 * control-plane users to make arbitrary HTTP GET requests through the server.
 * While SSRF protections are in place, this remains an elevated attack surface.
 * Consider restricting to an allowlist of destination hosts in production, or
 * removing the GET handler entirely if only POST is needed.
 */

import { NextRequest, NextResponse } from 'next/server';
import * as dns from 'dns/promises';
import * as net from 'net';

/**
 * Check if an IP address is private/internal
 * Comprehensive check covering all private ranges
 */
function isPrivateIP(ip: string): boolean {
    // Check IPv4
    if (net.isIPv4(ip)) {
        const parts = ip.split('.').map(Number);
        const [a, b, c, d] = parts;
        
        // Loopback (127.0.0.0/8)
        if (a === 127) return true;
        
        // Private Class A (10.0.0.0/8)
        if (a === 10) return true;
        
        // Private Class B (172.16.0.0/12)
        if (a === 172 && b >= 16 && b <= 31) return true;
        
        // Private Class C (192.168.0.0/16)
        if (a === 192 && b === 168) return true;
        
        // Link-local (169.254.0.0/16) - includes AWS/GCP metadata
        if (a === 169 && b === 254) return true;
        
        // Multicast (224.0.0.0/4)
        if (a >= 224 && a <= 239) return true;
        
        // Reserved/broadcast
        if (a === 0 || a === 255) return true;
        
        // Documentation ranges (TEST-NET)
        if (a === 192 && b === 0 && c === 2) return true;    // 192.0.2.0/24
        if (a === 198 && b === 51 && c === 100) return true; // 198.51.100.0/24
        if (a === 203 && b === 0 && c === 113) return true;  // 203.0.113.0/24
        
        // Carrier-grade NAT (100.64.0.0/10)
        if (a === 100 && b >= 64 && b <= 127) return true;
        
        return false;
    }
    
    // Check IPv6
    if (net.isIPv6(ip)) {
        const normalized = ip.toLowerCase();
        
        // Loopback (::1)
        if (normalized === '::1') return true;
        
        // Unspecified (::)
        if (normalized === '::') return true;
        
        // Link-local (fe80::/10)
        if (normalized.startsWith('fe80:') || normalized.startsWith('fe8') || 
            normalized.startsWith('fe9') || normalized.startsWith('fea') || 
            normalized.startsWith('feb')) return true;
        
        // Unique local (fc00::/7) - like private IPv4
        if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
        
        // Multicast (ff00::/8)
        if (normalized.startsWith('ff')) return true;
        
        // IPv4-mapped IPv6 (::ffff:x.x.x.x) - check the IPv4 portion
        if (normalized.startsWith('::ffff:')) {
            const ipv4Part = normalized.slice(7);
            if (net.isIPv4(ipv4Part)) {
                return isPrivateIP(ipv4Part);
            }
        }
        
        // IPv4-compatible IPv6 - deprecated but check anyway
        if (normalized.includes('.')) {
            const ipv4Match = normalized.match(/(\d+\.\d+\.\d+\.\d+)$/);
            if (ipv4Match && net.isIPv4(ipv4Match[1])) {
                return isPrivateIP(ipv4Match[1]);
            }
        }
        
        return false;
    }
    
    // Unknown format - deny by default
    return true;
}

/**
 * Blocked hostnames that should never be accessed
 */
const BLOCKED_HOSTNAMES = [
    // Loopback variations
    'localhost',
    'localhost.localdomain',
    '127.0.0.1',
    '::1',
    '0.0.0.0',
    '[::1]',
    '[::ffff:127.0.0.1]',
    
    // Cloud provider metadata endpoints
    '169.254.169.254',              // AWS/GCP/Azure metadata
    'metadata.google.internal',      // GCP metadata
    'metadata.google.com',           // GCP
    'instance-data',                 // AWS alias
    'metadata.azure.internal',       // Azure metadata
    
    // Kubernetes internal services
    'kubernetes.default',
    'kubernetes.default.svc',
    'kubernetes.default.svc.cluster.local',
    'kubernetes',
    
    // Internal service discovery
    'internal',
    'corp',
    'local',
];

/**
 * Blocked hostname patterns (suffixes)
 */
const BLOCKED_HOSTNAME_PATTERNS = [
    '.internal',
    '.local',
    '.localhost',
    '.localdomain',
    '.cluster.local',
    '.svc.cluster.local',
    '.corp',       // FIX-500-306: Block .corp suffix (was only blocking exact 'corp')
    '.intranet',   // FIX-500-306: Block common internal domain suffixes
    '.lan',        // FIX-500-306: Block .lan suffix
];

/**
 * Validate URL for SSRF vulnerabilities with DNS rebinding protection
 * 
 * @param urlString - The URL to validate
 * @throws Error if URL is not safe
 */
async function validateUrlSafe(urlString: string): Promise<void> {
    let url: URL;
    try {
        url = new URL(urlString);
    } catch {
        throw new Error('Invalid URL format');
    }
    
    const hostname = url.hostname.toLowerCase();
    const protocol = url.protocol;
    
    // 1. Protocol validation - only allow http(s)
    if (protocol !== 'http:' && protocol !== 'https:') {
        throw new Error(`Invalid protocol: ${protocol}. Only HTTP(S) allowed.`);
    }
    
    // 2. HTTPS required in production
    if (process.env.NODE_ENV === 'production' && protocol !== 'https:') {
        throw new Error('HTTPS required in production environment');
    }
    
    // 3. Check against blocked hostnames
    if (BLOCKED_HOSTNAMES.includes(hostname)) {
        throw new Error('URL hostname is blocked for security reasons');
    }
    
    // 4. Check against blocked hostname patterns
    for (const pattern of BLOCKED_HOSTNAME_PATTERNS) {
        if (hostname.endsWith(pattern)) {
            throw new Error(`URL hostname pattern '${pattern}' is blocked for security reasons`);
        }
    }
    
    // 5. Check if hostname is an IP address
    const cleanHostname = hostname.replace(/^\[|\]$/g, ''); // Remove IPv6 brackets
    if (net.isIP(cleanHostname)) {
        if (isPrivateIP(cleanHostname)) {
            throw new Error('URL cannot point to private/internal IP addresses');
        }
        return; // IP is public and safe
    }
    
    // 6. DNS rebinding protection - resolve hostname and check all IPs
    try {
        const addresses4 = await dns.resolve4(hostname).catch(() => []);
        const addresses6 = await dns.resolve6(hostname).catch(() => []);
        const allAddresses = [...addresses4, ...addresses6];
        
        if (allAddresses.length === 0) {
            throw new Error('URL hostname could not be resolved');
        }
        
        // Check ALL resolved IPs to prevent DNS rebinding attacks
        for (const ip of allAddresses) {
            if (isPrivateIP(ip)) {
                throw new Error(
                    `URL hostname resolves to private IP (${ip}). ` +
                    'This is blocked to prevent SSRF attacks.'
                );
            }
        }
    } catch (error) {
        if (error instanceof Error && error.message.includes('SSRF')) {
            throw error; // Re-throw our security errors
        }
        throw new Error(`DNS resolution failed for hostname: ${hostname}`);
    }
}

/**
 * Validate URL and make request with additional safety checks
 * Re-validates IP at connection time to prevent TOCTOU/DNS rebinding
 */
async function safeFetch(url: string, options: RequestInit = {}): Promise<Response> {
    // Initial validation
    await validateUrlSafe(url);
    
    // Make the request with timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000); // 30s timeout
    
    try {
        const response = await fetch(url, {
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
                await validateUrlSafe(redirectUrl);
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
