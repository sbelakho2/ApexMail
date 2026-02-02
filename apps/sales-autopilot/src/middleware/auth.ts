/**
 * Control Plane Authentication Middleware for Sales Autopilot API
 * 
 * CRITICAL SECURITY: This middleware ensures ONLY the Control Plane UI and
 * authorized internal services can access the Sales Autopilot API.
 * 
 * Customer API keys CANNOT access these endpoints.
 */

import type { Context, Next } from 'hono';
import { createLogger } from '@apexmail/lib';

const logger = createLogger({ name: 'control-plane-auth', level: 'info' });

// Internal API key for control plane access
const CONTROL_PLANE_API_KEY = process.env.CONTROL_PLANE_API_KEY;

// Internal service keys (for inter-service communication)
const INTERNAL_SERVICE_KEYS = process.env.INTERNAL_SERVICE_KEYS?.split(',') || [];

// Header name for control plane API key
const API_KEY_HEADER = 'x-control-plane-key';

// Alternative: JWT from control plane UI session
const SESSION_HEADER = 'x-control-plane-session';

// IP whitelist for production
const ALLOWED_IPS = process.env.CONTROL_PLANE_ALLOWED_IPS?.split(',') || [];

/**
 * Gets the client IP from the request
 */
function getClientIp(c: Context): string {
    const forwarded = c.req.header('x-forwarded-for');
    if (forwarded) {
        const firstIp = forwarded.split(',')[0];
        return firstIp ? firstIp.trim() : '127.0.0.1';
    }
    return c.req.header('x-real-ip') || '127.0.0.1';
}

/**
 * Validates the control plane API key
 */
function validateApiKey(apiKey: string): boolean {
    if (!CONTROL_PLANE_API_KEY) {
        logger.warn('CONTROL_PLANE_API_KEY not configured');
        // In development, allow if not configured
        return process.env.NODE_ENV === 'development';
    }
    
    // Check main control plane key
    if (apiKey === CONTROL_PLANE_API_KEY) {
        return true;
    }
    
    // Check internal service keys
    if (INTERNAL_SERVICE_KEYS.includes(apiKey)) {
        return true;
    }
    
    return false;
}

/**
 * Validates a control plane session token
 */
function validateSessionToken(token: string): boolean {
    try {
        const [payload, signature] = token.split('.');
        if (!payload || !signature) return false;
        
        const decoded = JSON.parse(Buffer.from(payload, 'base64').toString());
        
        // Must be a control plane session
        if (decoded.type !== 'control_plane') {
            logger.warn('Attempted access with non-control-plane session');
            return false;
        }
        
        // Check expiration
        if (decoded.exp && Date.now() > decoded.exp) {
            return false;
        }
        
        // In production, verify signature
        // TODO: Implement signature verification
        
        return true;
    } catch {
        return false;
    }
}

/**
 * Checks if the IP is allowed
 */
function isIpAllowed(clientIp: string): boolean {
    // In development, allow all
    if (process.env.NODE_ENV === 'development') {
        return true;
    }
    
    // If no whitelist, allow localhost only
    if (ALLOWED_IPS.length === 0) {
        return clientIp === '127.0.0.1' || clientIp === '::1';
    }
    
    return ALLOWED_IPS.includes(clientIp) || ALLOWED_IPS.includes('*');
}

/**
 * Control Plane Authentication Middleware
 * 
 * Usage:
 * ```typescript
 * app.use('/api/v1/*', controlPlaneAuth());
 * ```
 */
export function controlPlaneAuth() {
    return async (c: Context, next: Next) => {
        const clientIp = getClientIp(c);
        const path = c.req.path;
        
        // Log access attempt
        logger.info('Control plane API access attempt', { ip: clientIp, path });
        
        // === IP Check ===
        if (!isIpAllowed(clientIp)) {
            logger.warn('Blocked access from non-allowed IP', { ip: clientIp, path });
            return c.json(
                { 
                    success: false, 
                    error: 'Access denied',
                    code: 'IP_NOT_ALLOWED',
                },
                403
            );
        }
        
        // === API Key Check ===
        const apiKey = c.req.header(API_KEY_HEADER);
        if (apiKey) {
            if (validateApiKey(apiKey)) {
                // Set context for downstream handlers
                c.set('authType', 'api_key');
                c.set('isControlPlane', true);
                return next();
            }
            
            logger.warn('Invalid control plane API key', { ip: clientIp, path });
            return c.json(
                { 
                    success: false, 
                    error: 'Invalid API key',
                    code: 'INVALID_API_KEY',
                },
                401
            );
        }
        
        // === Session Token Check ===
        const sessionToken = c.req.header(SESSION_HEADER);
        if (sessionToken) {
            if (validateSessionToken(sessionToken)) {
                c.set('authType', 'session');
                c.set('isControlPlane', true);
                return next();
            }
            
            logger.warn('Invalid control plane session', { ip: clientIp, path });
            return c.json(
                { 
                    success: false, 
                    error: 'Invalid or expired session',
                    code: 'INVALID_SESSION',
                },
                401
            );
        }
        
        // No authentication provided
        logger.warn('No control plane authentication provided', { ip: clientIp, path });
        return c.json(
            { 
                success: false, 
                error: 'Authentication required',
                code: 'AUTH_REQUIRED',
                message: 'Control plane API key or session required',
            },
            401
        );
    };
}

/**
 * Blocks customer API keys from accessing control plane endpoints
 * This is an additional safety check
 */
export function blockCustomerAuth() {
    return async (c: Context, next: Next) => {
        // Check for customer API key header
        const customerApiKey = c.req.header('x-api-key');
        if (customerApiKey) {
            const clientIp = getClientIp(c);
            logger.warn('Customer API key used on control plane endpoint', { 
                ip: clientIp, 
                path: c.req.path,
                // Don't log the actual key for security
                keyPrefix: customerApiKey.substring(0, 8) + '...',
            });
            
            return c.json(
                { 
                    success: false, 
                    error: 'Customer API keys cannot access control plane',
                    code: 'CUSTOMER_KEY_BLOCKED',
                },
                403
            );
        }
        
        // Check for customer JWT auth
        const authHeader = c.req.header('authorization');
        if (authHeader?.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            // Quick check - customer tokens don't have 'control_plane' type
            try {
                const [payload] = token.split('.');
                if (payload) {
                    const decoded = JSON.parse(Buffer.from(payload, 'base64').toString());
                    if (decoded.tid) { // Customer tokens have tenant ID
                        logger.warn('Customer JWT used on control plane endpoint', {
                            ip: getClientIp(c),
                            path: c.req.path,
                            tenantId: decoded.tid,
                        });
                        
                        return c.json(
                            { 
                                success: false, 
                                error: 'Customer tokens cannot access control plane',
                                code: 'CUSTOMER_TOKEN_BLOCKED',
                            },
                            403
                        );
                    }
                }
            } catch {
                // Not a valid JWT, let it through to be rejected by normal auth
            }
        }
        
        return next();
    };
}
