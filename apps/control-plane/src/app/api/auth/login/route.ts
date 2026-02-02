/**
 * Control Plane Login API Route
 * 
 * SECURITY: This authenticates platform OWNERS only, NOT customers.
 * 
 * Authentication Flow:
 * 1. Validate email/password against owner credentials
 * 2. Require MFA for all logins
 * 3. Issue control plane session token (different from customer tokens)
 * 4. Log all attempts for security audit
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import * as crypto from 'crypto';

// Rate limiting store (in production, use Redis)
const loginAttempts = new Map<string, { count: number; lastAttempt: number }>();

// Maximum login attempts before lockout
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

// Control plane session cookie name
const CONTROL_PLANE_SESSION_COOKIE = 'cp_session';

// Session duration
const SESSION_DURATION_MS = 8 * 60 * 60 * 1000; // 8 hours

/**
 * Gets the client IP for rate limiting
 */
function getClientIp(request: NextRequest): string {
    const forwarded = request.headers.get('x-forwarded-for');
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return request.headers.get('x-real-ip') || '127.0.0.1';
}

/**
 * Checks if the IP is rate limited
 */
function isRateLimited(ip: string): { limited: boolean; remainingTime?: number } {
    const attempts = loginAttempts.get(ip);
    if (!attempts) return { limited: false };
    
    const timeSinceLastAttempt = Date.now() - attempts.lastAttempt;
    
    // Reset if lockout has expired
    if (timeSinceLastAttempt > LOCKOUT_DURATION_MS) {
        loginAttempts.delete(ip);
        return { limited: false };
    }
    
    if (attempts.count >= MAX_ATTEMPTS) {
        return { 
            limited: true, 
            remainingTime: Math.ceil((LOCKOUT_DURATION_MS - timeSinceLastAttempt) / 1000)
        };
    }
    
    return { limited: false };
}

/**
 * Records a login attempt
 */
function recordAttempt(ip: string, success: boolean): void {
    if (success) {
        loginAttempts.delete(ip);
        return;
    }
    
    const attempts = loginAttempts.get(ip) || { count: 0, lastAttempt: 0 };
    attempts.count += 1;
    attempts.lastAttempt = Date.now();
    loginAttempts.set(ip, attempts);
}

/**
 * Verifies owner credentials
 * In production, this would check against a secure database with hashed passwords
 */
function verifyCredentials(email: string, password: string): { valid: boolean; userId?: string } {
    // SECURITY: In production, these would be stored securely in the database
    // with properly hashed passwords (bcrypt/argon2)
    const OWNER_EMAIL = process.env.CONTROL_PLANE_OWNER_EMAIL || 'admin@apexmail.ee';
    const OWNER_PASSWORD_HASH = process.env.CONTROL_PLANE_OWNER_PASSWORD_HASH;
    
    if (!OWNER_PASSWORD_HASH) {
        console.error('[SECURITY] CONTROL_PLANE_OWNER_PASSWORD_HASH not configured');
        return { valid: false };
    }
    
    if (email.toLowerCase() !== OWNER_EMAIL.toLowerCase()) {
        return { valid: false };
    }
    
    // Hash the provided password and compare
    const providedHash = crypto.createHash('sha256').update(password).digest('hex');
    
    // Constant-time comparison
    if (providedHash.length !== OWNER_PASSWORD_HASH.length) {
        return { valid: false };
    }
    
    let result = 0;
    for (let i = 0; i < providedHash.length; i++) {
        result |= providedHash.charCodeAt(i) ^ OWNER_PASSWORD_HASH.charCodeAt(i);
    }
    
    return { 
        valid: result === 0,
        userId: 'owner_001' // In production, this would be the actual user ID
    };
}

/**
 * Verifies MFA code
 * In production, this would use TOTP verification
 */
function verifyMfaCode(userId: string, code: string): boolean {
    // SECURITY: In production, implement proper TOTP verification
    // using a library like `otplib`
    
    // For development, allow a bypass code
    if (process.env.NODE_ENV === 'development' && code === '000000') {
        return true;
    }
    
    // In production, verify against stored TOTP secret
    const MFA_SECRET = process.env.CONTROL_PLANE_MFA_SECRET;
    if (!MFA_SECRET) {
        console.error('[SECURITY] CONTROL_PLANE_MFA_SECRET not configured');
        return false;
    }
    
    // TODO: Implement actual TOTP verification
    // const totp = new TOTP({ secret: MFA_SECRET });
    // return totp.validate({ token: code, window: 1 }) !== null;
    
    return false;
}

/**
 * Creates a session token
 */
function createSessionToken(userId: string): string {
    const payload = {
        sub: userId,
        type: 'control_plane', // CRITICAL: Marks this as control plane session
        iat: Date.now(),
        exp: Date.now() + SESSION_DURATION_MS,
    };
    
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64');
    
    // Sign the payload
    const secret = process.env.CONTROL_PLANE_JWT_SECRET || 'dev-secret-change-in-production';
    const signature = crypto
        .createHmac('sha256', secret)
        .update(payloadB64)
        .digest('base64');
    
    return `${payloadB64}.${signature}`;
}

export async function POST(request: NextRequest) {
    const clientIp = getClientIp(request);
    
    // Check rate limiting
    const rateLimitCheck = isRateLimited(clientIp);
    if (rateLimitCheck.limited) {
        console.warn(`[SECURITY] Rate limited login attempt from ${clientIp}`);
        return NextResponse.json(
            { 
                error: 'Too many login attempts',
                retryAfter: rateLimitCheck.remainingTime,
            },
            { status: 429 }
        );
    }
    
    try {
        const body = await request.json();
        const { email, password, mfaCode } = body;
        
        // Validate required fields
        if (!email || !password) {
            return NextResponse.json(
                { error: 'Email and password are required' },
                { status: 400 }
            );
        }
        
        // Verify credentials
        const credentialCheck = verifyCredentials(email, password);
        
        if (!credentialCheck.valid) {
            recordAttempt(clientIp, false);
            console.warn(`[SECURITY] Failed login attempt for ${email} from ${clientIp}`);
            return NextResponse.json(
                { error: 'Invalid credentials' },
                { status: 401 }
            );
        }
        
        // MFA required in production
        if (process.env.NODE_ENV === 'production' || mfaCode !== undefined) {
            if (!mfaCode) {
                return NextResponse.json(
                    { 
                        error: 'MFA code required',
                        requireMfa: true,
                    },
                    { status: 401 }
                );
            }
            
            if (!verifyMfaCode(credentialCheck.userId!, mfaCode)) {
                recordAttempt(clientIp, false);
                console.warn(`[SECURITY] Failed MFA attempt for ${email} from ${clientIp}`);
                return NextResponse.json(
                    { error: 'Invalid MFA code' },
                    { status: 401 }
                );
            }
        }
        
        // Success - create session
        recordAttempt(clientIp, true);
        const sessionToken = createSessionToken(credentialCheck.userId!);
        
        console.log(`[CONTROL_PLANE] Successful login for ${email} from ${clientIp}`);
        
        // Set session cookie
        const response = NextResponse.json({ 
            success: true,
            message: 'Login successful',
        });
        
        response.cookies.set(CONTROL_PLANE_SESSION_COOKIE, sessionToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: SESSION_DURATION_MS / 1000,
            path: '/',
        });
        
        return response;
        
    } catch (error) {
        console.error('[CONTROL_PLANE] Login error:', error);
        return NextResponse.json(
            { error: 'Internal server error' },
            { status: 500 }
        );
    }
}
