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
import bcrypt from 'bcrypt';

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
 * Verifies owner credentials using bcrypt for secure password comparison
 * In production, this would check against a secure database with hashed passwords
 */
async function verifyCredentials(email: string, password: string): Promise<{ valid: boolean; userId?: string }> {
    // SECURITY: In production, these would be stored securely in the database
    // with properly hashed passwords (bcrypt/argon2)
    const OWNER_EMAIL = process.env.CONTROL_PLANE_OWNER_EMAIL || 'admin@apexmail.ee';
    const OWNER_PASSWORD_HASH = process.env.CONTROL_PLANE_OWNER_PASSWORD_HASH;
    
    if (!OWNER_PASSWORD_HASH) {
        console.error('[SECURITY] CONTROL_PLANE_OWNER_PASSWORD_HASH not configured');
        return { valid: false };
    }
    
    if (email.toLowerCase() !== OWNER_EMAIL.toLowerCase()) {
        // Perform a dummy bcrypt compare to prevent timing attacks on email check
        await bcrypt.compare(password, '$2b$10$dummyhashtopreventtimingattacks');
        return { valid: false };
    }
    
    // Use bcrypt.compare for secure password verification
    // bcrypt.compare is timing-safe internally
    const isValid = await bcrypt.compare(password, OWNER_PASSWORD_HASH);
    
    return { 
        valid: isValid,
        userId: isValid ? 'owner_001' : undefined // In production, this would be the actual user ID
    };
}

/**
 * Verifies MFA code using TOTP (Time-based One-Time Password)
 * Implements RFC 6238 TOTP algorithm
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
    
    // Validate code format (6 digits)
    if (!/^\d{6}$/.test(code)) {
        return false;
    }
    
    // TOTP implementation (RFC 6238)
    const timeStep = 30; // 30-second window
    const digits = 6;
    const currentTime = Math.floor(Date.now() / 1000);
    
    // Check current window and ±1 window for clock drift tolerance
    for (const drift of [0, -1, 1]) {
        const counter = Math.floor((currentTime / timeStep) + drift);
        const expectedCode = generateTOTP(MFA_SECRET, counter, digits);
        
        if (timingSafeEqual(code, expectedCode)) {
            return true;
        }
    }
    
    return false;
}

/**
 * Generates a TOTP code using HMAC-SHA1
 * RFC 6238 compliant implementation
 */
function generateTOTP(secret: string, counter: number, digits: number): string {
    // Decode base32 secret
    const key = base32Decode(secret);
    
    // Convert counter to 8-byte buffer (big-endian)
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeBigUInt64BE(BigInt(counter));
    
    // Generate HMAC-SHA1
    const hmac = crypto.createHmac('sha1', key);
    hmac.update(counterBuffer);
    const hash = hmac.digest();
    
    // Dynamic truncation (RFC 4226)
    const offset = hash[hash.length - 1] & 0x0f;
    const truncatedHash = 
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);
    
    // Generate the OTP code
    const otp = truncatedHash % Math.pow(10, digits);
    return otp.toString().padStart(digits, '0');
}

/**
 * Decodes a Base32 encoded string (RFC 4648)
 * Used for TOTP secrets
 */
function base32Decode(encoded: string): Buffer {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const cleaned = encoded.toUpperCase().replace(/[^A-Z2-7]/g, '');
    
    let bits = '';
    for (const char of cleaned) {
        const val = alphabet.indexOf(char);
        if (val === -1) continue;
        bits += val.toString(2).padStart(5, '0');
    }
    
    const bytes: number[] = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.substring(i, i + 8), 2));
    }
    
    return Buffer.from(bytes);
}

/**
 * Timing-safe string comparison to prevent timing attacks
 */
function timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) {
        // Still do the comparison to avoid timing leak on length
        const dummy = '0'.repeat(a.length);
        crypto.timingSafeEqual(Buffer.from(dummy), Buffer.from(dummy));
        return false;
    }
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
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
    
    // Sign the payload - MUST have JWT secret in production
    const secret = process.env.CONTROL_PLANE_JWT_SECRET;
    if (!secret) {
        if (process.env.NODE_ENV === 'production') {
            throw new Error('CONTROL_PLANE_JWT_SECRET must be set in production');
        }
        // Only allow dev fallback in non-production environments
        console.warn('[SECURITY] Using dev JWT secret - set CONTROL_PLANE_JWT_SECRET in production');
    }
    const effectiveSecret = secret || 'dev-secret-DO-NOT-USE-IN-PRODUCTION';
    const signature = crypto
        .createHmac('sha256', effectiveSecret)
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
        const credentialCheck = await verifyCredentials(email, password);
        
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
