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
import { validateCsrf } from '@/lib/csrf';
import { query } from '@/lib/db';

// Rate limiting storage (database-backed for multi-instance consistency)
let rateLimitTableReady: Promise<void> | null = null;

async function ensureRateLimitTable(): Promise<void> {
    if (!rateLimitTableReady) {
        rateLimitTableReady = (async () => {
            await query(
                `CREATE TABLE IF NOT EXISTS control_plane_login_attempts (
                    ip_address TEXT PRIMARY KEY,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    first_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )`
            );
        })().catch((error) => {
            rateLimitTableReady = null;
            throw error;
        });
    }

    await rateLimitTableReady;
}

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
        // FIX-500-304: Use rightmost entry — the one added by our trusted reverse proxy.
        const parts = forwarded.split(',').map(s => s.trim()).filter(Boolean);
        const proxiedIp = parts[parts.length - 1];
        if (proxiedIp) {
            return proxiedIp;
        }
    }
    return request.headers.get('x-real-ip') || '127.0.0.1';
}

/**
 * Checks if the IP is rate limited
 */
async function isRateLimited(ip: string): Promise<{ limited: boolean; remainingTime?: number }> {
    await ensureRateLimitTable();

    const rows = await query<{ attempt_count: number; last_attempt_at: Date }>(
        `SELECT attempt_count, last_attempt_at
         FROM control_plane_login_attempts
         WHERE ip_address = $1`,
        [ip]
    );

    const attempts = rows[0];
    if (!attempts) return { limited: false };

    const lastAttemptAt = new Date(attempts.last_attempt_at).getTime();
    const timeSinceLastAttempt = Date.now() - lastAttemptAt;

    if (timeSinceLastAttempt > LOCKOUT_DURATION_MS) {
        await query('DELETE FROM control_plane_login_attempts WHERE ip_address = $1', [ip]);
        return { limited: false };
    }

    if (attempts.attempt_count >= MAX_ATTEMPTS) {
        return {
            limited: true,
            remainingTime: Math.ceil((LOCKOUT_DURATION_MS - timeSinceLastAttempt) / 1000),
        };
    }

    return { limited: false };
}

/**
 * Records a login attempt
 */
async function recordAttempt(ip: string, success: boolean): Promise<void> {
    await ensureRateLimitTable();

    if (success) {
        await query('DELETE FROM control_plane_login_attempts WHERE ip_address = $1', [ip]);
        return;
    }

    await query(
        `INSERT INTO control_plane_login_attempts (ip_address, attempt_count, first_attempt_at, last_attempt_at)
         VALUES ($1, 1, NOW(), NOW())
         ON CONFLICT (ip_address)
         DO UPDATE SET
            attempt_count = control_plane_login_attempts.attempt_count + 1,
            last_attempt_at = NOW()`,
        [ip]
    );
}

/**
 * Verifies owner credentials using bcrypt for secure password comparison
 * In production, this would check against a secure database with hashed passwords
 */
async function verifyCredentials(email: string, password: string): Promise<{ valid: boolean; userId?: string; name?: string; role?: string }> {
    // SECURITY: All credentials MUST come from environment variables.
    // No hardcoded passwords, no plaintext fallbacks.
    
    // Build owner credentials from environment
    const OWNER_CREDENTIALS: Array<{
        email: string;
        passwordHash: string;
        userId: string;
        name: string;
        role: string;
    }> = [];

    // CEO account
    if (process.env.CEO_EMAIL && process.env.CEO_PASSWORD_HASH) {
        OWNER_CREDENTIALS.push({
            email: process.env.CEO_EMAIL,
            passwordHash: process.env.CEO_PASSWORD_HASH,
            userId: 'owner_ceo',
            name: process.env.CEO_DISPLAY_NAME || 'CEO',
            role: 'super_admin',
        });
    }

    // Additional admin account
    if (process.env.CONTROL_PLANE_OWNER_EMAIL && process.env.CONTROL_PLANE_OWNER_PASSWORD_HASH) {
        OWNER_CREDENTIALS.push({
            email: process.env.CONTROL_PLANE_OWNER_EMAIL,
            passwordHash: process.env.CONTROL_PLANE_OWNER_PASSWORD_HASH,
            userId: 'owner_001',
            name: process.env.CONTROL_PLANE_OWNER_NAME || 'Admin',
            role: 'admin',
        });
    }

    if (OWNER_CREDENTIALS.length === 0) {
        console.error('[SECURITY CRITICAL] No owner credentials configured. Set CEO_EMAIL + CEO_PASSWORD_HASH or CONTROL_PLANE_OWNER_EMAIL + CONTROL_PLANE_OWNER_PASSWORD_HASH environment variables.');
        // Still do timing-safe delay to avoid leak
        await bcrypt.hash('dummy', 10);
        return { valid: false };
    }
    
    // Find matching user
    const owner = OWNER_CREDENTIALS.find(o => o.email.toLowerCase() === email.toLowerCase());
    
    if (!owner) {
        // Perform a constant-time operation to prevent email enumeration
        await bcrypt.hash('dummy', 10);
        return { valid: false };
    }
    
    // Verify password using bcrypt (timing-safe internally)
    let isValid = false;
    try {
        isValid = await bcrypt.compare(password, owner.passwordHash);
    } catch {
        console.error('[AUTH] bcrypt compare failed');
        isValid = false;
    }
    
    return { 
        valid: isValid,
        userId: isValid ? owner.userId : undefined,
        name: isValid ? owner.name : undefined,
        role: isValid ? owner.role : undefined,
    };
}

/**
 * Verifies MFA code using TOTP (Time-based One-Time Password)
 * Implements RFC 6238 TOTP algorithm
 */
function verifyMfaCode(userId: string, code: string): boolean {
    // SECURITY: Proper TOTP verification using RFC 6238
    // No bypass codes allowed - NODE_ENV checks are unreliable
    
    // Verify against stored TOTP secret
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
function createSessionToken(userId: string, name?: string, role?: string): string {
    const payload = {
        sub: userId,
        name: name || 'Owner',
        role: role || 'admin',
        type: 'control_plane', // CRITICAL: Marks this as control plane session
        iat: Date.now(),
        exp: Date.now() + SESSION_DURATION_MS,
    };
    
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    
    // Sign the payload — CONTROL_PLANE_JWT_SECRET MUST be set
    const secret = process.env.CONTROL_PLANE_JWT_SECRET;
    if (!secret) {
        throw new Error(
            'CONTROL_PLANE_JWT_SECRET is not configured. ' +
            'Set this environment variable before starting the control plane.'
        );
    }
    const signature = crypto
        .createHmac('sha256', secret)
        .update(payloadB64)
        .digest('base64url');
    
    return `${payloadB64}.${signature}`;
}

export async function POST(request: NextRequest) {
    const csrf = validateCsrf(request);
    if (!csrf.ok) {
        return csrf.response ?? NextResponse.json({ error: 'Invalid CSRF token' }, { status: 403 });
    }

    const clientIp = getClientIp(request);
    
    // Check rate limiting
    const rateLimitCheck = await isRateLimited(clientIp);
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
            await recordAttempt(clientIp, false);
            return NextResponse.json(
                { error: 'Email and password are required' },
                { status: 400 }
            );
        }
        
        // Verify credentials
        const credentialCheck = await verifyCredentials(email, password);
        
        if (!credentialCheck.valid) {
            await recordAttempt(clientIp, false);
            console.warn(`[SECURITY] Failed login attempt for ${email} from ${clientIp}`);
            return NextResponse.json(
                { error: 'Invalid credentials' },
                { status: 401 }
            );
        }

        if (!credentialCheck.userId) {
            await recordAttempt(clientIp, false);
            console.error('[SECURITY] Credential check succeeded without userId');
            return NextResponse.json(
                { error: 'Authentication failed' },
                { status: 500 }
            );
        }
        
        // MFA enforcement
        const mfaConfigured = !!process.env.CONTROL_PLANE_MFA_SECRET;
        const isProduction = process.env.NODE_ENV === 'production';
        
        if (isProduction && !mfaConfigured) {
            console.error('[SECURITY CRITICAL] CONTROL_PLANE_MFA_SECRET not configured in production - blocking login');
            return NextResponse.json(
                { error: 'Server configuration error' },
                { status: 500 }
            );
        }
        
        if (mfaConfigured) {
            // MFA is configured — ALWAYS require it, regardless of whether the field was sent
            if (!mfaCode) {
                return NextResponse.json(
                    { 
                        error: 'MFA code required',
                        requireMfa: true,
                    },
                    { status: 401 }
                );
            }
            
            if (!verifyMfaCode(credentialCheck.userId, mfaCode)) {
                await recordAttempt(clientIp, false);
                console.warn(`[SECURITY] Failed MFA attempt for ${email} from ${clientIp}`);
                return NextResponse.json(
                    { error: 'Invalid MFA code' },
                    { status: 401 }
                );
            }
        } else {
            // Development mode: MFA not configured, allow login with warning
            console.warn('[AUTH] MFA not configured - set CONTROL_PLANE_MFA_SECRET to enable');
        }
        
        // Success - create session
        await recordAttempt(clientIp, true);
        const sessionToken = createSessionToken(
            credentialCheck.userId,
            credentialCheck.name,
            credentialCheck.role
        );
        
        // Set session cookie
        const response = NextResponse.json({ 
            success: true,
            message: 'Login successful',
            user: {
                name: credentialCheck.name,
                role: credentialCheck.role,
            },
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
        await recordAttempt(clientIp, false).catch((recordError) => {
            console.error('[CONTROL_PLANE] Failed to record failed login attempt', recordError);
        });
        console.error('[CONTROL_PLANE] Login error:', error);
        return NextResponse.json(
            { error: 'Internal server error' },
            { status: 500 }
        );
    }
}
