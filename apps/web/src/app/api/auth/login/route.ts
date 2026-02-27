/**
 * Customer Console Login API Route
 *
 * Proxies login to the core API and stores the JWT in a secure, httpOnly cookie.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { z } from 'zod';
import { validateCsrf } from '@/lib/csrf';
import { verifyMCaptchaToken } from '@/lib/security/mcaptcha';

const loginSchema = z.object({
    email: z.string().email().max(254),
    password: z.string().min(1).max(1000),
    tenantId: z.string().uuid().optional(),
    rememberMe: z.boolean().optional(),
    mfaCode: z.string().max(8).optional(),
    mcaptchaToken: z.string().max(4096).optional(),
});

const USER_SESSION_COOKIE = 'am_session';
const DEFAULT_SESSION_MAX_AGE_SECONDS = 60 * 60 * 12;
const REMEMBER_ME_SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 30;

type LoginErrorPayload = {
    error?: unknown;
    errorCode?: unknown;
};

function getSafeLoginError(status: number, payload: LoginErrorPayload): { error: string; errorCode?: string } {
    const rawErrorCode = typeof payload.errorCode === 'string'
        ? payload.errorCode
        : (typeof payload.error === 'object' && payload.error && typeof (payload.error as { code?: unknown }).code === 'string'
            ? (payload.error as { code: string }).code
            : undefined);

    if (status === 429) {
        return { error: 'Too many sign-in attempts. Please wait and try again.', errorCode: 'RATE_LIMITED' };
    }

    if (status === 423 || rawErrorCode === 'ACCOUNT_LOCKED') {
        return { error: 'Your account is temporarily locked. Reset your password or contact support.', errorCode: 'ACCOUNT_LOCKED' };
    }

    if (status === 401 || status === 400 || rawErrorCode === 'INVALID_CREDENTIALS') {
        return { error: 'Incorrect email, password, or verification code.', errorCode: 'INVALID_CREDENTIALS' };
    }

    if (status === 403 || rawErrorCode === 'MFA_REQUIRED') {
        return { error: 'Additional verification is required.', errorCode: 'MFA_REQUIRED' };
    }

    if (status === 400 || status === 403) {
        if (rawErrorCode === 'MCAPTCHA_REQUIRED') {
            return { error: 'Complete the CAPTCHA challenge and try again.', errorCode: 'MCAPTCHA_REQUIRED' };
        }
        if (rawErrorCode === 'MCAPTCHA_INVALID') {
            return { error: 'CAPTCHA verification failed. Please retry.', errorCode: 'MCAPTCHA_INVALID' };
        }
    }

    return { error: 'Unable to sign in. Please try again.' };
}

function parseExpiryToSeconds(value: string | number | undefined): number | undefined {
    if (value === undefined || value === null) return undefined;

    if (typeof value === 'number') {
        return Number.isFinite(value) ? value : undefined;
    }

    const trimmed = value.trim();
    if (/^\d+$/.test(trimmed)) {
        return Number.parseInt(trimmed, 10);
    }

    const match = trimmed.match(/^(\d+)([smhd])$/i);
    if (!match) return undefined;

    const amount = Number.parseInt(match[1], 10);
    const unit = match[2].toLowerCase();

    switch (unit) {
        case 's':
            return amount;
        case 'm':
            return amount * 60;
        case 'h':
            return amount * 60 * 60;
        case 'd':
            return amount * 60 * 60 * 24;
        default:
            return undefined;
    }
}

export async function POST(request: NextRequest) {
    const csrf = await validateCsrf(request);
    if (!csrf.ok) {
        return csrf.response!;
    }

    try {
        const body = await request.json();
        const { email, password, tenantId, rememberMe, mfaCode, mcaptchaToken } = loginSchema.parse(body);

        const captchaResult = await verifyMCaptchaToken(mcaptchaToken);
        if (!captchaResult.ok) {
            const status = captchaResult.reason === 'provider' || captchaResult.reason === 'misconfigured' ? 503 : 400;
            const errorCode = captchaResult.reason === 'missing'
                ? 'MCAPTCHA_REQUIRED'
                : captchaResult.reason === 'invalid'
                    ? 'MCAPTCHA_INVALID'
                    : 'MCAPTCHA_UNAVAILABLE';

            return NextResponse.json(
                {
                    error: errorCode === 'MCAPTCHA_REQUIRED'
                        ? 'Complete the CAPTCHA challenge and try again.'
                        : errorCode === 'MCAPTCHA_INVALID'
                            ? 'CAPTCHA verification failed. Please retry.'
                            : 'CAPTCHA verification service is unavailable. Please try again shortly.',
                    errorCode,
                },
                { status }
            );
        }

        const apiBaseUrl = process.env.API_URL || 'http://localhost:3001';
        const response = await fetch(`${apiBaseUrl}/v1/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, tenantId, rememberMe, mfaCode }),
            signal: AbortSignal.timeout(5000),
        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            const safeError = getSafeLoginError(response.status, data as LoginErrorPayload);
            return NextResponse.json(
                safeError,
                { status: response.status }
            );
        }

        const token = data?.token as string | undefined;
        const expiresIn = data?.expiresIn as string | number | undefined;

        if (!token) {
            return NextResponse.json(
                { error: 'Login response missing token' },
                { status: 502 }
            );
        }

        const maxAge = parseExpiryToSeconds(expiresIn)
            ?? (rememberMe ? REMEMBER_ME_SESSION_MAX_AGE_SECONDS : DEFAULT_SESSION_MAX_AGE_SECONDS);

        const result = NextResponse.json({
            success: true,
            user: data?.user ?? null,
        });

        result.cookies.set(USER_SESSION_COOKIE, token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/',
            maxAge: maxAge,
        });

        return result;
    } catch (error) {
        if (error instanceof z.ZodError) {
            return NextResponse.json(
                { error: 'Invalid login payload', details: error.errors },
                { status: 400 }
            );
        }

        return NextResponse.json(
            { error: 'Internal server error' },
            { status: 500 }
        );
    }
}
