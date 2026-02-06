/**
 * Customer Console Login API Route
 *
 * Proxies login to the core API and stores the JWT in a secure, httpOnly cookie.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { z } from 'zod';
import { validateCsrf } from '@/lib/csrf';

const loginSchema = z.object({
    email: z.string().email().max(254),
    password: z.string().min(1).max(1000),
    tenantId: z.string().uuid().optional(),
});

const USER_SESSION_COOKIE = 'am_session';

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
    const csrf = validateCsrf(request);
    if (!csrf.ok) {
        return csrf.response!;
    }

    try {
        const body = await request.json();
        const { email, password, tenantId } = loginSchema.parse(body);

        const apiBaseUrl = process.env.API_URL || 'http://localhost:3001';
        const response = await fetch(`${apiBaseUrl}/v1/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, tenantId }),
        });

        const data = await response.json();

        if (!response.ok) {
            return NextResponse.json(
                { error: data?.error?.message || data?.error || 'Invalid credentials' },
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

        const maxAge = parseExpiryToSeconds(expiresIn);

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
