import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { z } from 'zod';
import { validateCsrf } from '@/lib/csrf';

const forgotPasswordSchema = z.object({
  email: z.string().email().max(254),
});

const FORGOT_PASSWORD_WINDOW_MS = 15 * 60 * 1000;
const FORGOT_PASSWORD_MAX_REQUESTS = 5;
const rateLimitBuckets = new Map<string, number[]>();

function getClientIp(request: NextRequest): string {
  const forwardedFor = request.headers.get('x-forwarded-for');
  if (forwardedFor) {
    const firstIp = forwardedFor.split(',')[0]?.trim();
    if (firstIp) return firstIp;
  }

  const realIp = request.headers.get('x-real-ip');
  return realIp?.trim() || 'unknown';
}

function isRateLimited(clientIp: string, now: number): boolean {
  const recent = (rateLimitBuckets.get(clientIp) || []).filter((ts) => now - ts < FORGOT_PASSWORD_WINDOW_MS);

  if (recent.length >= FORGOT_PASSWORD_MAX_REQUESTS) {
    rateLimitBuckets.set(clientIp, recent);
    return true;
  }

  recent.push(now);
  rateLimitBuckets.set(clientIp, recent);

  if (rateLimitBuckets.size > 5000) {
    for (const [ip, timestamps] of rateLimitBuckets) {
      const active = timestamps.filter((ts) => now - ts < FORGOT_PASSWORD_WINDOW_MS);
      if (active.length === 0) {
        rateLimitBuckets.delete(ip);
      } else {
        rateLimitBuckets.set(ip, active);
      }
    }
  }

  return false;
}

export async function POST(request: NextRequest) {
  const csrf = await validateCsrf(request);
  if (!csrf.ok) {
    return csrf.response!;
  }

  const now = Date.now();
  const clientIp = getClientIp(request);
  if (isRateLimited(clientIp, now)) {
    return NextResponse.json({ error: 'Too many reset requests. Please try again later.' }, { status: 429 });
  }

  let email: string;

  try {
    const body = await request.json();
    email = forgotPasswordSchema.parse(body).email;
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: 'Invalid email address.' }, { status: 400 });
    }

    return NextResponse.json({ error: 'Invalid request payload.' }, { status: 400 });
  }

  const apiBaseUrl = process.env.API_URL || 'http://localhost:3001';

  try {
    const upstream = await fetch(`${apiBaseUrl}/v1/auth/forgot-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
      signal: AbortSignal.timeout(5000),
    });

    if (!upstream.ok && upstream.status >= 500) {
      return NextResponse.json({ error: 'Password reset service temporarily unavailable.' }, { status: 502 });
    }

    return NextResponse.json({ success: true });
  } catch {
    return NextResponse.json({ error: 'Password reset service temporarily unavailable.' }, { status: 502 });
  }
}
