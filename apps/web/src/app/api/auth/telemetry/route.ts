import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

function sanitizeLogString(value: unknown, fallback: string, maxLength = 64): string {
  if (typeof value !== 'string') {
    return fallback;
  }

  return value
    .replace(/[\r\n\t\0\f\v]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength) || fallback;
}

function sanitizeStatus(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }

  const status = Math.trunc(value);
  if (status < 100 || status > 599) {
    return null;
  }

  return status;
}

function sanitizeTimestamp(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return Date.now();
  }

  return Math.trunc(value);
}

export async function POST(request: NextRequest) {
  try {
    const payload = await request.json();
    console.info('[auth-telemetry]', {
      reason: sanitizeLogString(payload?.reason, 'unknown'),
      status: sanitizeStatus(payload?.status),
      networkClass: sanitizeLogString(payload?.networkClass, 'unknown', 32),
      at: sanitizeTimestamp(payload?.at),
    });
  } catch {
    // Keep telemetry endpoint non-blocking
  }

  return NextResponse.json({ success: true });
}
