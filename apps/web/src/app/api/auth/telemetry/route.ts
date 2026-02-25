import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export async function POST(request: NextRequest) {
  try {
    const payload = await request.json();
    console.info('[auth-telemetry]', {
      reason: payload?.reason ?? 'unknown',
      status: payload?.status ?? null,
      networkClass: payload?.networkClass ?? 'unknown',
      at: payload?.at ?? Date.now(),
    });
  } catch {
    // Keep telemetry endpoint non-blocking
  }

  return NextResponse.json({ success: true });
}
