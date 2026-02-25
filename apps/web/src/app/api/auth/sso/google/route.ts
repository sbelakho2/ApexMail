import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export async function GET(request: NextRequest) {
  const apiBaseUrl = process.env.API_URL || 'http://localhost:3001';
  const next = request.nextUrl.searchParams.get('next');
  const callbackPath = next && next.startsWith('/') ? next : '/dashboard';
  const callbackUrl = `${request.nextUrl.origin}${callbackPath}`;
  const target = `${apiBaseUrl}/v1/auth/sso/google?returnUrl=${encodeURIComponent(callbackUrl)}`;
  return NextResponse.redirect(target);
}
