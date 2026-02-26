import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import * as crypto from 'crypto';

const GITHUB_SSO_STATE_COOKIE = 'am_sso_state_github';

function createOAuthState(): string {
  return crypto.randomBytes(32).toString('base64url');
}

export async function GET(request: NextRequest) {
  const apiBaseUrl = process.env.API_URL || 'http://localhost:3001';
  const next = request.nextUrl.searchParams.get('next');
  const callbackPath = next && next.startsWith('/') ? next : '/dashboard';
  const callbackUrl = `${request.nextUrl.origin}${callbackPath}`;
  const state = createOAuthState();
  const target = `${apiBaseUrl}/v1/auth/sso/github?returnUrl=${encodeURIComponent(callbackUrl)}&state=${encodeURIComponent(state)}`;

  const response = NextResponse.redirect(target);
  response.cookies.set(GITHUB_SSO_STATE_COOKIE, state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 10,
  });

  return response;
}
