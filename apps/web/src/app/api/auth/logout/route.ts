import { NextResponse } from 'next/server';

const USER_SESSION_COOKIE = 'am_session';
const IMPERSONATION_SESSION_COOKIE = 'impersonation_session';

export async function POST() {
  const response = NextResponse.json({ success: true });
  response.cookies.delete(USER_SESSION_COOKIE);
  response.cookies.delete(IMPERSONATION_SESSION_COOKIE);
  return response;
}
