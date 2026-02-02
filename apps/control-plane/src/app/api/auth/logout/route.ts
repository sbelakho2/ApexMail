/**
 * Control Plane Logout API Route
 */

import { NextResponse } from 'next/server';

const CONTROL_PLANE_SESSION_COOKIE = 'cp_session';

export async function POST() {
    const response = NextResponse.json({ 
        success: true,
        message: 'Logged out successfully',
    });
    
    // Clear the session cookie
    response.cookies.delete(CONTROL_PLANE_SESSION_COOKIE);
    
    return response;
}

export async function GET() {
    // Also support GET for simple logout links
    const response = NextResponse.redirect(new URL('/login', process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3020'));
    response.cookies.delete(CONTROL_PLANE_SESSION_COOKIE);
    return response;
}
