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

// FIX-500-030: GET logout removed — enables CSRF via <img src="/api/auth/logout">.
// Logout MUST be POST-only to require an intentional action.
