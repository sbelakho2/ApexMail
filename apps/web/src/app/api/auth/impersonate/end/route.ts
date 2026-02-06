/**
 * End Impersonation Session API
 * 
 * Clears the impersonation session and logs the event.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const IMPERSONATION_SESSION_COOKIE = 'impersonation_session';

export async function POST(request: NextRequest) {
    const impersonationToken = request.cookies.get(IMPERSONATION_SESSION_COOKIE)?.value;
    
    if (impersonationToken) {
        // Log the session end (in production, add to audit log)
        try {
            const [payloadB64] = impersonationToken.split('.');
            const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
            
            console.log(`[AUDIT] Impersonation session ended`, {
                operatorId: payload.operatorId,
                operatorName: payload.operatorName,
                tenantId: payload.tenantId,
                tokenId: payload.tokenId,
                timestamp: new Date().toISOString(),
            });
        } catch {
            // Log anyway even if token parse fails
            console.log(`[AUDIT] Impersonation session ended (token parse failed)`);
        }
    }
    
    // Clear the cookie
    const response = NextResponse.json({ success: true });
    response.cookies.delete(IMPERSONATION_SESSION_COOKIE);
    
    return response;
}
