/**
 * End Impersonation Session API
 * 
 * Clears the impersonation session and logs the event.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { verifySignedToken } from '@/lib/signatures';
import { logAuditEvent } from '@/lib/server-logger';

const IMPERSONATION_SESSION_COOKIE = 'impersonation_session';

async function validateImpersonationSessionToken(token: string): Promise<{
    valid: boolean;
    payload?: {
        operatorId?: string;
        operatorName?: string;
        tenantId?: string;
        tokenId?: string;
    };
}> {
    try {
        const secret = process.env.SESSION_SECRET;
        if (!secret) {
            return { valid: false };
        }

        const validation = await verifySignedToken<{
            operatorId?: unknown;
            operatorName?: unknown;
            tenantId?: unknown;
            tokenId?: unknown;
        }>(token, secret);

        if (!validation.valid || !validation.payload) {
            return { valid: false };
        }

        const payload = validation.payload;
        return {
            valid: true,
            payload: {
                operatorId: typeof payload.operatorId === 'string' ? payload.operatorId : undefined,
                operatorName: typeof payload.operatorName === 'string' ? payload.operatorName : undefined,
                tenantId: typeof payload.tenantId === 'string' ? payload.tenantId : undefined,
                tokenId: typeof payload.tokenId === 'string' ? payload.tokenId : undefined,
            },
        };
    } catch {
        return { valid: false };
    }
}

export async function POST(request: NextRequest) {
    const impersonationToken = request.cookies.get(IMPERSONATION_SESSION_COOKIE)?.value;
    
    if (impersonationToken) {
        const validation = await validateImpersonationSessionToken(impersonationToken);

        if (validation.valid && validation.payload) {
            logAuditEvent('impersonation_session_ended', {
                operatorId: validation.payload.operatorId,
                operatorName: validation.payload.operatorName,
                tenantId: validation.payload.tenantId,
                tokenId: validation.payload.tokenId,
            });
        } else {
            logAuditEvent('impersonation_session_ended_parse_failed', {});
        }
    }
    
    // Clear the cookie
    const response = NextResponse.json({ success: true });
    response.cookies.delete(IMPERSONATION_SESSION_COOKIE);
    
    return response;
}
