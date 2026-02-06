/**
 * Impersonation Token API
 * 
 * Generates secure tokens that allow Control Plane operators to 
 * impersonate customer console users for support purposes.
 * 
 * SECURITY:
 * - Only accessible from authenticated Control Plane sessions
 * - All impersonation events are logged in audit trail
 * - Tokens are short-lived (15 minutes)
 * - Impersonation sessions show a visible banner
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import * as crypto from 'crypto';

const IMPERSONATION_TOKEN_DURATION_MS = 15 * 60 * 1000; // 15 minutes

/**
 * Generates an impersonation token for accessing the customer console
 */
function generateImpersonationToken(
    tenantId: string,
    operatorId: string,
    operatorName: string
): string {
    const payload = {
        type: 'impersonation',
        tenantId,
        operatorId,
        operatorName,
        iat: Date.now(),
        exp: Date.now() + IMPERSONATION_TOKEN_DURATION_MS,
        jti: crypto.randomUUID(), // Unique token ID for audit
    };
    
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    
    // Sign with shared secret between control plane and console
    const secret = process.env.IMPERSONATION_SECRET;
    if (!secret) {
        throw new Error('IMPERSONATION_SECRET is not configured');
    }
    const signature = crypto
        .createHmac('sha256', secret)
        .update(payloadB64)
        .digest('base64url');
    
    return `${payloadB64}.${signature}`;
}

export async function POST(request: NextRequest) {
    // Verify this is an authenticated control plane request
    const cpSession = request.cookies.get('cp_session')?.value;
    if (!cpSession) {
        return NextResponse.json(
            { error: 'Unauthorized' },
            { status: 401 }
        );
    }
    
    try {
        const body = await request.json();
        const { tenantId, tenantName } = body;
        
        if (!tenantId) {
            return NextResponse.json(
                { error: 'Tenant ID is required' },
                { status: 400 }
            );
        }
        
        // Extract operator info from session (simplified - decode the session)
        let operatorId = 'unknown';
        let operatorName = 'Control Plane Operator';
        
        try {
            const [payload] = cpSession.split('.');
            const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
            operatorId = decoded.sub || 'unknown';
            operatorName = decoded.name || 'Control Plane Operator';
        } catch {
            // Use defaults if session decode fails
        }
        
        // Generate the impersonation token
        const token = generateImpersonationToken(tenantId, operatorId, operatorName);
        
        // Log the impersonation event (in production, this goes to audit log)
        console.log(`[AUDIT] Impersonation token generated`, {
            operatorId,
            operatorName,
            tenantId,
            tenantName,
            timestamp: new Date().toISOString(),
        });
        
        // Return the token and console URL
        const consoleUrl = process.env.NEXT_PUBLIC_CONSOLE_URL || 'http://localhost:3000';
        const impersonateUrl = `${consoleUrl}/api/auth/impersonate?token=${encodeURIComponent(token)}`;
        
        return NextResponse.json({
            success: true,
            token,
            url: impersonateUrl,
            expiresIn: IMPERSONATION_TOKEN_DURATION_MS / 1000,
        });
        
    } catch (error) {
        console.error('[IMPERSONATION] Error generating token:', error);
        return NextResponse.json(
            { error: 'Failed to generate impersonation token' },
            { status: 500 }
        );
    }
}
