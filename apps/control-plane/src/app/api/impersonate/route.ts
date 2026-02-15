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
import { query } from '@/lib/db';

const IMPERSONATION_TOKEN_DURATION_MS = 15 * 60 * 1000; // 15 minutes

interface ControlPlaneSessionPayload {
    sub: string;
    name?: string;
    type: string;
    iat: number;
    exp: number;
}

function verifyControlPlaneSession(sessionToken: string): ControlPlaneSessionPayload | null {
    try {
        const [payloadB64, signatureB64] = sessionToken.split('.');
        if (!payloadB64 || !signatureB64) {
            return null;
        }

        const secret = process.env.CONTROL_PLANE_JWT_SECRET;
        if (!secret) {
            return null;
        }

        const expectedSignature = crypto
            .createHmac('sha256', secret)
            .update(payloadB64)
            .digest('base64url');

        const providedBuffer = Buffer.from(signatureB64, 'utf8');
        const expectedBuffer = Buffer.from(expectedSignature, 'utf8');
        if (providedBuffer.length !== expectedBuffer.length) {
            return null;
        }

        if (!crypto.timingSafeEqual(providedBuffer, expectedBuffer)) {
            return null;
        }

        const decoded = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8')) as ControlPlaneSessionPayload;
        if (!decoded.sub || decoded.type !== 'control_plane') {
            return null;
        }

        if (decoded.exp && Date.now() > decoded.exp) {
            return null;
        }

        return decoded;
    } catch {
        return null;
    }
}

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

        // FIX-500-305: Validate that tenantId corresponds to an actual tenant
        const tenantRows = await query<{ id: string }>(
            `SELECT id FROM tenants WHERE id = $1 AND status != 'deleted'`,
            [tenantId]
        );
        if (!tenantRows || tenantRows.length === 0) {
            return NextResponse.json(
                { error: 'Tenant not found or has been deleted' },
                { status: 404 }
            );
        }
        
        const session = verifyControlPlaneSession(cpSession);
        if (!session) {
            return NextResponse.json(
                { error: 'Invalid or expired control plane session' },
                { status: 401 }
            );
        }
        const operatorId = session.sub;
        const operatorName = session.name || 'Control Plane Operator';
        const forwardedFor = request.headers.get('x-forwarded-for');
        const realIp = request.headers.get('x-real-ip');
        const ipAddress = forwardedFor?.split(',')[0]?.trim() || realIp || null;
        const userAgent = request.headers.get('user-agent');
        
        // Generate the impersonation token
        const token = generateImpersonationToken(tenantId, operatorId, operatorName);

        await query(
            `INSERT INTO audit_logs (
                timestamp,
                action,
                resource_type,
                resource_id,
                user_id,
                tenant_id,
                ip_address,
                user_agent,
                metadata
            ) VALUES (
                NOW(),
                'control_plane.impersonation.token_created',
                'tenant',
                $1,
                $2,
                $1,
                $3,
                $4,
                $5::jsonb
            )`,
            [
                tenantId,
                operatorId,
                ipAddress,
                userAgent,
                JSON.stringify({ operatorName, tenantName: tenantName ?? null }),
            ]
        ).catch((auditError) => {
            console.error('[IMPERSONATION] Failed to persist audit record', auditError);
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
