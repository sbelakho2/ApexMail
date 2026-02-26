/**
 * Secrets Management API
 *
 * FIX-500-138: DB-backed secrets management — no demo data.
 * Queries the `secrets` table for CRUD operations.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';
import { z } from 'zod';

export const dynamic = 'force-dynamic';

// SEC-004 FIX: Add strict input validation schema
const createSecretSchema = z.object({
    name: z.string()
        .min(1, 'Name is required')
        .max(100, 'Name must be 100 characters or less')
        .regex(/^[a-zA-Z0-9_-]+$/, 'Name must contain only alphanumeric characters, underscores, and hyphens'),
    type: z.enum(['api_key', 'oauth_secret', 'encryption_key', 'signing_key', 'custom']),
    description: z.string().max(500, 'Description must be 500 characters or less').optional().default(''),
    rotationPolicy: z.enum(['manual', 'daily', 'weekly', 'monthly']).optional().default('manual'),
});

interface SecretRow {
    id: string;
    name: string;
    type: string;
    description: string;
    rotation_policy: string;
    status: string;
    access_count: string;
    last_accessed: string | null;
    last_rotated: string;
    expires_at: string | null;
    created_at: string;
    updated_at: string;
}

async function logSecretAudit(action: string, secretId: string, metadata?: Record<string, unknown>) {
    try {
        await query(
            `INSERT INTO audit_logs (
                timestamp,
                action,
                resource_type,
                resource_id,
                metadata
            ) VALUES (
                NOW(),
                $1,
                'secret',
                $2,
                $3::jsonb
            )`,
            [action, secretId, JSON.stringify(metadata ?? {})]
        );
    } catch (error) {
        console.error('Secrets audit log error:', error);
    }
}

function mapRow(r: SecretRow) {
    return {
        id: r.id,
        name: r.name,
        type: r.type,
        description: r.description,
        rotationPolicy: r.rotation_policy,
        status: r.status,
        accessCount: parseInt(String(r.access_count), 10),
        lastAccessed: r.last_accessed,
        lastRotated: r.last_rotated,
        expiresAt: r.expires_at,
        createdAt: r.created_at,
        updatedAt: r.updated_at,
    };
}

export async function GET() {
    try {
        const rows = await query<SecretRow>(
            `SELECT id, name, type, description, rotation_policy, status,
                    access_count, last_accessed, last_rotated, expires_at,
                    created_at, updated_at
             FROM secrets
             ORDER BY created_at DESC`
        );
        return NextResponse.json(rows.map(mapRow));
    } catch (error) {
        console.error('Secrets GET error:', error);
        return NextResponse.json({ error: 'Failed to fetch secrets' }, { status: 500 });
    }
}

export async function POST(request: Request) {
    try {
        const body = await request.json();
        
        // SEC-004 FIX: Validate input with zod schema
        const parseResult = createSecretSchema.safeParse(body);
        if (!parseResult.success) {
            return NextResponse.json(
                { error: 'Invalid input', details: parseResult.error.flatten().fieldErrors },
                { status: 400 }
            );
        }
        
        const { name, type, description, rotationPolicy } = parseResult.data;
        
        const rows = await query<SecretRow>(
            `INSERT INTO secrets (name, type, description, rotation_policy, status)
             VALUES ($1, $2, $3, $4, 'active')
             RETURNING *`,
            [name, type, description, rotationPolicy]
        );
        if (rows.length === 0) {
            return NextResponse.json({ error: 'Failed to create secret' }, { status: 500 });
        }
        await logSecretAudit('control_plane.secret.created', rows[0].id, { type, name });
        return NextResponse.json(mapRow(rows[0]), { status: 201 });
    } catch (error) {
        console.error('Secrets POST error:', error);
        return NextResponse.json({ error: 'Failed to create secret' }, { status: 500 });
    }
}

export async function PATCH(request: Request) {
    try {
        const body = await request.json();
        const { id, action } = body as { id: string; action: 'rotate' | 'revoke' };
        if (!id || !action) {
            return NextResponse.json({ error: 'Secret ID and action are required' }, { status: 400 });
        }
        if (action === 'rotate') {
            const rows = await query<{ id: string; last_rotated: string }>(
                `UPDATE secrets SET last_rotated = NOW(), status = 'active', updated_at = NOW()
                 WHERE id = $1 RETURNING id, last_rotated`,
                [id]
            );
            if (rows.length === 0) {
                return NextResponse.json({ error: 'Secret not found' }, { status: 404 });
            }
            await logSecretAudit('control_plane.secret.rotated', id);
            return NextResponse.json({ success: true, message: `Secret ${id} rotated`, lastRotated: rows[0].last_rotated, status: 'active' });
        }
        if (action === 'revoke') {
            const rows = await query<{ id: string }>(
                `UPDATE secrets SET status = 'revoked', updated_at = NOW() WHERE id = $1 RETURNING id`,
                [id]
            );
            if (rows.length === 0) {
                return NextResponse.json({ error: 'Secret not found' }, { status: 404 });
            }
            await logSecretAudit('control_plane.secret.revoked', id);
            return NextResponse.json({ success: true, message: `Secret ${id} revoked`, status: 'revoked' });
        }
        return NextResponse.json({ error: 'Invalid action' }, { status: 400 });
    } catch (error) {
        console.error('Secrets PATCH error:', error);
        return NextResponse.json({ error: 'Failed to update secret' }, { status: 500 });
    }
}

export async function DELETE(request: Request) {
    try {
        let id: string | null = null;

        try {
            const body = await request.json() as { id?: string };
            id = body.id ?? null;
        } catch {
            const { searchParams } = new URL(request.url);
            id = searchParams.get('id');
        }

        if (!id) {
            return NextResponse.json({ error: 'Secret ID is required' }, { status: 400 });
        }
        const rows = await query<{ id: string }>(
            `DELETE FROM secrets WHERE id = $1 RETURNING id`,
            [id]
        );
        if (rows.length === 0) {
            return NextResponse.json({ error: 'Secret not found' }, { status: 404 });
        }
        await logSecretAudit('control_plane.secret.deleted', id);
        return NextResponse.json({ success: true, message: `Secret ${id} deleted` });
    } catch (error) {
        console.error('Secrets DELETE error:', error);
        return NextResponse.json({ error: 'Failed to delete secret' }, { status: 500 });
    }
}
