/**
 * Secrets Management API
 *
 * FIX-500-138: DB-backed secrets management — no demo data.
 * Queries the `secrets` table for CRUD operations.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

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
        const { name, type, description, rotationPolicy } = body as {
            name: string; type: string; description: string; rotationPolicy: string;
        };
        if (!name || !type) {
            return NextResponse.json({ error: 'Name and type are required' }, { status: 400 });
        }
        const rows = await query<SecretRow>(
            `INSERT INTO secrets (name, type, description, rotation_policy, status)
             VALUES ($1, $2, $3, $4, 'active')
             RETURNING *`,
            [name, type, description || '', rotationPolicy || 'manual']
        );
        if (rows.length === 0) {
            return NextResponse.json({ error: 'Failed to create secret' }, { status: 500 });
        }
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
        const { searchParams } = new URL(request.url);
        const id = searchParams.get('id');
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
        return NextResponse.json({ success: true, message: `Secret ${id} deleted` });
    } catch (error) {
        console.error('Secrets DELETE error:', error);
        return NextResponse.json({ error: 'Failed to delete secret' }, { status: 500 });
    }
}
