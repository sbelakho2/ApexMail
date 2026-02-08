/**
 * Feature Flags API
 *
 * FIX-500-139: DB-backed feature flag management — no demo data.
 * Queries feature_flags + feature_flag_overrides tables.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

interface FlagRow {
    id: string;
    key: string;
    name: string;
    description: string;
    type: string;
    enabled: boolean;
    percentage: number | null;
    allowlist: string[] | null;
    category: string;
    updated_by: string | null;
    created_at: string;
    updated_at: string;
}

interface OverrideRow {
    id: string;
    tenant_id: string;
    tenant_name: string | null;
    flag_key: string;
    value: boolean;
    reason: string | null;
    created_at: string;
}

export async function GET() {
    try {
        const [flags, overrides] = await Promise.all([
            query<FlagRow>(
                `SELECT id, key, name, description, type, enabled, percentage,
                        allowlist, category, updated_by, created_at, updated_at
                 FROM feature_flags
                 ORDER BY category, name`
            ),
            query<OverrideRow>(
                `SELECT id, tenant_id, tenant_name, flag_key, value, reason, created_at
                 FROM feature_flag_overrides
                 ORDER BY created_at DESC`
            ),
        ]);

        return NextResponse.json({
            flags: flags.map((f) => ({
                id: f.id,
                key: f.key,
                name: f.name,
                description: f.description,
                type: f.type,
                enabled: f.enabled,
                percentage: f.percentage,
                allowlist: f.allowlist,
                category: f.category,
                updatedBy: f.updated_by,
                createdAt: f.created_at,
                updatedAt: f.updated_at,
            })),
            overrides: overrides.map((o) => ({
                tenantId: o.tenant_id,
                tenantName: o.tenant_name,
                flagKey: o.flag_key,
                value: o.value,
                reason: o.reason,
                createdAt: o.created_at,
            })),
        });
    } catch (error) {
        console.error('Features API error:', error);
        return NextResponse.json({ error: 'Failed to fetch feature flags' }, { status: 500 });
    }
}

export async function POST(request: Request) {
    try {
        const body = await request.json();
        const { key, name, description, type, enabled, percentage, allowlist, category } = body as {
            key: string; name: string; description?: string; type?: string;
            enabled?: boolean; percentage?: number; allowlist?: string[]; category?: string;
        };
        if (!key || !name) {
            return NextResponse.json({ error: 'key and name are required' }, { status: 400 });
        }
        const rows = await query<FlagRow>(
            `INSERT INTO feature_flags (key, name, description, type, enabled, percentage, allowlist, category)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING *`,
            [key, name, description || '', type || 'boolean', enabled ?? false,
             percentage ?? null, allowlist ? JSON.stringify(allowlist) : null, category || 'core']
        );
        if (rows.length === 0) {
            return NextResponse.json({ error: 'Failed to create flag' }, { status: 500 });
        }
        return NextResponse.json(rows[0], { status: 201 });
    } catch (error) {
        console.error('Features POST error:', error);
        return NextResponse.json({ error: 'Failed to create feature flag' }, { status: 500 });
    }
}

export async function PATCH(request: Request) {
    try {
        const body = await request.json();
        const { id, enabled, percentage, allowlist } = body as {
            id: string; enabled?: boolean; percentage?: number; allowlist?: string[];
        };
        if (!id) {
            return NextResponse.json({ error: 'Flag ID is required' }, { status: 400 });
        }

        const sets: string[] = ['updated_at = NOW()'];
        const values: unknown[] = [];
        let idx = 1;

        if (enabled !== undefined) { sets.push(`enabled = $${idx++}`); values.push(enabled); }
        if (percentage !== undefined) { sets.push(`percentage = $${idx++}`); values.push(percentage); }
        if (allowlist !== undefined) { sets.push(`allowlist = $${idx++}`); values.push(JSON.stringify(allowlist)); }

        values.push(id);
        const rows = await query<FlagRow>(
            `UPDATE feature_flags SET ${sets.join(', ')} WHERE id = $${idx} RETURNING *`,
            values
        );
        if (rows.length === 0) {
            return NextResponse.json({ error: 'Flag not found' }, { status: 404 });
        }
        return NextResponse.json(rows[0]);
    } catch (error) {
        console.error('Features PATCH error:', error);
        return NextResponse.json({ error: 'Failed to update feature flag' }, { status: 500 });
    }
}
