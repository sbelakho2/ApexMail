/**
 * IP Warmup API
 *
 * FIX-500-141: DB-backed warmup management — no demo data.
 * Queries ip_pools, ip_pool_addresses, and isp_warmup_schedules tables
 * (created in migration 002).
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

interface PoolRow {
    id: string;
    name: string;
    description: string | null;
    warmup_enabled: boolean;
    warmup_started_at: string | null;
    warmup_day: number;
    daily_limit: number | null;
    status: string;
    created_at: string;
    updated_at: string;
}

interface AddressRow {
    id: string;
    pool_id: string;
    ip_address: string;
    hostname: string | null;
    ptr_verified: boolean;
    warmup_enabled: boolean;
    warmup_started_at: string | null;
    warmup_day: number;
    daily_limit: number | null;
    daily_sent: number;
    last_reset_at: string | null;
    reputation_score: number | null;
    status: string;
    created_at: string;
    updated_at: string;
}

interface ScheduleRow {
    id: string;
    isp_name: string;
    mx_patterns: string[];
    warmup_schedule: number[];
    notes: string | null;
    created_at: string;
    updated_at: string;
}

async function logWarmupAudit(request: Request, poolId: string, action: 'start' | 'pause' | 'reset'): Promise<void> {
    const forwardedFor = request.headers.get('x-forwarded-for');
    const realIp = request.headers.get('x-real-ip');
    const ipAddress = forwardedFor?.split(',')[0]?.trim() || realIp || null;
    const userAgent = request.headers.get('user-agent');

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
            $1,
            'warmup_pool',
            $2,
            NULL,
            NULL,
            $3,
            $4,
            $5::jsonb
        )`,
        [
            `control_plane.warmup.${action}`,
            poolId,
            ipAddress,
            userAgent,
            JSON.stringify({ action }),
        ]
    );
}

export async function GET(request: Request) {
    try {
        const url = new URL(request.url);
        const poolLimit = Math.min(Math.max(parseInt(url.searchParams.get('poolLimit') || '50', 10) || 50, 1), 200);
        const poolOffset = Math.max(parseInt(url.searchParams.get('poolOffset') || '0', 10) || 0, 0);
        const addressLimit = Math.min(Math.max(parseInt(url.searchParams.get('addressLimit') || '500', 10) || 500, 1), 2000);
        const addressOffset = Math.max(parseInt(url.searchParams.get('addressOffset') || '0', 10) || 0, 0);
        const scheduleLimit = Math.min(Math.max(parseInt(url.searchParams.get('scheduleLimit') || '100', 10) || 100, 1), 500);
        const scheduleOffset = Math.max(parseInt(url.searchParams.get('scheduleOffset') || '0', 10) || 0, 0);

        const [pools, addresses, schedules] = await Promise.all([
            query<PoolRow>(
                `SELECT id, name, description, warmup_enabled, warmup_started_at,
                        warmup_day, daily_limit, status, created_at, updated_at
                 FROM ip_pools
                 ORDER BY name ASC
                 LIMIT $1 OFFSET $2`,
                [poolLimit, poolOffset]
            ),
            query<AddressRow>(
                `SELECT id, pool_id, ip_address, hostname, ptr_verified,
                        warmup_enabled, warmup_started_at, warmup_day,
                        daily_limit, daily_sent, last_reset_at,
                        reputation_score, status, created_at, updated_at
                 FROM ip_pool_addresses
                 ORDER BY pool_id, ip_address
                 LIMIT $1 OFFSET $2`,
                [addressLimit, addressOffset]
            ),
            query<ScheduleRow>(
                `SELECT id, isp_name, mx_patterns, warmup_schedule, notes,
                        created_at, updated_at
                 FROM isp_warmup_schedules
                 ORDER BY isp_name ASC
                 LIMIT $1 OFFSET $2`,
                [scheduleLimit, scheduleOffset]
            ),
        ]);

        const addressesByPool = new Map<string, AddressRow[]>();
        for (const a of addresses) {
            const arr = addressesByPool.get(a.pool_id) ?? [];
            arr.push(a);
            addressesByPool.set(a.pool_id, arr);
        }

        return NextResponse.json({
            pools: pools.map((p) => ({
                id: p.id,
                name: p.name,
                description: p.description,
                warmupEnabled: p.warmup_enabled,
                warmupStartedAt: p.warmup_started_at,
                warmupDay: p.warmup_day,
                dailyLimit: p.daily_limit,
                status: p.status,
                createdAt: p.created_at,
                updatedAt: p.updated_at,
                addresses: (addressesByPool.get(p.id) ?? []).map((a) => ({
                    id: a.id,
                    ipAddress: a.ip_address,
                    hostname: a.hostname,
                    ptrVerified: a.ptr_verified,
                    warmupEnabled: a.warmup_enabled,
                    warmupStartedAt: a.warmup_started_at,
                    warmupDay: a.warmup_day,
                    dailyLimit: a.daily_limit,
                    dailySent: a.daily_sent,
                    lastResetAt: a.last_reset_at,
                    reputationScore: a.reputation_score,
                    status: a.status,
                })),
            })),
            schedules: schedules.map((s) => ({
                id: s.id,
                ispName: s.isp_name,
                mxPatterns: s.mx_patterns,
                warmupSchedule: s.warmup_schedule,
                notes: s.notes,
            })),
        });
    } catch (error) {
        console.error('Warmup API error:', error);
        return NextResponse.json({ error: 'Failed to fetch warmup data' }, { status: 500 });
    }
}

export async function POST(request: Request) {
    try {
        const body = await request.json();
        const { poolId, action } = body;

        if (!poolId) {
            return NextResponse.json({ error: 'Pool ID required' }, { status: 400 });
        }

        if (action === 'start') {
            const updated = await query<PoolRow>(
                `UPDATE ip_pools
                 SET warmup_enabled = true,
                     warmup_started_at = COALESCE(warmup_started_at, NOW()),
                     warmup_day = COALESCE(warmup_day, 0),
                     updated_at = NOW()
                 WHERE id = $1
                 RETURNING *`,
                [poolId]
            );
            if (updated.length === 0) {
                return NextResponse.json({ error: 'Pool not found' }, { status: 404 });
            }
            await query(
                `UPDATE ip_pool_addresses
                 SET warmup_enabled = true,
                     warmup_started_at = COALESCE(warmup_started_at, NOW()),
                     warmup_day = COALESCE(warmup_day, 0),
                     updated_at = NOW()
                 WHERE pool_id = $1`,
                [poolId]
            );
            await logWarmupAudit(request, poolId, 'start');
            return NextResponse.json({ success: true, pool: updated[0] });
        }

        if (action === 'pause') {
            const updated = await query<PoolRow>(
                `UPDATE ip_pools
                 SET warmup_enabled = false, updated_at = NOW()
                 WHERE id = $1
                 RETURNING *`,
                [poolId]
            );
            if (updated.length === 0) {
                return NextResponse.json({ error: 'Pool not found' }, { status: 404 });
            }
            await logWarmupAudit(request, poolId, 'pause');
            return NextResponse.json({ success: true, pool: updated[0] });
        }

        if (action === 'reset') {
            const updated = await query<PoolRow>(
                `UPDATE ip_pools
                 SET warmup_day = 0, warmup_started_at = NOW(), updated_at = NOW()
                 WHERE id = $1
                 RETURNING *`,
                [poolId]
            );
            if (updated.length === 0) {
                return NextResponse.json({ error: 'Pool not found' }, { status: 404 });
            }
            await query(
                `UPDATE ip_pool_addresses
                 SET warmup_day = 0, warmup_started_at = NOW(), daily_sent = 0, updated_at = NOW()
                 WHERE pool_id = $1`,
                [poolId]
            );
            await logWarmupAudit(request, poolId, 'reset');
            return NextResponse.json({ success: true, pool: updated[0] });
        }

        return NextResponse.json({ error: 'Unknown action. Use: start, pause, reset' }, { status: 400 });
    } catch (error) {
        console.error('Warmup POST error:', error);
        return NextResponse.json({ error: 'Failed to update warmup' }, { status: 500 });
    }
}
