/**
 * System Health API
 *
 * FIX-500-140: Real service health queries — no demo data.
 * Queries queue_jobs for queue depths, ip_pool_addresses for MTA nodes,
 * system_alerts for alerts. Worker health is derived from queue_jobs heartbeats.
 */

import { NextResponse } from 'next/server';
import { query } from '@/lib/db';

export const dynamic = 'force-dynamic';

interface QueueRow {
    queue_name: string;
    depth: string;
    processing: string;
}

interface WorkerRow {
    id: string;
    worker_id: string;
    queue_name: string;
    status: string;
    attempts: string;
    last_heartbeat: string | null;
    created_at: string;
}

interface MtaRow {
    id: string;
    ip_address: string;
    pool_id: string;
    status: string;
    warmup_day: number;
    daily_limit: number;
    daily_sent: number;
    warmup_started_at: string | null;
    is_fully_warmed: boolean;
}

interface AlertRow {
    id: string;
    severity: string;
    component: string;
    message: string;
    created_at: string;
    acknowledged: boolean;
}

export async function GET() {
    try {
        const [queueRows, workerRows, mtaRows, alertRows] = await Promise.all([
            // Queue depths from queue_jobs table
            query<QueueRow>(
                `SELECT queue_name,
                        COUNT(*) FILTER (WHERE status = 'pending') AS depth,
                        COUNT(*) FILTER (WHERE status = 'processing') AS processing
                 FROM queue_jobs
                 GROUP BY queue_name
                 ORDER BY queue_name`
            ),
            // Worker status — recent distinct workers from queue_jobs
            query<WorkerRow>(
                `SELECT DISTINCT ON (worker_id)
                        id, worker_id, queue_name, status, attempts,
                        updated_at AS last_heartbeat, created_at
                 FROM queue_jobs
                 WHERE worker_id IS NOT NULL
                 ORDER BY worker_id, updated_at DESC
                 LIMIT 50`
            ),
            // MTA nodes from ip_pool_addresses
            query<MtaRow>(
                `SELECT id, ip_address, pool_id, status, warmup_day,
                        daily_limit, daily_sent, warmup_started_at, is_fully_warmed
                 FROM ip_pool_addresses
                 ORDER BY pool_id, ip_address
                 LIMIT 50`
            ),
            // System alerts
            query<AlertRow>(
                `SELECT id, severity, component, message, created_at,
                        COALESCE(acknowledged, false) AS acknowledged
                 FROM system_alerts
                 ORDER BY created_at DESC
                 LIMIT 50`
            ),
        ]);

        const queues = queueRows.map((q) => ({
            name: q.queue_name,
            depth: parseInt(q.depth, 10),
            processing: parseInt(q.processing, 10),
            status: parseInt(q.depth, 10) > 1000 ? 'warning' : 'healthy',
        }));

        const workers = workerRows.map((w) => ({
            id: w.id,
            name: w.worker_id,
            type: w.queue_name,
            status: w.status === 'processing' ? 'running' : 'idle',
            lastHeartbeat: w.last_heartbeat,
        }));

        const mtaNodes = mtaRows.map((m) => ({
            id: m.id,
            ipAddress: m.ip_address,
            poolId: m.pool_id,
            status: m.status,
            warmupDay: m.warmup_day,
            dailyLimit: m.daily_limit,
            dailySent: m.daily_sent,
            isFullyWarmed: m.is_fully_warmed,
        }));

        const alerts = alertRows.map((a) => ({
            id: a.id,
            severity: a.severity,
            component: a.component,
            message: a.message,
            timestamp: a.created_at,
            acknowledged: a.acknowledged,
        }));

        return NextResponse.json({ queues, workers, mtaNodes, alerts });
    } catch (error) {
        console.error('System health API error:', error);
        return NextResponse.json({ error: 'Failed to fetch system health' }, { status: 500 });
    }
}
