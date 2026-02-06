/**
 * System Health API
 * 
 * Returns queue metrics, worker status, MTA node health, and system alerts.
 * Used by the /system page.
 * 
 * In production this would query Redis for queue depths and a service
 * registry for worker/MTA health. For now returns demo data with the
 * proper API contract established.
 */

import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

// TODO: Replace with real Redis/service-registry queries
const DEMO_QUEUES = [
    { name: 'email:send', description: 'Outbound email queue', depth: 1247, processing: 50, throughput: 850, avgLatency: 45, status: 'healthy' },
    { name: 'email:priority', description: 'Priority/transactional emails', depth: 23, processing: 10, throughput: 120, avgLatency: 12, status: 'healthy' },
    { name: 'webhook:delivery', description: 'Webhook event delivery', depth: 892, processing: 25, throughput: 340, avgLatency: 180, status: 'warning' },
    { name: 'analytics:events', description: 'Analytics event processing', depth: 45023, processing: 100, throughput: 2500, avgLatency: 320, status: 'healthy' },
    { name: 'bounce:process', description: 'Bounce/complaint handling', depth: 156, processing: 15, throughput: 45, avgLatency: 85, status: 'healthy' },
    { name: 'warmup:schedule', description: 'IP warmup scheduling', depth: 12, processing: 2, throughput: 8, avgLatency: 250, status: 'healthy' },
];

const DEMO_WORKERS = [
    { id: 'w1', name: 'email-sender-1', type: 'email_sender', status: 'running', host: 'worker-01.us-east-1', cpu: 45, memory: 62, jobsProcessed: 124532, lastHeartbeat: new Date(Date.now() - 5000).toISOString(), uptime: 864000 },
    { id: 'w2', name: 'email-sender-2', type: 'email_sender', status: 'running', host: 'worker-02.us-east-1', cpu: 52, memory: 58, jobsProcessed: 118945, lastHeartbeat: new Date(Date.now() - 3000).toISOString(), uptime: 864000 },
    { id: 'w3', name: 'email-sender-3', type: 'email_sender', status: 'running', host: 'worker-03.eu-west-1', cpu: 38, memory: 55, jobsProcessed: 98234, lastHeartbeat: new Date(Date.now() - 8000).toISOString(), uptime: 432000 },
    { id: 'w4', name: 'webhook-processor-1', type: 'webhook_processor', status: 'running', host: 'worker-04.us-east-1', cpu: 28, memory: 42, jobsProcessed: 45678, lastHeartbeat: new Date(Date.now() - 2000).toISOString(), uptime: 864000 },
    { id: 'w5', name: 'analytics-worker-1', type: 'analytics_worker', status: 'running', host: 'worker-05.us-east-1', cpu: 72, memory: 78, jobsProcessed: 892341, lastHeartbeat: new Date(Date.now() - 4000).toISOString(), uptime: 604800 },
    { id: 'w6', name: 'bounce-handler-1', type: 'bounce_handler', status: 'idle', host: 'worker-06.us-east-1', cpu: 5, memory: 35, jobsProcessed: 12456, lastHeartbeat: new Date(Date.now() - 1000).toISOString(), uptime: 864000 },
    { id: 'w7', name: 'warmup-scheduler-1', type: 'warmup_scheduler', status: 'running', host: 'worker-07.us-east-1', cpu: 12, memory: 28, jobsProcessed: 3456, lastHeartbeat: new Date(Date.now() - 6000).toISOString(), uptime: 864000 },
    { id: 'w8', name: 'email-sender-4', type: 'email_sender', status: 'error', host: 'worker-08.ap-south-1', cpu: 0, memory: 0, jobsProcessed: 45678, lastHeartbeat: new Date(Date.now() - 300000).toISOString(), uptime: 0 },
];

const DEMO_MTA_NODES = [
    { id: 'mta1', hostname: 'mta-01.us-east-1', ipAddress: '198.51.100.1', region: 'us-east-1', status: 'healthy', emailsSentToday: 245000, bounceRate: 0.8, avgLatency: 42, blacklisted: false, lastCheck: new Date(Date.now() - 60000).toISOString() },
    { id: 'mta2', hostname: 'mta-02.us-east-1', ipAddress: '198.51.100.2', region: 'us-east-1', status: 'healthy', emailsSentToday: 238000, bounceRate: 0.9, avgLatency: 45, blacklisted: false, lastCheck: new Date(Date.now() - 60000).toISOString() },
    { id: 'mta3', hostname: 'mta-03.eu-west-1', ipAddress: '203.0.113.1', region: 'eu-west-1', status: 'healthy', emailsSentToday: 156000, bounceRate: 0.7, avgLatency: 38, blacklisted: false, lastCheck: new Date(Date.now() - 60000).toISOString() },
    { id: 'mta4', hostname: 'mta-04.eu-west-1', ipAddress: '203.0.113.2', region: 'eu-west-1', status: 'degraded', emailsSentToday: 89000, bounceRate: 2.1, avgLatency: 125, blacklisted: false, lastCheck: new Date(Date.now() - 60000).toISOString() },
    { id: 'mta5', hostname: 'mta-05.ap-south-1', ipAddress: '192.0.2.1', region: 'ap-south-1', status: 'healthy', emailsSentToday: 78000, bounceRate: 0.6, avgLatency: 52, blacklisted: false, lastCheck: new Date(Date.now() - 60000).toISOString() },
    { id: 'mta6', hostname: 'mta-06.ap-south-1', ipAddress: '192.0.2.2', region: 'ap-south-1', status: 'maintenance', emailsSentToday: 0, bounceRate: 0, avgLatency: 0, blacklisted: false, lastCheck: new Date(Date.now() - 60000).toISOString() },
];

const DEMO_ALERTS = [
    { id: 'a1', severity: 'critical', component: 'worker', message: 'Worker email-sender-4 has not sent heartbeat in 5 minutes', timestamp: new Date(Date.now() - 300000).toISOString(), acknowledged: false },
    { id: 'a2', severity: 'warning', component: 'queue', message: 'Webhook delivery queue depth exceeds threshold (892 > 500)', timestamp: new Date(Date.now() - 600000).toISOString(), acknowledged: false },
    { id: 'a3', severity: 'warning', component: 'mta', message: 'MTA mta-04.eu-west-1 showing elevated latency (125ms)', timestamp: new Date(Date.now() - 900000).toISOString(), acknowledged: true },
    { id: 'a4', severity: 'info', component: 'mta', message: 'MTA mta-06.ap-south-1 entered maintenance mode', timestamp: new Date(Date.now() - 3600000).toISOString(), acknowledged: true },
];

export async function GET() {
    try {
        // TODO: Query Redis for real queue depths
        // TODO: Query service registry for worker health
        // TODO: Query MTA health check endpoints

        return NextResponse.json({
            queues: DEMO_QUEUES,
            workers: DEMO_WORKERS,
            mtaNodes: DEMO_MTA_NODES,
            alerts: DEMO_ALERTS,
        });
    } catch (error) {
        console.error('System health API error:', error);
        return NextResponse.json(
            { error: 'Failed to fetch system health' },
            { status: 500 }
        );
    }
}
