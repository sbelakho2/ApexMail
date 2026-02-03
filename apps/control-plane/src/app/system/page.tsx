'use client';

import { useState, useEffect, useCallback } from 'react';
import { formatNumber, cn, timeAgo } from '../../lib/utils';

/**
 * System Health Dashboard - Infrastructure monitoring
 * 
 * The owner can:
 * - Monitor Redis queue depths
 * - View worker/processor status
 * - Check MTA node health
 * - See real-time system metrics
 * - Respond to infrastructure alerts
 */

interface QueueMetric {
    name: string;
    description: string;
    depth: number;
    processing: number;
    throughput: number;
    avgLatency: number;
    status: 'healthy' | 'warning' | 'critical';
}

interface WorkerStatus {
    id: string;
    name: string;
    type: 'email_sender' | 'webhook_processor' | 'analytics_worker' | 'bounce_handler' | 'warmup_scheduler';
    status: 'running' | 'idle' | 'stopped' | 'error';
    host: string;
    cpu: number;
    memory: number;
    jobsProcessed: number;
    lastHeartbeat: string;
    uptime: number;
}

interface MTANode {
    id: string;
    hostname: string;
    ipAddress: string;
    region: string;
    status: 'healthy' | 'degraded' | 'down' | 'maintenance';
    emailsSentToday: number;
    bounceRate: number;
    avgLatency: number;
    blacklisted: boolean;
    lastCheck: string;
}

interface SystemAlert {
    id: string;
    severity: 'info' | 'warning' | 'critical';
    component: string;
    message: string;
    timestamp: string;
    acknowledged: boolean;
}

const DEMO_QUEUES: QueueMetric[] = [
    { name: 'email:send', description: 'Outbound email queue', depth: 1247, processing: 50, throughput: 850, avgLatency: 45, status: 'healthy' },
    { name: 'email:priority', description: 'Priority/transactional emails', depth: 23, processing: 10, throughput: 120, avgLatency: 12, status: 'healthy' },
    { name: 'webhook:delivery', description: 'Webhook event delivery', depth: 892, processing: 25, throughput: 340, avgLatency: 180, status: 'warning' },
    { name: 'analytics:events', description: 'Analytics event processing', depth: 45023, processing: 100, throughput: 2500, avgLatency: 320, status: 'healthy' },
    { name: 'bounce:process', description: 'Bounce/complaint handling', depth: 156, processing: 15, throughput: 45, avgLatency: 85, status: 'healthy' },
    { name: 'warmup:schedule', description: 'IP warmup scheduling', depth: 12, processing: 2, throughput: 8, avgLatency: 250, status: 'healthy' },
];

const DEMO_WORKERS: WorkerStatus[] = [
    { id: 'w1', name: 'email-sender-1', type: 'email_sender', status: 'running', host: 'worker-01.us-east-1', cpu: 45, memory: 62, jobsProcessed: 124532, lastHeartbeat: new Date(Date.now() - 5000).toISOString(), uptime: 864000 },
    { id: 'w2', name: 'email-sender-2', type: 'email_sender', status: 'running', host: 'worker-02.us-east-1', cpu: 52, memory: 58, jobsProcessed: 118945, lastHeartbeat: new Date(Date.now() - 3000).toISOString(), uptime: 864000 },
    { id: 'w3', name: 'email-sender-3', type: 'email_sender', status: 'running', host: 'worker-03.eu-west-1', cpu: 38, memory: 55, jobsProcessed: 98234, lastHeartbeat: new Date(Date.now() - 8000).toISOString(), uptime: 432000 },
    { id: 'w4', name: 'webhook-processor-1', type: 'webhook_processor', status: 'running', host: 'worker-04.us-east-1', cpu: 28, memory: 42, jobsProcessed: 45678, lastHeartbeat: new Date(Date.now() - 2000).toISOString(), uptime: 864000 },
    { id: 'w5', name: 'analytics-worker-1', type: 'analytics_worker', status: 'running', host: 'worker-05.us-east-1', cpu: 72, memory: 78, jobsProcessed: 892341, lastHeartbeat: new Date(Date.now() - 4000).toISOString(), uptime: 604800 },
    { id: 'w6', name: 'bounce-handler-1', type: 'bounce_handler', status: 'idle', host: 'worker-06.us-east-1', cpu: 5, memory: 35, jobsProcessed: 12456, lastHeartbeat: new Date(Date.now() - 1000).toISOString(), uptime: 864000 },
    { id: 'w7', name: 'warmup-scheduler-1', type: 'warmup_scheduler', status: 'running', host: 'worker-07.us-east-1', cpu: 12, memory: 28, jobsProcessed: 3456, lastHeartbeat: new Date(Date.now() - 6000).toISOString(), uptime: 864000 },
    { id: 'w8', name: 'email-sender-4', type: 'email_sender', status: 'error', host: 'worker-08.ap-south-1', cpu: 0, memory: 0, jobsProcessed: 45678, lastHeartbeat: new Date(Date.now() - 300000).toISOString(), uptime: 0 },
];

const DEMO_MTA_NODES: MTANode[] = [
    { id: 'mta1', hostname: 'mta-01.us-east-1', ipAddress: '198.51.100.1', region: 'us-east-1', status: 'healthy', emailsSentToday: 245000, bounceRate: 0.8, avgLatency: 42, blacklisted: false, lastCheck: new Date(Date.now() - 60000).toISOString() },
    { id: 'mta2', hostname: 'mta-02.us-east-1', ipAddress: '198.51.100.2', region: 'us-east-1', status: 'healthy', emailsSentToday: 238000, bounceRate: 0.9, avgLatency: 45, blacklisted: false, lastCheck: new Date(Date.now() - 60000).toISOString() },
    { id: 'mta3', hostname: 'mta-03.eu-west-1', ipAddress: '203.0.113.1', region: 'eu-west-1', status: 'healthy', emailsSentToday: 156000, bounceRate: 0.7, avgLatency: 38, blacklisted: false, lastCheck: new Date(Date.now() - 60000).toISOString() },
    { id: 'mta4', hostname: 'mta-04.eu-west-1', ipAddress: '203.0.113.2', region: 'eu-west-1', status: 'degraded', emailsSentToday: 89000, bounceRate: 2.1, avgLatency: 125, blacklisted: false, lastCheck: new Date(Date.now() - 60000).toISOString() },
    { id: 'mta5', hostname: 'mta-05.ap-south-1', ipAddress: '192.0.2.1', region: 'ap-south-1', status: 'healthy', emailsSentToday: 78000, bounceRate: 0.6, avgLatency: 52, blacklisted: false, lastCheck: new Date(Date.now() - 60000).toISOString() },
    { id: 'mta6', hostname: 'mta-06.ap-south-1', ipAddress: '192.0.2.2', region: 'ap-south-1', status: 'maintenance', emailsSentToday: 0, bounceRate: 0, avgLatency: 0, blacklisted: false, lastCheck: new Date(Date.now() - 60000).toISOString() },
];

const DEMO_ALERTS: SystemAlert[] = [
    { id: 'a1', severity: 'critical', component: 'worker', message: 'Worker email-sender-4 has not sent heartbeat in 5 minutes', timestamp: new Date(Date.now() - 300000).toISOString(), acknowledged: false },
    { id: 'a2', severity: 'warning', component: 'queue', message: 'Webhook delivery queue depth exceeds threshold (892 > 500)', timestamp: new Date(Date.now() - 600000).toISOString(), acknowledged: false },
    { id: 'a3', severity: 'warning', component: 'mta', message: 'MTA mta-04.eu-west-1 showing elevated latency (125ms)', timestamp: new Date(Date.now() - 900000).toISOString(), acknowledged: true },
    { id: 'a4', severity: 'info', component: 'mta', message: 'MTA mta-06.ap-south-1 entered maintenance mode', timestamp: new Date(Date.now() - 3600000).toISOString(), acknowledged: true },
];

const WORKER_TYPE_LABELS: Record<string, string> = {
    email_sender: 'Email Sender',
    webhook_processor: 'Webhook Processor',
    analytics_worker: 'Analytics Worker',
    bounce_handler: 'Bounce Handler',
    warmup_scheduler: 'Warmup Scheduler',
};

const STATUS_COLORS: Record<string, { bg: string; text: string; dot: string }> = {
    healthy: { bg: 'bg-emerald-100', text: 'text-emerald-700', dot: 'bg-emerald-500' },
    running: { bg: 'bg-emerald-100', text: 'text-emerald-700', dot: 'bg-emerald-500' },
    warning: { bg: 'bg-amber-100', text: 'text-amber-700', dot: 'bg-amber-500' },
    degraded: { bg: 'bg-amber-100', text: 'text-amber-700', dot: 'bg-amber-500' },
    idle: { bg: 'bg-blue-100', text: 'text-blue-700', dot: 'bg-blue-500' },
    critical: { bg: 'bg-red-100', text: 'text-red-700', dot: 'bg-red-500' },
    error: { bg: 'bg-red-100', text: 'text-red-700', dot: 'bg-red-500' },
    stopped: { bg: 'bg-surface-100', text: 'text-surface-600', dot: 'bg-surface-400' },
    down: { bg: 'bg-red-100', text: 'text-red-700', dot: 'bg-red-500' },
    maintenance: { bg: 'bg-violet-100', text: 'text-violet-700', dot: 'bg-violet-500' },
};

function formatUptime(seconds: number): string {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    if (days > 0) return `${days}d ${hours}h`;
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${minutes}m`;
}

export default function SystemHealthPage() {
    const [queues, setQueues] = useState<QueueMetric[]>([]);
    const [workers, setWorkers] = useState<WorkerStatus[]>([]);
    const [mtaNodes, setMtaNodes] = useState<MTANode[]>([]);
    const [alerts, setAlerts] = useState<SystemAlert[]>([]);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState<'overview' | 'queues' | 'workers' | 'mta'>('overview');
    const [autoRefresh, setAutoRefresh] = useState(true);
    const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

    const loadData = useCallback(async () => {
        try {
            // In production: fetch from Ops API
            setQueues(DEMO_QUEUES);
            setWorkers(DEMO_WORKERS);
            setMtaNodes(DEMO_MTA_NODES);
            setAlerts(DEMO_ALERTS);
            setLastRefresh(new Date());
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        loadData();
    }, [loadData]);

    useEffect(() => {
        if (!autoRefresh) return;
        const interval = setInterval(loadData, 30000);
        return () => clearInterval(interval);
    }, [autoRefresh, loadData]);

    function acknowledgeAlert(alertId: string) {
        setAlerts(prev => prev.map(a => 
            a.id === alertId ? { ...a, acknowledged: true } : a
        ));
    }

    function restartWorker(workerId: string) {
        // In production: POST to Ops API
        alert(`Restart command sent to worker ${workerId}`);
    }

    const activeAlerts = alerts.filter(a => !a.acknowledged);
    const criticalAlerts = activeAlerts.filter(a => a.severity === 'critical');
    const healthyWorkers = workers.filter(w => w.status === 'running' || w.status === 'idle').length;
    const healthyMTA = mtaNodes.filter(n => n.status === 'healthy').length;
    const totalQueueDepth = queues.reduce((acc, q) => acc + q.depth, 0);

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    return (
        <div className="max-w-7xl mx-auto">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-surface-900">System Health</h1>
                    <p className="text-surface-600 mt-1">
                        Infrastructure monitoring • Last updated {timeAgo(lastRefresh.toISOString())}
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    <label className="flex items-center gap-2 text-sm text-surface-600">
                        <input
                            type="checkbox"
                            checked={autoRefresh}
                            onChange={(e) => setAutoRefresh(e.target.checked)}
                            className="rounded border-surface-300 text-blue-600 focus:ring-blue-500"
                        />
                        Auto-refresh (30s)
                    </label>
                    <button
                        onClick={loadData}
                        className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700 font-medium transition-colors"
                    >
                        🔄 Refresh Now
                    </button>
                </div>
            </div>

            {/* Critical Alerts Banner */}
            {criticalAlerts.length > 0 && (
                <div className="bg-red-50 border border-red-200 rounded-xl p-4 mb-6">
                    <div className="flex items-center gap-2 text-red-700 font-medium mb-2">
                        🚨 {criticalAlerts.length} Critical Alert{criticalAlerts.length > 1 ? 's' : ''}
                    </div>
                    <div className="space-y-2">
                        {criticalAlerts.map(alert => (
                            <div key={alert.id} className="flex items-center justify-between text-sm">
                                <span className="text-red-700">{alert.message}</span>
                                <button
                                    onClick={() => acknowledgeAlert(alert.id)}
                                    className="px-2.5 py-1 bg-red-100 text-red-700 rounded text-xs font-medium hover:bg-red-200"
                                >
                                    Acknowledge
                                </button>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Overview Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">System Status</div>
                    <div className={cn(
                        'text-2xl font-bold mt-1',
                        criticalAlerts.length > 0 ? 'text-red-600' : 
                        activeAlerts.length > 0 ? 'text-amber-600' : 'text-emerald-600'
                    )}>
                        {criticalAlerts.length > 0 ? 'Critical' : 
                         activeAlerts.length > 0 ? 'Degraded' : 'Healthy'}
                    </div>
                    <div className="text-xs text-surface-400 mt-1">{activeAlerts.length} active alerts</div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">Workers</div>
                    <div className="text-2xl font-bold text-surface-900 mt-1">
                        {healthyWorkers}/{workers.length}
                    </div>
                    <div className="text-xs text-surface-400 mt-1">Running</div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">MTA Nodes</div>
                    <div className="text-2xl font-bold text-surface-900 mt-1">
                        {healthyMTA}/{mtaNodes.length}
                    </div>
                    <div className="text-xs text-surface-400 mt-1">Healthy</div>
                </div>
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-4 shadow-sm">
                    <div className="text-sm text-surface-500 font-medium">Queue Depth</div>
                    <div className="text-2xl font-bold text-surface-900 mt-1">
                        {formatNumber(totalQueueDepth)}
                    </div>
                    <div className="text-xs text-surface-400 mt-1">Total jobs pending</div>
                </div>
            </div>

            {/* Tabs */}
            <div className="border-b border-surface-200 mb-6 overflow-x-auto">
                <nav className="flex gap-6 min-w-max">
                    {[
                        { key: 'overview', label: 'Overview', icon: '📊' },
                        { key: 'queues', label: 'Queues', icon: '📥' },
                        { key: 'workers', label: 'Workers', icon: '⚙️' },
                        { key: 'mta', label: 'MTA Nodes', icon: '📤' },
                    ].map(tab => (
                        <button
                            key={tab.key}
                            onClick={() => setActiveTab(tab.key as typeof activeTab)}
                            className={cn(
                                'flex items-center gap-2 pb-3 text-sm font-medium transition-colors border-b-2 -mb-px',
                                activeTab === tab.key
                                    ? 'border-blue-600 text-blue-600'
                                    : 'border-transparent text-surface-500 hover:text-surface-700'
                            )}
                        >
                            <span>{tab.icon}</span>
                            {tab.label}
                        </button>
                    ))}
                </nav>
            </div>

            {/* Overview Tab */}
            {activeTab === 'overview' && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Alerts */}
                    <div className="bg-surface-0 rounded-xl border border-surface-200 overflow-hidden shadow-sm">
                        <div className="p-4 border-b border-surface-200 bg-surface-50">
                            <h3 className="font-semibold text-surface-900">Recent Alerts</h3>
                        </div>
                        <div className="divide-y divide-surface-100 max-h-[300px] overflow-y-auto">
                            {alerts.length === 0 ? (
                                <div className="p-8 text-center text-surface-500">No alerts</div>
                            ) : (
                                alerts.map(alert => (
                                    <div key={alert.id} className={cn(
                                        'p-4 flex items-start gap-3',
                                        alert.acknowledged && 'opacity-50'
                                    )}>
                                        <span className={cn(
                                            'w-2 h-2 rounded-full mt-2 flex-shrink-0',
                                            alert.severity === 'critical' ? 'bg-red-500' :
                                            alert.severity === 'warning' ? 'bg-amber-500' : 'bg-blue-500'
                                        )} />
                                        <div className="flex-1 min-w-0">
                                            <p className="text-sm text-surface-700">{alert.message}</p>
                                            <p className="text-xs text-surface-400 mt-1">
                                                {alert.component} • {timeAgo(alert.timestamp)}
                                            </p>
                                        </div>
                                        {!alert.acknowledged && (
                                            <button
                                                onClick={() => acknowledgeAlert(alert.id)}
                                                className="px-2.5 py-1 text-xs font-medium text-surface-600 hover:text-surface-900"
                                            >
                                                Ack
                                            </button>
                                        )}
                                    </div>
                                ))
                            )}
                        </div>
                    </div>

                    {/* Queue Summary */}
                    <div className="bg-surface-0 rounded-xl border border-surface-200 overflow-hidden shadow-sm">
                        <div className="p-4 border-b border-surface-200 bg-surface-50">
                            <h3 className="font-semibold text-surface-900">Queue Health</h3>
                        </div>
                        <div className="divide-y divide-surface-100">
                            {queues.map(queue => {
                                const statusColors = STATUS_COLORS[queue.status];
                                return (
                                    <div key={queue.name} className="p-4 flex items-center justify-between">
                                        <div>
                                            <div className="font-mono text-sm text-surface-900">{queue.name}</div>
                                            <div className="text-xs text-surface-400">{queue.description}</div>
                                        </div>
                                        <div className="flex items-center gap-4">
                                            <div className="text-right">
                                                <div className="text-sm font-medium text-surface-900">{formatNumber(queue.depth)}</div>
                                                <div className="text-xs text-surface-400">depth</div>
                                            </div>
                                            <span className={cn(
                                                'w-3 h-3 rounded-full',
                                                statusColors.dot
                                            )} />
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                </div>
            )}

            {/* Queues Tab */}
            {activeTab === 'queues' && (
                <div className="bg-surface-0 rounded-xl border border-surface-200 overflow-hidden shadow-sm">
                    <div className="overflow-x-auto">
                        <table className="w-full min-w-[800px]">
                            <thead className="bg-surface-50 border-b border-surface-200">
                                <tr>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Queue</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Status</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-surface-600 uppercase tracking-wider">Depth</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-surface-600 uppercase tracking-wider">Processing</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-surface-600 uppercase tracking-wider">Throughput</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-surface-600 uppercase tracking-wider">Avg Latency</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-surface-100">
                                {queues.map(queue => {
                                    const statusColors = STATUS_COLORS[queue.status];
                                    return (
                                        <tr key={queue.name} className="hover:bg-surface-50/50">
                                            <td className="px-4 py-4">
                                                <div className="font-mono text-sm text-surface-900">{queue.name}</div>
                                                <div className="text-xs text-surface-400">{queue.description}</div>
                                            </td>
                                            <td className="px-4 py-4">
                                                <span className={cn(
                                                    'px-2.5 py-0.5 rounded-full text-xs font-medium',
                                                    statusColors.bg,
                                                    statusColors.text
                                                )}>
                                                    {queue.status}
                                                </span>
                                            </td>
                                            <td className="px-4 py-4 text-right font-medium text-surface-900">
                                                {formatNumber(queue.depth)}
                                            </td>
                                            <td className="px-4 py-4 text-right text-surface-600">
                                                {queue.processing}
                                            </td>
                                            <td className="px-4 py-4 text-right text-surface-600">
                                                {formatNumber(queue.throughput)}/min
                                            </td>
                                            <td className="px-4 py-4 text-right text-surface-600">
                                                {queue.avgLatency}ms
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* Workers Tab */}
            {activeTab === 'workers' && (
                <div className="bg-surface-0 rounded-xl border border-surface-200 overflow-hidden shadow-sm">
                    <div className="overflow-x-auto">
                        <table className="w-full min-w-[900px]">
                            <thead className="bg-surface-50 border-b border-surface-200">
                                <tr>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Worker</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Type</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Status</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Host</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-surface-600 uppercase tracking-wider">CPU</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-surface-600 uppercase tracking-wider">Memory</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-surface-600 uppercase tracking-wider">Jobs</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-surface-600 uppercase tracking-wider">Uptime</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-surface-600 uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-surface-100">
                                {workers.map(worker => {
                                    const statusColors = STATUS_COLORS[worker.status];
                                    return (
                                        <tr key={worker.id} className="hover:bg-surface-50/50">
                                            <td className="px-4 py-4">
                                                <div className="font-mono text-sm text-surface-900">{worker.name}</div>
                                            </td>
                                            <td className="px-4 py-4 text-sm text-surface-600">
                                                {WORKER_TYPE_LABELS[worker.type]}
                                            </td>
                                            <td className="px-4 py-4">
                                                <span className={cn(
                                                    'px-2.5 py-0.5 rounded-full text-xs font-medium',
                                                    statusColors.bg,
                                                    statusColors.text
                                                )}>
                                                    {worker.status}
                                                </span>
                                            </td>
                                            <td className="px-4 py-4 text-sm text-surface-600 font-mono">
                                                {worker.host}
                                            </td>
                                            <td className="px-4 py-4 text-right">
                                                <div className="flex items-center justify-end gap-2">
                                                    <div className="w-16 h-2 bg-surface-100 rounded-full overflow-hidden">
                                                        <div 
                                                            className={cn(
                                                                'h-full rounded-full',
                                                                worker.cpu > 80 ? 'bg-red-500' :
                                                                worker.cpu > 60 ? 'bg-amber-500' : 'bg-emerald-500'
                                                            )}
                                                            style={{ width: `${worker.cpu}%` }}
                                                        />
                                                    </div>
                                                    <span className="text-sm text-surface-600 w-10 text-right">{worker.cpu}%</span>
                                                </div>
                                            </td>
                                            <td className="px-4 py-4 text-right">
                                                <div className="flex items-center justify-end gap-2">
                                                    <div className="w-16 h-2 bg-surface-100 rounded-full overflow-hidden">
                                                        <div 
                                                            className={cn(
                                                                'h-full rounded-full',
                                                                worker.memory > 80 ? 'bg-red-500' :
                                                                worker.memory > 60 ? 'bg-amber-500' : 'bg-emerald-500'
                                                            )}
                                                            style={{ width: `${worker.memory}%` }}
                                                        />
                                                    </div>
                                                    <span className="text-sm text-surface-600 w-10 text-right">{worker.memory}%</span>
                                                </div>
                                            </td>
                                            <td className="px-4 py-4 text-right text-sm text-surface-600">
                                                {formatNumber(worker.jobsProcessed)}
                                            </td>
                                            <td className="px-4 py-4 text-right text-sm text-surface-600">
                                                {worker.uptime > 0 ? formatUptime(worker.uptime) : '—'}
                                            </td>
                                            <td className="px-4 py-4 text-right">
                                                <button
                                                    onClick={() => restartWorker(worker.id)}
                                                    className="px-2.5 py-1 text-xs font-medium text-surface-600 bg-surface-100 hover:bg-surface-200 rounded transition-colors"
                                                >
                                                    Restart
                                                </button>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* MTA Tab */}
            {activeTab === 'mta' && (
                <div className="bg-surface-0 rounded-xl border border-surface-200 overflow-hidden shadow-sm">
                    <div className="overflow-x-auto">
                        <table className="w-full min-w-[900px]">
                            <thead className="bg-surface-50 border-b border-surface-200">
                                <tr>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Node</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">IP</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Region</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-surface-600 uppercase tracking-wider">Status</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-surface-600 uppercase tracking-wider">Sent Today</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-surface-600 uppercase tracking-wider">Bounce Rate</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-surface-600 uppercase tracking-wider">Latency</th>
                                    <th className="px-4 py-3 text-center text-xs font-semibold text-surface-600 uppercase tracking-wider">Blacklist</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-surface-100">
                                {mtaNodes.map(node => {
                                    const statusColors = STATUS_COLORS[node.status];
                                    return (
                                        <tr key={node.id} className="hover:bg-surface-50/50">
                                            <td className="px-4 py-4">
                                                <div className="font-mono text-sm text-surface-900">{node.hostname}</div>
                                            </td>
                                            <td className="px-4 py-4 font-mono text-sm text-surface-600">
                                                {node.ipAddress}
                                            </td>
                                            <td className="px-4 py-4 text-sm text-surface-600">
                                                {node.region}
                                            </td>
                                            <td className="px-4 py-4">
                                                <span className={cn(
                                                    'px-2.5 py-0.5 rounded-full text-xs font-medium',
                                                    statusColors.bg,
                                                    statusColors.text
                                                )}>
                                                    {node.status}
                                                </span>
                                            </td>
                                            <td className="px-4 py-4 text-right text-sm text-surface-900 font-medium">
                                                {formatNumber(node.emailsSentToday)}
                                            </td>
                                            <td className="px-4 py-4 text-right">
                                                <span className={cn(
                                                    'text-sm font-medium',
                                                    node.bounceRate > 2 ? 'text-red-600' :
                                                    node.bounceRate > 1 ? 'text-amber-600' : 'text-surface-600'
                                                )}>
                                                    {node.bounceRate.toFixed(1)}%
                                                </span>
                                            </td>
                                            <td className="px-4 py-4 text-right text-sm text-surface-600">
                                                {node.avgLatency > 0 ? `${node.avgLatency}ms` : '—'}
                                            </td>
                                            <td className="px-4 py-4 text-center">
                                                {node.blacklisted ? (
                                                    <span className="px-2.5 py-0.5 bg-red-100 text-red-700 rounded text-xs font-medium">Listed</span>
                                                ) : (
                                                    <span className="px-2.5 py-0.5 bg-emerald-100 text-emerald-700 rounded text-xs font-medium">Clean</span>
                                                )}
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    );
}
