'use client';

import { useState, useEffect, useCallback } from 'react';
import { formatNumber, cn, timeAgo } from '../../lib/utils';
import { useDialog } from '../../components/ui/confirm-dialog';

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



const WORKER_TYPE_LABELS: Record<string, string> = {
    email_sender: 'Email Sender',
    webhook_processor: 'Webhook Processor',
    analytics_worker: 'Analytics Worker',
    bounce_handler: 'Bounce Handler',
    warmup_scheduler: 'Warmup Scheduler',
};

const STATUS_COLORS: Record<string, { bg: string; text: string; dot: string }> = {
    healthy: { bg: 'bg-success/10', text: 'text-success', dot: 'bg-success' },
    running: { bg: 'bg-success/10', text: 'text-success', dot: 'bg-success' },
    warning: { bg: 'bg-warning/10', text: 'text-warning', dot: 'bg-warning' },
    degraded: { bg: 'bg-warning/10', text: 'text-warning', dot: 'bg-warning' },
    idle: { bg: 'bg-blue-500/10', text: 'text-blue-500', dot: 'bg-blue-500' },
    critical: { bg: 'bg-destructive/10', text: 'text-destructive', dot: 'bg-destructive' },
    error: { bg: 'bg-destructive/10', text: 'text-destructive', dot: 'bg-destructive' },
    stopped: { bg: 'bg-muted', text: 'text-muted-foreground', dot: 'bg-muted-foreground' },
    down: { bg: 'bg-destructive/10', text: 'text-destructive', dot: 'bg-destructive' },
    maintenance: { bg: 'bg-violet-500/10', text: 'text-violet-500', dot: 'bg-violet-500' },
};

function formatUptime(seconds: number): string {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    if (days > 0) return `${days}d ${hours}h`;
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${minutes}m`;
}

export default function SystemHealthPage() {
    const dialog = useDialog();
    const [queues, setQueues] = useState<QueueMetric[]>([]);
    const [workers, setWorkers] = useState<WorkerStatus[]>([]);
    const [mtaNodes, setMtaNodes] = useState<MTANode[]>([]);
    const [alerts, setAlerts] = useState<SystemAlert[]>([]);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState<'overview' | 'queues' | 'workers' | 'mta'>('overview');
    const [autoRefresh, setAutoRefresh] = useState(true);
    const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

    const loadData = useCallback(async () => {
        try {
            const response = await fetch('/api/system/health', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch system health: ${response.status}`);
            const data = await response.json();
            setQueues(data.queues);
            setWorkers(data.workers);
            setMtaNodes(data.mtaNodes);
            setAlerts(data.alerts);
            setLastRefresh(new Date());
        } catch (err) {
            console.error('Failed to load system health:', err);
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
        dialog.alert({ title: 'Worker Restart', message: `Restart command sent to worker ${workerId}` });
    }

    const activeAlerts = alerts.filter(a => !a.acknowledged);
    const criticalAlerts = activeAlerts.filter(a => a.severity === 'critical');
    const healthyWorkers = workers.filter(w => w.status === 'running' || w.status === 'idle').length;
    const healthyMTA = mtaNodes.filter(n => n.status === 'healthy').length;
    const totalQueueDepth = queues.reduce((acc, q) => acc + q.depth, 0);

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            </div>
        );
    }

    return (
        <div className="max-w-7xl mx-auto">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">System Health</h1>
                    <p className="text-muted-foreground mt-1">
                        Infrastructure monitoring • Last updated {lastRefresh ? timeAgo(lastRefresh.toISOString()) : '...'}
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    <label className="flex items-center gap-2 text-sm text-muted-foreground">
                        <input
                            type="checkbox"
                            checked={autoRefresh}
                            onChange={(e) => setAutoRefresh(e.target.checked)}
                            className="rounded border-input text-primary focus:ring-primary"
                        />
                        Auto-refresh (30s)
                    </label>
                    <button
                        onClick={loadData}
                        className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm hover:bg-primary/90 font-medium transition-colors"
                    >
                        Refresh Now
                    </button>
                </div>
            </div>

            {/* Critical Alerts Banner */}
            {criticalAlerts.length > 0 && (
                <div className="bg-destructive/10 border border-destructive/20 rounded-xl p-4 mb-6">
                    <div className="flex items-center gap-2 text-destructive font-medium mb-2">
                        {criticalAlerts.length} Critical Alert{criticalAlerts.length > 1 ? 's' : ''}
                    </div>
                    <div className="space-y-2">
                        {criticalAlerts.map(alert => (
                            <div key={alert.id} className="flex items-center justify-between text-sm">
                                <span className="text-destructive">{alert.message}</span>
                                <button
                                    onClick={() => acknowledgeAlert(alert.id)}
                                    className="px-2.5 py-1 bg-destructive/10 text-destructive rounded text-xs font-medium hover:bg-destructive/20"
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
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">System Status</div>
                    <div className={cn(
                        'text-2xl font-bold mt-1',
                        criticalAlerts.length > 0 ? 'text-destructive' : 
                        activeAlerts.length > 0 ? 'text-warning' : 'text-success'
                    )}>
                        {criticalAlerts.length > 0 ? 'Critical' : 
                         activeAlerts.length > 0 ? 'Degraded' : 'Healthy'}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">{activeAlerts.length} active alerts</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Workers</div>
                    <div className="text-2xl font-bold text-foreground mt-1">
                        {healthyWorkers}/{workers.length}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">Running</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">MTA Nodes</div>
                    <div className="text-2xl font-bold text-foreground mt-1">
                        {healthyMTA}/{mtaNodes.length}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">Healthy</div>
                </div>
                <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
                    <div className="text-sm text-muted-foreground font-medium">Queue Depth</div>
                    <div className="text-2xl font-bold text-foreground mt-1">
                        {formatNumber(totalQueueDepth)}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">Total jobs pending</div>
                </div>
            </div>

            {/* Tabs */}
            <div className="border-b border-border mb-6 overflow-x-auto">
                <nav className="flex gap-6 min-w-max">
                    {[
                        { key: 'overview', label: 'Overview', icon: 'OV' },
                        { key: 'queues', label: 'Queues', icon: 'Q' },
                        { key: 'workers', label: 'Workers', icon: 'WK' },
                        { key: 'mta', label: 'MTA Nodes', icon: 'MTA' },
                    ].map(tab => (
                        <button
                            key={tab.key}
                            onClick={() => setActiveTab(tab.key as typeof activeTab)}
                            className={cn(
                                'flex items-center gap-2 pb-3 text-sm font-medium transition-colors border-b-2 -mb-px',
                                activeTab === tab.key
                                    ? 'border-primary text-primary'
                                    : 'border-transparent text-muted-foreground hover:text-foreground'
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
                    <div className="bg-card rounded-xl border border-border overflow-hidden shadow-sm">
                        <div className="p-4 border-b border-border bg-muted/50">
                            <h3 className="font-semibold text-foreground">Recent Alerts</h3>
                        </div>
                        <div className="divide-y divide-border max-h-[300px] overflow-y-auto">
                            {alerts.length === 0 ? (
                                <div className="p-8 text-center text-muted-foreground">No alerts</div>
                            ) : (
                                alerts.map(alert => (
                                    <div key={alert.id} className={cn(
                                        'p-4 flex items-start gap-3',
                                        alert.acknowledged && 'opacity-50'
                                    )}>
                                        <span className={cn(
                                            'w-2 h-2 rounded-full mt-2 flex-shrink-0',
                                            alert.severity === 'critical' ? 'bg-destructive' :
                                            alert.severity === 'warning' ? 'bg-warning' : 'bg-blue-500'
                                        )} />
                                        <div className="flex-1 min-w-0">
                                            <p className="text-sm text-foreground">{alert.message}</p>
                                            <p className="text-xs text-muted-foreground mt-1">
                                                {alert.component} • {timeAgo(alert.timestamp)}
                                            </p>
                                        </div>
                                        {!alert.acknowledged && (
                                            <button
                                                onClick={() => acknowledgeAlert(alert.id)}
                                                className="px-2.5 py-1 text-xs font-medium text-muted-foreground hover:text-foreground"
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
                    <div className="bg-card rounded-xl border border-border overflow-hidden shadow-sm">
                        <div className="p-4 border-b border-border bg-muted/50">
                            <h3 className="font-semibold text-foreground">Queue Health</h3>
                        </div>
                        <div className="divide-y divide-border">
                            {queues.map(queue => {
                                const statusColors = STATUS_COLORS[queue.status];
                                return (
                                    <div key={queue.name} className="p-4 flex items-center justify-between">
                                        <div>
                                            <div className="font-mono text-sm text-foreground">{queue.name}</div>
                                            <div className="text-xs text-muted-foreground">{queue.description}</div>
                                        </div>
                                        <div className="flex items-center gap-4">
                                            <div className="text-right">
                                                <div className="text-sm font-medium text-foreground">{formatNumber(queue.depth)}</div>
                                                <div className="text-xs text-muted-foreground">depth</div>
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
                <div className="bg-card rounded-xl border border-border overflow-hidden shadow-sm">
                    <div className="overflow-x-auto">
                        <table className="w-full min-w-[800px]">
                            <thead className="bg-muted/50 border-b border-border">
                                <tr>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Queue</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Depth</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Processing</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Throughput</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Avg Latency</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border">
                                {queues.map(queue => {
                                    const statusColors = STATUS_COLORS[queue.status];
                                    return (
                                        <tr key={queue.name} className="hover:bg-muted/50">
                                            <td className="px-4 py-4">
                                                <div className="font-mono text-sm text-foreground">{queue.name}</div>
                                                <div className="text-xs text-muted-foreground">{queue.description}</div>
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
                                            <td className="px-4 py-4 text-right font-medium text-foreground">
                                                {formatNumber(queue.depth)}
                                            </td>
                                            <td className="px-4 py-4 text-right text-muted-foreground">
                                                {queue.processing}
                                            </td>
                                            <td className="px-4 py-4 text-right text-muted-foreground">
                                                {formatNumber(queue.throughput)}/min
                                            </td>
                                            <td className="px-4 py-4 text-right text-muted-foreground">
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
                <div className="bg-card rounded-xl border border-border overflow-hidden shadow-sm">
                    <div className="overflow-x-auto">
                        <table className="w-full min-w-[900px]">
                            <thead className="bg-muted/50 border-b border-border">
                                <tr>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Worker</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Type</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Host</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">CPU</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Memory</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Jobs</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Uptime</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border">
                                {workers.map(worker => {
                                    const statusColors = STATUS_COLORS[worker.status];
                                    return (
                                        <tr key={worker.id} className="hover:bg-muted/50">
                                            <td className="px-4 py-4">
                                                <div className="font-mono text-sm text-foreground">{worker.name}</div>
                                            </td>
                                            <td className="px-4 py-4 text-sm text-muted-foreground">
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
                                            <td className="px-4 py-4 text-sm text-muted-foreground font-mono">
                                                {worker.host}
                                            </td>
                                            <td className="px-4 py-4 text-right">
                                                <div className="flex items-center justify-end gap-2">
                                                    <div className="w-16 h-2 bg-muted rounded-full overflow-hidden">
                                                        <svg width="100%" height="100%" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true">
                                                            <rect
                                                                x="0"
                                                                y="0"
                                                                width={Math.max(0, Math.min(100, worker.cpu))}
                                                                height="8"
                                                                className={cn(
                                                                    worker.cpu > 80 ? 'fill-destructive' :
                                                                    worker.cpu > 60 ? 'fill-warning' : 'fill-success'
                                                                )}
                                                            />
                                                        </svg>
                                                    </div>
                                                    <span className="text-sm text-muted-foreground w-10 text-right">{worker.cpu}%</span>
                                                </div>
                                            </td>
                                            <td className="px-4 py-4 text-right">
                                                <div className="flex items-center justify-end gap-2">
                                                    <div className="w-16 h-2 bg-muted rounded-full overflow-hidden">
                                                        <svg width="100%" height="100%" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true">
                                                            <rect
                                                                x="0"
                                                                y="0"
                                                                width={Math.max(0, Math.min(100, worker.memory))}
                                                                height="8"
                                                                className={cn(
                                                                    worker.memory > 80 ? 'fill-destructive' :
                                                                    worker.memory > 60 ? 'fill-warning' : 'fill-success'
                                                                )}
                                                            />
                                                        </svg>
                                                    </div>
                                                    <span className="text-sm text-muted-foreground w-10 text-right">{worker.memory}%</span>
                                                </div>
                                            </td>
                                            <td className="px-4 py-4 text-right text-sm text-muted-foreground">
                                                {formatNumber(worker.jobsProcessed)}
                                            </td>
                                            <td className="px-4 py-4 text-right text-sm text-muted-foreground">
                                                {worker.uptime > 0 ? formatUptime(worker.uptime) : '—'}
                                            </td>
                                            <td className="px-4 py-4 text-right">
                                                <button
                                                    onClick={() => restartWorker(worker.id)}
                                                    className="px-2.5 py-1 text-xs font-medium text-muted-foreground bg-muted hover:bg-muted/80 rounded transition-colors"
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
                <div className="bg-card rounded-xl border border-border overflow-hidden shadow-sm">
                    <div className="overflow-x-auto">
                        <table className="w-full min-w-[900px]">
                            <thead className="bg-muted/50 border-b border-border">
                                <tr>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Node</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">IP</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Region</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Sent Today</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Bounce Rate</th>
                                    <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Latency</th>
                                    <th className="px-4 py-3 text-center text-xs font-semibold text-muted-foreground uppercase tracking-wider">Blacklist</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border">
                                {mtaNodes.map(node => {
                                    const statusColors = STATUS_COLORS[node.status];
                                    return (
                                        <tr key={node.id} className="hover:bg-muted/50">
                                            <td className="px-4 py-4">
                                                <div className="font-mono text-sm text-foreground">{node.hostname}</div>
                                            </td>
                                            <td className="px-4 py-4 font-mono text-sm text-muted-foreground">
                                                {node.ipAddress}
                                            </td>
                                            <td className="px-4 py-4 text-sm text-muted-foreground">
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
                                            <td className="px-4 py-4 text-right text-sm text-foreground font-medium">
                                                {formatNumber(node.emailsSentToday)}
                                            </td>
                                            <td className="px-4 py-4 text-right">
                                                <span className={cn(
                                                    'text-sm font-medium',
                                                    node.bounceRate > 2 ? 'text-destructive' :
                                                    node.bounceRate > 1 ? 'text-warning' : 'text-muted-foreground'
                                                )}>
                                                    {node.bounceRate.toFixed(1)}%
                                                </span>
                                            </td>
                                            <td className="px-4 py-4 text-right text-sm text-muted-foreground">
                                                {node.avgLatency > 0 ? `${node.avgLatency}ms` : '—'}
                                            </td>
                                            <td className="px-4 py-4 text-center">
                                                {node.blacklisted ? (
                                                    <span className="px-2.5 py-0.5 bg-destructive/10 text-destructive rounded text-xs font-medium">Listed</span>
                                                ) : (
                                                    <span className="px-2.5 py-0.5 bg-success/10 text-success rounded text-xs font-medium">Clean</span>
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
