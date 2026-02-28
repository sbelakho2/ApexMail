'use client';

import { useState, useEffect } from 'react';
import { formatDate, cn } from '../../lib/utils';
import { useDialog } from '../../components/ui/confirm-dialog';

/**
 * Audit Logs - Complete audit trail viewer
 * 
 * The owner can:
 * - Search and filter audit events
 * - Export audit logs for compliance
 * - Set up alerting rules
 * - Verify log integrity
 */

interface AuditEntry {
    id: string;
    timestamp: string;
    action: string;
    resource: string;
    resourceId: string;
    actorType: 'user' | 'system' | 'api';
    actorId: string;
    tenantId: string | null;
    status: 'success' | 'failure';
    ipAddress: string;
    userAgent: string;
    details: Record<string, unknown>;
}



// Action categories for filtering and grouping
const _ACTION_CATEGORIES = {
    'auth': ['auth.login', 'auth.logout', 'auth.mfa_enabled'],
    'email': ['email.sent', 'email.delivered', 'email.bounced', 'email.complained'],
    'api': ['api_key.created', 'api_key.revoked', 'rate_limit.exceeded'],
    'domain': ['domain.added', 'domain.verified', 'domain.removed'],
    'gdpr': ['gdpr.request_created', 'gdpr.request_processed', 'gdpr.data_exported'],
    'billing': ['subscription.created', 'subscription.upgraded', 'subscription.cancelled'],
};

export default function AuditLogsPage() {
    const dialog = useDialog();
    const [logs, setLogs] = useState<AuditEntry[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedLog, setSelectedLog] = useState<AuditEntry | null>(null);
    const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
    const [exportJob, setExportJob] = useState<{
        id: string;
        status: 'queued' | 'running' | 'completed' | 'failed';
        downloadUrl?: string;
        error?: string;
    } | null>(null);
    const [filters, setFilters] = useState({
        search: '',
        action: '',
        status: '',
        tenantId: '',
        dateFrom: '',
        dateTo: '',
    });

    useEffect(() => {
        loadAuditLogs();
    }, []);

    async function loadAuditLogs() {
        try {
            const response = await fetch('/api/audit', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch audit logs: ${response.status}`);
            const data = await response.json();
            setLogs(data);
        } catch (err) {
            console.error('Failed to load audit logs:', err);
        } finally {
            setLoading(false);
        }
    }

    function getActionIcon(action: string): string {
        if (action.startsWith('auth')) return 'Auth';
        if (action.startsWith('email')) return 'Email';
        if (action.startsWith('api')) return 'API';
        if (action.startsWith('domain')) return 'Domain';
        if (action.startsWith('gdpr')) return 'GDPR';
        if (action.startsWith('webhook')) return 'Webhook';
        if (action.startsWith('template')) return 'Template';
        if (action.startsWith('subscription') || action.startsWith('billing')) return 'Billing';
        if (action.startsWith('rate_limit')) return 'Rate';
        return 'Log';
    }

    async function exportLogs() {
        try {
            const response = await fetch('/api/audit/export', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filters }),
            });
            if (!response.ok) {
                throw new Error(`Failed to start export (${response.status})`);
            }

            const job = await response.json();
            setExportJob({ id: job.id, status: 'queued' });

            const interval = setInterval(async () => {
                try {
                    const statusRes = await fetch(`/api/audit/export/${job.id}`, { credentials: 'include' });
                    if (!statusRes.ok) {
                        throw new Error(`Failed to poll export (${statusRes.status})`);
                    }
                    const statusPayload = await statusRes.json();
                    setExportJob(prev => prev ? {
                        ...prev,
                        status: statusPayload.status,
                        downloadUrl: statusPayload.downloadUrl,
                        error: statusPayload.error,
                    } : prev);

                    if (statusPayload.status === 'completed' || statusPayload.status === 'failed') {
                        clearInterval(interval);
                    }
                } catch (error) {
                    clearInterval(interval);
                    setExportJob(prev => prev ? {
                        ...prev,
                        status: 'failed',
                        error: error instanceof Error ? error.message : 'Unknown export polling error',
                    } : prev);
                }
            }, 2500);
        } catch (error) {
            await dialog.alert({
                title: 'Export Failed',
                message: error instanceof Error ? error.message : 'Unable to start export job',
            });
        }
    }

    const filteredLogs = logs.filter(log => {
        if (filters.search && !JSON.stringify(log).toLowerCase().includes(filters.search.toLowerCase())) return false;
        if (filters.action && !log.action.startsWith(filters.action)) return false;
        if (filters.status && log.status !== filters.status) return false;
        if (filters.tenantId && log.tenantId !== filters.tenantId) return false;
        if (filters.dateFrom && new Date(log.timestamp) < new Date(filters.dateFrom)) return false;
        if (filters.dateTo) {
            const dateTo = new Date(filters.dateTo);
            dateTo.setHours(23, 59, 59, 999);
            if (new Date(log.timestamp) > dateTo) return false;
        }
        return true;
    });

    const uniqueTenants = [...new Set(logs.map(l => l.tenantId).filter(Boolean))];

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
        );
    }

    return (
        <div className="cp-page">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">Audit Logs</h1>
                    <p className="text-muted-foreground mt-1">
                        Complete audit trail for compliance and security monitoring
                    </p>
                </div>
                <div className="flex gap-3">
                    <button aria-label="Configure audit alerts" type="button" className="px-4 py-2 bg-card border border-border rounded-lg text-sm font-medium text-foreground hover:bg-muted/50 hover:border-input shadow-sm transition-all">
                            Configure Alerts
                    </button>
                    <button
                        aria-label="Export audit logs"
                        onClick={exportLogs}
                        className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 shadow-sm transition-all hover:shadow-md"
                    >
                        Export Logs
                    </button>
                </div>
            </div>

            {exportJob && (
                <div className={cn(
                    'mb-4 rounded-lg border px-4 py-3 text-sm',
                    exportJob.status === 'failed' ? 'border-destructive/30 bg-destructive/10 text-destructive' :
                    exportJob.status === 'completed' ? 'border-success/30 bg-success/10 text-success' :
                    'border-primary/30 bg-primary/5 text-primary'
                )}>
                    <div className="flex items-center justify-between gap-3">
                        <span>
                            Export job {exportJob.id}: {exportJob.status}
                            {exportJob.error ? ` — ${exportJob.error}` : ''}
                        </span>
                        {exportJob.status === 'completed' && exportJob.downloadUrl && (
                            <a
                                href={exportJob.downloadUrl}
                                className="text-sm font-medium underline"
                                download
                            >
                                Download export
                            </a>
                        )}
                    </div>
                </div>
            )}

            {/* Filters */}
            <div className="bg-card rounded-xl border border-border p-5 mb-8 shadow-sm">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                        <label className="text-xs font-semibold text-muted-foreground mb-1.5 block uppercase tracking-wider">Search</label>
                        <div className="relative">
                            <input
                                type="text"
                                placeholder="Search logs..."
                                value={filters.search}
                                onChange={(e) => setFilters(prev => ({ ...prev, search: e.target.value }))}
                                className="w-full px-3 py-2 pr-10 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary transition-all text-foreground placeholder:text-muted-foreground bg-background"
                            />
                            {filters.search && (
                                <button
                                    type="button"
                                    onClick={() => setFilters(prev => ({ ...prev, search: '' }))}
                                    className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-muted-foreground hover:text-foreground"
                                    aria-label="Clear audit search"
                                >
                                    ×
                                </button>
                            )}
                        </div>
                    </div>
                    <div>
                        <label className="text-xs font-semibold text-muted-foreground mb-1.5 block uppercase tracking-wider">Action Category</label>
                        <select
                            value={filters.action}
                            onChange={(e) => setFilters(prev => ({ ...prev, action: e.target.value }))}
                            className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary transition-all text-foreground bg-background"
                        >
                            <option value="">All Actions</option>
                            <option value="auth">Authentication</option>
                            <option value="email">Email Events</option>
                            <option value="api">API Operations</option>
                            <option value="domain">Domain Management</option>
                            <option value="gdpr">GDPR</option>
                            <option value="subscription">Billing</option>
                        </select>
                    </div>
                    <div className="flex items-end">
                        <div className="flex w-full gap-2">
                            <button
                                onClick={() => setShowAdvancedFilters((prev) => !prev)}
                                className="px-4 py-2 text-sm font-medium text-foreground bg-muted hover:bg-muted/80 rounded-lg transition-colors flex-1"
                            >
                                {showAdvancedFilters ? 'Hide Advanced' : 'Show Advanced'}
                            </button>
                            <button
                                onClick={() => setFilters({ search: '', action: '', status: '', tenantId: '', dateFrom: '', dateTo: '' })}
                                className="px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground hover:bg-muted rounded-lg transition-colors flex-1"
                            >
                                Clear
                            </button>
                        </div>
                    </div>
                </div>

                {showAdvancedFilters && (
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-4 pt-4 border-t border-border">
                        <div>
                            <label className="text-xs font-semibold text-muted-foreground mb-1.5 block uppercase tracking-wider">Status</label>
                            <select
                                value={filters.status}
                                onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value }))}
                                className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary transition-all text-foreground bg-background"
                            >
                                <option value="">All Statuses</option>
                                <option value="success">Success</option>
                                <option value="failure">Failure</option>
                            </select>
                        </div>
                        <div>
                            <label className="text-xs font-semibold text-muted-foreground mb-1.5 block uppercase tracking-wider">Tenant</label>
                            <select
                                value={filters.tenantId}
                                onChange={(e) => setFilters(prev => ({ ...prev, tenantId: e.target.value }))}
                                className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary transition-all text-foreground bg-background"
                            >
                                <option value="">All Tenants</option>
                                {uniqueTenants.map(tenant => (
                                    <option key={tenant} value={tenant!}>{tenant}</option>
                                ))}
                            </select>
                        </div>
                        <div>
                            <label className="text-xs font-semibold text-muted-foreground mb-1.5 block uppercase tracking-wider">From Date</label>
                            <input
                                type="date"
                                value={filters.dateFrom}
                                onChange={(e) => setFilters(prev => ({ ...prev, dateFrom: e.target.value }))}
                                className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary transition-all text-foreground bg-background"
                            />
                        </div>
                        <div>
                            <label className="text-xs font-semibold text-muted-foreground mb-1.5 block uppercase tracking-wider">To Date</label>
                            <input
                                type="date"
                                value={filters.dateTo}
                                onChange={(e) => setFilters(prev => ({ ...prev, dateTo: e.target.value }))}
                                className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary transition-all text-foreground bg-background"
                            />
                        </div>
                    </div>
                )}
            </div>

            {/* Audit Log List */}
            <div className="bg-card rounded-xl border border-border shadow-sm overflow-hidden">
                <div className="px-6 py-4 border-b border-border bg-muted/50">
                    <span className="text-sm font-medium text-muted-foreground">{filteredLogs.length} events found</span>
                </div>
                <div className="divide-y divide-border">
                    {filteredLogs.length === 0 ? (
                        <div className="p-8 text-center">
                            <p className="text-sm text-muted-foreground">No audit events match your current filters.</p>
                            <button
                                type="button"
                                onClick={() => setFilters({ search: '', action: '', status: '', tenantId: '', dateFrom: '', dateTo: '' })}
                                className="mt-2 text-sm text-primary hover:underline"
                            >
                                Clear filters and broaden search
                            </button>
                        </div>
                    ) : filteredLogs.map(log => (
                        <div
                            key={log.id}
                            className="p-4 hover:bg-muted/50 cursor-pointer transition-colors"
                            onClick={() => setSelectedLog(log)}
                        >
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-4">
                                    <span className="text-2xl bg-muted rounded-lg p-2">{getActionIcon(log.action)}</span>
                                    <div>
                                        <div className="flex items-center gap-2.5">
                                            <span className="font-semibold text-foreground">{log.action}</span>
                                            <span className={cn(
                                                'px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide border',
                                                log.status === 'success' ? 'bg-success/10 text-success border-success/20' : 'bg-destructive/10 text-destructive border-destructive/20'
                                            )}>
                                                {log.status}
                                            </span>
                                        </div>
                                        <div className="text-sm text-muted-foreground mt-0.5 flex items-center gap-2">
                                            <span className="font-medium text-foreground">{log.resource}:</span> 
                                            <span className="font-mono text-xs bg-muted px-1.5 py-0.5 rounded">{log.resourceId}</span>
                                            {log.tenantId && (
                                                <>
                                                    <span className="text-muted-foreground/50">•</span>
                                                    <span>{log.tenantId}</span>
                                                </>
                                            )}
                                        </div>
                                    </div>
                                </div>
                                <div className="text-right">
                                    <div className="text-sm font-medium text-foreground">{formatDate(log.timestamp)}</div>
                                    <div className="text-xs font-mono text-muted-foreground mt-1">{log.ipAddress}</div>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Log Detail Modal */}
            {selectedLog && (
                <div className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setSelectedLog(null)}>
                    <div className="bg-card rounded-2xl p-6 w-full max-w-2xl shadow-2xl border border-border max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-8 border-b border-border pb-6">
                            <div className="flex items-center gap-4">
                                <span className="text-4xl bg-muted p-3 rounded-xl">{getActionIcon(selectedLog.action)}</span>
                                <div>
                                    <h2 className="text-xl font-bold text-foreground">{selectedLog.action}</h2>
                                    <div className="mt-1">
                                        <span className={cn(
                                            'px-2.5 py-0.5 rounded-md text-xs font-bold uppercase tracking-wide border',
                                            selectedLog.status === 'success' ? 'bg-success/10 text-success border-success/20' : 'bg-destructive/10 text-destructive border-destructive/20'
                                        )}>
                                            {selectedLog.status}
                                        </span>
                                    </div>
                                </div>
                            </div>
                                <button 
                                    type="button"
                                    onClick={() => setSelectedLog(null)} 
                                    className="text-muted-foreground hover:text-foreground p-2 rounded-lg hover:bg-muted transition-colors"
                                    aria-label="Close modal"
                                >
                                    Close
                                </button>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-6 mb-8">
                            <div className="group">
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Timestamp</label>
                                <div className="font-medium text-foreground bg-muted/50 px-3 py-2 rounded-lg border border-transparent group-hover:border-border transition-colors">{formatDate(selectedLog.timestamp)}</div>
                            </div>
                            <div className="group">
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Event ID</label>
                                <div className="font-mono text-sm text-muted-foreground bg-muted/50 px-3 py-2 rounded-lg border border-transparent group-hover:border-border transition-colors">{selectedLog.id}</div>
                            </div>
                            <div className="group">
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Resource</label>
                                <div className="font-medium text-foreground bg-muted/50 px-3 py-2 rounded-lg border border-transparent group-hover:border-border transition-colors capitalize">{selectedLog.resource}</div>
                            </div>
                            <div className="group">
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Resource ID</label>
                                <div className="font-mono text-sm text-muted-foreground bg-muted/50 px-3 py-2 rounded-lg border border-transparent group-hover:border-border transition-colors">{selectedLog.resourceId}</div>
                            </div>
                            <div className="group">
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Actor Type</label>
                                <div className="font-medium text-foreground bg-muted/50 px-3 py-2 rounded-lg border border-transparent group-hover:border-border transition-colors capitalize">{selectedLog.actorType}</div>
                            </div>
                            <div className="group">
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Actor ID</label>
                                <div className="font-mono text-sm text-muted-foreground bg-muted/50 px-3 py-2 rounded-lg border border-transparent group-hover:border-border transition-colors">{selectedLog.actorId}</div>
                            </div>
                            <div className="group">
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">Tenant</label>
                                <div className="font-medium text-foreground bg-muted/50 px-3 py-2 rounded-lg border border-transparent group-hover:border-border transition-colors">{selectedLog.tenantId || 'System'}</div>
                            </div>
                            <div className="group">
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1 block">IP Address</label>
                                <div className="font-mono text-sm text-muted-foreground bg-muted/50 px-3 py-2 rounded-lg border border-transparent group-hover:border-border transition-colors">{selectedLog.ipAddress}</div>
                            </div>
                        </div>

                        <div className="mb-8">
                            <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 block">User Agent</label>
                            <div className="font-mono text-sm text-muted-foreground bg-muted/50 p-3 rounded-lg border border-border break-words overflow-x-auto max-h-32">{selectedLog.userAgent}</div>
                        </div>

                        <div>
                            <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 block">Event Details</label>
                            <div className="bg-slate-950 rounded-xl overflow-hidden shadow-inner">
                                <div className="flex items-center justify-between px-4 py-2 bg-slate-900 border-b border-slate-800">
                                    <span className="text-xs font-mono text-slate-400">JSON</span>
                                </div>
                                <pre className="font-mono text-sm text-blue-400 p-4 overflow-x-auto">
                                    {JSON.stringify(selectedLog.details, null, 2)}
                                </pre>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
