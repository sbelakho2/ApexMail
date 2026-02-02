'use client';

import { useState, useEffect } from 'react';
import { formatDate, cn } from '../../lib/utils';

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

const DEMO_AUDIT_LOGS: AuditEntry[] = [
    { id: '1', timestamp: new Date(Date.now() - 60000).toISOString(), action: 'email.sent', resource: 'message', resourceId: 'msg-12345', actorType: 'api', actorId: 'api-key-abc', tenantId: 'tenant-saas', status: 'success', ipAddress: '52.23.145.12', userAgent: 'ApexMail-SDK/1.0', details: { recipients: 1, template: 'welcome' } },
    { id: '2', timestamp: new Date(Date.now() - 120000).toISOString(), action: 'auth.login', resource: 'session', resourceId: 'sess-xyz', actorType: 'user', actorId: 'user-456', tenantId: 'tenant-newsletter', status: 'success', ipAddress: '192.168.1.100', userAgent: 'Mozilla/5.0...', details: { method: 'password' } },
    { id: '3', timestamp: new Date(Date.now() - 180000).toISOString(), action: 'auth.login', resource: 'session', resourceId: 'sess-fail', actorType: 'user', actorId: 'unknown', tenantId: null, status: 'failure', ipAddress: '45.33.32.156', userAgent: 'curl/7.68.0', details: { reason: 'invalid_credentials', attempts: 5 } },
    { id: '4', timestamp: new Date(Date.now() - 240000).toISOString(), action: 'domain.verified', resource: 'domain', resourceId: 'dom-789', actorType: 'system', actorId: 'dns-verifier', tenantId: 'tenant-ecommerce', status: 'success', ipAddress: '127.0.0.1', userAgent: 'ApexMail-Worker', details: { domain: 'shop.example.com', records: ['SPF', 'DKIM'] } },
    { id: '5', timestamp: new Date(Date.now() - 300000).toISOString(), action: 'api_key.created', resource: 'api_key', resourceId: 'key-new', actorType: 'user', actorId: 'user-admin', tenantId: 'tenant-growth', status: 'success', ipAddress: '10.0.0.5', userAgent: 'Mozilla/5.0...', details: { permissions: ['send', 'read'] } },
    { id: '6', timestamp: new Date(Date.now() - 360000).toISOString(), action: 'webhook.delivered', resource: 'webhook', resourceId: 'hook-456', actorType: 'system', actorId: 'webhook-worker', tenantId: 'tenant-saas', status: 'success', ipAddress: '127.0.0.1', userAgent: 'ApexMail-Webhook', details: { event: 'email.delivered', retries: 0 } },
    { id: '7', timestamp: new Date(Date.now() - 420000).toISOString(), action: 'template.updated', resource: 'template', resourceId: 'tpl-welcome', actorType: 'user', actorId: 'user-123', tenantId: 'tenant-newsletter', status: 'success', ipAddress: '192.168.1.50', userAgent: 'Mozilla/5.0...', details: { version: 3 } },
    { id: '8', timestamp: new Date(Date.now() - 480000).toISOString(), action: 'gdpr.request_created', resource: 'gdpr_request', resourceId: 'gdpr-001', actorType: 'system', actorId: 'gdpr-processor', tenantId: 'tenant-ecommerce', status: 'success', ipAddress: '127.0.0.1', userAgent: 'ApexMail-GDPR', details: { type: 'deletion', email: 'user@***.com' } },
    { id: '9', timestamp: new Date(Date.now() - 540000).toISOString(), action: 'rate_limit.exceeded', resource: 'api', resourceId: 'endpoint-send', actorType: 'api', actorId: 'api-key-xyz', tenantId: 'tenant-spammy', status: 'failure', ipAddress: '203.0.113.50', userAgent: 'ApexMail-SDK/1.0', details: { limit: 1000, current: 1001 } },
    { id: '10', timestamp: new Date(Date.now() - 600000).toISOString(), action: 'subscription.upgraded', resource: 'subscription', resourceId: 'sub-456', actorType: 'system', actorId: 'billing-worker', tenantId: 'tenant-growth', status: 'success', ipAddress: '127.0.0.1', userAgent: 'ApexMail-Billing', details: { from: 'starter', to: 'professional' } },
];

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
    const [logs, setLogs] = useState<AuditEntry[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedLog, setSelectedLog] = useState<AuditEntry | null>(null);
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
            // In production: fetch from Compliance API
            setLogs(DEMO_AUDIT_LOGS);
        } finally {
            setLoading(false);
        }
    }

    function getActionIcon(action: string): string {
        if (action.startsWith('auth')) return '🔐';
        if (action.startsWith('email')) return '📧';
        if (action.startsWith('api')) return '🔑';
        if (action.startsWith('domain')) return '🌐';
        if (action.startsWith('gdpr')) return '🇪🇺';
        if (action.startsWith('webhook')) return '🔗';
        if (action.startsWith('template')) return '📄';
        if (action.startsWith('subscription') || action.startsWith('billing')) return '💳';
        if (action.startsWith('rate_limit')) return '⚡';
        return '📋';
    }

    async function exportLogs() {
        // In production: call Compliance API to generate export
        alert('Export started. You will receive a download link via email.');
    }

    const filteredLogs = logs.filter(log => {
        if (filters.search && !JSON.stringify(log).toLowerCase().includes(filters.search.toLowerCase())) return false;
        if (filters.action && !log.action.startsWith(filters.action)) return false;
        if (filters.status && log.status !== filters.status) return false;
        if (filters.tenantId && log.tenantId !== filters.tenantId) return false;
        return true;
    });

    const uniqueTenants = [...new Set(logs.map(l => l.tenantId).filter(Boolean))];

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
            </div>
        );
    }

    return (
        <div className="max-w-7xl mx-auto">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900">Audit Logs</h1>
                    <p className="text-gray-600 mt-1">
                        Complete audit trail for compliance and security monitoring
                    </p>
                </div>
                <div className="flex gap-2">
                    <button className="px-4 py-2 bg-white border border-gray-200 rounded-lg text-sm hover:bg-gray-50">
                        ⚙️ Configure Alerts
                    </button>
                    <button
                        onClick={exportLogs}
                        className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm hover:bg-indigo-700"
                    >
                        📥 Export Logs
                    </button>
                </div>
            </div>

            {/* Filters */}
            <div className="bg-white rounded-xl border border-gray-200 p-4 mb-6">
                <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                    <div>
                        <label className="text-xs text-gray-500 mb-1 block">Search</label>
                        <input
                            type="text"
                            placeholder="Search logs..."
                            value={filters.search}
                            onChange={(e) => setFilters(prev => ({ ...prev, search: e.target.value }))}
                            className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                        />
                    </div>
                    <div>
                        <label className="text-xs text-gray-500 mb-1 block">Action Category</label>
                        <select
                            value={filters.action}
                            onChange={(e) => setFilters(prev => ({ ...prev, action: e.target.value }))}
                            className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
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
                    <div>
                        <label className="text-xs text-gray-500 mb-1 block">Status</label>
                        <select
                            value={filters.status}
                            onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value }))}
                            className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                        >
                            <option value="">All Statuses</option>
                            <option value="success">Success</option>
                            <option value="failure">Failure</option>
                        </select>
                    </div>
                    <div>
                        <label className="text-xs text-gray-500 mb-1 block">Tenant</label>
                        <select
                            value={filters.tenantId}
                            onChange={(e) => setFilters(prev => ({ ...prev, tenantId: e.target.value }))}
                            className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm"
                        >
                            <option value="">All Tenants</option>
                            {uniqueTenants.map(tenant => (
                                <option key={tenant} value={tenant!}>{tenant}</option>
                            ))}
                        </select>
                    </div>
                    <div className="flex items-end">
                        <button
                            onClick={() => setFilters({ search: '', action: '', status: '', tenantId: '', dateFrom: '', dateTo: '' })}
                            className="px-4 py-2 text-sm text-gray-600 hover:text-gray-900"
                        >
                            Clear Filters
                        </button>
                    </div>
                </div>
            </div>

            {/* Audit Log List */}
            <div className="bg-white rounded-xl border border-gray-200">
                <div className="p-4 border-b border-gray-200">
                    <span className="text-sm text-gray-500">{filteredLogs.length} events</span>
                </div>
                <div className="divide-y divide-gray-100">
                    {filteredLogs.map(log => (
                        <div
                            key={log.id}
                            className="p-4 hover:bg-gray-50 cursor-pointer"
                            onClick={() => setSelectedLog(log)}
                        >
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <span className="text-xl">{getActionIcon(log.action)}</span>
                                    <div>
                                        <div className="flex items-center gap-2">
                                            <span className="font-medium text-gray-900">{log.action}</span>
                                            <span className={cn(
                                                'px-2 py-0.5 rounded text-xs font-medium',
                                                log.status === 'success' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                                            )}>
                                                {log.status}
                                            </span>
                                        </div>
                                        <div className="text-sm text-gray-500">
                                            {log.resource}: {log.resourceId}
                                            {log.tenantId && <span className="ml-2">• {log.tenantId}</span>}
                                        </div>
                                    </div>
                                </div>
                                <div className="text-right">
                                    <div className="text-sm text-gray-900">{formatDate(log.timestamp)}</div>
                                    <div className="text-xs text-gray-500">{log.ipAddress}</div>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Log Detail Modal */}
            {selectedLog && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setSelectedLog(null)}>
                    <div className="bg-white rounded-xl p-6 w-full max-w-2xl shadow-xl max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-6">
                            <div className="flex items-center gap-3">
                                <span className="text-3xl">{getActionIcon(selectedLog.action)}</span>
                                <div>
                                    <h2 className="text-xl font-bold text-gray-900">{selectedLog.action}</h2>
                                    <span className={cn(
                                        'px-2 py-0.5 rounded text-xs font-medium',
                                        selectedLog.status === 'success' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                                    )}>
                                        {selectedLog.status}
                                    </span>
                                </div>
                            </div>
                            <button onClick={() => setSelectedLog(null)} className="text-gray-400 hover:text-gray-600">
                                ✕
                            </button>
                        </div>

                        <div className="grid grid-cols-2 gap-4 mb-6">
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Timestamp</label>
                                <div className="font-medium">{formatDate(selectedLog.timestamp)}</div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Event ID</label>
                                <div className="font-medium font-mono text-sm">{selectedLog.id}</div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Resource</label>
                                <div className="font-medium">{selectedLog.resource}</div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Resource ID</label>
                                <div className="font-medium font-mono text-sm">{selectedLog.resourceId}</div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Actor Type</label>
                                <div className="font-medium">{selectedLog.actorType}</div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Actor ID</label>
                                <div className="font-medium font-mono text-sm">{selectedLog.actorId}</div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">Tenant</label>
                                <div className="font-medium">{selectedLog.tenantId || 'System'}</div>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 uppercase">IP Address</label>
                                <div className="font-medium font-mono text-sm">{selectedLog.ipAddress}</div>
                            </div>
                        </div>

                        <div className="mb-6">
                            <label className="text-xs text-gray-500 uppercase mb-2 block">User Agent</label>
                            <div className="font-mono text-sm bg-gray-50 p-2 rounded">{selectedLog.userAgent}</div>
                        </div>

                        <div>
                            <label className="text-xs text-gray-500 uppercase mb-2 block">Event Details</label>
                            <pre className="font-mono text-sm bg-gray-900 text-green-400 p-4 rounded-lg overflow-x-auto">
                                {JSON.stringify(selectedLog.details, null, 2)}
                            </pre>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
