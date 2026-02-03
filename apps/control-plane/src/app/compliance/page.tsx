'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { formatNumber, cn } from '../../lib/utils';

/**
 * Compliance Admin - Unified compliance dashboard
 * 
 * The owner can:
 * - Monitor overall platform compliance status
 * - View risk metrics across all tenants
 * - Access GDPR request queue
 * - Review audit trails
 * - Manage compliance policies
 */

interface ComplianceOverview {
    riskSummary: {
        low: number;
        medium: number;
        high: number;
        critical: number;
    };
    gdprRequests: {
        pending: number;
        processing: number;
        completed: number;
        overdue: number;
    };
    auditStats: {
        todayEvents: number;
        weekEvents: number;
        alertsTriggered: number;
    };
    policyCompliance: {
        name: string;
        compliant: number;
        total: number;
    }[];
    recentAlerts: {
        id: string;
        type: string;
        message: string;
        severity: 'low' | 'medium' | 'high' | 'critical';
        tenantId: string;
        timestamp: string;
    }[];
}

export default function CompliancePage() {
    const [overview, setOverview] = useState<ComplianceOverview | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadComplianceOverview();
    }, []);

    async function loadComplianceOverview() {
        try {
            // In production: fetch from Compliance API
            setOverview({
                riskSummary: {
                    low: 128,
                    medium: 23,
                    high: 4,
                    critical: 1,
                },
                gdprRequests: {
                    pending: 3,
                    processing: 2,
                    completed: 156,
                    overdue: 0,
                },
                auditStats: {
                    todayEvents: 1847,
                    weekEvents: 12450,
                    alertsTriggered: 7,
                },
                policyCompliance: [
                    { name: 'SPF Records', compliant: 152, total: 156 },
                    { name: 'DKIM Signing', compliant: 156, total: 156 },
                    { name: 'DMARC Policy', compliant: 145, total: 156 },
                    { name: 'Bounce Rate < 5%', compliant: 148, total: 156 },
                    { name: 'Complaint Rate < 0.1%', compliant: 151, total: 156 },
                    { name: 'Unsubscribe Link', compliant: 156, total: 156 },
                ],
                recentAlerts: [
                    { id: '1', type: 'high_bounce', message: 'Tenant "spammy.io" exceeded 10% bounce rate', severity: 'high', tenantId: 'tenant-123', timestamp: new Date(Date.now() - 1800000).toISOString() },
                    { id: '2', type: 'spam_report', message: 'Spike in spam complaints for "newsletter.co"', severity: 'medium', tenantId: 'tenant-456', timestamp: new Date(Date.now() - 3600000).toISOString() },
                    { id: '3', type: 'auth_failure', message: 'Multiple failed auth attempts from IP 192.168.1.1', severity: 'medium', tenantId: 'system', timestamp: new Date(Date.now() - 7200000).toISOString() },
                    { id: '4', type: 'gdpr_deadline', message: 'GDPR request #42 approaching SLA deadline', severity: 'high', tenantId: 'tenant-789', timestamp: new Date(Date.now() - 14400000).toISOString() },
                    { id: '5', type: 'volume_spike', message: 'Unusual volume spike detected for "marketing.io"', severity: 'low', tenantId: 'tenant-321', timestamp: new Date(Date.now() - 21600000).toISOString() },
                ],
            });
        } finally {
            setLoading(false);
        }
    }

    if (loading || !overview) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    const totalTenants = overview.riskSummary.low + overview.riskSummary.medium + overview.riskSummary.high + overview.riskSummary.critical;

    return (
        <div className="max-w-7xl mx-auto">
            <div className="mb-8">
                <h1 className="text-2xl font-bold text-surface-900">Compliance Admin</h1>
                <p className="text-surface-500 mt-1">
                    Platform-wide compliance monitoring and governance
                </p>
            </div>

            {/* Alert Banner */}
            {(overview.riskSummary.critical > 0 || overview.gdprRequests.overdue > 0) && (
                <div className="mb-8 p-4 bg-red-50 border border-red-200 rounded-xl shadow-sm">
                    <div className="flex items-center gap-2 text-red-800 font-medium mb-2">
                        🚨 Critical Issues Requiring Immediate Attention
                    </div>
                    <div className="flex gap-4 text-sm text-red-700">
                        {overview.riskSummary.critical > 0 && (
                            <Link href="/risk" className="hover:underline hover:text-red-900 decoration-red-300">
                                {overview.riskSummary.critical} tenant(s) with critical risk
                            </Link>
                        )}
                        {overview.gdprRequests.overdue > 0 && (
                            <Link href="/gdpr" className="hover:underline hover:text-red-900 decoration-red-300">
                                {overview.gdprRequests.overdue} overdue GDPR request(s)
                            </Link>
                        )}
                    </div>
                </div>
            )}

            {/* Quick Navigation */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                <Link href="/risk" className="block bg-surface-0 rounded-xl border border-surface-200 p-5 shadow-sm hover:shadow-md transition-all hover:border-surface-300 group">
                    <div className="flex items-center gap-3 mb-2">
                        <span className="text-2xl group-hover:scale-110 transition-transform">⚠️</span>
                        <span className="font-semibold text-surface-900">Risk Monitoring</span>
                    </div>
                    <div className="text-2xl font-bold text-amber-600">
                        {overview.riskSummary.high + overview.riskSummary.critical}
                    </div>
                    <div className="text-sm text-surface-500">High-risk tenants</div>
                </Link>
                <Link href="/audit" className="block bg-surface-0 rounded-xl border border-surface-200 p-5 shadow-sm hover:shadow-md transition-all hover:border-surface-300 group">
                    <div className="flex items-center gap-3 mb-2">
                        <span className="text-2xl group-hover:scale-110 transition-transform">📜</span>
                        <span className="font-semibold text-surface-900">Audit Logs</span>
                    </div>
                    <div className="text-2xl font-bold text-blue-600">
                        {formatNumber(overview.auditStats.todayEvents)}
                    </div>
                    <div className="text-sm text-surface-500">Events today</div>
                </Link>
                <Link href="/gdpr" className="block bg-surface-0 rounded-xl border border-surface-200 p-5 shadow-sm hover:shadow-md transition-all hover:border-surface-300 group">
                    <div className="flex items-center gap-3 mb-2">
                        <span className="text-2xl group-hover:scale-110 transition-transform">🇪🇺</span>
                        <span className="font-semibold text-surface-900">GDPR Requests</span>
                    </div>
                    <div className="text-2xl font-bold text-blue-600">
                        {overview.gdprRequests.pending + overview.gdprRequests.processing}
                    </div>
                    <div className="text-sm text-surface-500">Pending requests</div>
                </Link>
                <Link href="/secrets" className="block bg-surface-0 rounded-xl border border-surface-200 p-5 shadow-sm hover:shadow-md transition-all hover:border-surface-300 group">
                    <div className="flex items-center gap-3 mb-2">
                        <span className="text-2xl group-hover:scale-110 transition-transform">🔐</span>
                        <span className="font-semibold text-surface-900">Secrets Vault</span>
                    </div>
                    <div className="text-2xl font-bold text-emerald-600">
                        Secure
                    </div>
                    <div className="text-sm text-surface-500">All secrets encrypted</div>
                </Link>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Risk Distribution */}
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-6 shadow-sm">
                    <h2 className="text-lg font-semibold text-surface-900 mb-6">Tenant Risk Distribution</h2>
                    <div className="space-y-5">
                        {[
                            { level: 'low' as const, count: overview.riskSummary.low, label: 'Low Risk' },
                            { level: 'medium' as const, count: overview.riskSummary.medium, label: 'Medium Risk' },
                            { level: 'high' as const, count: overview.riskSummary.high, label: 'High Risk' },
                            { level: 'critical' as const, count: overview.riskSummary.critical, label: 'Critical' },
                        ].map(({ level, count, label }) => (
                            <div key={level} className="flex items-center gap-4">
                                <div className="w-24 text-sm font-medium text-surface-600">{label}</div>
                                <div className="flex-1 bg-surface-100 rounded-full h-3 overflow-hidden">
                                    <div
                                        className={cn(
                                            'h-full rounded-full transition-all duration-500',
                                            level === 'low' && 'bg-emerald-500',
                                            level === 'medium' && 'bg-amber-400',
                                            level === 'high' && 'bg-orange-500',
                                            level === 'critical' && 'bg-red-500'
                                        )}
                                        style={{ width: `${(count / totalTenants) * 100}%` }}
                                    />
                                </div>
                                <div className="w-16 text-right font-medium text-surface-700">{count}</div>
                            </div>
                        ))}
                    </div>
                    <div className="mt-4 pt-4 border-t border-surface-100 text-sm text-surface-500">
                        {totalTenants} total tenants monitored
                    </div>
                </div>

                {/* Policy Compliance */}
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-6 shadow-sm">
                    <h2 className="text-lg font-semibold text-surface-900 mb-6">Policy Compliance</h2>
                    <div className="space-y-4">
                        {overview.policyCompliance.map((policy) => (
                            <div key={policy.name} className="flex items-center justify-between">
                                <div className="text-sm font-medium text-surface-700">{policy.name}</div>
                                <div className="flex items-center gap-3">
                                    <div className="w-32 bg-surface-100 rounded-full h-2 overflow-hidden">
                                        <div
                                            className={cn(
                                                'h-full rounded-full transition-all duration-500',
                                                policy.compliant / policy.total >= 0.95 && 'bg-emerald-500',
                                                policy.compliant / policy.total >= 0.8 && policy.compliant / policy.total < 0.95 && 'bg-amber-400',
                                                policy.compliant / policy.total < 0.8 && 'bg-red-500'
                                            )}
                                            style={{ width: `${(policy.compliant / policy.total) * 100}%` }}
                                        />
                                    </div>
                                    <span className={cn(
                                        'text-sm font-bold w-12 text-right',
                                        policy.compliant / policy.total >= 0.95 && 'text-emerald-700',
                                        policy.compliant / policy.total >= 0.8 && policy.compliant / policy.total < 0.95 && 'text-amber-700',
                                        policy.compliant / policy.total < 0.8 && 'text-red-700'
                                    )}>
                                        {Math.round((policy.compliant / policy.total) * 100)}%
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Recent Alerts */}
                <div className="lg:col-span-2 bg-surface-0 rounded-xl border border-surface-200 p-6 shadow-sm">
                    <div className="flex items-center justify-between mb-6">
                        <h2 className="text-lg font-semibold text-surface-900">Recent Compliance Alerts</h2>
                        <Link href="/audit" className="text-sm font-medium text-blue-600 hover:text-blue-700 hover:underline">
                            View all →
                        </Link>
                    </div>
                    <div className="space-y-2">
                        {overview.recentAlerts.map((alert) => (
                            <div key={alert.id} className="flex items-start gap-4 p-4 rounded-xl hover:bg-surface-50 transition-colors border border-transparent hover:border-surface-200">
                                <span className={cn(
                                    'px-2.5 py-0.5 rounded-md text-xs font-bold uppercase tracking-wide border',
                                    alert.severity === 'critical' ? 'bg-red-50 text-red-700 border-red-200' :
                                    alert.severity === 'high' ? 'bg-orange-50 text-orange-700 border-orange-200' :
                                    alert.severity === 'medium' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                                    'bg-blue-50 text-blue-700 border-blue-200'
                                )}>
                                    {alert.severity}
                                </span>
                                <div className="flex-1 min-w-0">
                                    <div className="text-sm font-medium text-surface-900">{alert.message}</div>
                                    <div className="text-xs text-surface-500 mt-1 flex items-center gap-2">
                                        <span className="font-semibold">{alert.type}</span>
                                        <span>•</span>
                                        <span>{new Date(alert.timestamp).toLocaleString()}</span>
                                    </div>
                                </div>
                                <button className="text-sm font-medium text-blue-600 hover:text-blue-800 whitespace-nowrap">
                                    Investigate
                                </button>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
}
