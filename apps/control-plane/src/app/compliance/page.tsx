'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { formatNumber, cn, getRiskColor } from '../../lib/utils';

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
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
            </div>
        );
    }

    const totalTenants = overview.riskSummary.low + overview.riskSummary.medium + overview.riskSummary.high + overview.riskSummary.critical;

    return (
        <div className="max-w-7xl mx-auto">
            <div className="mb-6">
                <h1 className="text-2xl font-bold text-gray-900">Compliance Admin</h1>
                <p className="text-gray-600 mt-1">
                    Platform-wide compliance monitoring and governance
                </p>
            </div>

            {/* Alert Banner */}
            {(overview.riskSummary.critical > 0 || overview.gdprRequests.overdue > 0) && (
                <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
                    <div className="flex items-center gap-2 text-red-800 font-medium mb-2">
                        🚨 Critical Issues Requiring Immediate Attention
                    </div>
                    <div className="flex gap-4 text-sm text-red-700">
                        {overview.riskSummary.critical > 0 && (
                            <Link href="/risk" className="hover:underline">
                                {overview.riskSummary.critical} tenant(s) with critical risk
                            </Link>
                        )}
                        {overview.gdprRequests.overdue > 0 && (
                            <Link href="/gdpr" className="hover:underline">
                                {overview.gdprRequests.overdue} overdue GDPR request(s)
                            </Link>
                        )}
                    </div>
                </div>
            )}

            {/* Quick Navigation */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                <Link href="/risk" className="block bg-white rounded-xl border border-gray-200 p-4 hover:shadow-md transition-shadow">
                    <div className="flex items-center gap-3 mb-2">
                        <span className="text-2xl">⚠️</span>
                        <span className="font-semibold text-gray-900">Risk Monitoring</span>
                    </div>
                    <div className="text-2xl font-bold text-orange-600">
                        {overview.riskSummary.high + overview.riskSummary.critical}
                    </div>
                    <div className="text-sm text-gray-500">High-risk tenants</div>
                </Link>
                <Link href="/audit" className="block bg-white rounded-xl border border-gray-200 p-4 hover:shadow-md transition-shadow">
                    <div className="flex items-center gap-3 mb-2">
                        <span className="text-2xl">📜</span>
                        <span className="font-semibold text-gray-900">Audit Logs</span>
                    </div>
                    <div className="text-2xl font-bold text-blue-600">
                        {formatNumber(overview.auditStats.todayEvents)}
                    </div>
                    <div className="text-sm text-gray-500">Events today</div>
                </Link>
                <Link href="/gdpr" className="block bg-white rounded-xl border border-gray-200 p-4 hover:shadow-md transition-shadow">
                    <div className="flex items-center gap-3 mb-2">
                        <span className="text-2xl">🇪🇺</span>
                        <span className="font-semibold text-gray-900">GDPR Requests</span>
                    </div>
                    <div className="text-2xl font-bold text-indigo-600">
                        {overview.gdprRequests.pending + overview.gdprRequests.processing}
                    </div>
                    <div className="text-sm text-gray-500">Pending requests</div>
                </Link>
                <Link href="/secrets" className="block bg-white rounded-xl border border-gray-200 p-4 hover:shadow-md transition-shadow">
                    <div className="flex items-center gap-3 mb-2">
                        <span className="text-2xl">🔐</span>
                        <span className="font-semibold text-gray-900">Secrets Vault</span>
                    </div>
                    <div className="text-2xl font-bold text-green-600">
                        Secure
                    </div>
                    <div className="text-sm text-gray-500">All secrets encrypted</div>
                </Link>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Risk Distribution */}
                <div className="bg-white rounded-xl border border-gray-200 p-6">
                    <h2 className="text-lg font-semibold mb-4">Tenant Risk Distribution</h2>
                    <div className="space-y-4">
                        {[
                            { level: 'low' as const, count: overview.riskSummary.low, label: 'Low Risk' },
                            { level: 'medium' as const, count: overview.riskSummary.medium, label: 'Medium Risk' },
                            { level: 'high' as const, count: overview.riskSummary.high, label: 'High Risk' },
                            { level: 'critical' as const, count: overview.riskSummary.critical, label: 'Critical' },
                        ].map(({ level, count, label }) => (
                            <div key={level} className="flex items-center gap-4">
                                <div className="w-24 text-sm text-gray-600">{label}</div>
                                <div className="flex-1 bg-gray-100 rounded-full h-4 overflow-hidden">
                                    <div
                                        className={cn(
                                            'h-full rounded-full',
                                            level === 'low' && 'bg-green-500',
                                            level === 'medium' && 'bg-yellow-500',
                                            level === 'high' && 'bg-orange-500',
                                            level === 'critical' && 'bg-red-500'
                                        )}
                                        style={{ width: `${(count / totalTenants) * 100}%` }}
                                    />
                                </div>
                                <div className="w-16 text-right font-medium">{count}</div>
                            </div>
                        ))}
                    </div>
                    <div className="mt-4 pt-4 border-t border-gray-100 text-sm text-gray-500">
                        {totalTenants} total tenants monitored
                    </div>
                </div>

                {/* Policy Compliance */}
                <div className="bg-white rounded-xl border border-gray-200 p-6">
                    <h2 className="text-lg font-semibold mb-4">Policy Compliance</h2>
                    <div className="space-y-3">
                        {overview.policyCompliance.map((policy) => (
                            <div key={policy.name} className="flex items-center justify-between">
                                <div className="text-sm text-gray-700">{policy.name}</div>
                                <div className="flex items-center gap-2">
                                    <div className="w-32 bg-gray-100 rounded-full h-2 overflow-hidden">
                                        <div
                                            className={cn(
                                                'h-full rounded-full',
                                                policy.compliant / policy.total >= 0.95 && 'bg-green-500',
                                                policy.compliant / policy.total >= 0.8 && policy.compliant / policy.total < 0.95 && 'bg-yellow-500',
                                                policy.compliant / policy.total < 0.8 && 'bg-red-500'
                                            )}
                                            style={{ width: `${(policy.compliant / policy.total) * 100}%` }}
                                        />
                                    </div>
                                    <span className={cn(
                                        'text-sm font-medium',
                                        policy.compliant / policy.total >= 0.95 && 'text-green-600',
                                        policy.compliant / policy.total >= 0.8 && policy.compliant / policy.total < 0.95 && 'text-yellow-600',
                                        policy.compliant / policy.total < 0.8 && 'text-red-600'
                                    )}>
                                        {Math.round((policy.compliant / policy.total) * 100)}%
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Recent Alerts */}
                <div className="lg:col-span-2 bg-white rounded-xl border border-gray-200 p-6">
                    <div className="flex items-center justify-between mb-4">
                        <h2 className="text-lg font-semibold">Recent Compliance Alerts</h2>
                        <Link href="/audit" className="text-sm text-indigo-600 hover:underline">
                            View all →
                        </Link>
                    </div>
                    <div className="space-y-3">
                        {overview.recentAlerts.map((alert) => (
                            <div key={alert.id} className="flex items-start gap-3 p-3 rounded-lg hover:bg-gray-50">
                                <span className={cn(
                                    'px-2 py-0.5 rounded text-xs font-medium',
                                    getRiskColor(alert.severity)
                                )}>
                                    {alert.severity}
                                </span>
                                <div className="flex-1">
                                    <div className="text-sm text-gray-900">{alert.message}</div>
                                    <div className="text-xs text-gray-500 mt-1">
                                        {alert.type} • {new Date(alert.timestamp).toLocaleString()}
                                    </div>
                                </div>
                                <button className="text-sm text-indigo-600 hover:underline">
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
