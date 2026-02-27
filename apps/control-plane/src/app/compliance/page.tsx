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
            const response = await fetch('/api/compliance/overview', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch compliance data: ${response.status}`);
            const data = await response.json();
            setOverview(data);
        } catch (err) {
            console.error('Failed to load compliance overview:', err);
        } finally {
            setLoading(false);
        }
    }

    if (loading || !overview) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
        );
    }

    const totalTenants = overview.riskSummary.low + overview.riskSummary.medium + overview.riskSummary.high + overview.riskSummary.critical;

    return (
        <div className="max-w-7xl mx-auto">
            <div className="mb-8">
                <h1 className="text-2xl font-bold text-foreground">Compliance Admin</h1>
                <p className="text-muted-foreground mt-1">
                    Platform-wide compliance monitoring and governance
                </p>
            </div>

            {/* Alert Banner */}
            {(overview.riskSummary.critical > 0 || overview.gdprRequests.overdue > 0) && (
                <div className="mb-8 p-4 bg-destructive/10 border border-destructive/20 rounded-xl shadow-sm">
                    <div className="flex items-center gap-2 text-destructive font-medium mb-2">
                        Critical Issues Requiring Immediate Attention
                    </div>
                    <div className="flex gap-4 text-sm text-destructive/90">
                        {overview.riskSummary.critical > 0 && (
                            <Link href="/risk" className="hover:underline hover:text-destructive decoration-destructive/50">
                                {overview.riskSummary.critical} tenant(s) with critical risk
                            </Link>
                        )}
                        {overview.gdprRequests.overdue > 0 && (
                            <Link href="/gdpr" className="hover:underline hover:text-destructive decoration-destructive/50">
                                {overview.gdprRequests.overdue} overdue GDPR request(s)
                            </Link>
                        )}
                    </div>
                </div>
            )}

            {/* Quick Navigation */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                <Link href="/risk" className="block bg-card rounded-xl border border-border p-5 shadow-sm hover:shadow-md transition-all hover:border-muted-foreground/20 group">
                    <div className="flex items-center gap-3 mb-2">
                        <span className="text-2xl group-hover:scale-110 transition-transform">Risk</span>
                        <span className="font-semibold text-foreground">Risk Monitoring</span>
                    </div>
                    <div className="text-2xl font-bold text-warning">
                        {overview.riskSummary.high + overview.riskSummary.critical}
                    </div>
                    <div className="text-sm text-muted-foreground">High-risk tenants</div>
                </Link>
                <Link href="/audit" className="block bg-card rounded-xl border border-border p-5 shadow-sm hover:shadow-md transition-all hover:border-muted-foreground/20 group">
                    <div className="flex items-center gap-3 mb-2">
                        <span className="text-2xl group-hover:scale-110 transition-transform">Audit</span>
                        <span className="font-semibold text-foreground">Audit Logs</span>
                    </div>
                    <div className="text-2xl font-bold text-primary">
                        {formatNumber(overview.auditStats.todayEvents)}
                    </div>
                    <div className="text-sm text-muted-foreground">Events today</div>
                </Link>
                <Link href="/gdpr" className="block bg-card rounded-xl border border-border p-5 shadow-sm hover:shadow-md transition-all hover:border-muted-foreground/20 group">
                    <div className="flex items-center gap-3 mb-2">
                        <span className="text-2xl group-hover:scale-110 transition-transform">GDPR</span>
                        <span className="font-semibold text-foreground">GDPR Requests</span>
                    </div>
                    <div className="text-2xl font-bold text-primary">
                        {overview.gdprRequests.pending + overview.gdprRequests.processing}
                    </div>
                    <div className="text-sm text-muted-foreground">Pending requests</div>
                </Link>
                <Link href="/secrets" className="block bg-card rounded-xl border border-border p-5 shadow-sm hover:shadow-md transition-all hover:border-muted-foreground/20 group">
                    <div className="flex items-center gap-3 mb-2">
                        <span className="text-2xl group-hover:scale-110 transition-transform">Vault</span>
                        <span className="font-semibold text-foreground">Secrets Vault</span>
                    </div>
                    <div className="text-2xl font-bold text-success">
                        Secure
                    </div>
                    <div className="text-sm text-muted-foreground">All secrets encrypted</div>
                </Link>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Risk Distribution */}
                <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                    <h2 className="text-lg font-semibold text-foreground mb-6">Tenant Risk Distribution</h2>
                    <div className="space-y-5">
                        {[
                            { level: 'low' as const, count: overview.riskSummary.low, label: 'Low Risk' },
                            { level: 'medium' as const, count: overview.riskSummary.medium, label: 'Medium Risk' },
                            { level: 'high' as const, count: overview.riskSummary.high, label: 'High Risk' },
                            { level: 'critical' as const, count: overview.riskSummary.critical, label: 'Critical' },
                        ].map(({ level, count, label }) => (
                            <div key={level} className="flex items-center gap-4">
                                <div className="w-24 text-sm font-medium text-muted-foreground">{label}</div>
                                <div className="flex-1 bg-muted rounded-full h-3 overflow-hidden">
                                    <svg width="100%" height="100%" viewBox="0 0 100 12" preserveAspectRatio="none" aria-hidden="true">
                                        <rect
                                            x="0"
                                            y="0"
                                            width={Math.max(0, Math.min(100, (count / Math.max(totalTenants, 1)) * 100))}
                                            height="12"
                                            className={cn(
                                                level === 'low' && 'fill-success',
                                                level === 'medium' && 'fill-warning',
                                                level === 'high' && 'fill-orange-500',
                                                level === 'critical' && 'fill-destructive'
                                            )}
                                        />
                                    </svg>
                                </div>
                                <div className="w-16 text-right font-medium text-foreground">{count}</div>
                            </div>
                        ))}
                    </div>
                    <div className="mt-4 pt-4 border-t border-border text-sm text-muted-foreground">
                        {totalTenants} total tenants monitored
                    </div>
                </div>

                {/* Policy Compliance */}
                <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
                    <h2 className="text-lg font-semibold text-foreground mb-6">Policy Compliance</h2>
                    <div className="space-y-4">
                        {overview.policyCompliance.map((policy) => (
                            <div key={policy.name} className="flex items-center justify-between">
                                <div className="text-sm font-medium text-foreground">{policy.name}</div>
                                <div className="flex items-center gap-3">
                                    <div className="w-32 bg-muted rounded-full h-2 overflow-hidden">
                                        <svg width="100%" height="100%" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true">
                                            <rect
                                                x="0"
                                                y="0"
                                                width={Math.max(0, Math.min(100, (policy.compliant / Math.max(policy.total, 1)) * 100))}
                                                height="8"
                                                className={cn(
                                                    policy.compliant / policy.total >= 0.95 && 'fill-success',
                                                    policy.compliant / policy.total >= 0.8 && policy.compliant / policy.total < 0.95 && 'fill-warning',
                                                    policy.compliant / policy.total < 0.8 && 'fill-destructive'
                                                )}
                                            />
                                        </svg>
                                    </div>
                                    <span className={cn(
                                        'text-sm font-bold w-12 text-right',
                                        policy.compliant / policy.total >= 0.95 && 'text-success',
                                        policy.compliant / policy.total >= 0.8 && policy.compliant / policy.total < 0.95 && 'text-warning',
                                        policy.compliant / policy.total < 0.8 && 'text-destructive'
                                    )}>
                                        {Math.round((policy.compliant / policy.total) * 100)}%
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Recent Alerts */}
                <div className="lg:col-span-2 bg-card rounded-xl border border-border p-6 shadow-sm">
                    <div className="flex items-center justify-between mb-6">
                        <h2 className="text-lg font-semibold text-foreground">Recent Compliance Alerts</h2>
                        <Link href="/audit" className="text-sm font-medium text-primary hover:text-primary/90 hover:underline">
                            View all →
                        </Link>
                    </div>
                    <div className="space-y-2">
                        {overview.recentAlerts.map((alert) => (
                            <div key={alert.id} className="flex items-start gap-4 p-4 rounded-xl hover:bg-muted/50 transition-colors border border-transparent hover:border-border">
                                <span className={cn(
                                    'px-2.5 py-0.5 rounded-md text-xs font-bold uppercase tracking-wide border',
                                    alert.severity === 'critical' ? 'bg-destructive/10 text-destructive border-destructive/20' :
                                    alert.severity === 'high' ? 'bg-orange-500/10 text-orange-600 border-orange-500/20' :
                                    alert.severity === 'medium' ? 'bg-warning/10 text-warning border-warning/20' :
                                    'bg-info/10 text-info border-info/20'
                                )}>
                                    {alert.severity}
                                </span>
                                <div className="flex-1 min-w-0">
                                    <div className="text-sm font-medium text-foreground">{alert.message}</div>
                                    <div className="text-xs text-muted-foreground mt-1 flex items-center gap-2">
                                        <span className="font-semibold">{alert.type}</span>
                                        <span>•</span>
                                        <span>{new Date(alert.timestamp).toLocaleString()}</span>
                                    </div>
                                </div>
                                <button aria-label={`Investigate compliance alert: ${alert.message}`} type="button" className="text-sm font-medium text-primary hover:text-primary/80 whitespace-nowrap">
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
