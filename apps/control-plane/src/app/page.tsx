'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { formatNumber, timeAgo } from '../lib/utils';

/**
 * Control Plane Dashboard
 * 
 * Provides the business owner with a unified view of:
 * - Sales pipeline performance
 * - Platform health and compliance status
 * - Revenue metrics
 * - Critical alerts requiring attention
 */

interface DashboardStats {
    sales: {
        activeLeads: number;
        leadsThisWeek: number;
        campaignsRunning: number;
        demosScheduled: number;
        conversionRate: number;
    };
    compliance: {
        riskAlerts: number;
        criticalTenants: number;
        gdprPending: number;
        auditEventsToday: number;
    };
    platform: {
        activeTenants: number;
        totalEmails: number;
        mrr: number;
        healthStatus: 'healthy' | 'degraded' | 'down';
    };
    recentActivity: Array<{
        id: string;
        type: string;
        message: string;
        timestamp: string;
    }>;
}

export default function ControlPlaneDashboard() {
    const [stats, setStats] = useState<DashboardStats | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // Fetch dashboard stats from APIs
        async function loadStats() {
            try {
                // In production, these would be real API calls
                // For now, use realistic placeholder data
                setStats({
                    sales: {
                        activeLeads: 247,
                        leadsThisWeek: 32,
                        campaignsRunning: 8,
                        demosScheduled: 5,
                        conversionRate: 0.12,
                    },
                    compliance: {
                        riskAlerts: 2,
                        criticalTenants: 1,
                        gdprPending: 3,
                        auditEventsToday: 1847,
                    },
                    platform: {
                        activeTenants: 156,
                        totalEmails: 2847923,
                        mrr: 45890,
                        healthStatus: 'healthy',
                    },
                    recentActivity: [
                        { id: '1', type: 'lead', message: 'New high-score lead: TechCorp Inc.', timestamp: new Date(Date.now() - 300000).toISOString() },
                        { id: '2', type: 'risk', message: 'Tenant "spammy.io" flagged for high bounce rate', timestamp: new Date(Date.now() - 1800000).toISOString() },
                        { id: '3', type: 'campaign', message: 'Campaign "SaaS Founders" reached 1000 emails', timestamp: new Date(Date.now() - 3600000).toISOString() },
                        { id: '4', type: 'gdpr', message: 'New data deletion request from user@example.com', timestamp: new Date(Date.now() - 7200000).toISOString() },
                        { id: '5', type: 'revenue', message: 'New enterprise contract signed: €2,500/mo', timestamp: new Date(Date.now() - 14400000).toISOString() },
                    ],
                });
            } finally {
                setLoading(false);
            }
        }
        loadStats();
    }, []);

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="flex flex-col items-center gap-3">
                    <div className="animate-spin rounded-full h-10 w-10 border-2 border-blue-600 border-t-transparent"></div>
                    <span className="text-sm text-surface-500">Loading dashboard...</span>
                </div>
            </div>
        );
    }

    if (!stats) return null;

    return (
        <div className="max-w-7xl mx-auto">
            <div className="mb-8">
                <h1 className="text-2xl font-bold text-surface-900">Control Plane Dashboard</h1>
                <p className="text-surface-500 mt-1">
                    Business operations overview • Last updated: {new Date().toLocaleTimeString()}
                </p>
            </div>

            {/* Critical Alerts */}
            {(stats.compliance.riskAlerts > 0 || stats.compliance.criticalTenants > 0) && (
                <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-xl">
                    <div className="flex items-center gap-2 text-red-800 font-semibold mb-2">
                        ⚠️ Requires Attention
                    </div>
                    <div className="flex gap-4 text-sm text-red-700">
                        {stats.compliance.riskAlerts > 0 && (
                            <Link href="/risk" className="hover:underline flex items-center gap-1">
                                <span className="font-medium">{stats.compliance.riskAlerts}</span> risk alert{stats.compliance.riskAlerts > 1 ? 's' : ''}
                            </Link>
                        )}
                        {stats.compliance.criticalTenants > 0 && (
                            <Link href="/risk" className="hover:underline flex items-center gap-1">
                                <span className="font-medium">{stats.compliance.criticalTenants}</span> critical tenant{stats.compliance.criticalTenants > 1 ? 's' : ''}
                            </Link>
                        )}
                        {stats.compliance.gdprPending > 0 && (
                            <Link href="/gdpr" className="hover:underline flex items-center gap-1">
                                <span className="font-medium">{stats.compliance.gdprPending}</span> pending GDPR request{stats.compliance.gdprPending > 1 ? 's' : ''}
                            </Link>
                        )}
                    </div>
                </div>
            )}

            {/* Quick Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
                <StatCard
                    title="Active Leads"
                    value={formatNumber(stats.sales.activeLeads)}
                    change={`+${stats.sales.leadsThisWeek} this week`}
                    icon="🎯"
                    href="/crm"
                />
                <StatCard
                    title="Campaigns Running"
                    value={stats.sales.campaignsRunning.toString()}
                    change={`${stats.sales.demosScheduled} demos scheduled`}
                    icon="📧"
                    href="/campaigns"
                />
                <StatCard
                    title="Monthly Revenue"
                    value={`€${formatNumber(stats.platform.mrr)}`}
                    change={`${stats.platform.activeTenants} active tenants`}
                    icon="💰"
                    href="/revenue"
                />
                <StatCard
                    title="Platform Health"
                    value={stats.platform.healthStatus === 'healthy' ? 'All Systems Go' : 'Issues Detected'}
                    change={`${formatNumber(stats.platform.totalEmails)} emails sent`}
                    icon={stats.platform.healthStatus === 'healthy' ? '✅' : '⚠️'}
                    variant={stats.platform.healthStatus === 'healthy' ? 'success' : 'warning'}
                />
            </div>

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Sales Overview */}
                <div className="lg:col-span-2 bg-surface-0 rounded-xl border border-surface-200 p-6 shadow-sm">
                    <div className="flex items-center justify-between mb-4">
                        <h2 className="text-lg font-semibold text-surface-900">Sales Pipeline</h2>
                        <Link href="/crm" className="text-sm text-blue-600 hover:text-blue-700 font-medium">
                            View CRM →
                        </Link>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
                        <PipelineStage label="Prospects" count={89} color="bg-surface-100" />
                        <PipelineStage label="Outreach" count={64} color="bg-blue-100" />
                        <PipelineStage label="Engaged" count={47} color="bg-amber-100" />
                        <PipelineStage label="Demo" count={32} color="bg-violet-100" />
                        <PipelineStage label="Closed" count={15} color="bg-emerald-100" />
                    </div>
                    <div className="mt-6 pt-4 border-t border-surface-100">
                        <div className="flex items-center justify-between text-sm">
                            <span className="text-surface-600">Conversion Rate</span>
                            <span className="font-semibold text-surface-900">{(stats.sales.conversionRate * 100).toFixed(1)}%</span>
                        </div>
                    </div>
                </div>

                {/* Compliance Status */}
                <div className="bg-surface-0 rounded-xl border border-surface-200 p-6 shadow-sm">
                    <div className="flex items-center justify-between mb-4">
                        <h2 className="text-lg font-semibold text-surface-900">Compliance Status</h2>
                        <Link href="/compliance" className="text-sm text-blue-600 hover:text-blue-700 font-medium">
                            View All →
                        </Link>
                    </div>
                    <div className="space-y-4">
                        <ComplianceItem
                            label="Risk Alerts"
                            value={stats.compliance.riskAlerts}
                            status={stats.compliance.riskAlerts > 0 ? 'warning' : 'good'}
                        />
                        <ComplianceItem
                            label="GDPR Pending"
                            value={stats.compliance.gdprPending}
                            status={stats.compliance.gdprPending > 5 ? 'warning' : 'good'}
                        />
                        <ComplianceItem
                            label="Audit Events Today"
                            value={stats.compliance.auditEventsToday}
                            status="info"
                        />
                        <ComplianceItem
                            label="Critical Tenants"
                            value={stats.compliance.criticalTenants}
                            status={stats.compliance.criticalTenants > 0 ? 'critical' : 'good'}
                        />
                    </div>
                </div>
            </div>

            {/* Recent Activity */}
            <div className="mt-6 bg-surface-0 rounded-xl border border-surface-200 p-6 shadow-sm">
                <h2 className="text-lg font-semibold text-surface-900 mb-4">Recent Activity</h2>
                <div className="space-y-3">
                    {stats.recentActivity.map((activity) => (
                        <div key={activity.id} className="flex items-center gap-3 py-2.5 border-b border-surface-50 last:border-0">
                            <span className="text-lg">
                                {activity.type === 'lead' && '🎯'}
                                {activity.type === 'risk' && '⚠️'}
                                {activity.type === 'campaign' && '📧'}
                                {activity.type === 'gdpr' && '🇪🇺'}
                                {activity.type === 'revenue' && '💰'}
                            </span>
                            <span className="flex-1 text-sm text-surface-700">{activity.message}</span>
                            <span className="text-xs text-surface-400 font-medium">{timeAgo(activity.timestamp)}</span>
                        </div>
                    ))}
                </div>
            </div>

            {/* Process Isolation Status */}
            <div className="mt-6 bg-gradient-to-br from-surface-50 to-blue-50 rounded-xl border border-surface-200 p-6">
                <h2 className="text-lg font-semibold text-surface-900 mb-4">🔒 Process Isolation Status</h2>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <ProcessCard name="Control Plane UI" port="3020" status="isolated" />
                    <ProcessCard name="Sales Autopilot" port="3010" status="isolated" />
                    <ProcessCard name="Compliance API" port="3011" status="isolated" />
                    <ProcessCard name="Customer API" port="3001" status="disconnected" />
                </div>
            </div>
        </div>
    );
}

function StatCard({
    title,
    value,
    change,
    icon,
    href,
    variant = 'default',
}: {
    title: string;
    value: string;
    change: string;
    icon: string;
    href?: string;
    variant?: 'default' | 'success' | 'warning';
}) {
    const content = (
        <div className={`rounded-xl border p-6 shadow-sm transition-all hover:shadow-md ${
            variant === 'success' ? 'bg-emerald-50 border-emerald-200' :
            variant === 'warning' ? 'bg-amber-50 border-amber-200' :
            'bg-surface-0 border-surface-200'
        }`}>
            <div className="flex items-center justify-between mb-3">
                <span className="text-2xl">{icon}</span>
            </div>
            <div className="text-2xl font-bold text-surface-900">{value}</div>
            <div className="text-sm font-medium text-surface-600 mt-1">{title}</div>
            <div className="text-xs text-surface-400 mt-1">{change}</div>
        </div>
    );

    return href ? (
        <Link href={href} className="block">
            {content}
        </Link>
    ) : content;
}

function PipelineStage({ label, count, color }: { label: string; count: number; color: string }) {
    return (
        <div className="text-center">
            <div className={`${color} rounded-xl py-6 mb-2 transition-transform hover:scale-105`}>
                <div className="text-2xl font-bold text-surface-900">{count}</div>
            </div>
            <div className="text-xs font-medium text-surface-600">{label}</div>
        </div>
    );
}

function ComplianceItem({
    label,
    value,
    status,
}: {
    label: string;
    value: number;
    status: 'good' | 'warning' | 'critical' | 'info';
}) {
    const statusColors = {
        good: 'text-emerald-700 bg-emerald-50 border border-emerald-100',
        warning: 'text-amber-700 bg-amber-50 border border-amber-100',
        critical: 'text-red-700 bg-red-50 border border-red-100',
        info: 'text-blue-700 bg-blue-50 border border-blue-100',
    };

    return (
        <div className="flex items-center justify-between py-1">
            <span className="text-sm text-surface-600">{label}</span>
            <span className={`px-2.5 py-0.5 rounded-full text-sm font-semibold ${statusColors[status]}`}>
                {formatNumber(value)}
            </span>
        </div>
    );
}

function ProcessCard({
    name,
    port,
    status,
}: {
    name: string;
    port: string;
    status: 'isolated' | 'disconnected';
}) {
    return (
        <div className="bg-surface-0 rounded-xl p-4 border border-surface-200 shadow-sm">
            <div className="text-sm font-medium text-surface-600">{name}</div>
            <div className="text-lg font-bold text-surface-900">Port {port}</div>
            <div className={`text-xs font-medium flex items-center gap-1 mt-1 ${status === 'isolated' ? 'text-emerald-600' : 'text-surface-400'}`}>
                <span className={`w-2 h-2 rounded-full ${status === 'isolated' ? 'bg-emerald-500' : 'bg-surface-300'}`}></span>
                {status === 'isolated' ? 'Isolated' : 'Not Connected'}
            </div>
        </div>
    );
}
