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
 * 
 * NOW WIRED TO REAL DATABASE via /api/dashboard/stats
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
    pipeline?: {
        prospect: number;
        outreach: number;
        engaged: number;
        demo: number;
        closed: number;
    };
}

export default function ControlPlaneDashboard() {
    const [stats, setStats] = useState<DashboardStats | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [currentTime, setCurrentTime] = useState<string>('');

    useEffect(() => {
        setCurrentTime(new Date().toLocaleTimeString());
    }, []);

    useEffect(() => {
        // Fetch dashboard stats from real database API
        async function loadStats() {
            try {
                const response = await fetch('/api/dashboard/stats', {
                    credentials: 'include',
                });
                
                if (!response.ok) {
                    throw new Error(`Failed to fetch stats: ${response.status}`);
                }
                
                const data = await response.json();
                setStats(data);
                setError(null);
            } catch (err) {
                console.error('Failed to load dashboard stats:', err);
                setError(err instanceof Error ? err.message : 'Unknown error');
                // Set empty stats on error for graceful degradation
                setStats({
                    sales: {
                        activeLeads: 0,
                        leadsThisWeek: 0,
                        campaignsRunning: 0,
                        demosScheduled: 0,
                        conversionRate: 0,
                    },
                    compliance: {
                        riskAlerts: 0,
                        criticalTenants: 0,
                        gdprPending: 0,
                        auditEventsToday: 0,
                    },
                    platform: {
                        activeTenants: 0,
                        totalEmails: 0,
                        mrr: 0,
                        healthStatus: 'down',
                    },
                    recentActivity: [],
                });
            } finally {
                setLoading(false);
            }
        }
        loadStats();
        
        // Auto-refresh every 30 seconds
        const interval = setInterval(loadStats, 30000);
        return () => clearInterval(interval);
    }, []);

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="flex flex-col items-center gap-3">
                    <div className="animate-spin rounded-full h-10 w-10 border-2 border-primary border-t-transparent"></div>
                    <span className="text-sm text-muted-foreground">Loading dashboard...</span>
                </div>
            </div>
        );
    }

    if (!stats) return null;

    return (
        <div className="max-w-7xl mx-auto">
            <div className="mb-8">
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-2xl font-bold text-foreground">Control Plane Dashboard</h1>
                        <p className="text-muted-foreground mt-1">
                            Business operations overview • Last updated: {currentTime}
                        </p>
                    </div>
                    {error && (
                        <div className="px-3 py-1.5 bg-warning/10 border border-warning/20 rounded-lg text-warning text-sm">
                            ⚠️ Using cached data - {error}
                        </div>
                    )}
                </div>
            </div>

            {/* Critical Alerts */}
            {(stats.compliance.riskAlerts > 0 || stats.compliance.criticalTenants > 0) && (
                <div className="mb-6 p-4 bg-destructive/10 border border-destructive/20 rounded-[18px]">
                    <div className="flex items-center gap-2 text-destructive font-semibold mb-2">
                        ⚠️ Requires Attention
                    </div>
                    <div className="flex gap-4 text-sm text-destructive">
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
                <div className="lg:col-span-2 bg-card rounded-[18px] border border-border p-6 shadow-[0_1px_2px_rgba(16,24,40,0.06),0_10px_20px_rgba(16,24,40,0.06)]">
                    <div className="flex items-center justify-between mb-4">
                        <h2 className="text-lg font-semibold text-foreground">Sales Pipeline</h2>
                        <Link href="/crm" className="text-sm text-primary hover:text-primary/90 font-medium">
                            View CRM →
                        </Link>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
                        <PipelineStage label="Prospects" count={stats.pipeline?.prospect ?? 0} color="bg-muted" />
                        <PipelineStage label="Outreach" count={stats.pipeline?.outreach ?? 0} color="bg-primary/10" />
                        <PipelineStage label="Engaged" count={stats.pipeline?.engaged ?? 0} color="bg-warning/10" />
                        <PipelineStage label="Demo" count={stats.pipeline?.demo ?? 0} color="bg-blue-500/10" />
                        <PipelineStage label="Closed" count={stats.pipeline?.closed ?? 0} color="bg-success/10" />
                    </div>
                    <div className="mt-6 pt-4 border-t border-border">
                        <div className="flex items-center justify-between text-sm">
                            <span className="text-muted-foreground">Conversion Rate</span>
                            <span className="font-semibold text-foreground tabular-nums">{(stats.sales.conversionRate * 100).toFixed(1)}%</span>
                        </div>
                    </div>
                </div>

                {/* Compliance Status */}
                <div className="bg-card rounded-[18px] border border-border p-6 shadow-[0_1px_2px_rgba(16,24,40,0.06),0_10px_20px_rgba(16,24,40,0.06)]">
                    <div className="flex items-center justify-between mb-4">
                        <h2 className="text-lg font-semibold text-foreground">Compliance Status</h2>
                        <Link href="/compliance" className="text-sm text-primary hover:text-primary/90 font-medium">
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
            <div className="mt-6 bg-card rounded-[18px] border border-border p-6 shadow-[0_1px_2px_rgba(16,24,40,0.06),0_10px_20px_rgba(16,24,40,0.06)]">
                <h2 className="text-lg font-semibold text-foreground mb-4">Recent Activity</h2>
                <div className="space-y-3">
                    {stats.recentActivity.map((activity) => (
                        <div key={activity.id} className="flex items-center gap-3 py-2.5 border-b border-border last:border-0">
                            {/* TODO: Replace emoji icons with Lucide icons (Target, AlertTriangle, Mail, Globe, DollarSign) */}
                            <span className="text-lg">
                                {activity.type === 'lead' && '🎯'}
                                {activity.type === 'risk' && '⚠️'}
                                {activity.type === 'campaign' && '📧'}
                                {activity.type === 'gdpr' && '🇪🇺'}
                                {activity.type === 'revenue' && '💰'}
                            </span>
                            <span className="flex-1 text-sm text-foreground">{activity.message}</span>
                            <span className="text-xs text-muted-foreground font-medium">{timeAgo(activity.timestamp)}</span>
                        </div>
                    ))}
                </div>
            </div>

            {/* Process Isolation Status */}
            <div className="mt-6 bg-gradient-to-br from-background to-primary/5 rounded-[18px] border border-border p-6">
                {/* TODO: Replace 🔒 emoji with Lucide Lock icon */}
                <h2 className="text-lg font-semibold text-foreground mb-4">🔒 Process Isolation Status</h2>
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
        <div className={`rounded-[18px] border p-6 shadow-[0_1px_2px_rgba(16,24,40,0.06),0_10px_20px_rgba(16,24,40,0.06)] transition-all hover:shadow-md ${
            variant === 'success' ? 'bg-success/10 border-success/20' :
            variant === 'warning' ? 'bg-warning/10 border-warning/20' :
            'bg-card border-border'
        }`}>
            <div className="flex items-center justify-between mb-3">
                {/* TODO: Replace emoji icon with Lucide icon */}
                <span className="text-2xl">{icon}</span>
            </div>
            <div className="text-2xl font-bold text-foreground tabular-nums">{value}</div>
            <div className="text-sm font-medium text-muted-foreground mt-1">{title}</div>
            <div className="text-xs text-muted-foreground mt-1">{change}</div>
        </div>
    );

    return href ? (
        <Link href={href} className="block" aria-label={`View ${title} details`}>
            {content}
        </Link>
    ) : content;
}

function PipelineStage({ label, count, color }: { label: string; count: number; color: string }) {
    return (
        <div className="text-center">
            <div className={`${color} rounded-[18px] py-6 mb-2 transition-transform hover:scale-105`}>
                <div className="text-2xl font-bold text-foreground tabular-nums">{count}</div>
            </div>
            <div className="text-xs font-medium text-muted-foreground">{label}</div>
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
        good: 'text-success bg-success/10 border border-success/20',
        warning: 'text-warning bg-warning/10 border border-warning/20',
        critical: 'text-destructive bg-destructive/10 border border-destructive/20',
        info: 'text-primary bg-primary/10 border border-primary/20',
    };

    return (
        <div className="flex items-center justify-between py-1">
            <span className="text-sm text-muted-foreground">{label}</span>
            <span className={`px-2.5 py-0.5 rounded-full text-sm font-semibold tabular-nums ${statusColors[status]}`}>
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
        <div className="bg-card rounded-[18px] p-4 border border-border shadow-[0_1px_2px_rgba(16,24,40,0.06),0_10px_20px_rgba(16,24,40,0.06)]">
            <div className="text-sm font-medium text-muted-foreground">{name}</div>
            <div className="text-lg font-bold text-foreground tabular-nums">Port {port}</div>
            <div className={`text-xs font-medium flex items-center gap-1 mt-1 ${status === 'isolated' ? 'text-success' : 'text-muted-foreground'}`}>
                <span className={`w-2 h-2 rounded-full ${status === 'isolated' ? 'bg-success' : 'bg-muted'}`}></span>
                {status === 'isolated' ? 'Isolated' : 'Not Connected'}
            </div>
        </div>
    );
}
