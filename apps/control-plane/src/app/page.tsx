'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { 
    Target, 
    Mail, 
    Euro, 
    Activity, 
    AlertTriangle, 
    ShieldCheck, 
    Lock,
    ArrowRight,
} from '../components/ui/icons';
import { cn, formatNumber, formatTimeWithSeconds, getLocalTimeZone, timeAgo } from '../lib/utils';

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

function DashboardLoadingSkeleton() {
    return (
        <div className="cp-page animate-pulse">
            <div className="mb-10">
                <div className="h-10 w-48 rounded bg-muted" />
                <div className="mt-2 h-4 w-96 rounded bg-muted" />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
                {Array.from({ length: 4 }).map((_, idx) => (
                    <div key={idx} className="h-36 rounded-xl bg-muted" />
                ))}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 h-72 rounded-xl bg-muted" />
                <div className="h-72 rounded-xl bg-muted" />
            </div>
        </div>
    );
}

export default function ControlPlaneDashboard() {
    const [stats, setStats] = useState<DashboardStats | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [currentTime, setCurrentTime] = useState<string>('');
    const timezone = getLocalTimeZone();

    useEffect(() => {
        setCurrentTime(formatTimeWithSeconds(new Date()));
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
        return <DashboardLoadingSkeleton />;
    }

    if (!stats) return null;

    return (
        <div className="cp-page">
            <div className="mb-10">
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-3xl font-bold text-foreground tracking-tight">Control Plane</h1>
                        <p className="text-surface-500 mt-1 font-medium">
                            Platform operations & infrastructure governance • Last updated: {currentTime} ({timezone})
                        </p>
                    </div>
                    {error && (
                        <div className="px-3 py-1.5 bg-warning/10 border border-warning/20 rounded-lg text-warning text-sm">
                            Warning: Using cached data - {error}
                        </div>
                    )}
                </div>
            </div>

            {/* Critical Alerts */}
            {(stats.compliance.riskAlerts > 0 || stats.compliance.criticalTenants > 0) && (
                <div className="mb-6 p-4 bg-destructive/10 border border-destructive/20 rounded-lg">
                    <div className="flex items-center gap-2 text-destructive font-semibold mb-2">
                        <AlertTriangle className="w-5 h-5" />
                        Requires Attention
                    </div>
                    <div className="flex gap-4 text-sm text-destructive">
                        {stats.compliance.riskAlerts > 0 && (
                            <Link href="/risk" className="hover:underline flex items-center gap-1.5 px-3 py-1 rounded-full bg-destructive/10 border border-destructive/20 transition-colors hover:bg-destructive/20">
                                <span className="font-bold">{stats.compliance.riskAlerts}</span> risk alert{stats.compliance.riskAlerts > 1 ? 's' : ''}
                            </Link>
                        )}
                        {stats.compliance.criticalTenants > 0 && (
                            <Link href="/risk" className="hover:underline flex items-center gap-1.5 px-3 py-1 rounded-full bg-destructive/10 border border-destructive/20 transition-colors hover:bg-destructive/20">
                                <span className="font-bold">{stats.compliance.criticalTenants}</span> critical tenant{stats.compliance.criticalTenants > 1 ? 's' : ''}
                            </Link>
                        )}
                        {stats.compliance.gdprPending > 0 && (
                            <Link href="/gdpr" className="hover:underline flex items-center gap-1.5 px-3 py-1 rounded-full bg-destructive/10 border border-destructive/20 transition-colors hover:bg-destructive/20">
                                <span className="font-bold">{stats.compliance.gdprPending}</span> pending GDPR request{stats.compliance.gdprPending > 1 ? 's' : ''}
                            </Link>
                        )}
                    </div>
                </div>
            )}

            {/* Quick Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
                <StatCard
                    title="Active Leads"
                    value={formatNumber(stats.sales.activeLeads)}
                    change={`+${stats.sales.leadsThisWeek} this week`}
                    icon={<Target className="w-5 h-5" />}
                    href="/crm"
                    color="text-brand-600"
                    bgColor="bg-brand-50"
                />
                <StatCard
                    title="Campaigns Running"
                    value={stats.sales.campaignsRunning.toString()}
                    change={`${stats.sales.demosScheduled} demos scheduled`}
                    icon={<Mail className="w-5 h-5" />}
                    href="/campaigns"
                    color="text-brand-600"
                    bgColor="bg-brand-50"
                />
                <StatCard
                    title="Monthly Revenue"
                    value={`€${formatNumber(stats.platform.mrr)}`}
                    change={`${stats.platform.activeTenants} active tenants`}
                    icon={<Euro className="w-5 h-5" />}
                    href="/revenue"
                    color="text-brand-600"
                    bgColor="bg-brand-50"
                />
                <StatCard
                    title="Platform Health"
                    value={stats.platform.healthStatus === 'healthy' ? 'All Systems Go' : 'Issues Detected'}
                    change={`${formatNumber(stats.platform.totalEmails)} emails sent`}
                    icon={stats.platform.healthStatus === 'healthy' ? <Activity className="w-5 h-5" /> : <AlertTriangle className="w-5 h-5" />}
                    variant={stats.platform.healthStatus === 'healthy' ? 'success' : 'warning'}
                    color={stats.platform.healthStatus === 'healthy' ? 'text-success-600' : 'text-warning-600'}
                    bgColor={stats.platform.healthStatus === 'healthy' ? 'bg-success-50' : 'bg-warning-50'}
                />
            </div>

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Sales Overview */}
                <div className="lg:col-span-2 apex-card rounded-2xl p-6">
                    <div className="flex items-center justify-between mb-6">
                        <h2 className="text-lg font-bold text-foreground">Sales Pipeline</h2>
                        <Link href="/crm" className="text-sm text-brand-600 hover:text-brand-700 font-bold">
                            View CRM →
                        </Link>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
                        <PipelineStage label="Prospects" count={stats.pipeline?.prospect ?? 0} color="bg-surface-50" />
                        <PipelineStage label="Outreach" count={stats.pipeline?.outreach ?? 0} color="bg-brand-50" />
                        <PipelineStage label="Engaged" count={stats.pipeline?.engaged ?? 0} color="bg-warning-50" />
                        <PipelineStage label="Demo" count={stats.pipeline?.demo ?? 0} color="bg-info-50" />
                        <PipelineStage label="Closed" count={stats.pipeline?.closed ?? 0} color="bg-success-50" />
                    </div>
                    <div className="mt-8 pt-6 border-t border-surface-50">
                        <div className="flex items-center justify-between text-sm">
                            <span className="font-bold text-surface-500 uppercase tracking-widest text-[11px]">Conversion Rate</span>
                            <span className="font-bold text-surface-900 apex-metric-number flex items-center gap-1">
                                {(stats.sales.conversionRate * 100).toFixed(1)}%
                                <ArrowRight className="w-3.5 h-3.5 text-surface-400" />
                            </span>
                        </div>
                    </div>
                </div>

                {/* Compliance Status */}
                <div className="apex-card rounded-2xl p-6">
                    <div className="flex items-center justify-between mb-6">
                        <h2 className="text-lg font-bold text-foreground">Compliance</h2>
                        <Link href="/compliance" className="text-sm text-brand-600 hover:text-brand-700 font-bold">
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
            <div className="mt-8 apex-card rounded-2xl p-6">
                <h2 className="text-lg font-bold text-foreground mb-6">Recent Activity</h2>
                <div className="space-y-1">
                    {stats.recentActivity.map((activity) => (
                        <div key={activity.id} className="flex items-center gap-4 py-3 border-b border-surface-50 last:border-0 group hover:bg-surface-50/50 transition-colors -mx-2 px-2 rounded-lg">
                            <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-surface-50 text-surface-400 group-hover:bg-brand-50 group-hover:text-brand-600 transition-colors">
                                {activity.type === 'lead' && <Target className="w-4 h-4" />}
                                {activity.type === 'risk' && <AlertTriangle className="w-4 h-4" />}
                                {activity.type === 'campaign' && <Mail className="w-4 h-4" />}
                                {activity.type === 'gdpr' && <ShieldCheck className="w-4 h-4" />}
                                {activity.type === 'revenue' && <Euro className="w-4 h-4" />}
                            </span>
                            <span className="flex-1 text-sm font-medium text-surface-700">{activity.message}</span>
                            <span className="text-xs text-surface-400 font-bold apex-metric-number uppercase">{timeAgo(activity.timestamp)}</span>
                        </div>
                    ))}
                </div>
            </div>

            {/* Process Isolation Status */}
            <div className="mt-8 bg-gradient-to-br from-brand-600 to-brand-800 rounded-2xl p-8 text-white shadow-xl shadow-brand-500/20 relative overflow-hidden">
                <div className="absolute top-0 right-0 p-4 opacity-10">
                    <Lock className="w-32 h-32 rotate-12" />
                </div>
                <h2 className="text-xl font-bold mb-6 flex items-center gap-3 relative z-10">
                    <Lock className="w-5 h-5" />
                    Infrastructure Isolation
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-6 relative z-10">
                    <ProcessCard name="Control Plane" port="3020" status="isolated" />
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
    color = 'text-primary',
    bgColor = 'bg-primary/5',
}: {
    title: string;
    value: string;
    change: string;
    icon: React.ReactNode;
    href?: string;
    variant?: 'default' | 'success' | 'warning';
    color?: string;
    bgColor?: string;
}) {
    const content = (
        <div className={cn(
            'apex-card rounded-2xl p-6 transition-premium hover:-translate-y-0.5',
            variant === 'success' ? 'border-success/30' : variant === 'warning' ? 'border-warning/30' : ''
        )}>
            <div className="flex items-center justify-between mb-4">
                <div className={cn('p-2.5 rounded-xl transition-colors', bgColor)}>
                    <span className={color}>{icon}</span>
                </div>
                {href && <ArrowRight className="w-4 h-4 text-surface-400 group-hover:text-brand-600 transition-colors" />}
            </div>
            <div className="text-3xl apex-metric-number">{value}</div>
            <div className="text-xs font-bold uppercase tracking-widest text-surface-500 mt-2">{title}</div>
            <div className="text-sm font-medium text-surface-400 mt-1">{change}</div>
        </div>
    );

    return href ? (
        <Link href={href} className="block group" aria-label={`View ${title} details`}>
            {content}
        </Link>
    ) : content;
}

function PipelineStage({ label, count, color }: { label: string; count: number; color: string }) {
    return (
        <div className="text-center group">
            <div className={cn(color, "rounded-2xl py-8 mb-3 transition-all duration-300 group-hover:scale-105 group-hover:shadow-md border border-transparent group-hover:border-surface-100")}>
                <div className="text-3xl apex-metric-number">{count}</div>
            </div>
            <div className="text-[11px] font-bold uppercase tracking-widest text-surface-400 group-hover:text-surface-600 transition-colors">{label}</div>
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
        good: 'text-success-700 bg-success-50 border-success-100',
        warning: 'text-warning-700 bg-warning-50 border-warning-100',
        critical: 'text-danger-700 bg-danger-50 border-danger-100',
        info: 'text-brand-700 bg-brand-50 border-brand-100',
    };

    return (
        <div className="flex items-center justify-between py-2 border-b border-surface-50 last:border-0">
            <span className="text-[13px] font-bold text-surface-500 uppercase tracking-widest">{label}</span>
            <span className={cn("px-3 py-1 rounded-full text-xs font-bold apex-metric-number border shadow-sm", statusColors[status])}>
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
        <div className="bg-white/10 backdrop-blur-md rounded-xl p-5 border border-white/10 hover:bg-white/15 transition-colors">
            <div className="text-[11px] font-bold uppercase tracking-widest text-white/60 mb-1">{name}</div>
            <div className="text-xl apex-metric-number">Port {port}</div>
            <div className={`text-xs font-bold flex items-center gap-2 mt-3 ${status === 'isolated' ? 'text-success-400' : 'text-white/40'}`}>
                <span className={`w-2 h-2 rounded-full ${status === 'isolated' ? 'bg-success-400 shadow-[0_0_8px_rgba(74,222,128,0.5)]' : 'bg-white/20'}`}></span>
                {status === 'isolated' ? 'Isolated' : 'Disconnected'}
            </div>
        </div>
    );
}
