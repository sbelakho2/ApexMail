'use client';

import * as React from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
    Send,
    Mail,
    ArrowUpRight,
    ArrowDownRight,
    MoreHorizontal,
    Eye,
    MousePointer,
    Calendar,
    Zap,
    AlertCircle,
    Shield,
    FileText,
    Code2,
    RefreshCw,
} from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import { ApexAreaChart, ApexBarChart } from '@/components/charts';
import { cn, formatNumber, formatPercent, formatRelativeTime } from '@/lib/utils';
import { EmptyState } from '@/components/ui/empty-state';
import { StatusIndicator } from '@/components/ui/status-indicator';
import { useAPI, APIError } from '@/hooks/use-api';

// ---------- Types matching GET /v1/analytics/dashboard response ----------

interface DashboardData {
    period: { since: string; until: string };
    messages: { total: number; queued: number; sent: number; delivered: number; failed: number };
    engagement: {
        sent: number; delivered: number; opened: number; clicked: number;
        bounced: number; complained: number;
        rates: { delivery: string; open: string; click: string; bounce: string; complaint: string };
    };
    domains: { total: number; verified: number; pending: number; failed: number };
    suppressions: { total: number; bounces: number; complaints: number; unsubscribes: number; manual: number };
    health: { score: number; grade: string };
}

interface VolumePoint { date: string; sent: number; delivered: number; bounced: number }
interface EngagementPoint { date: string; opens: number; clicks: number; [key: string]: string | number }
interface RecentMessageApiRow {
    id?: string;
    subject?: string;
    status?: string;
    sentAt?: string;
    scheduledAt?: string;
    recipientCount?: number;
}

interface DashboardSourcesStatus {
    overview: 'ok' | 'error';
    volume: 'ok' | 'error';
    engagement: 'ok' | 'error';
    campaigns: 'ok' | 'error';
}

// ---------- Data fetching hook ----------

function useDashboard(windowDays: number, refreshKey: number) {
    const [lastUpdated, setLastUpdated] = React.useState<string | null>(null);
    const [loadingTimedOut, setLoadingTimedOut] = React.useState(false);
    const since = React.useMemo(() => new Date(Date.now() - windowDays * 86_400_000).toISOString(), [windowDays]);
    const until = React.useMemo(() => new Date().toISOString(), [windowDays, refreshKey]);

    const requestConfig = React.useMemo(
        () => ({
            refreshInterval: 300_000, // 5 min — analytics don't need real-time polling
            keepPreviousData: true,
        }),
        []
    );

    const dashboardQuery = useAPI<{ dashboard?: DashboardData }>(
        `/v1/analytics/dashboard?since=${since}&until=${until}`,
        requestConfig
    );
    const volumeQuery = useAPI<{ volume?: VolumePoint[] }>(
        `/v1/analytics/volume?since=${since}&until=${until}&granularity=day`,
        requestConfig
    );
    const engagementQuery = useAPI<{ engagement?: EngagementPoint[] }>(
        `/v1/analytics/engagement?since=${since}&until=${until}&granularity=day`,
        requestConfig
    );
    const messagesQuery = useAPI<{ messages?: RecentMessageApiRow[]; data?: RecentMessageApiRow[] }>(
        '/v1/messages?limit=5&sort=createdAt:desc',
        requestConfig
    );

    const loading = dashboardQuery.isLoading || volumeQuery.isLoading || engagementQuery.isLoading || messagesQuery.isLoading;

    const sourcesStatus: DashboardSourcesStatus = {
        overview: dashboardQuery.error ? 'error' : 'ok',
        volume: volumeQuery.error ? 'error' : 'ok',
        engagement: engagementQuery.error ? 'error' : 'ok',
        campaigns: messagesQuery.error ? 'error' : 'ok',
    };

    const data = dashboardQuery.data?.dashboard ?? null;
    const volume = volumeQuery.data?.volume ?? [];
    const engagement = engagementQuery.data?.engagement ?? [];
    const campaigns = React.useMemo(() => {
        const rows = (messagesQuery.data?.messages ?? messagesQuery.data?.data ?? []) as RecentMessageApiRow[];
        return rows.slice(0, 5).map((message) => ({
            id: message.id ?? crypto.randomUUID(),
            name: message.subject || 'Untitled',
            status: message.status ?? 'unknown',
            sentAt: message.sentAt,
            scheduledAt: message.scheduledAt,
            sent: message.recipientCount ?? 0,
            openRate: 0,
            clickRate: 0,
        }));
    }, [messagesQuery.data]);

    const firstError = [dashboardQuery.error, volumeQuery.error, engagementQuery.error, messagesQuery.error].find(Boolean) as APIError | undefined;
    const allSourcesFailed = Object.values(sourcesStatus).every((status) => status === 'error');
    const error = React.useMemo(() => {
        if (allSourcesFailed) return 'All analytics sources are currently unavailable.';
        if (!firstError) return null;
        const baseMessage = 'Temporary analytics fetch failure. Please retry.';
        return firstError.message ? `${baseMessage} (${firstError.message})` : baseMessage;
    }, [allSourcesFailed, firstError]);

    React.useEffect(() => {
        if (!loading) {
            setLoadingTimedOut(false);
            return;
        }

        const timer = window.setTimeout(() => {
            setLoadingTimedOut(true);
        }, 15_000);

        return () => window.clearTimeout(timer);
    }, [loading]);

    React.useEffect(() => {
        if (!loading) {
            setLastUpdated(new Date().toISOString());
        }
    }, [loading, data, volume.length, engagement.length, campaigns.length]);

    return { data, volume, engagement, campaigns, loading, error, lastUpdated, sourcesStatus, loadingTimedOut };
}

// ---------- Stat builder ----------

function buildStats(d: DashboardData | null) {
    if (!d) return [];
    const openRate = parseFloat(d.engagement.rates.open);
    const clickRate = parseFloat(d.engagement.rates.click);
    return [
        { title: 'Emails Delivered', value: d.engagement.delivered, change: parseFloat(d.engagement.rates.delivery), changeType: 'positive' as const, icon: Send, color: 'text-success', bgColor: 'bg-success/10' },
        { title: 'Emails Sent', value: d.engagement.sent, change: 0, changeType: 'positive' as const, icon: Mail, color: 'text-primary', bgColor: 'bg-primary/10' },
        { title: 'Open Rate', value: openRate, change: openRate, changeType: (openRate >= 20 ? 'positive' : 'negative') as 'positive' | 'negative', icon: Eye, color: 'text-warning', bgColor: 'bg-warning/10', isPercent: true },
        { title: 'Click Rate', value: clickRate, change: clickRate, changeType: (clickRate >= 2 ? 'positive' : 'negative') as 'positive' | 'negative', icon: MousePointer, color: 'text-danger', bgColor: 'bg-danger/10', isPercent: true },
    ];
}

function DashboardSkeleton() {
    return (
        <div className="space-y-10 px-4 md:px-6 lg:px-8 pb-12 animate-pulse">
            <div className="h-24 w-full bg-surface-100 rounded-2xl" />
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                {[1, 2, 3, 4].map((i) => (
                    <div key={i} className="h-32 bg-surface-100 rounded-2xl" />
                ))}
            </div>
            <div className="grid gap-8 lg:grid-cols-2">
                <div className="h-80 bg-surface-100 rounded-2xl" />
                <div className="h-80 bg-surface-100 rounded-2xl" />
            </div>
        </div>
    );
}

export default function DashboardPage() {
    const router = useRouter();
    const [windowDays, setWindowDays] = React.useState<7 | 30 | 90>(30);
    const [refreshKey, setRefreshKey] = React.useState(0);
    const { data, volume, engagement, campaigns, loading, error, lastUpdated, sourcesStatus, loadingTimedOut } = useDashboard(windowDays, refreshKey);
    const stats = buildStats(data);
    const lastUpdatedLabel = lastUpdated ? formatRelativeTime(new Date(lastUpdated)) : 'just now';
    const isStale = Boolean(lastUpdated) && Date.now() - new Date(lastUpdated as string).getTime() > 60_000;
    const countFormatter = React.useCallback((value: number) => formatNumber(value), []);

    if (loading && !loadingTimedOut) {
        return <DashboardSkeleton />;
    }

    return (
        <div className="space-y-10 px-4 md:px-6 lg:px-8 pb-12">
            <PageHeader
                title="Dashboard"
                description="Enterprise delivery performance and engagement analytics"
                actions={<>
                    <div className="hidden sm:flex items-center gap-2">
                        {[7, 30, 90].map((days) => (
                            <Button
                                key={days}
                                type="button"
                                variant={windowDays === days ? (days === 30 ? 'warning' : 'secondary') : 'outline'}
                                className="border-surface-200 shadow-sm"
                                onClick={() => setWindowDays(days as 7 | 30 | 90)}
                            >
                                <Calendar className="mr-2 h-4 w-4" />Last {days} Days
                            </Button>
                        ))}
                    </div>
                    <Button variant="outline" className="border-surface-200 shadow-sm" onClick={() => setRefreshKey((prev) => prev + 1)}>
                        <RefreshCw className="mr-2 h-4 w-4" />Refresh
                    </Button>
                    <Button variant="success" className="shadow-lg shadow-success/20" onClick={() => { router.push('/campaigns/new'); }}><Zap className="mr-2 h-4 w-4" />Quick Send</Button>
                </>}
            />

            {isStale ? (
                <Card className="border-warning/40 bg-warning/10" data-testid="metrics-stale-badge">
                    <CardContent className="p-3 text-sm text-foreground">Metrics are stale while background revalidation runs.</CardContent>
                </Card>
            ) : null}

            {data && (parseFloat(data.engagement.rates.bounce) > 2 || parseFloat(data.engagement.rates.delivery) < 95) ? (
                <Card className="border-warning/40 bg-warning/10">
                    <CardContent className="p-4 text-sm text-foreground">
                        <p className="font-semibold">Anomaly detected in deliverability trends.</p>
                        <p className="text-muted-foreground mt-1">Bounce or delivery thresholds exceeded in the selected window. Review recent activity and suppression changes.</p>
                    </CardContent>
                </Card>
            ) : null}

            {error && (
                <Card className="border-destructive/50 bg-destructive/10">
                    <CardContent className="flex items-center justify-between gap-3 p-4">
                        <div className="flex items-center gap-3 min-w-0">
                        <AlertCircle className="h-5 w-5 text-destructive" />
                        <p className="text-sm text-destructive">Could not load live data. {error}</p>
                        </div>
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setRefreshKey((prev) => prev + 1)}
                            className="border-destructive/40 text-destructive hover:bg-destructive/10"
                        >
                            Retry
                        </Button>
                    </CardContent>
                </Card>
            )}

            {/* Stats Grid */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4" data-testid="metrics-grid">
                {(stats.length > 0 ? stats : [
                    { title: 'Emails Delivered', value: 0, change: 0, changeType: 'positive' as const, icon: Send, color: 'text-brand-600', bgColor: 'bg-brand-50' },
                    { title: 'Emails Sent', value: 0, change: 0, changeType: 'positive' as const, icon: Mail, color: 'text-brand-600', bgColor: 'bg-brand-50' },
                    { title: 'Open Rate', value: 0, change: 0, changeType: 'positive' as const, icon: Eye, color: 'text-brand-600', bgColor: 'bg-brand-50', isPercent: true },
                    { title: 'Click Rate', value: 0, change: 0, changeType: 'positive' as const, icon: MousePointer, color: 'text-brand-600', bgColor: 'bg-brand-50', isPercent: true },
                ]).map((stat) => (
                    <Card key={stat.title} className="border-none shadow-premium hover:shadow-premium-hover transition-all duration-300 group min-w-0">
                        <CardContent className="p-6">
                            <div className="flex items-center justify-between">
                                <div className={cn('rounded-xl p-2.5 transition-colors group-hover:bg-brand-100', stat.bgColor)}>
                                    <stat.icon className={cn('h-5 w-5', stat.color)} />
                                </div>
                                {stat.change > 0 && (
                                    <div className={cn('flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold', stat.changeType === 'positive' ? 'bg-success-50 text-success-700' : 'bg-danger-50 text-danger-700')}>
                                        {stat.changeType === 'positive' ? <ArrowUpRight className="h-3 w-3" /> : <ArrowDownRight className="h-3 w-3" />}
                                        {Math.abs(stat.change).toFixed(1)}%
                                    </div>
                                )}
                            </div>
                            <div className="mt-4 space-y-1 min-w-0">
                                <p className="text-xs font-bold uppercase tracking-widest text-surface-500 truncate">{stat.title}</p>
                                <p className="text-3xl font-bold apex-metric-number tracking-tight">
                                    {'isPercent' in stat && stat.isPercent ? formatPercent(stat.value) : formatNumber(stat.value)}
                                </p>
                            </div>
                        </CardContent>
                    </Card>
                ))}
            </div>

            {/* Charts */}
            <div className="grid gap-8 lg:grid-cols-2" data-testid="charts-section">
                <Card className="border-none shadow-premium bg-card overflow-hidden" data-testid="chart-engagement" aria-label="Engagement trends chart">
                    <CardHeader className="border-b border-surface-50 pb-6">
                        <div className="flex items-center justify-between">
                            <div>
                                <CardTitle className="text-lg font-bold">Engagement Trends</CardTitle>
                                <CardDescription>Unique opens and clicks across all regions</CardDescription>
                                <p className="mt-1 text-xs text-muted-foreground">Last updated {lastUpdatedLabel}</p>
                            </div>
                            <Badge variant="secondary" className="bg-brand-50 text-brand-700 border-brand-100 font-bold">{sourcesStatus.engagement === 'ok' ? 'Live' : 'Unavailable'}</Badge>
                        </div>
                    </CardHeader>
                    <CardContent className="pt-8">
                        {sourcesStatus.engagement === 'error' ? (
                            <div className="rounded-xl border border-border bg-muted/30 p-6 text-sm text-muted-foreground">
                                Engagement metrics are temporarily unavailable. Try refreshing in a moment.
                            </div>
                        ) : (
                            <ApexAreaChart
                                data={engagement.length > 0 ? engagement : [{ date: 'No data', opens: 0, clicks: 0 }]}
                                xKey="date"
                                areas={[{ key: 'opens', name: 'Opens', color: '#2563eb' }, { key: 'clicks', name: 'Clicks', color: '#16a34a' }]}
                                formatter={countFormatter}
                                height={320}
                            />
                        )}
                    </CardContent>
                </Card>
                <Card className="border-none shadow-premium bg-card overflow-hidden" data-testid="chart-volume" aria-label="Sending volume chart">
                    <CardHeader className="border-b border-surface-50 pb-6">
                        <div className="flex items-center justify-between">
                            <div>
                                <CardTitle className="text-lg font-bold">Sending Volume</CardTitle>
                                <CardDescription>Daily message throughput analysis</CardDescription>
                                <p className="mt-1 text-xs text-muted-foreground">Last updated {lastUpdatedLabel}</p>
                            </div>
                        </div>
                    </CardHeader>
                    <CardContent className="pt-8">
                        {sourcesStatus.volume === 'error' ? (
                            <div className="rounded-xl border border-border bg-muted/30 p-6 text-sm text-muted-foreground">
                                Sending volume metrics are temporarily unavailable. Try refreshing in a moment.
                            </div>
                        ) : (
                            <ApexBarChart
                                data={volume.length > 0 ? volume.map(v => ({ date: v.date, sent: v.sent })) : [{ date: 'No data', sent: 0 }]}
                                xKey="date"
                                bars={[{ key: 'sent', name: 'Emails Sent', color: '#2563eb' }]}
                                formatter={countFormatter}
                                height={320}
                            />
                        )}
                    </CardContent>
                </Card>
            </div>

            {/* Recent Messages & Health */}
            <div className="grid gap-8 lg:grid-cols-3">
                <Card className="lg:col-span-2 border-none shadow-premium overflow-hidden" data-testid="activity-feed">
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 border-b border-surface-50 pb-6">
                        <div>
                            <CardTitle className="text-lg font-bold">Recent Activity</CardTitle>
                            <CardDescription>Latest transactional and marketing deliveries</CardDescription>
                            <p className="mt-1 text-xs text-muted-foreground">Last updated {lastUpdatedLabel}</p>
                        </div>
                        <Button variant="ghost" size="sm" className="text-brand-600 font-bold hover:bg-brand-50" onClick={() => router.push('/reports')}>View Analytics</Button>
                    </CardHeader>
                    <CardContent className="p-0">
                        {sourcesStatus.campaigns === 'error' ? (
                            <div className="p-8 text-sm text-muted-foreground">
                                Recent activity is temporarily unavailable. You can continue using the dashboard while this data source recovers.
                            </div>
                        ) : campaigns.length === 0 ? (
                            <div className="p-12">
                                <EmptyState
                                    icon={Mail}
                                    title="No messages sent yet"
                                    description="Start by creating your first campaign to see sending analytics and performance metrics here."
                                    action={{
                                        label: 'Create Campaign',
                                        onClick: () => router.push('/campaigns/new')
                                    }}
                                />
                            </div>
                        ) : (
                            <Table>
                                <TableHeader className="bg-surface-50/50">
                                    <TableRow>
                                        <TableHead className="font-bold uppercase tracking-wider text-[11px] text-surface-500 pl-6">Subject</TableHead>
                                        <TableHead className="font-bold uppercase tracking-wider text-[11px] text-surface-500">Status</TableHead>
                                        <TableHead className="font-bold uppercase tracking-wider text-[11px] text-surface-500 text-right">Volume</TableHead>
                                        <TableHead className="font-bold uppercase tracking-wider text-[11px] text-surface-500 text-right">Open Rate</TableHead>
                                        <TableHead className="font-bold uppercase tracking-wider text-[11px] text-surface-500 text-right">CTR</TableHead>
                                        <TableHead className="pr-6" />
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {campaigns.map((c) => {
                                        return (
                                            <TableRow key={c.id} className="group hover:bg-surface-50/50 transition-colors">
                                                <TableCell className="pl-6 min-w-0">
                                                    <p className="font-bold text-surface-900 group-hover:text-brand-700 transition-colors truncate max-w-[240px]">
                                                        {c.name}
                                                    </p>
                                                    <p className="text-xs text-surface-500 font-medium">
                                                        {c.sentAt ? formatRelativeTime(new Date(c.sentAt)) : c.scheduledAt ? `Scheduled ${formatRelativeTime(new Date(c.scheduledAt))}` : '—'}
                                                    </p>
                                                </TableCell>
                                                <TableCell>
                                                    <StatusIndicator status={c.status} className="font-bold rounded-full px-3" />
                                                </TableCell>
                                                <TableCell className="text-right font-medium apex-metric-number">{formatNumber(c.sent)}</TableCell>
                                                <TableCell className="text-right font-bold apex-metric-number text-surface-900">{c.openRate > 0 ? `${c.openRate.toFixed(1)}%` : '-'}</TableCell>
                                                <TableCell className="text-right font-bold apex-metric-number text-surface-900">{c.clickRate > 0 ? `${c.clickRate.toFixed(1)}%` : '-'}</TableCell>
                                                <TableCell className="pr-6 text-right">
                                                    <DropdownMenu>
                                                        <DropdownMenuTrigger asChild><Button variant="ghost" size="icon" aria-label="Campaign row actions" className="h-8 w-8 hover:bg-brand-50 hover:text-brand-600"><MoreHorizontal className="h-4 w-4" /></Button></DropdownMenuTrigger>
                                                        <DropdownMenuContent align="end" className="rounded-xl shadow-xl border-surface-100"><DropdownMenuItem className="font-medium" onClick={() => router.push(`/campaigns/${c.id}`)}>View Details</DropdownMenuItem><DropdownMenuItem className="font-medium text-brand-600" onClick={() => router.push(`/campaigns/${c.id}?resend=1`)}>Re-send Message</DropdownMenuItem></DropdownMenuContent>
                                                    </DropdownMenu>
                                                </TableCell>
                                            </TableRow>
                                        );
                                    })}
                                </TableBody>
                            </Table>
                        )}
                    </CardContent>
                </Card>

                <Card className="border-none shadow-premium bg-card overflow-hidden">
                    <CardHeader className="border-b border-surface-50 pb-6">
                        <CardTitle className="text-lg font-bold">Sender Reputation</CardTitle>
                        <CardDescription>Global delivery health metrics</CardDescription>
                        <p className="mt-1 text-xs text-muted-foreground">Last updated {lastUpdatedLabel}</p>
                    </CardHeader>
                    <CardContent className="space-y-8 pt-8">
                        {data ? (
                            <>
                                <div className="p-6 rounded-2xl bg-gradient-to-br from-brand-600 to-brand-800 text-white text-center shadow-lg shadow-brand-500/20">
                                    <p className="text-5xl font-bold apex-metric-number tracking-tighter">{data.health?.score ?? '—'}</p>
                                    <p className="text-sm font-bold uppercase tracking-widest text-white/70 mt-2">Health Score ({data.health?.grade ?? '—'})</p>
                                </div>
                                <div className="space-y-5">
                                    {[{ label: 'Delivery Rate', val: data.engagement.rates.delivery, variant: 'success' as const },
                                      { label: 'Open Rate', val: data.engagement.rates.open, variant: 'default' as const },
                                      { label: 'Bounce Rate', val: data.engagement.rates.bounce, variant: 'error' as const }].map(r => (
                                        <div key={r.label} className="space-y-2">
                                            <div className="flex justify-between text-sm"><span className="font-bold text-surface-500 uppercase tracking-widest text-[11px]">{r.label}</span><span className="font-bold apex-metric-number text-surface-900">{r.val}%</span></div>
                                            <Progress value={parseFloat(r.val)} size="sm" indicatorVariant={r.variant} />
                                        </div>
                                    ))}
                                </div>
                                <div className="pt-6 border-t border-surface-100 grid grid-cols-2 gap-6 text-center">
                                    <div><p className="text-xl font-bold apex-metric-number text-surface-900">{data.domains.verified}</p><p className="text-[11px] font-bold uppercase tracking-wider text-surface-500">Verified Domains</p></div>
                                    <div><p className="text-xl font-bold apex-metric-number text-surface-900">{data.suppressions.total}</p><p className="text-[11px] font-bold uppercase tracking-wider text-surface-500">Suppressions</p></div>
                                </div>
                            </>
                        ) : (
                            <div className="animate-pulse py-6 space-y-5" aria-label="Loading sender reputation metrics">
                                <div className="h-24 rounded-2xl bg-muted" />
                                <div className="space-y-3">
                                    <div className="h-8 rounded-lg bg-muted" />
                                    <div className="h-8 rounded-lg bg-muted" />
                                    <div className="h-8 rounded-lg bg-muted" />
                                </div>
                                <div className="grid grid-cols-2 gap-3">
                                    <div className="h-14 rounded-lg bg-muted" />
                                    <div className="h-14 rounded-lg bg-muted" />
                                </div>
                            </div>
                        )}
                    </CardContent>
                </Card>
            </div>

            {/* Quick Actions */}
            <Card className="border-none shadow-premium bg-card overflow-hidden mt-8">
                <CardHeader className="border-b border-surface-50 pb-6">
                    <CardTitle className="text-lg font-bold">Quick Actions</CardTitle>
                    <CardDescription>Common tasks to help you get started</CardDescription>
                </CardHeader>
                <CardContent className="pt-8">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <ActionCard
                            title="Verify Domain"
                            description="Add DKIM and SPF records to your DNS provider."
                            icon={<Shield className="h-5 w-5 text-brand-600" />}
                            href="/domains"
                        />
                        <ActionCard
                            title="Create Template"
                            description="Build a reusable email layout with our visual editor."
                            icon={<FileText className="h-5 w-5 text-brand-600" />}
                            href="/templates"
                        />
                        <ActionCard
                            title="API Documentation"
                            description="Explore our REST API and SDKs for integration."
                            icon={<Code2 className="h-5 w-5 text-brand-600" />}
                            href="https://docs.apexmail.ee"
                            external
                        />
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}

function ActionCard({ title, description, icon, href, external = false }: { title: string; description: string; icon: React.ReactNode; href: string; external?: boolean }) {
    return (
        <Link 
            href={href} 
            target={external ? "_blank" : undefined}
            className="flex items-start gap-4 p-5 rounded-xl border border-surface-100 bg-surface-50/30 hover:bg-brand-50 hover:border-brand-100 transition-all duration-300 group"
        >
            <div className="p-2.5 rounded-lg bg-card shadow-sm group-hover:bg-primary/10 transition-colors">
                {icon}
            </div>
            <div>
                <h4 className="font-bold text-surface-900 group-hover:text-brand-700 transition-colors">{title}</h4>
                <p className="text-xs text-surface-500 font-medium leading-relaxed mt-1">{description}</p>
            </div>
        </Link>
    );
}
