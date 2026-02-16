'use client';

import * as React from 'react';
import Link from 'next/link';
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
    Loader2,
    AlertCircle,
    Shield,
    FileText,
    Code2,
} from 'lucide-react';
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

interface VolumePoint { date: string; sent: number; delivered: number; bounced: number; [key: string]: string | number }
interface EngagementPoint { date: string; opens: number; clicks: number; [key: string]: string | number }
interface RecentMessage {
    id: string; name: string; status: string;
    sentAt?: string; scheduledAt?: string;
    sent: number; openRate: number; clickRate: number;
}

// ---------- Data fetching hook ----------

function useDashboard() {
    const [data, setData] = React.useState<DashboardData | null>(null);
    const [volume, setVolume] = React.useState<VolumePoint[]>([]);
    const [engagement, setEngagement] = React.useState<EngagementPoint[]>([]);
    const [campaigns, setCampaigns] = React.useState<RecentMessage[]>([]);
    const [loading, setLoading] = React.useState(true);
    const [error, setError] = React.useState<string | null>(null);

    React.useEffect(() => {
        let cancelled = false;
        async function load() {
            try {
                const since = new Date(Date.now() - 30 * 86_400_000).toISOString();
                const until = new Date().toISOString();
                const [dashRes, volRes, engRes, campRes] = await Promise.allSettled([
                    fetch(`/api/v1/analytics/dashboard?since=${since}&until=${until}`),
                    fetch(`/api/v1/analytics/volume?since=${since}&until=${until}&granularity=day`),
                    fetch(`/api/v1/analytics/engagement?since=${since}&until=${until}&granularity=day`),
                    fetch('/api/v1/messages?limit=5&sort=createdAt:desc'),
                ]);
                if (cancelled) return;
                if (dashRes.status === 'fulfilled' && dashRes.value.ok) {
                    setData((await dashRes.value.json()).dashboard);
                }
                if (volRes.status === 'fulfilled' && volRes.value.ok) {
                    setVolume((await volRes.value.json()).volume ?? []);
                }
                if (engRes.status === 'fulfilled' && engRes.value.ok) {
                    setEngagement((await engRes.value.json()).engagement ?? []);
                }
                if (campRes.status === 'fulfilled' && campRes.value.ok) {
                    const json = await campRes.value.json();
                    const msgs = json.messages ?? json.data ?? [];
                    // eslint-disable-next-line @typescript-eslint/no-explicit-any
                    setCampaigns(msgs.slice(0, 5).map((m: any) => ({
                        id: m.id, name: m.subject || 'Untitled', status: m.status,
                        sentAt: m.sentAt, scheduledAt: m.scheduledAt,
                        sent: m.recipientCount ?? 0, openRate: 0, clickRate: 0,
                    })));
                }
            } catch (err) {
                if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load');
            } finally {
                if (!cancelled) setLoading(false);
            }
        }
        load();
        return () => { cancelled = true; };
    }, []);

    return { data, volume, engagement, campaigns, loading, error };
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

const statusStyles: Record<string, { label: string; variant: 'default' | 'success' | 'warning' | 'secondary' }> = {
    sent: { label: 'Sent', variant: 'success' }, delivered: { label: 'Delivered', variant: 'success' },
    sending: { label: 'Sending', variant: 'warning' }, queued: { label: 'Queued', variant: 'secondary' },
    scheduled: { label: 'Scheduled', variant: 'secondary' }, draft: { label: 'Draft', variant: 'default' },
    failed: { label: 'Failed', variant: 'default' }, paused: { label: 'Paused', variant: 'default' },
};

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
    const { data, volume, engagement, campaigns, loading, error } = useDashboard();
    const stats = buildStats(data);

    if (loading) {
        return <DashboardSkeleton />;
    }

    return (
        <div className="space-y-10 px-4 md:px-6 lg:px-8 pb-12">
            <PageHeader
                title="Dashboard"
                description="Enterprise delivery performance and engagement analytics"
                actions={<>
                    <Button variant="outline" className="hidden sm:flex border-surface-200 shadow-sm"><Calendar className="mr-2 h-4 w-4" />Last 30 Days</Button>
                    <Button className="bg-primary shadow-lg shadow-primary/20"><Zap className="mr-2 h-4 w-4" />Quick Send</Button>
                </>}
            />

            {error && (
                <Card className="border-destructive/50 bg-destructive/10">
                    <CardContent className="flex items-center gap-3 p-4">
                        <AlertCircle className="h-5 w-5 text-destructive" />
                        <p className="text-sm text-destructive">Could not load live data. {error}</p>
                    </CardContent>
                </Card>
            )}

            {/* Stats Grid */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                {(stats.length > 0 ? stats : [
                    { title: 'Emails Delivered', value: 0, change: 0, changeType: 'positive' as const, icon: Send, color: 'text-brand-600', bgColor: 'bg-brand-50' },
                    { title: 'Emails Sent', value: 0, change: 0, changeType: 'positive' as const, icon: Mail, color: 'text-brand-600', bgColor: 'bg-brand-50' },
                    { title: 'Open Rate', value: 0, change: 0, changeType: 'positive' as const, icon: Eye, color: 'text-brand-600', bgColor: 'bg-brand-50', isPercent: true },
                    { title: 'Click Rate', value: 0, change: 0, changeType: 'positive' as const, icon: MousePointer, color: 'text-brand-600', bgColor: 'bg-brand-50', isPercent: true },
                ]).map((stat) => (
                    <Card key={stat.title} className="border-none shadow-premium hover:shadow-premium-hover transition-all duration-300 group">
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
                            <div className="mt-4 space-y-1">
                                <p className="text-xs font-bold uppercase tracking-widest text-surface-500">{stat.title}</p>
                                <p className="text-3xl font-bold tabular-nums tracking-tight">
                                    {'isPercent' in stat && stat.isPercent ? formatPercent(stat.value / 100) : formatNumber(stat.value)}
                                </p>
                            </div>
                        </CardContent>
                    </Card>
                ))}
            </div>

            {/* Charts */}
            <div className="grid gap-8 lg:grid-cols-2">
                <Card className="border-none shadow-premium bg-white overflow-hidden">
                    <CardHeader className="border-b border-surface-50 pb-6">
                        <div className="flex items-center justify-between">
                            <div>
                                <CardTitle className="text-lg font-bold">Engagement Trends</CardTitle>
                                <CardDescription>Unique opens and clicks across all regions</CardDescription>
                            </div>
                            <Badge variant="secondary" className="bg-brand-50 text-brand-700 border-brand-100 font-bold">Live</Badge>
                        </div>
                    </CardHeader>
                    <CardContent className="pt-8">
                        <ApexAreaChart
                            data={engagement.length > 0 ? engagement : [{ date: 'No data', opens: 0, clicks: 0 }]}
                            xKey="date"
                            areas={[{ key: 'opens', name: 'Opens', color: '#2563eb' }, { key: 'clicks', name: 'Clicks', color: '#16a34a' }]}
                            height={320}
                        />
                    </CardContent>
                </Card>
                <Card className="border-none shadow-premium bg-white overflow-hidden">
                    <CardHeader className="border-b border-surface-50 pb-6">
                        <div className="flex items-center justify-between">
                            <div>
                                <CardTitle className="text-lg font-bold">Sending Volume</CardTitle>
                                <CardDescription>Daily message throughput analysis</CardDescription>
                            </div>
                        </div>
                    </CardHeader>
                    <CardContent className="pt-8">
                        <ApexBarChart
                            data={volume.length > 0 ? volume.map(v => ({ date: v.date, sent: v.sent })) : [{ date: 'No data', sent: 0 }]}
                            xKey="date"
                            bars={[{ key: 'sent', name: 'Emails Sent', color: '#2563eb' }]}
                            height={320}
                        />
                    </CardContent>
                </Card>
            </div>

            {/* Recent Messages & Health */}
            <div className="grid gap-8 lg:grid-cols-3">
                <Card className="lg:col-span-2 border-none shadow-premium overflow-hidden">
                    <CardHeader className="flex flex-row items-center justify-between border-b border-surface-50 pb-6">
                        <div>
                            <CardTitle className="text-lg font-bold">Recent Activity</CardTitle>
                            <CardDescription>Latest transactional and marketing deliveries</CardDescription>
                        </div>
                        <Button variant="ghost" size="sm" className="text-brand-600 font-bold hover:bg-brand-50">View Analytics</Button>
                    </CardHeader>
                    <CardContent className="p-0">
                        {campaigns.length === 0 ? (
                            <div className="p-12">
                                <EmptyState
                                    icon={Mail}
                                    title="No messages sent yet"
                                    description="Start by creating your first campaign to see sending analytics and performance metrics here."
                                    action={{
                                        label: 'Create Campaign',
                                        onClick: () => window.location.href = '/campaigns/new'
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
                                        const style = statusStyles[c.status] || { label: c.status, variant: 'default' as const };
                                        return (
                                            <TableRow key={c.id} className="group hover:bg-surface-50/50 transition-colors">
                                                <TableCell className="pl-6">
                                                    <p className="font-bold text-surface-900 group-hover:text-brand-700 transition-colors">{c.name}</p>
                                                    <p className="text-xs text-surface-500 font-medium">
                                                        {c.sentAt ? formatRelativeTime(new Date(c.sentAt)) : c.scheduledAt ? `Scheduled ${formatRelativeTime(new Date(c.scheduledAt))}` : '—'}
                                                    </p>
                                                </TableCell>
                                                <TableCell>
                                                    <Badge variant={style.variant} className="font-bold rounded-full px-3">{style.label}</Badge>
                                                </TableCell>
                                                <TableCell className="text-right font-medium tabular-nums">{formatNumber(c.sent)}</TableCell>
                                                <TableCell className="text-right font-bold tabular-nums text-surface-900">{c.openRate > 0 ? `${c.openRate.toFixed(1)}%` : '-'}</TableCell>
                                                <TableCell className="text-right font-bold tabular-nums text-surface-900">{c.clickRate > 0 ? `${c.clickRate.toFixed(1)}%` : '-'}</TableCell>
                                                <TableCell className="pr-6 text-right">
                                                    <DropdownMenu>
                                                        <DropdownMenuTrigger asChild><Button variant="ghost" size="icon" className="h-8 w-8 hover:bg-brand-50 hover:text-brand-600"><MoreHorizontal className="h-4 w-4" /></Button></DropdownMenuTrigger>
                                                        <DropdownMenuContent align="end" className="rounded-xl shadow-xl border-surface-100"><DropdownMenuItem className="font-medium">View Details</DropdownMenuItem><DropdownMenuItem className="font-medium text-brand-600">Re-send Message</DropdownMenuItem></DropdownMenuContent>
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

                <Card className="border-none shadow-premium bg-white overflow-hidden">
                    <CardHeader className="border-b border-surface-50 pb-6">
                        <CardTitle className="text-lg font-bold">Sender Reputation</CardTitle>
                        <CardDescription>Global delivery health metrics</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-8 pt-8">
                        {data ? (
                            <>
                                <div className="p-6 rounded-2xl bg-gradient-to-br from-brand-600 to-brand-800 text-white text-center shadow-lg shadow-brand-500/20">
                                    <p className="text-5xl font-bold tabular-nums tracking-tighter">{data.health?.score ?? '—'}</p>
                                    <p className="text-sm font-bold uppercase tracking-widest text-white/70 mt-2">Health Score ({data.health?.grade ?? '—'})</p>
                                </div>
                                <div className="space-y-5">
                                    {[{ label: 'Delivery Rate', val: data.engagement.rates.delivery, variant: 'success' as const },
                                      { label: 'Open Rate', val: data.engagement.rates.open, variant: 'default' as const },
                                      { label: 'Bounce Rate', val: data.engagement.rates.bounce, variant: 'error' as const }].map(r => (
                                        <div key={r.label} className="space-y-2">
                                            <div className="flex justify-between text-sm"><span className="font-bold text-surface-500 uppercase tracking-widest text-[11px]">{r.label}</span><span className="font-bold tabular-nums text-surface-900">{r.val}%</span></div>
                                            <Progress value={parseFloat(r.val)} size="sm" indicatorVariant={r.variant} />
                                        </div>
                                    ))}
                                </div>
                                <div className="pt-6 border-t border-surface-100 grid grid-cols-2 gap-6 text-center">
                                    <div><p className="text-xl font-bold tabular-nums text-surface-900">{data.domains.verified}</p><p className="text-[11px] font-bold uppercase tracking-wider text-surface-500">Verified Domains</p></div>
                                    <div><p className="text-xl font-bold tabular-nums text-surface-900">{data.suppressions.total}</p><p className="text-[11px] font-bold uppercase tracking-wider text-surface-500">Suppressions</p></div>
                                </div>
                            </>
                        ) : (
                            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                                <Loader2 className="h-8 w-8 mb-4 animate-spin text-brand-600" /><p className="text-sm font-medium">Synchronizing metrics...</p>
                            </div>
                        )}
                    </CardContent>
                </Card>
            </div>

            {/* Quick Actions */}
            <Card className="border-none shadow-premium bg-white overflow-hidden mt-8">
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
                            href="/settings/domains"
                        />
                        <ActionCard
                            title="Create Template"
                            description="Build a reusable email layout with our visual editor."
                            icon={<FileText className="h-5 w-5 text-brand-600" />}
                            href="/templates/new"
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
            <div className="p-2.5 rounded-lg bg-white shadow-sm group-hover:bg-brand-100 transition-colors">
                {icon}
            </div>
            <div>
                <h4 className="font-bold text-surface-900 group-hover:text-brand-700 transition-colors">{title}</h4>
                <p className="text-xs text-surface-500 font-medium leading-relaxed mt-1">{description}</p>
            </div>
        </Link>
    );
}
