'use client';

import * as React from 'react';
import {
    Send,
    Users,
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
import { Skeleton } from '@/components/ui/skeleton';
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
        <div className="space-y-8">
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                {Array.from({ length: 4 }).map((_, i) => (
                    <Card key={i}><CardContent className="p-6"><Skeleton className="h-20 w-full" /></CardContent></Card>
                ))}
            </div>
            <div className="grid gap-6 lg:grid-cols-2">
                <Card><CardContent className="p-6"><Skeleton className="h-[300px] w-full" /></CardContent></Card>
                <Card><CardContent className="p-6"><Skeleton className="h-[300px] w-full" /></CardContent></Card>
            </div>
        </div>
    );
}

export default function DashboardPage() {
    const { data, volume, engagement, campaigns, loading, error } = useDashboard();
    const stats = buildStats(data);

    if (loading) {
        return (
            <div className="space-y-8 px-4 md:px-6 lg:px-8">
                <PageHeader title="Dashboard" description="Welcome back! Here's an overview of your email marketing performance." />
                <DashboardSkeleton />
            </div>
        );
    }

    return (
        <div className="space-y-8 px-4 md:px-6 lg:px-8">
            <PageHeader
                title="Dashboard"
                description="Welcome back! Here's an overview of your email marketing performance."
                actions={<>
                    <Button variant="outline"><Calendar className="mr-2 h-4 w-4" />Last 30 Days</Button>
                    <Button><Send className="mr-2 h-4 w-4" />New Campaign</Button>
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
                    { title: 'Emails Delivered', value: 0, change: 0, changeType: 'positive' as const, icon: Send, color: 'text-success', bgColor: 'bg-success/10' },
                    { title: 'Emails Sent', value: 0, change: 0, changeType: 'positive' as const, icon: Mail, color: 'text-primary', bgColor: 'bg-primary/10' },
                    { title: 'Open Rate', value: 0, change: 0, changeType: 'positive' as const, icon: Eye, color: 'text-warning', bgColor: 'bg-warning/10', isPercent: true },
                    { title: 'Click Rate', value: 0, change: 0, changeType: 'positive' as const, icon: MousePointer, color: 'text-danger', bgColor: 'bg-danger/10', isPercent: true },
                ]).map((stat) => (
                    <Card key={stat.title}>
                        <CardContent className="p-6">
                            <div className="flex items-center justify-between">
                                <div className={cn('rounded-sm p-2', stat.bgColor)}>
                                    <stat.icon className={cn('h-5 w-5', stat.color)} />
                                </div>
                                {stat.change > 0 && (
                                    <div className={cn('flex items-center text-sm font-bold tabular-nums', stat.changeType === 'positive' ? 'text-success' : 'text-destructive')}>
                                        {stat.changeType === 'positive' ? <ArrowUpRight className="mr-1 h-4 w-4" /> : <ArrowDownRight className="mr-1 h-4 w-4" />}
                                        {Math.abs(stat.change).toFixed(1)}%
                                    </div>
                                )}
                            </div>
                            <div className="mt-4">
                                <p className="text-sm text-muted-foreground">{stat.title}</p>
                                <p className="text-2xl font-bold tabular-nums">
                                    {'isPercent' in stat && stat.isPercent ? formatPercent(stat.value / 100) : formatNumber(stat.value)}
                                </p>
                            </div>
                        </CardContent>
                    </Card>
                ))}
            </div>

            {/* Charts */}
            <div className="grid gap-6 lg:grid-cols-2">
                <ApexAreaChart
                    data={engagement.length > 0 ? engagement : [{ date: 'No data', opens: 0, clicks: 0 }]}
                    xKey="date"
                    areas={[{ key: 'opens', name: 'Opens', color: '#2563eb' }, { key: 'clicks', name: 'Clicks', color: '#16a34a' }]}
                    title="Engagement" description="Opens and clicks over the past 30 days" height={300}
                />
                <ApexBarChart
                    data={volume.length > 0 ? volume.map(v => ({ date: v.date, sent: v.sent })) : [{ date: 'No data', sent: 0 }]}
                    xKey="date"
                    bars={[{ key: 'sent', name: 'Emails Sent', color: '#2563eb' }]}
                    title="Sending Volume" description="Emails sent over the past 30 days" height={300}
                />
            </div>

            {/* Recent Messages & Health */}
            <div className="grid gap-6 lg:grid-cols-3">
                <Card className="lg:col-span-2">
                    <CardHeader className="flex flex-row items-center justify-between">
                        <div><CardTitle>Recent Messages</CardTitle><CardDescription>Your latest email sends</CardDescription></div>
                        <Button variant="ghost" size="sm">View All</Button>
                    </CardHeader>
                    <CardContent>
                        {campaigns.length === 0 ? (
                            <EmptyState
                                icon={Mail}
                                title="No messages sent yet"
                                description="Start by creating your first campaign to see sending analytics and performance metrics here."
                                action={{
                                    label: 'Create Campaign',
                                    onClick: () => window.location.href = '/campaigns/new'
                                }}
                            />
                        ) : (
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>Subject</TableHead><TableHead>Status</TableHead>
                                        <TableHead className="text-right">Recipients</TableHead>
                                        <TableHead className="text-right">Open Rate</TableHead>
                                        <TableHead className="text-right">CTR</TableHead><TableHead />
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {campaigns.map((c) => {
                                        const style = statusStyles[c.status] || { label: c.status, variant: 'default' as const };
                                        return (
                                            <TableRow key={c.id}>
                                                <TableCell>
                                                    <p className="font-medium">{c.name}</p>
                                                    <p className="text-sm text-muted-foreground">
                                                        {c.sentAt ? formatRelativeTime(new Date(c.sentAt)) : c.scheduledAt ? `Scheduled ${formatRelativeTime(new Date(c.scheduledAt))}` : '—'}
                                                    </p>
                                                </TableCell>
                                                <TableCell><Badge variant={style.variant}>{style.label}</Badge></TableCell>
                                                <TableCell className="text-right">{formatNumber(c.sent)}</TableCell>
                                                <TableCell className="text-right">{c.openRate > 0 ? `${c.openRate.toFixed(1)}%` : '-'}</TableCell>
                                                <TableCell className="text-right">{c.clickRate > 0 ? `${c.clickRate.toFixed(1)}%` : '-'}</TableCell>
                                                <TableCell>
                                                    <DropdownMenu>
                                                        <DropdownMenuTrigger asChild><Button variant="ghost" size="icon" aria-label="Actions"><MoreHorizontal className="h-4 w-4" /></Button></DropdownMenuTrigger>
                                                        <DropdownMenuContent align="end"><DropdownMenuItem>View Details</DropdownMenuItem><DropdownMenuItem>Duplicate</DropdownMenuItem></DropdownMenuContent>
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

                <Card>
                    <CardHeader><CardTitle>Delivery Health</CardTitle><CardDescription>Overall sending reputation</CardDescription></CardHeader>
                    <CardContent className="space-y-6">
                        {data ? (
                            <>
                                <div className="text-center">
                                    <p className="text-4xl font-bold tabular-nums">{data.health?.score ?? '—'}</p>
                                    <p className="text-sm text-muted-foreground mt-1">Health Score ({data.health?.grade ?? '—'})</p>
                                </div>
                                <div className="space-y-3">
                                    {[{ label: 'Delivery Rate', val: data.engagement.rates.delivery },
                                      { label: 'Open Rate', val: data.engagement.rates.open },
                                      { label: 'Bounce Rate', val: data.engagement.rates.bounce }].map(r => (
                                        <div key={r.label} className="space-y-1">
                                            <div className="flex justify-between text-sm"><span className="text-muted-foreground">{r.label}</span><span className="font-medium">{r.val}%</span></div>
                                            <Progress value={parseFloat(r.val)} className="h-2" />
                                        </div>
                                    ))}
                                </div>
                                <div className="pt-2 border-t grid grid-cols-2 gap-3 text-center">
                                    <div><p className="text-lg font-bold tabular-nums">{data.domains.verified}</p><p className="text-sm text-muted-foreground">Verified Domains</p></div>
                                    <div><p className="text-lg font-bold tabular-nums">{data.suppressions.total}</p><p className="text-sm text-muted-foreground">Suppressions</p></div>
                                </div>
                            </>
                        ) : (
                            <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                                <Loader2 className="h-6 w-6 mb-2 animate-spin" /><p className="text-sm">Loading...</p>
                            </div>
                        )}
                    </CardContent>
                </Card>
            </div>

            {/* Quick Actions */}
            <Card>
                <CardHeader><CardTitle>Quick Actions</CardTitle><CardDescription>Common tasks to help you get started</CardDescription></CardHeader>
                <CardContent>
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                        <Button variant="outline" className="h-auto flex-col gap-2 p-6"><Send className="h-6 w-6 text-primary" /><span>Create Campaign</span></Button>
                        <Button variant="outline" className="h-auto flex-col gap-2 p-6"><Users className="h-6 w-6 text-success" /><span>Import Contacts</span></Button>
                        <Button variant="outline" className="h-auto flex-col gap-2 p-6"><Mail className="h-6 w-6 text-warning" /><span>Design Template</span></Button>
                        <Button variant="outline" className="h-auto flex-col gap-2 p-6"><Zap className="h-6 w-6 text-info" /><span>Setup Automation</span></Button>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
