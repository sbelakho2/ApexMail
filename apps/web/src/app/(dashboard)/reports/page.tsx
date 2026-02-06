'use client';

import * as React from 'react';
import { BarChart3, Download, Calendar } from 'lucide-react';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { ApexAreaChart, ApexBarChart } from '@/components/charts';
import { formatNumber } from '@/lib/utils';

interface StatsData {
    sent: number; delivered: number; opened: number; clicked: number; bounced: number;
    rates: { delivery: string; open: string; click: string; bounce: string };
}

export default function ReportsPage() {
    const [stats, setStats] = React.useState<StatsData | null>(null);
    const [volume, setVolume] = React.useState<Array<{ date: string; sent: number; delivered: number }>>([]);
    const [engagement, setEngagement] = React.useState<Array<{ date: string; opens: number; clicks: number }>>([]);
    const [loading, setLoading] = React.useState(true);

    React.useEffect(() => {
        const since = new Date(Date.now() - 30 * 86_400_000).toISOString();
        const until = new Date().toISOString();
        Promise.allSettled([
            fetch(`/api/v1/analytics/dashboard?since=${since}&until=${until}`),
            fetch(`/api/v1/analytics/volume?since=${since}&until=${until}&granularity=day`),
            fetch(`/api/v1/analytics/engagement?since=${since}&until=${until}&granularity=day`),
        ]).then(async ([dashRes, volRes, engRes]) => {
            if (dashRes.status === 'fulfilled' && dashRes.value.ok) {
                const json = await dashRes.value.json();
                setStats(json.dashboard?.engagement ?? null);
            }
            if (volRes.status === 'fulfilled' && volRes.value.ok) {
                setVolume((await volRes.value.json()).volume ?? []);
            }
            if (engRes.status === 'fulfilled' && engRes.value.ok) {
                setEngagement((await engRes.value.json()).engagement ?? []);
            }
        }).finally(() => setLoading(false));
    }, []);

    return (
        <div className="flex flex-col gap-6 px-4 md:px-6 lg:px-8">
            <PageHeader
                title="Reports"
                description="Analyze your email performance with detailed reports."
                breadcrumbs={[{ label: 'Reports' }]}
                actions={
                    <><Button variant="outline"><Calendar className="mr-2 h-4 w-4" />Last 30 Days</Button>
                    <Button variant="outline"><Download className="mr-2 h-4 w-4" />Export CSV</Button></>
                }
            />

            {loading ? (
                <div className="grid gap-4 md:grid-cols-4">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24" />)}</div>
            ) : stats && (
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                    {[
                        { label: 'Sent', value: stats.sent, sub: `${stats.rates.delivery}% delivered` },
                        { label: 'Opened', value: stats.opened, sub: `${stats.rates.open}% open rate` },
                        { label: 'Clicked', value: stats.clicked, sub: `${stats.rates.click}% click rate` },
                        { label: 'Bounced', value: stats.bounced, sub: `${stats.rates.bounce}% bounce rate` },
                    ].map(s => (
                        <Card key={s.label}>
                            <CardContent className="p-6">
                                <p className="text-sm text-muted-foreground">{s.label}</p>
                                <p className="text-2xl font-bold tabular-nums">{formatNumber(s.value)}</p>
                                <p className="text-xs text-muted-foreground mt-1">{s.sub}</p>
                            </CardContent>
                        </Card>
                    ))}
                </div>
            )}

            <div className="grid gap-6 lg:grid-cols-2">
                <ApexAreaChart
                    data={engagement.length > 0 ? engagement : [{ date: 'No data', opens: 0, clicks: 0 }]}
                    xKey="date" title="Engagement Over Time" description="Opens and clicks"
                    areas={[{ key: 'opens', name: 'Opens', color: '#2563EB' }, { key: 'clicks', name: 'Clicks', color: '#10B981' }]}
                    height={300}
                />
                <ApexBarChart
                    data={volume.length > 0 ? volume : [{ date: 'No data', sent: 0 }]}
                    xKey="date" title="Send Volume" description="Emails sent per day"
                    bars={[{ key: 'sent', name: 'Sent', color: '#2563EB' }]}
                    height={300}
                />
            </div>

            {!loading && !stats && (
                <Card>
                    <CardContent className="flex flex-col items-center justify-center py-16">
                        <BarChart3 className="h-10 w-10 text-muted-foreground mb-4" />
                        <p className="text-muted-foreground">Send your first campaign to see reports here.</p>
                    </CardContent>
                </Card>
            )}
        </div>
    );
}
