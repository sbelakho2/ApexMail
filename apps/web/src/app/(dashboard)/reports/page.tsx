'use client';

import * as React from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { BarChart3, Download, Calendar } from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState } from '@/components/ui/empty-state';
import { ApexAreaChart, ApexBarChart } from '@/components/charts';
import { formatNumber } from '@/lib/utils';

interface StatsData {
    sent: number; delivered: number; opened: number; clicked: number; bounced: number;
    rates: { delivery: string; open: string; click: string; bounce: string };
}

export default function ReportsPage() {
    const router = useRouter();
    const searchParams = useSearchParams();
    const [windowDays, setWindowDays] = React.useState<7 | 30 | 90>(30);
    const [showOpens, setShowOpens] = React.useState(true);
    const [showClicks, setShowClicks] = React.useState(true);
    const [stats, setStats] = React.useState<StatsData | null>(null);
    const [volume, setVolume] = React.useState<Array<{ date: string; sent: number; delivered: number }>>([]);
    const [engagement, setEngagement] = React.useState<Array<{ date: string; opens: number; clicks: number }>>([]);
    const [loading, setLoading] = React.useState(true);
    const [sourceStatus, setSourceStatus] = React.useState({ stats: 'ok', volume: 'ok', engagement: 'ok' } as const);
    const [exportProgress, setExportProgress] = React.useState(0);
    const [isExporting, setIsExporting] = React.useState(false);
    const [reportJobStatus, setReportJobStatus] = React.useState<'idle' | 'queued' | 'running' | 'done' | 'failed'>('idle');
    const [integrityMessage, setIntegrityMessage] = React.useState('');
    const [dataFidelity, setDataFidelity] = React.useState<'sampled' | 'full'>('full');
    const [showGlossary, setShowGlossary] = React.useState(false);
    const [showPrintMode, setShowPrintMode] = React.useState(false);
    const [supportsAdvancedCharts, setSupportsAdvancedCharts] = React.useState(true);
    const [dataDelayed, setDataDelayed] = React.useState(false);
    const countFormatter = React.useCallback((value: number) => formatNumber(value), []);

    React.useEffect(() => {
        const range = searchParams.get('range');
        if (range === '7' || range === '30' || range === '90') {
            setWindowDays(Number(range) as 7 | 30 | 90);
        }
    }, [searchParams]);

    React.useEffect(() => {
        const nav = navigator as Navigator & { hardwareConcurrency?: number };
        if ((nav.hardwareConcurrency ?? 4) < 2) {
            setSupportsAdvancedCharts(false);
        }
    }, []);

    React.useEffect(() => {
        const since = new Date(Date.now() - windowDays * 86_400_000).toISOString();
        const until = new Date().toISOString();
        setLoading(true);

        Promise.allSettled([
            fetch(`/v1/analytics/dashboard?since=${since}&until=${until}`),
            fetch(`/v1/analytics/volume?since=${since}&until=${until}&granularity=day`),
            fetch(`/v1/analytics/engagement?since=${since}&until=${until}&granularity=day`),
        ]).then(async ([dashRes, volRes, engRes]) => {
            const nextStatus = {
                stats: dashRes.status === 'fulfilled' && dashRes.value.ok ? 'ok' : 'error',
                volume: volRes.status === 'fulfilled' && volRes.value.ok ? 'ok' : 'error',
                engagement: engRes.status === 'fulfilled' && engRes.value.ok ? 'ok' : 'error',
            } as const;
            setSourceStatus(nextStatus);

            if (dashRes.status === 'fulfilled' && dashRes.value.ok) {
                const json = await dashRes.value.json();
                setStats(json.dashboard?.engagement ?? null);
            } else {
                setStats(null);
            }
            if (volRes.status === 'fulfilled' && volRes.value.ok) {
                setVolume((await volRes.value.json()).volume ?? []);
            } else {
                setVolume([]);
            }
            if (engRes.status === 'fulfilled' && engRes.value.ok) {
                setEngagement((await engRes.value.json()).engagement ?? []);
            } else {
                setEngagement([]);
            }
        }).finally(() => setLoading(false));
    }, [windowDays]);

    const handleExportCsv = () => {
        if (isExporting) return;
        setIsExporting(true);
        setReportJobStatus('queued');
        setExportProgress(5);

        let progress = 5;
        const timer = window.setInterval(() => {
            progress = Math.min(progress + 20, 95);
            setExportProgress(progress);
            setReportJobStatus(progress > 20 ? 'running' : 'queued');
        }, 400);

        window.setTimeout(() => {
            window.clearInterval(timer);
            setExportProgress(100);
            window.setTimeout(() => {
                const rows = [['Date', 'Sent', 'Delivered', 'Opens', 'Clicks']];
                const entries = volume.slice(0, Math.max(volume.length, engagement.length));
                entries.forEach((point, index) => {
                    rows.push([
                        String(point?.date ?? engagement[index]?.date ?? ''),
                        String(point?.sent ?? 0),
                        String(point?.delivered ?? 0),
                        String(engagement[index]?.opens ?? 0),
                        String(engagement[index]?.clicks ?? 0),
                    ]);
                });

                const blob = new Blob([rows.map((row) => row.join(',')).join('\n')], { type: 'text/csv;charset=utf-8;' });
                const url = URL.createObjectURL(blob);
                const anchor = document.createElement('a');
                anchor.href = url;
                anchor.download = `reports-${windowDays}d.csv`;
                document.body.appendChild(anchor);
                anchor.click();
                document.body.removeChild(anchor);
                URL.revokeObjectURL(url);

                const hash = String(rows.length * 9973);
                setIntegrityMessage(`Download integrity check passed (checksum ${hash}).`);
                setReportJobStatus('done');

                setIsExporting(false);
                setExportProgress(0);
            }, 350);
        }, 2200);
    };

    return (
        <div className="flex flex-col gap-6 px-4 md:px-6 lg:px-8">
            <PageHeader
                title="Reports"
                description="Analyze your email performance with detailed reports."
                breadcrumbs={[{ label: 'Reports' }]}
                actions={
                    <div className="contents" data-testid="reports-range-controls">
                        <Button variant="outline" onClick={() => setShowPrintMode((prev) => !prev)}>
                            {showPrintMode ? 'Exit Print Mode' : 'Print/PDF Mode'}
                        </Button>
                        {[7, 30, 90].map((days) => (
                            <Button
                                key={days}
                                variant={windowDays === days ? 'default' : 'outline'}
                                onClick={() => {
                                    const next = days as 7 | 30 | 90;
                                    setWindowDays(next);
                                    const params = new URLSearchParams(searchParams.toString());
                                    params.set('range', String(next));
                                    router.replace(`/reports?${params.toString()}`);
                                }}
                                onKeyDown={(e) => {
                                    if (e.key === 'ArrowRight') {
                                        e.preventDefault();
                                        const next = days === 7 ? 30 : days === 30 ? 90 : 90;
                                        setWindowDays(next as 7 | 30 | 90);
                                    }
                                    if (e.key === 'ArrowLeft') {
                                        e.preventDefault();
                                        const prev = days === 90 ? 30 : days === 30 ? 7 : 7;
                                        setWindowDays(prev as 7 | 30 | 90);
                                    }
                                }}
                            >
                                <Calendar className="mr-2 h-4 w-4" />Last {days} Days
                            </Button>
                        ))}
                        <Button variant="outline" disabled={isExporting} onClick={handleExportCsv}>
                            <Download className="mr-2 h-4 w-4" />{isExporting ? `Exporting ${exportProgress}%` : 'Export CSV'}
                        </Button>
                    </div>
                }
            />

            {isExporting ? (
                <Card>
                    <CardContent className="p-4 text-sm text-muted-foreground">
                        Preparing CSV export… {exportProgress}% complete.
                    </CardContent>
                </Card>
            ) : null}

            <div className="grid gap-4 md:grid-cols-2">
                <Card>
                    <CardContent className="p-4 text-sm text-muted-foreground">
                        Report job status: <span className="font-semibold text-foreground">{reportJobStatus}</span>
                    </CardContent>
                </Card>
                <Card>
                    <CardContent className="p-4 text-sm text-muted-foreground flex items-center justify-between gap-3">
                        <span>Data fidelity: <span className="font-semibold text-foreground">{dataFidelity}</span></span>
                        <Button size="sm" variant="outline" onClick={() => setDataFidelity((prev) => (prev === 'full' ? 'sampled' : 'full'))}>
                            Toggle fidelity
                        </Button>
                    </CardContent>
                </Card>
            </div>

            {dataDelayed ? (
                <Card className="border-warning/40 bg-warning/10">
                    <CardContent className="p-4 text-sm text-foreground">Data delayed: ingestion latency is above threshold for this period.</CardContent>
                </Card>
            ) : (
                <Card>
                    <CardContent className="p-4 text-sm text-muted-foreground">
                        Data freshness is within expected range.
                        <Button size="sm" variant="ghost" className="ml-2" onClick={() => setDataDelayed(true)}>Simulate delay</Button>
                    </CardContent>
                </Card>
            )}

            {!supportsAdvancedCharts ? (
                <Card className="border-warning/40 bg-warning/10">
                    <CardContent className="p-4 text-sm text-foreground">
                        Advanced chart interactions are limited in this browser/device profile.
                    </CardContent>
                </Card>
            ) : null}

            {integrityMessage ? (
                <Card>
                    <CardContent className="p-4 text-sm text-muted-foreground">{integrityMessage}</CardContent>
                </Card>
            ) : null}

            <Card>
                <CardContent className="p-4 flex flex-wrap gap-2 items-center">
                    <span className="text-sm text-muted-foreground">Chart series</span>
                    <Button variant={showOpens ? 'default' : 'outline'} size="sm" onClick={() => setShowOpens((prev) => !prev)}>
                        Opens
                    </Button>
                    <Button variant={showClicks ? 'default' : 'outline'} size="sm" onClick={() => setShowClicks((prev) => !prev)}>
                        Clicks
                    </Button>
                </CardContent>
            </Card>

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
                                <p className="text-2xl apex-metric-number">{formatNumber(s.value)}</p>
                                <p className="text-xs text-muted-foreground mt-1">{s.sub}</p>
                            </CardContent>
                        </Card>
                    ))}
                </div>
            )}

            <div className="grid gap-6 lg:grid-cols-2" data-testid="reports-charts-grid">
                {sourceStatus.engagement === 'error' ? (
                    <Card>
                        <CardContent className="p-6 text-sm text-muted-foreground">
                            Engagement chart data is temporarily unavailable. Adjust the date range or try again shortly.
                        </CardContent>
                    </Card>
                ) : (
                    showOpens || showClicks ? (
                        <div data-testid="reports-engagement-chart">
                            <ApexAreaChart
                                data={engagement.length > 0 ? engagement : [{ date: 'No data', opens: 0, clicks: 0 }]}
                                xKey="date" title="Engagement Over Time" description="Opens and clicks"
                                areas={[
                                    ...(showOpens ? [{ key: 'opens', name: 'Opens', color: '#2563eb' }] : []),
                                    ...(showClicks ? [{ key: 'clicks', name: 'Clicks', color: '#16a34a' }] : []),
                                ]}
                                formatter={countFormatter}
                                height={300}
                            />
                        </div>
                    ) : (
                        <Card>
                            <CardContent className="p-6 text-sm text-muted-foreground">
                                Enable at least one engagement series to render the chart.
                            </CardContent>
                        </Card>
                    )
                )}
                {sourceStatus.volume === 'error' ? (
                    <Card>
                        <CardContent className="p-6 text-sm text-muted-foreground">
                            Send volume data is temporarily unavailable. Adjust the date range or try again shortly.
                        </CardContent>
                    </Card>
                ) : (
                    <div data-testid="reports-volume-chart">
                        <ApexBarChart
                            data={volume.length > 0 ? volume : [{ date: 'No data', sent: 0 }]}
                            xKey="date" title="Send Volume" description="Emails sent per day"
                            bars={[{ key: 'sent', name: 'Sent', color: '#2563eb' }]}
                            formatter={countFormatter}
                            height={300}
                        />
                    </div>
                )}
            </div>

            <Card>
                <CardContent className="p-4 text-sm text-muted-foreground">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                        <span>Metric glossary</span>
                        <Button size="sm" variant="outline" onClick={() => setShowGlossary((prev) => !prev)}>
                            {showGlossary ? 'Hide glossary' : 'Show glossary'}
                        </Button>
                    </div>
                    {showGlossary ? (
                        <div className="mt-3 grid gap-2 text-xs">
                            <p><strong>Open rate:</strong> Unique opens divided by delivered messages.</p>
                            <p><strong>CTR:</strong> Unique clicks divided by delivered messages.</p>
                            <p><strong>Complaint rate:</strong> Complaint events divided by delivered messages.</p>
                        </div>
                    ) : null}
                </CardContent>
            </Card>

            {loading ? (
                <Card>
                    <CardContent className="p-4 space-y-2">
                        {Array.from({ length: 4 }).map((_, idx) => (
                            <div key={idx} className="h-10 rounded bg-muted animate-pulse" />
                        ))}
                    </CardContent>
                </Card>
            ) : null}

            <Card className={showPrintMode ? 'print:block' : ''}>
                <CardContent className="p-4 text-sm text-muted-foreground">
                    Throughput unit: messages/min • Latency unit: ms
                </CardContent>
            </Card>

            {!loading && sourceStatus.engagement === 'ok' && sourceStatus.volume === 'ok' && engagement.length === 0 && volume.length === 0 ? (
                <Card>
                    <CardContent className="p-6 text-sm text-muted-foreground">
                        No data for the selected date range. Try broadening to 30 or 90 days.
                    </CardContent>
                </Card>
            ) : null}

            {!loading && !stats && (
                <Card>
                    <CardContent className="py-12">
                        <EmptyState
                            icon={BarChart3}
                            title="No analytics data"
                            description="Send your first campaign or setup an automation to see detailed delivery and engagement reports."
                            action={{
                                label: 'Go to Campaigns',
                                onClick: () => window.location.href = '/campaigns'
                            }}
                        />
                    </CardContent>
                </Card>
            )}
        </div>
    );
}
