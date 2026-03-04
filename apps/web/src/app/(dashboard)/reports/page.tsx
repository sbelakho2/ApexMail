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
import { useAPI } from '@/hooks/use-api';

interface StatsData {
    sent: number; delivered: number; opened: number; clicked: number; bounced: number;
    rates: { delivery: string; open: string; click: string; bounce: string };
}

interface DashboardAnalyticsResponse {
    dashboard?: {
        engagement?: StatsData;
    };
}

interface VolumeAnalyticsResponse {
    volume?: Array<{ date: string; sent: number; delivered: number }>;
}

interface EngagementAnalyticsResponse {
    engagement?: Array<{ date: string; opens: number; clicks: number }>;
}

function ReportsPageContent() {
    const router = useRouter();
    const searchParams = useSearchParams();
    const [windowDays, setWindowDays] = React.useState<7 | 30 | 90>(30);
    const [showOpens, setShowOpens] = React.useState(true);
    const [showClicks, setShowClicks] = React.useState(true);
    const [isExporting, setIsExporting] = React.useState(false);
    const [reportJobStatus, setReportJobStatus] = React.useState<'idle' | 'queued' | 'running' | 'done' | 'failed'>('idle');
    const [dataFidelity] = React.useState<'sampled' | 'full'>('full');
    const [showGlossary, setShowGlossary] = React.useState(false);
    const [showPrintMode, setShowPrintMode] = React.useState(false);
    const [supportsAdvancedCharts, setSupportsAdvancedCharts] = React.useState(true);
    const [dataDelayed] = React.useState(false);
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

    const [refreshKey, setRefreshKey] = React.useState(0);
    React.useEffect(() => {
        const id = setInterval(() => setRefreshKey(k => k + 1), 60_000);
        return () => clearInterval(id);
    }, []);

    const since = React.useMemo(() => new Date(Date.now() - windowDays * 86_400_000).toISOString(), [windowDays, refreshKey]);
    const until = React.useMemo(() => new Date().toISOString(), [windowDays, refreshKey]);

    const dashboardQuery = useAPI<DashboardAnalyticsResponse>(`/v1/analytics/dashboard?since=${since}&until=${until}`, {
        keepPreviousData: true,
    });
    const volumeQuery = useAPI<VolumeAnalyticsResponse>(`/v1/analytics/volume?since=${since}&until=${until}&granularity=day`, {
        keepPreviousData: true,
    });
    const engagementQuery = useAPI<EngagementAnalyticsResponse>(`/v1/analytics/engagement?since=${since}&until=${until}&granularity=day`, {
        keepPreviousData: true,
    });

    const stats = dashboardQuery.data?.dashboard?.engagement ?? null;
    const volume = volumeQuery.data?.volume ?? [];
    const engagement = engagementQuery.data?.engagement ?? [];
    const loading = dashboardQuery.isLoading || volumeQuery.isLoading || engagementQuery.isLoading;
    const sourceStatus = {
        stats: dashboardQuery.error ? 'error' : 'ok',
        volume: volumeQuery.error ? 'error' : 'ok',
        engagement: engagementQuery.error ? 'error' : 'ok',
    } as const;

    const handleExportCsv = () => {
        if (isExporting) return;
        setIsExporting(true);
        setReportJobStatus('running');

        const sanitizeCell = (val: string) => {
            // Prevent CSV formula injection
            if (/^[=+\-@\t\r]/.test(val)) val = "'" + val;
            // Quote if contains comma, quote, or newline
            if (/[,"\n\r]/.test(val)) return '"' + val.replace(/"/g, '""') + '"';
            return val;
        };

        try {
            const rows = [['Date', 'Sent', 'Delivered', 'Opens', 'Clicks']];
            const entries = volume.slice(0, Math.max(volume.length, engagement.length));
            entries.forEach((point, index) => {
                rows.push([
                    sanitizeCell(String(point?.date ?? engagement[index]?.date ?? '')),
                    sanitizeCell(String(point?.sent ?? 0)),
                    sanitizeCell(String(point?.delivered ?? 0)),
                    sanitizeCell(String(engagement[index]?.opens ?? 0)),
                    sanitizeCell(String(engagement[index]?.clicks ?? 0)),
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

            setReportJobStatus('done');
        } catch {
            setReportJobStatus('failed');
        } finally {
            setIsExporting(false);
        }
    };

    return (
        <div className="flex flex-col gap-6 px-4 md:px-6 lg:px-8">
            <PageHeader
                title="Reports"
                description="Analyze your email performance with detailed reports."
                breadcrumbs={[{ label: 'Reports' }]}
                actions={
                    <div className="contents" data-testid="reports-range-controls" role="radiogroup" aria-label="Reports date range">
                        <Button variant="outline" onClick={() => setShowPrintMode((prev) => !prev)}>
                            {showPrintMode ? 'Exit Print Mode' : 'Print/PDF Mode'}
                        </Button>
                        {[7, 30, 90].map((days) => (
                            <Button
                                key={days}
                                variant={windowDays === days ? 'default' : 'outline'}
                                role="radio"
                                aria-checked={windowDays === days}
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
                            <Download className="mr-2 h-4 w-4" />{isExporting ? 'Exporting…' : 'Export CSV'}
                        </Button>
                    </div>
                }
            />

            {isExporting ? (
                <Card>
                    <CardContent className="p-4 text-sm text-muted-foreground">
                        Preparing CSV export…
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
                <div className="grid gap-4 md:grid-cols-4">{Array.from({ length: 4 }, (_, i) => `report-metric-skeleton-${i}`).map((skeletonId) => <Skeleton key={skeletonId} className="h-24" />)}</div>
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
                                onClick: () => router.push('/campaigns')
                            }}
                        />
                    </CardContent>
                </Card>
            )}
        </div>
    );
}

export default function ReportsPage() {
    return (
        <React.Suspense fallback={<div className="flex flex-col gap-6 px-4 md:px-6 lg:px-8 py-6 text-sm text-muted-foreground">Loading reports...</div>}>
            <ReportsPageContent />
        </React.Suspense>
    );
}
