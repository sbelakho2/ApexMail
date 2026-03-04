'use client';

import { useEffect, useState, useCallback } from 'react';
import { formatNumber, formatPercentage, timeAgo, cn } from '@/lib/utils';
import { getCsrfToken } from '@/lib/client-csrf';
import { useDialog } from '@/components/ui/confirm-dialog';
import { PageLoadingState } from '@/components/ui/async-state';

/* ─── Types mirroring the backend shapes ─── */

type LoopStatus = 'idle' | 'running' | 'paused' | 'safe_mode';

interface Overview {
    status: LoopStatus;
    canStart: boolean;
    canStop: boolean;
    hoursRun: number;
    currentHour: number;
    pendingApprovals: number;
    activeCandidates: number;
    safeModeCount: number;
    safetyOk: boolean;
    safetyMessage: string;
}

interface HourlyMetrics {
    totalSent: number;
    totalOpened: number;
    totalClicked: number;
    totalReplied: number;
    totalNegative: number;
    totalBounced: number;
    totalUnsubscribed: number;
    aggregateOpenRate: number;
    aggregateReplyRate: number;
    aggregateNegativeRate: number;
    aggregateBounceRate: number;
}

interface Candidate {
    armId: string;
    label: string;
    stage: string;
    icpCluster: string;
    impressions: number;
    opens: number;
    clicks: number;
    replies: number;
    negatives: number;
    openRate: number;
    replyRate: number;
    negativeRate: number;
    lowerBound: number;
    upperBound: number;
    consecutiveHoursBeating: number;
    status: 'active' | 'pruned' | 'promoted' | 'killed' | 'baseline';
}

interface HourlyOutcome {
    hour: number;
    verdict: string;
    baselineOpenRate: number;
    aggregateOpenRate: number;
    baselineReplyRate: number;
    aggregateReplyRate: number;
    candidatesPromoted: string[];
    candidatesPruned: string[];
    candidatesKilled: string[];
    newVariantsSeeded: number;
    safeModeTriggered: boolean;
}

interface PendingEmail {
    id: string;
    contactEmail: string;
    subject: string;
    bodyPreview: string;
    armLabel: string;
    campaignId: string;
    createdAt: string;
    status: string;
}

interface BaselineData {
    hasBaseline: boolean;
    comparison?: {
        baseline: { subjectLabel: string; valuePropLabel: string; openRate: number; replyRate: number; negativeRate: number; impressions: number };
        aggregate: { openRate: number; replyRate: number; negativeRate: number; totalSent: number };
        deltas: { openRateDelta: number; replyRateDelta: number; negativeRateDelta: number };
        verdict: string;
    };
}

interface ActionEntry {
    action: string;
    performedAt: string;
    operatorId: string;
    detail: string;
}

interface SafetyReport {
    throttleStatus: { throttle: boolean; halt: boolean; reason: string };
    recentTraces: unknown[];
    banditPoolCount: number;
    totalArms: number;
    frozenArms: number;
    cadenceAtLimit: number;
    cadenceStopped: number;
}

/* ─── Helper to fetch a section from the API route ─── */

async function fetchSection<T>(section: string): Promise<T> {
    const res = await fetch(`/api/autopilot?section=${section}`, { credentials: 'include' });
    if (!res.ok) throw new Error(`Failed to fetch ${section}`);
    return res.json();
}

async function postAction(action: string, extra: Record<string, unknown> = {}) {
    const csrfToken = await getCsrfToken();
    const res = await fetch('/api/autopilot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
        credentials: 'include',
        body: JSON.stringify({ action, ...extra }),
    });
    if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error(body || `Action failed with status ${res.status}`);
    }
    return res.json().catch(() => null);
}

/* ─── Status / verdict badge helpers ─── */

function statusBadge(status: string) {
    const map: Record<string, string> = {
        active: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
        promoted: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
        baseline: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
        pruned: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400',
        killed: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
    };
    return map[status] ?? 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300';
}

function verdictBadge(v: string) {
    const map: Record<string, string> = {
        improved: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
        held_steady: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
        retreated: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
    };
    return map[v] ?? 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300';
}

function loopStatusColor(s: LoopStatus) {
    switch (s) {
        case 'running': return 'text-green-600 dark:text-green-400';
        case 'safe_mode': return 'text-amber-600 dark:text-amber-400';
        case 'paused': return 'text-yellow-600 dark:text-yellow-400';
        default: return 'text-muted-foreground';
    }
}

function deltaArrow(delta: number) {
    if (delta > 0.001) return <span className="text-green-600 dark:text-green-400">▲ +{formatPercentage(delta)}</span>;
    if (delta < -0.001) return <span className="text-red-600 dark:text-red-400">▼ {formatPercentage(delta)}</span>;
    return <span className="text-muted-foreground">— 0.0%</span>;
}

/* ─── Tabs ─── */

const TABS = [
    { key: 'overview', label: 'Overview' },
    { key: 'candidates', label: 'Candidates' },
    { key: 'approvals', label: 'Approvals' },
    { key: 'outcomes', label: 'Hourly Log' },
    { key: 'safety', label: 'Safety' },
    { key: 'actions', label: 'Actions' },
] as const;

type TabKey = (typeof TABS)[number]['key'];

/* ─── Main Page ─── */

export default function AutopilotConsolePage() {
    const [tab, setTab] = useState<TabKey>('overview');
    const [loading, setLoading] = useState(true);
    const [acting, setActing] = useState(false);
    const dialog = useDialog();

    const [overview, setOverview] = useState<Overview | null>(null);
    const [metrics, setMetrics] = useState<HourlyMetrics | null>(null);
    const [baseline, setBaseline] = useState<BaselineData | null>(null);
    const [candidates, setCandidates] = useState<Candidate[]>([]);
    const [outcomes, setOutcomes] = useState<HourlyOutcome[]>([]);
    const [pending, setPending] = useState<PendingEmail[]>([]);
    const [actions, setActions] = useState<ActionEntry[]>([]);
    const [safety, setSafety] = useState<SafetyReport | null>(null);

    const loadAll = useCallback(async () => {
        setLoading(true);
        try {
            const results = await Promise.allSettled([
                fetchSection<Overview>('overview'),
                fetchSection<HourlyMetrics>('metrics'),
                fetchSection<BaselineData>('baseline'),
                fetchSection<Candidate[]>('candidates'),
                fetchSection<HourlyOutcome[]>('outcomes'),
                fetchSection<PendingEmail[]>('pending'),
                fetchSection<ActionEntry[]>('actions'),
                fetchSection<SafetyReport>('safety'),
            ]);
            if (results[0].status === 'fulfilled') setOverview(results[0].value);
            if (results[1].status === 'fulfilled') setMetrics(results[1].value);
            if (results[2].status === 'fulfilled') setBaseline(results[2].value);
            if (results[3].status === 'fulfilled') setCandidates(results[3].value);
            if (results[4].status === 'fulfilled') setOutcomes(results[4].value);
            if (results[5].status === 'fulfilled') setPending(results[5].value);
            if (results[6].status === 'fulfilled') setActions(results[6].value);
            if (results[7].status === 'fulfilled') setSafety(results[7].value);
            const failedCount = results.filter(r => r.status === 'rejected').length;
            if (failedCount > 0 && failedCount < results.length) {
                console.warn(`${failedCount} autopilot sections failed to load`);
            } else if (failedCount === results.length) {
                throw new Error('All autopilot sections failed to load');
            }
        } catch (e) {
            console.error('Failed to load autopilot data:', e);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { loadAll(); }, [loadAll]);

    /* ─ Power toggle ─ */
    async function toggleSystem() {
        if (!overview) return;
        const action = overview.status === 'running' ? 'stop' : 'start';
        const confirmed = await dialog.confirm({
            title: action === 'stop' ? 'Stop Autopilot' : 'Start Autopilot',
            message: action === 'stop'
                ? 'Stop the autopilot loop? All in-flight optimization will pause and pending emails will not be sent until restarted.'
                : 'Start the autopilot optimization loop? It will begin sending test variants and collecting metrics immediately.',
            confirmLabel: action === 'stop' ? 'Stop Loop' : 'Start Loop',
            variant: action === 'stop' ? 'destructive' : 'default',
        });
        if (!confirmed) return;
        setActing(true);
        try {
            await postAction(action);
            await loadAll();
        } catch (err) {
            await dialog.alert({ title: 'Action Failed', message: err instanceof Error ? err.message : `Failed to ${action} autopilot` });
        } finally {
            setActing(false);
        }
    }

    /* ─ Email approval actions ─ */
    async function approveEmail(id: string) {
        setActing(true);
        try {
            await postAction('approve', { id });
            await loadAll();
        } catch (err) {
            await dialog.alert({ title: 'Approve Failed', message: err instanceof Error ? err.message : 'Failed to approve email' });
        } finally {
            setActing(false);
        }
    }
    async function rejectEmail(id: string) {
        setActing(true);
        try {
            await postAction('reject', { id });
            await loadAll();
        } catch (err) {
            await dialog.alert({ title: 'Reject Failed', message: err instanceof Error ? err.message : 'Failed to reject email' });
        } finally {
            setActing(false);
        }
    }
    async function approveAll() {
        const confirmed = await dialog.confirm({
            title: 'Approve All Pending Emails',
            message: `Approve all ${pending.length} pending email(s)? They will be queued for delivery immediately.`,
            confirmLabel: 'Approve All',
            variant: 'destructive',
        });
        if (!confirmed) return;
        setActing(true);
        try {
            await postAction('approve-all');
            await loadAll();
        } catch (err) {
            await dialog.alert({ title: 'Approve All Failed', message: err instanceof Error ? err.message : 'Failed to approve all emails' });
        } finally {
            setActing(false);
        }
    }
    async function exitSafeMode() {
        const confirmed = await dialog.confirm({
            title: 'Exit Safe Mode',
            message: 'Exit safe mode and resume normal autopilot operation? Ensure the issue that triggered safe mode has been resolved.',
            confirmLabel: 'Exit Safe Mode',
            variant: 'destructive',
        });
        if (!confirmed) return;
        setActing(true);
        try {
            await postAction('exit-safe-mode');
            await loadAll();
        } catch (err) {
            await dialog.alert({ title: 'Exit Safe Mode Failed', message: err instanceof Error ? err.message : 'Failed to exit safe mode' });
        } finally {
            setActing(false);
        }
    }

    if (loading) {
        return <PageLoadingState label="Loading autopilot data..." />;
    }

    if (!overview) {
        return (
            <div className="flex flex-col items-center justify-center h-[60vh] gap-4">
                <p className="text-muted-foreground">Failed to load autopilot data.</p>
                <button onClick={loadAll} className="px-4 py-2 text-sm bg-primary text-primary-foreground rounded-lg hover:bg-primary/90">Retry</button>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div>
                    <h1 className="text-2xl font-bold tracking-tight">Autopilot Console</h1>
                    <p className="text-muted-foreground mt-1">
                        Hourly optimization loop — Thompson sampling · copy gates · safety rails
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    {overview?.status === 'safe_mode' && (
                        <button
                            onClick={exitSafeMode}
                            disabled={acting}
                            className="px-3 py-2 rounded-md text-sm font-medium bg-amber-100 text-amber-800 hover:bg-amber-200 dark:bg-amber-900/30 dark:text-amber-400 dark:hover:bg-amber-900/50 transition-colors disabled:opacity-50"
                        >
                            Exit Safe Mode
                        </button>
                    )}
                    <button
                        onClick={toggleSystem}
                        disabled={acting}
                        className={cn(
                            'px-4 py-2 rounded-md text-sm font-semibold transition-colors disabled:opacity-50',
                            overview?.status === 'running'
                                ? 'bg-red-600 text-white hover:bg-red-700'
                                : 'bg-green-600 text-white hover:bg-green-700',
                        )}
                    >
                        {overview?.status === 'running' ? 'Stop Loop' : 'Start Loop'}
                    </button>
                    <button
                        onClick={loadAll}
                        disabled={loading}
                        className="px-3 py-2 rounded-md text-sm border border-border hover:bg-muted transition-colors disabled:opacity-50"
                    >
                        ↻ Refresh
                    </button>
                </div>
            </div>

            {/* Tab bar */}
            <div className="flex gap-1 border-b border-border overflow-x-auto">
                {TABS.map((t) => (
                    <button
                        key={t.key}
                        onClick={() => setTab(t.key)}
                        className={cn(
                            'px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
                            tab === t.key
                                ? 'border-primary text-primary'
                                : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border',
                        )}
                    >
                        {t.label}
                        {t.key === 'approvals' && pending.length > 0 && (
                            <span className="ml-2 bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 text-xs px-1.5 py-0.5 rounded-full">
                                {pending.length}
                            </span>
                        )}
                    </button>
                ))}
            </div>

            {/* Tab content */}
            {tab === 'overview' && overview && metrics && <OverviewTab overview={overview} metrics={metrics} baseline={baseline} />}
            {tab === 'candidates' && <CandidatesTab candidates={candidates} />}
            {tab === 'approvals' && <ApprovalsTab pending={pending} approveEmail={approveEmail} rejectEmail={rejectEmail} approveAll={approveAll} acting={acting} />}
            {tab === 'outcomes' && <OutcomesTab outcomes={outcomes} />}
            {tab === 'safety' && safety && <SafetyTab safety={safety} />}
            {tab === 'actions' && <ActionsTab actions={actions} />}
        </div>
    );
}

/* ════════════════════════════════ TAB COMPONENTS ════════════════════════════════ */

/* ─── Overview Tab ─── */

function OverviewTab({ overview, metrics, baseline }: { overview: Overview; metrics: HourlyMetrics; baseline: BaselineData | null }) {
    return (
        <div className="space-y-6">
            {/* Status cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Card label="Loop Status">
                    <span className={cn('text-lg font-bold uppercase', loopStatusColor(overview.status))}>
                        {overview.status.replace('_', ' ')}
                    </span>
                </Card>
                <Card label="Hours Run">
                    <span className="text-2xl font-bold">{overview.hoursRun}</span>
                </Card>
                <Card label="Active Candidates">
                    <span className="text-2xl font-bold">{overview.activeCandidates}</span>
                </Card>
                <Card label="Pending Approvals">
                    <span className={cn('text-2xl font-bold', overview.pendingApprovals > 0 ? 'text-amber-600 dark:text-amber-400' : '')}>
                        {overview.pendingApprovals}
                    </span>
                </Card>
            </div>

            {/* Safety banner */}
            {!overview.safetyOk && (
                <div className="rounded-lg border border-red-300 bg-red-50 dark:bg-red-900/20 dark:border-red-800 p-4">
                    <p className="text-sm font-medium text-red-800 dark:text-red-400">
                        Safety issue: {overview.safetyMessage}
                    </p>
                </div>
            )}

            {/* Aggregate metrics */}
            <div>
                <h2 className="text-lg font-semibold mb-3">Aggregate Metrics</h2>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <Card label="Total Sent"><span className="text-xl font-bold">{formatNumber(metrics.totalSent)}</span></Card>
                    <Card label="Open Rate"><span className="text-xl font-bold">{formatPercentage(metrics.aggregateOpenRate)}</span></Card>
                    <Card label="Reply Rate"><span className="text-xl font-bold">{formatPercentage(metrics.aggregateReplyRate)}</span></Card>
                    <Card label="Negative Rate"><span className="text-xl font-bold">{formatPercentage(metrics.aggregateNegativeRate)}</span></Card>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
                    <Card label="Opened"><span className="text-xl font-bold">{formatNumber(metrics.totalOpened)}</span></Card>
                    <Card label="Clicked"><span className="text-xl font-bold">{formatNumber(metrics.totalClicked)}</span></Card>
                    <Card label="Replied"><span className="text-xl font-bold">{formatNumber(metrics.totalReplied)}</span></Card>
                    <Card label="Bounced"><span className="text-xl font-bold">{formatNumber(metrics.totalBounced)}</span></Card>
                </div>
            </div>

            {/* Baseline comparison */}
            {baseline?.hasBaseline && baseline.comparison && (
                <div>
                    <h2 className="text-lg font-semibold mb-3">Baseline Comparison</h2>
                    <div className="apex-card p-4 space-y-4">
                        <div className="flex items-center gap-2">
                            <span className="text-sm font-medium">Verdict:</span>
                            <span className={cn(
                                'px-2 py-0.5 rounded-full text-xs font-semibold',
                                baseline.comparison.verdict === 'improving'
                                    ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                                    : baseline.comparison.verdict === 'regressing'
                                        ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                                        : 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
                            )}>
                                {baseline.comparison.verdict}
                            </span>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <div className="space-y-1">
                                <p className="text-xs text-muted-foreground">Open Rate</p>
                                <p className="text-sm">
                                    Baseline: <strong>{formatPercentage(baseline.comparison.baseline.openRate)}</strong>
                                    {' → '}
                                    Aggregate: <strong>{formatPercentage(baseline.comparison.aggregate.openRate)}</strong>
                                </p>
                                <p className="text-xs">{deltaArrow(baseline.comparison.deltas.openRateDelta)}</p>
                            </div>
                            <div className="space-y-1">
                                <p className="text-xs text-muted-foreground">Reply Rate</p>
                                <p className="text-sm">
                                    Baseline: <strong>{formatPercentage(baseline.comparison.baseline.replyRate)}</strong>
                                    {' → '}
                                    Aggregate: <strong>{formatPercentage(baseline.comparison.aggregate.replyRate)}</strong>
                                </p>
                                <p className="text-xs">{deltaArrow(baseline.comparison.deltas.replyRateDelta)}</p>
                            </div>
                            <div className="space-y-1">
                                <p className="text-xs text-muted-foreground">Negative Rate</p>
                                <p className="text-sm">
                                    Baseline: <strong>{formatPercentage(baseline.comparison.baseline.negativeRate)}</strong>
                                    {' → '}
                                    Aggregate: <strong>{formatPercentage(baseline.comparison.aggregate.negativeRate)}</strong>
                                </p>
                                <p className="text-xs">{deltaArrow(baseline.comparison.deltas.negativeRateDelta)}</p>
                            </div>
                        </div>
                        <p className="text-xs text-muted-foreground">
                            Baseline: &quot;{baseline.comparison.baseline.subjectLabel}&quot; ({formatNumber(baseline.comparison.baseline.impressions)} impressions)
                        </p>
                    </div>
                </div>
            )}
        </div>
    );
}

/* ─── Candidates Tab ─── */

function CandidatesTab({ candidates }: { candidates: Candidate[] }) {
    const sortedCandidates = [...candidates].sort((a, b) => {
        const order = { baseline: 0, promoted: 1, active: 2, pruned: 3, killed: 4 };
        return (order[a.status] ?? 99) - (order[b.status] ?? 99);
    });

    return (
        <div className="space-y-4">
            <h2 className="text-lg font-semibold">Candidate Arms ({candidates.length})</h2>
            <div className="apex-card overflow-x-auto">
                <table className="w-full text-sm">
                    <thead>
                        <tr className="border-b border-border bg-muted/50">
                            <th className="px-3 py-2 text-left font-medium">Label</th>
                            <th className="px-3 py-2 text-left font-medium">ICP</th>
                            <th className="px-3 py-2 text-right font-medium">Impr.</th>
                            <th className="px-3 py-2 text-right font-medium">Open %</th>
                            <th className="px-3 py-2 text-right font-medium">Reply %</th>
                            <th className="px-3 py-2 text-right font-medium">Neg %</th>
                            <th className="px-3 py-2 text-right font-medium">CI (Reply)</th>
                            <th className="px-3 py-2 text-right font-medium">Hrs ▲</th>
                            <th className="px-3 py-2 text-center font-medium">Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {sortedCandidates.map((c) => (
                            <tr key={c.armId} className="border-b border-border last:border-0 hover:bg-muted/30 transition-colors">
                                <td className="px-3 py-2 font-medium max-w-[220px] truncate" title={c.label}>
                                    {c.label}
                                </td>
                                <td className="px-3 py-2 text-muted-foreground">{c.icpCluster}</td>
                                <td className="px-3 py-2 text-right apex-metric-number">{formatNumber(c.impressions)}</td>
                                <td className="px-3 py-2 text-right apex-metric-number">{formatPercentage(c.openRate)}</td>
                                <td className="px-3 py-2 text-right apex-metric-number font-medium">{formatPercentage(c.replyRate)}</td>
                                <td className="px-3 py-2 text-right apex-metric-number">{formatPercentage(c.negativeRate)}</td>
                                <td className="px-3 py-2 text-right apex-metric-number text-xs text-muted-foreground">
                                    [{formatPercentage(c.lowerBound)} – {formatPercentage(c.upperBound)}]
                                </td>
                                <td className="px-3 py-2 text-right apex-metric-number">{c.consecutiveHoursBeating}</td>
                                <td className="px-3 py-2 text-center">
                                    <span className={cn('px-2 py-0.5 rounded-full text-xs font-semibold', statusBadge(c.status))}>
                                        {c.status}
                                    </span>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

/* ─── Approvals Tab ─── */

function ApprovalsTab({ pending, approveEmail, rejectEmail, approveAll, acting }: {
    pending: PendingEmail[];
    approveEmail: (id: string) => void;
    rejectEmail: (id: string) => void;
    approveAll: () => void;
    acting: boolean;
}) {
    if (pending.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                <p className="text-lg font-medium">No pending approvals</p>
                <p className="text-sm mt-1">All emails have been reviewed.</p>
            </div>
        );
    }

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">Pending Approvals ({pending.length})</h2>
                <button
                    onClick={approveAll}
                    disabled={acting}
                    className="px-3 py-1.5 rounded-md text-sm font-medium bg-green-600 text-white hover:bg-green-700 transition-colors disabled:opacity-50"
                >
                    Approve All
                </button>
            </div>

            <div className="space-y-3">
                {pending.map((email) => (
                    <div key={email.id} className="apex-card p-4">
                        <div className="flex items-start justify-between gap-4">
                            <div className="flex-1 min-w-0 space-y-1">
                                <p className="font-medium">{email.subject}</p>
                                <p className="text-sm text-muted-foreground truncate">To: {email.contactEmail}</p>
                                <p className="text-sm text-muted-foreground line-clamp-2">{email.bodyPreview}</p>
                                <div className="flex items-center gap-3 text-xs text-muted-foreground mt-2">
                                    <span>Arm: {email.armLabel}</span>
                                    <span>•</span>
                                    <span>{timeAgo(email.createdAt)}</span>
                                </div>
                            </div>
                            <div className="flex gap-2 shrink-0">
                                <button
                                    onClick={() => approveEmail(email.id)}
                                    disabled={acting}
                                    className="px-3 py-1.5 rounded-md text-xs font-medium bg-green-100 text-green-800 hover:bg-green-200 dark:bg-green-900/30 dark:text-green-400 dark:hover:bg-green-900/50 transition-colors disabled:opacity-50"
                                >
                                    Approve
                                </button>
                                <button
                                    onClick={() => rejectEmail(email.id)}
                                    disabled={acting}
                                    className="px-3 py-1.5 rounded-md text-xs font-medium bg-red-100 text-red-800 hover:bg-red-200 dark:bg-red-900/30 dark:text-red-400 dark:hover:bg-red-900/50 transition-colors disabled:opacity-50"
                                >
                                    Reject
                                </button>
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

/* ─── Outcomes Tab ─── */

function OutcomesTab({ outcomes }: { outcomes: HourlyOutcome[] }) {
    return (
        <div className="space-y-4">
            <h2 className="text-lg font-semibold">Hourly Outcomes ({outcomes.length})</h2>
            <div className="apex-card overflow-x-auto">
                <table className="w-full text-sm">
                    <thead>
                        <tr className="border-b border-border bg-muted/50">
                            <th className="px-3 py-2 text-left font-medium">Hour</th>
                            <th className="px-3 py-2 text-center font-medium">Verdict</th>
                            <th className="px-3 py-2 text-right font-medium">BL Open %</th>
                            <th className="px-3 py-2 text-right font-medium">Agg Open %</th>
                            <th className="px-3 py-2 text-right font-medium">BL Reply %</th>
                            <th className="px-3 py-2 text-right font-medium">Agg Reply %</th>
                            <th className="px-3 py-2 text-right font-medium">Prom.</th>
                            <th className="px-3 py-2 text-right font-medium">Pruned</th>
                            <th className="px-3 py-2 text-right font-medium">Killed</th>
                            <th className="px-3 py-2 text-right font-medium">Seeded</th>
                            <th className="px-3 py-2 text-center font-medium">Safe</th>
                        </tr>
                    </thead>
                    <tbody>
                        {outcomes.map((o) => (
                            <tr key={o.hour} className="border-b border-border last:border-0 hover:bg-muted/30 transition-colors">
                                <td className="px-3 py-2 apex-metric-number font-medium">H{o.hour}</td>
                                <td className="px-3 py-2 text-center">
                                    <span className={cn('px-2 py-0.5 rounded-full text-xs font-semibold', verdictBadge(o.verdict))}>
                                        {o.verdict.replace('_', ' ')}
                                    </span>
                                </td>
                                <td className="px-3 py-2 text-right apex-metric-number">{formatPercentage(o.baselineOpenRate)}</td>
                                <td className="px-3 py-2 text-right apex-metric-number">{formatPercentage(o.aggregateOpenRate)}</td>
                                <td className="px-3 py-2 text-right apex-metric-number">{formatPercentage(o.baselineReplyRate)}</td>
                                <td className="px-3 py-2 text-right apex-metric-number">{formatPercentage(o.aggregateReplyRate)}</td>
                                <td className="px-3 py-2 text-right apex-metric-number">{o.candidatesPromoted.length}</td>
                                <td className="px-3 py-2 text-right apex-metric-number">{o.candidatesPruned.length}</td>
                                <td className="px-3 py-2 text-right apex-metric-number">{o.candidatesKilled.length}</td>
                                <td className="px-3 py-2 text-right apex-metric-number">{o.newVariantsSeeded}</td>
                                <td className="px-3 py-2 text-center">
                                    {o.safeModeTriggered ? <span className="text-red-600 dark:text-red-400">Warn</span> : <span className="text-green-600 dark:text-green-400">OK</span>}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

/* ─── Safety Tab ─── */

function SafetyTab({ safety }: { safety: SafetyReport }) {
    const ts = safety.throttleStatus;
    return (
        <div className="space-y-6">
            <h2 className="text-lg font-semibold">Safety Report</h2>

            {/* Throttle status */}
            <div className={cn(
                'rounded-lg border p-4',
                ts.halt ? 'border-red-300 bg-red-50 dark:bg-red-900/20 dark:border-red-800'
                    : ts.throttle ? 'border-amber-300 bg-amber-50 dark:bg-amber-900/20 dark:border-amber-800'
                        : 'border-green-300 bg-green-50 dark:bg-green-900/20 dark:border-green-800',
            )}>
                <p className="font-medium">
                    {ts.halt ? 'HALT' : ts.throttle ? 'Throttled' : 'All Clear'}
                </p>
                <p className="text-sm text-muted-foreground mt-1">{ts.reason}</p>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Card label="Bandit Pools"><span className="text-xl font-bold">{safety.banditPoolCount}</span></Card>
                <Card label="Total Arms"><span className="text-xl font-bold">{safety.totalArms}</span></Card>
                <Card label="Frozen Arms"><span className="text-xl font-bold">{safety.frozenArms}</span></Card>
                <Card label="Cadence at Limit"><span className="text-xl font-bold">{safety.cadenceAtLimit}</span></Card>
            </div>

            {safety.cadenceStopped > 0 && (
                <p className="text-sm text-muted-foreground">
                    {safety.cadenceStopped} contacts have reached their cadence stop limit.
                </p>
            )}
        </div>
    );
}

/* ─── Actions Tab ─── */

function ActionsTab({ actions }: { actions: ActionEntry[] }) {
    return (
        <div className="space-y-4">
            <h2 className="text-lg font-semibold">Action Log ({actions.length})</h2>
            {actions.length === 0 ? (
                <p className="text-muted-foreground py-8 text-center">No actions recorded yet.</p>
            ) : (
                <div className="space-y-2">
                    {actions.map((a) => (
                        <div key={`${a.action}-${a.performedAt}`} className="apex-card px-4 py-3 flex items-start gap-3">
                            <span className="text-xs font-mono bg-muted px-2 py-0.5 rounded shrink-0 mt-0.5">{a.action}</span>
                            <div className="flex-1 min-w-0">
                                <p className="text-sm">{a.detail}</p>
                                <p className="text-xs text-muted-foreground mt-1">{timeAgo(a.performedAt)}</p>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

/* ─── Reusable stat card ─── */

function Card({ label, children }: { label: string; children: React.ReactNode }) {
    return (
        <div className="apex-card p-4">
            <p className="text-xs font-medium text-muted-foreground mb-1">{label}</p>
            {children}
        </div>
    );
}
