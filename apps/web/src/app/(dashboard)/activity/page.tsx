'use client';

import * as React from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { Activity, Mail, Search, ChevronRight, RefreshCw, ChevronLeft } from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState } from '@/components/ui/empty-state';
import { cn, formatNumber } from '@/lib/utils';
import { useAPI } from '@/hooks/use-api';

/* ─── Types ─────────────────────────────────────────────────────────── */

interface EmailMessage {
    id: string;
    to: string;
    from: string;
    subject: string;
    status: 'queued' | 'sent' | 'delivered' | 'opened' | 'clicked' | 'bounced' | 'complained' | 'failed';
    campaignId?: string;
    campaignName?: string;
    createdAt: string;
    deliveredAt?: string;
    openedAt?: string;
    clickedAt?: string;
}

interface EmailEvent {
    id: string;
    type: 'queued' | 'sent' | 'delivered' | 'opened' | 'clicked' | 'bounced' | 'complained' | 'deferred' | 'dropped';
    timestamp: string;
    metadata?: Record<string, string>;
}

interface MessagesResponse {
    messages: EmailMessage[];
    total: number;
    page: number;
    pageSize: number;
}

interface MessageDetailResponse {
    message: EmailMessage;
    events: EmailEvent[];
}

/* ─── Status helpers ────────────────────────────────────────────────── */

const STATUS_CONFIG: Record<string, { label: string; dot: string; bg: string }> = {
    queued:     { label: 'Queued',     dot: 'bg-slate-400',  bg: 'bg-slate-400/10 text-slate-600 dark:text-slate-400' },
    sent:       { label: 'Sent',       dot: 'bg-blue-400',   bg: 'bg-blue-400/10 text-blue-600 dark:text-blue-400' },
    delivered:  { label: 'Delivered',  dot: 'bg-emerald-500', bg: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400' },
    opened:     { label: 'Opened',     dot: 'bg-violet-500', bg: 'bg-violet-500/10 text-violet-700 dark:text-violet-400' },
    clicked:    { label: 'Clicked',    dot: 'bg-sky-500',    bg: 'bg-sky-500/10 text-sky-700 dark:text-sky-400' },
    bounced:    { label: 'Bounced',    dot: 'bg-red-500',    bg: 'bg-red-500/10 text-red-700 dark:text-red-400' },
    complained: { label: 'Complaint',  dot: 'bg-orange-500', bg: 'bg-orange-500/10 text-orange-700 dark:text-orange-400' },
    failed:     { label: 'Failed',     dot: 'bg-red-600',    bg: 'bg-red-600/10 text-red-700 dark:text-red-400' },
    deferred:   { label: 'Deferred',   dot: 'bg-amber-400',  bg: 'bg-amber-400/10 text-amber-700 dark:text-amber-400' },
    dropped:    { label: 'Dropped',    dot: 'bg-gray-400',   bg: 'bg-gray-400/10 text-gray-600 dark:text-gray-400' },
};

function StatusBadge({ status }: { status: string }) {
    const cfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.queued;
    return (
        <span className={cn('inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold', cfg.bg)}>
            <span className={cn('h-1.5 w-1.5 rounded-full', cfg.dot)} />
            {cfg.label}
        </span>
    );
}

function relativeTime(iso: string): string {
    const diff = Date.now() - new Date(iso).getTime();
    const seconds = Math.floor(diff / 1000);
    if (seconds < 60) return 'just now';
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    if (days < 30) return `${days}d ago`;
    return new Date(iso).toLocaleDateString();
}

/* ─── Main component ────────────────────────────────────────────────── */

function ActivityPageContent() {
    const router = useRouter();
    const searchParams = useSearchParams();

    const [statusFilter, setStatusFilter] = React.useState<string>(searchParams.get('status') ?? '');
    const [searchInput, setSearchInput] = React.useState(searchParams.get('q') ?? '');
    const [searchQuery, setSearchQuery] = React.useState(searchParams.get('q') ?? '');
    const [page, setPage] = React.useState(1);
    const [selectedMessageId, setSelectedMessageId] = React.useState<string | null>(null);

    // Debounce search input → searchQuery used for API calls
    React.useEffect(() => {
        const timer = setTimeout(() => {
            setSearchQuery(searchInput);
            setPage(1);
        }, 300);
        return () => clearTimeout(timer);
    }, [searchInput]);

    const queryString = React.useMemo(() => {
        const params = new URLSearchParams();
        params.set('page', String(page));
        params.set('pageSize', '25');
        if (statusFilter) params.set('status', statusFilter);
        if (searchQuery.trim()) params.set('q', searchQuery.trim());
        return params.toString();
    }, [page, statusFilter, searchQuery]);

    const { data: messagesData, isLoading, mutate: refetchMessages } = useAPI<MessagesResponse>(
        `/v1/messages?${queryString}`,
        { refreshInterval: 30_000, keepPreviousData: true }
    );

    const { data: detailData, isLoading: detailLoading } = useAPI<MessageDetailResponse>(
        selectedMessageId ? `/v1/messages/${selectedMessageId}` : null,
        { keepPreviousData: false }
    );

    const messages = messagesData?.messages ?? [];
    const totalMessages = messagesData?.total ?? 0;
    const totalPages = Math.max(1, Math.ceil(totalMessages / 25));

    // Update URL params without full navigation
    React.useEffect(() => {
        const params = new URLSearchParams();
        if (statusFilter) params.set('status', statusFilter);
        if (searchQuery.trim()) params.set('q', searchQuery.trim());
        const qs = params.toString();
        router.replace(`/activity${qs ? `?${qs}` : ''}`, { scroll: false });
    }, [statusFilter, searchQuery, router]);

    const statusFilters = ['', 'queued', 'sent', 'delivered', 'opened', 'clicked', 'bounced', 'complained', 'failed'] as const;

    return (
        <div className="flex flex-col gap-6">
            <PageHeader
                title="Email Activity"
                description="Real-time log of every email sent from your account"
                breadcrumbs={[{ label: 'Dashboard', href: '/dashboard' }, { label: 'Activity' }]}
                actions={
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => { refetchMessages(); }}
                    >
                        <RefreshCw className="mr-2 h-4 w-4" />
                        Refresh
                    </Button>
                }
            />

            {/* Filters row */}
            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
                {/* Search */}
                <div className="relative flex-1 max-w-md">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
                    <Input
                        type="text"
                        value={searchInput}
                        onChange={e => setSearchInput(e.target.value)}
                        placeholder="Search by recipient or subject…"
                        aria-label="Search activity by recipient or subject"
                        className="w-full pl-9 min-h-[44px]"
                    />
                </div>

                {/* Status pills */}
                <div className="flex flex-wrap gap-1.5">
                    {statusFilters.map(s => (
                        <button
                            key={s || 'all'}
                            onClick={() => { setStatusFilter(s); setPage(1); }}
                            className={cn(
                                'px-3 py-1.5 rounded-full text-xs font-medium transition-colors min-h-[32px]',
                                statusFilter === s
                                    ? 'bg-primary text-primary-foreground shadow-sm'
                                    : 'bg-surface-100 text-muted-foreground hover:bg-surface-200',
                            )}
                        >
                            {s ? (STATUS_CONFIG[s]?.label ?? s) : 'All'}
                        </button>
                    ))}
                </div>
            </div>

            {/* Content area */}
            <div className="flex gap-6">
                {/* Message list */}
                <Card className="flex-1 overflow-hidden">
                    <CardContent className="p-0">
                        {isLoading && messages.length === 0 ? (
                            <div className="p-6 space-y-4">
                                {Array.from({ length: 6 }).map((_, i) => (
                                    <div key={i} className="flex items-center gap-4">
                                        <Skeleton className="h-4 w-4 rounded-full" />
                                        <Skeleton className="h-4 flex-1" />
                                        <Skeleton className="h-4 w-20" />
                                    </div>
                                ))}
                            </div>
                        ) : messages.length === 0 ? (
                            <div className="p-12">
                                <EmptyState
                                    icon={Mail}
                                    title="No messages found"
                                    description={
                                        statusFilter || searchQuery
                                            ? 'Try adjusting your filters or search query.'
                                            : 'Send your first email to see activity here.'
                                    }
                                />
                            </div>
                        ) : (
                            <>
                                <div className="divide-y divide-surface-200/70">
                                    {messages.map(msg => (
                                        <button
                                            key={msg.id}
                                            onClick={() => setSelectedMessageId(msg.id)}
                                            className={cn(
                                                'w-full text-left px-5 py-4 hover:bg-surface-50 transition-colors flex items-center gap-4 min-h-[60px]',
                                                selectedMessageId === msg.id && 'bg-primary/5 border-l-2 border-l-primary',
                                            )}
                                        >
                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center gap-2 mb-1">
                                                    <span className="text-sm font-medium text-foreground truncate">{msg.to}</span>
                                                    <StatusBadge status={msg.status} />
                                                </div>
                                                <p className="text-xs text-muted-foreground truncate">{msg.subject}</p>
                                                {msg.campaignName && (
                                                    <p className="text-xs text-muted-foreground/70 mt-0.5 truncate">
                                                        via {msg.campaignName}
                                                    </p>
                                                )}
                                            </div>
                                            <div className="flex items-center gap-2 flex-shrink-0">
                                                <span className="text-xs text-muted-foreground whitespace-nowrap">
                                                    {relativeTime(msg.createdAt)}
                                                </span>
                                                <ChevronRight className="h-4 w-4 text-muted-foreground/50" />
                                            </div>
                                        </button>
                                    ))}
                                </div>

                                {/* Pagination */}
                                <div className="flex items-center justify-between px-5 py-3 border-t border-surface-200/70 bg-surface-50/50">
                                    <span className="text-xs text-muted-foreground">
                                        {formatNumber(totalMessages)} message{totalMessages !== 1 ? 's' : ''} total
                                    </span>
                                    <div className="flex items-center gap-1">
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            disabled={page <= 1}
                                            onClick={() => setPage(p => Math.max(1, p - 1))}
                                        >
                                            <ChevronLeft className="h-4 w-4" />
                                        </Button>
                                        <span className="text-xs text-muted-foreground px-2">
                                            Page {page} of {totalPages}
                                        </span>
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            disabled={page >= totalPages}
                                            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                                        >
                                            <ChevronRight className="h-4 w-4" />
                                        </Button>
                                    </div>
                                </div>
                            </>
                        )}
                    </CardContent>
                </Card>

                {/* Detail panel */}
                {selectedMessageId && (
                    <Card className="w-[380px] flex-shrink-0 hidden lg:block overflow-hidden">
                        <CardContent className="p-0">
                            {detailLoading ? (
                                <div className="p-6 space-y-4">
                                    <Skeleton className="h-5 w-3/4" />
                                    <Skeleton className="h-4 w-1/2" />
                                    <Skeleton className="h-px w-full my-4" />
                                    {Array.from({ length: 4 }).map((_, i) => (
                                        <div key={i} className="flex items-center gap-3">
                                            <Skeleton className="h-3 w-3 rounded-full" />
                                            <Skeleton className="h-3 flex-1" />
                                        </div>
                                    ))}
                                </div>
                            ) : detailData?.message ? (
                                <div className="flex flex-col h-full">
                                    {/* Header */}
                                    <div className="p-5 border-b border-surface-200/70">
                                        <div className="flex items-center justify-between mb-2">
                                            <StatusBadge status={detailData.message.status} />
                                            <button
                                                onClick={() => setSelectedMessageId(null)}
                                                className="text-muted-foreground hover:text-foreground text-xs"
                                            >
                                                Close
                                            </button>
                                        </div>
                                        <h3 className="text-sm font-semibold text-foreground mb-1 line-clamp-2">
                                            {detailData.message.subject}
                                        </h3>
                                        <div className="space-y-1 text-xs text-muted-foreground">
                                            <p><span className="font-medium text-foreground/80">To:</span> {detailData.message.to}</p>
                                            <p><span className="font-medium text-foreground/80">From:</span> {detailData.message.from}</p>
                                            <p><span className="font-medium text-foreground/80">Sent:</span> {new Date(detailData.message.createdAt).toLocaleString()}</p>
                                            {detailData.message.campaignName && (
                                                <p><span className="font-medium text-foreground/80">Campaign:</span> {detailData.message.campaignName}</p>
                                            )}
                                        </div>
                                    </div>

                                    {/* Event timeline */}
                                    <div className="p-5 flex-1 overflow-y-auto">
                                        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-4">
                                            Event Timeline
                                        </h4>
                                        {detailData.events && detailData.events.length > 0 ? (
                                            <div className="relative">
                                                {/* Timeline line */}
                                                <div className="absolute left-[7px] top-2 bottom-2 w-px bg-surface-200" />

                                                <div className="space-y-4">
                                                    {detailData.events.map((event, idx) => {
                                                        const cfg = STATUS_CONFIG[event.type] ?? STATUS_CONFIG.queued;
                                                        return (
                                                            <div key={event.id ?? idx} className="flex items-start gap-3 relative">
                                                                <div className={cn('h-3.5 w-3.5 rounded-full border-2 border-background flex-shrink-0 mt-0.5 z-10', cfg.dot)} />
                                                                <div className="flex-1 min-w-0">
                                                                    <div className="flex items-center justify-between gap-2">
                                                                        <span className="text-xs font-medium text-foreground">
                                                                            {cfg.label}
                                                                        </span>
                                                                        <span className="text-[10px] text-muted-foreground whitespace-nowrap">
                                                                            {new Date(event.timestamp).toLocaleString()}
                                                                        </span>
                                                                    </div>
                                                                    {event.metadata && Object.keys(event.metadata).length > 0 && (
                                                                        <div className="mt-1 text-[10px] text-muted-foreground/70 space-y-0.5">
                                                                            {Object.entries(event.metadata).map(([k, v]) => (
                                                                                <p key={k}>
                                                                                    <span className="font-medium">{k}:</span> {v}
                                                                                </p>
                                                                            ))}
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            </div>
                                                        );
                                                    })}
                                                </div>
                                            </div>
                                        ) : (
                                            <p className="text-xs text-muted-foreground italic">No events recorded yet.</p>
                                        )}
                                    </div>
                                </div>
                            ) : (
                                <div className="p-6 text-center text-sm text-muted-foreground">
                                    Message not found
                                </div>
                            )}
                        </CardContent>
                    </Card>
                )}
            </div>
        </div>
    );
}

export default function ActivityPage() {
    return (
        <React.Suspense
            fallback={
                <div className="space-y-6">
                    <div className="flex justify-between items-end pb-6 mb-8 border-b border-surface-200/70">
                        <div>
                            <Skeleton className="h-8 w-48 mb-2" />
                            <Skeleton className="h-4 w-72" />
                        </div>
                    </div>
                    <div className="space-y-4">
                        {Array.from({ length: 8 }).map((_, i) => (
                            <Skeleton key={i} className="h-14 w-full rounded-lg" />
                        ))}
                    </div>
                </div>
            }
        >
            <ActivityPageContent />
        </React.Suspense>
    );
}
