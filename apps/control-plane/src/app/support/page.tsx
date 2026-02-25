'use client';

import { useState, useEffect, useRef, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { cn, timeAgo, getStatusChipClasses } from '../../lib/utils';

export const dynamic = 'force-dynamic';

/**
 * Support Tickets - Customer support helpdesk (Control Plane)
 *
 * Full DB-backed ticket management:
 * - View all support tickets across tenants
 * - Reply to tickets (persisted to DB)
 * - Update status/priority/assignee (persisted to DB)
 * - Ticket analytics dashboard
 * - Filter by status, priority, category, and tenant
 */

interface Ticket {
    id: string;
    subject: string;
    description: string;
    tenantId: string;
    tenantName: string;
    tenantEmail: string;
    status: 'open' | 'in_progress' | 'waiting_on_customer' | 'resolved' | 'closed';
    priority: 'low' | 'medium' | 'high' | 'urgent';
    category: 'billing' | 'technical' | 'feature_request' | 'bug' | 'general';
    assignee: string | null;
    createdAt: string;
    updatedAt: string;
    messages: TicketMessage[];
}

interface TicketMessage {
    id: string;
    content: string;
    author: string;
    authorType: 'customer' | 'support' | 'bot';
    createdAt: string;
    attachments: string[];
}

interface TicketAnalytics {
    totalTickets: number;
    openTickets: number;
    inProgressTickets: number;
    waitingTickets: number;
    resolvedTickets: number;
    closedTickets: number;
    urgentTickets: number;
    avgResolutionHours: number;
    ticketsByCategory: Record<string, number>;
    ticketsByPriority: Record<string, number>;
    ticketsOverTime: { date: string; count: number }[];
    topTenants: { tenantName: string; count: number }[];
    recentTickets: { id: string; subject: string; tenantName: string; status: string; priority: string; category: string; createdAt: string }[];
    responseTimeBuckets: Record<string, number>;
}

const STATUS_CONFIG: Record<string, { label: string; color: string; bgColor: string }> = {
    open: { label: 'Open', color: 'text-info', bgColor: 'bg-info/10' },
    in_progress: { label: 'In Progress', color: 'text-warning', bgColor: 'bg-warning/10' },
    waiting_on_customer: { label: 'Waiting on Customer', color: 'text-purple-600', bgColor: 'bg-purple-500/10' },
    resolved: { label: 'Resolved', color: 'text-success', bgColor: 'bg-success/10' },
    closed: { label: 'Closed', color: 'text-muted-foreground', bgColor: 'bg-muted' },
};

const PRIORITY_CONFIG: Record<string, { label: string; color: string; bgColor: string }> = {
    low: { label: 'Low', color: 'text-muted-foreground', bgColor: 'bg-muted' },
    medium: { label: 'Medium', color: 'text-info', bgColor: 'bg-info/10' },
    high: { label: 'High', color: 'text-orange-600', bgColor: 'bg-orange-500/10' },
    urgent: { label: 'Urgent', color: 'text-destructive', bgColor: 'bg-destructive/10' },
};

const CATEGORY_CONFIG: Record<string, { label: string; icon: string }> = {
    billing: { label: 'Billing', icon: '💳' },
    technical: { label: 'Technical', icon: '🔧' },
    feature_request: { label: 'Feature Request', icon: '💡' },
    bug: { label: 'Bug Report', icon: '🐛' },
    general: { label: 'General', icon: '📝' },
};

const TEAM_MEMBERS = ['Alex (Support)', 'Jordan (Support)', 'Sam (Engineering)', 'Taylor (Billing)'];

function SupportPageContent() {
    const searchParams = useSearchParams();
    const tenantFilter = searchParams.get('tenant');

    const [activeView, setActiveView] = useState<'tickets' | 'analytics'>('tickets');
    const [tickets, setTickets] = useState<Ticket[]>([]);
    const [analytics, setAnalytics] = useState<TicketAnalytics | null>(null);
    const [loading, setLoading] = useState(true);
    const [analyticsLoading, setAnalyticsLoading] = useState(false);
    const [selectedTicket, setSelectedTicket] = useState<Ticket | null>(null);
    const [filterStatus, setFilterStatus] = useState<string>('');
    const [filterPriority, setFilterPriority] = useState<string>('');
    const [filterCategory, setFilterCategory] = useState<string>('');
    const [searchQuery, setSearchQuery] = useState('');
    const [replyContent, setReplyContent] = useState('');
    const [sendingReply, setSendingReply] = useState(false);
    const [triageShortcut, setTriageShortcut] = useState<'none' | 'urgent_unassigned' | 'sla_breach' | 'my_queue'>('none');
    const messagesEndRef = useRef<HTMLDivElement>(null);
    const currentOperator = 'Alex (Support)';

    useEffect(() => { loadTickets(); }, []);
    useEffect(() => { if (activeView === 'analytics') loadAnalytics(); }, [activeView]);
    useEffect(() => { messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [selectedTicket?.messages]);

    async function loadTickets() {
        try {
            const response = await fetch('/api/support', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed: ${response.status}`);
            const data = await response.json();
            setTickets(data);
        } catch (err) {
            console.error('Failed to load tickets:', err);
        } finally {
            setLoading(false);
        }
    }

    async function loadAnalytics() {
        setAnalyticsLoading(true);
        try {
            const response = await fetch('/api/support/analytics', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed: ${response.status}`);
            setAnalytics(await response.json());
        } catch (err) {
            console.error('Failed to load analytics:', err);
        } finally {
            setAnalyticsLoading(false);
        }
    }

    async function updateTicketStatus(ticketId: string, status: Ticket['status']) {
        try {
            const response = await fetch('/api/support', {
                method: 'PUT',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ticketId, status }),
            });
            if (!response.ok) throw new Error('Failed to update');
            const updated = await response.json();

            setTickets(prev => prev.map(t =>
                t.id === ticketId ? { ...t, status: updated.status, updatedAt: updated.updatedAt } : t
            ));
            if (selectedTicket?.id === ticketId) {
                setSelectedTicket(prev => prev ? { ...prev, status: updated.status, updatedAt: updated.updatedAt } : null);
            }
        } catch (err) {
            console.error('Failed to update status:', err);
        }
    }

    async function assignTicket(ticketId: string, assignee: string | null) {
        try {
            const response = await fetch('/api/support', {
                method: 'PUT',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ticketId, assignee }),
            });
            if (!response.ok) throw new Error('Failed to assign');
            const updated = await response.json();

            setTickets(prev => prev.map(t =>
                t.id === ticketId ? { ...t, assignee: updated.assignee, updatedAt: updated.updatedAt } : t
            ));
            if (selectedTicket?.id === ticketId) {
                setSelectedTicket(prev => prev ? { ...prev, assignee: updated.assignee, updatedAt: updated.updatedAt } : null);
            }
        } catch (err) {
            console.error('Failed to assign:', err);
        }
    }

    async function updateTicketPriority(ticketId: string, priority: string) {
        try {
            const response = await fetch('/api/support', {
                method: 'PUT',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ticketId, priority }),
            });
            if (!response.ok) throw new Error('Failed to update priority');
            const updated = await response.json();

            setTickets(prev => prev.map(t =>
                t.id === ticketId ? { ...t, priority: updated.priority, updatedAt: updated.updatedAt } : t
            ));
            if (selectedTicket?.id === ticketId) {
                setSelectedTicket(prev => prev ? { ...prev, priority: updated.priority, updatedAt: updated.updatedAt } : null);
            }
        } catch (err) {
            console.error('Failed to update priority:', err);
        }
    }

    async function sendReply(andSetStatus?: string) {
        if (!selectedTicket || !replyContent.trim()) return;

        setSendingReply(true);
        try {
            const response = await fetch('/api/support', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ticketId: selectedTicket.id,
                    content: replyContent,
                    author: 'You (Support)',
                    setStatus: andSetStatus,
                }),
            });
            if (!response.ok) throw new Error('Failed to send reply');
            const newMessage = await response.json();

            const msgObj: TicketMessage = {
                id: newMessage.id,
                content: newMessage.content,
                author: newMessage.author,
                authorType: 'support',
                createdAt: newMessage.createdAt,
                attachments: [],
            };

            setTickets(prev => prev.map(t =>
                t.id === selectedTicket.id
                    ? {
                        ...t,
                        messages: [...t.messages, msgObj],
                        updatedAt: new Date().toISOString(),
                        ...(andSetStatus ? { status: andSetStatus as Ticket['status'] } : {}),
                      }
                    : t
            ));
            setSelectedTicket(prev => prev
                ? {
                    ...prev,
                    messages: [...prev.messages, msgObj],
                    updatedAt: new Date().toISOString(),
                    ...(andSetStatus ? { status: andSetStatus as Ticket['status'] } : {}),
                  }
                : null
            );
            setReplyContent('');
        } catch (err) {
            console.error('Failed to send reply:', err);
        } finally {
            setSendingReply(false);
        }
    }

    const filteredTickets = tickets.filter(t => {
        if (tenantFilter && t.tenantId !== tenantFilter) return false;
        if (filterStatus && t.status !== filterStatus) return false;
        if (filterPriority && t.priority !== filterPriority) return false;
        if (filterCategory && t.category !== filterCategory) return false;
        if (searchQuery) {
            const q = searchQuery.toLowerCase();
            if (!t.subject.toLowerCase().includes(q) && !t.tenantName.toLowerCase().includes(q) && !t.tenantEmail?.toLowerCase().includes(q)) return false;
        }
        if (triageShortcut === 'urgent_unassigned' && !(t.priority === 'urgent' && !t.assignee)) return false;
        if (triageShortcut === 'my_queue' && t.assignee !== currentOperator) return false;
        if (triageShortcut === 'sla_breach') {
            const openHours = (Date.now() - new Date(t.createdAt).getTime()) / (1000 * 60 * 60);
            const unresolved = t.status !== 'resolved' && t.status !== 'closed';
            if (!(unresolved && openHours >= 24)) return false;
        }
        return true;
    });

    const openCount = tickets.filter(t => t.status === 'open').length;
    const urgentCount = tickets.filter(t => t.priority === 'urgent' && t.status !== 'resolved' && t.status !== 'closed').length;

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            </div>
        );
    }

    return (
        <div className="max-w-7xl mx-auto">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-foreground">Support Tickets</h1>
                    <p className="text-muted-foreground mt-1">
                        {tickets.length} total • {openCount} open • {urgentCount} urgent
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={() => setActiveView('tickets')}
                        className={cn(
                            'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                            activeView === 'tickets'
                                ? 'bg-primary text-primary-foreground'
                                : 'bg-muted text-muted-foreground hover:text-foreground'
                        )}
                    >
                        Tickets
                    </button>
                    <button
                        onClick={() => setActiveView('analytics')}
                        className={cn(
                            'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                            activeView === 'analytics'
                                ? 'bg-primary text-primary-foreground'
                                : 'bg-muted text-muted-foreground hover:text-foreground'
                        )}
                    >
                        Analytics
                    </button>
                </div>
            </div>

            {/* Analytics View */}
            {activeView === 'analytics' && (
                <div>
                    {analyticsLoading ? (
                        <div className="flex items-center justify-center h-64">
                            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
                        </div>
                    ) : analytics ? (
                        <div className="space-y-6">
                            {/* KPI Cards */}
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                <div className="bg-card rounded-xl border p-4 shadow-sm">
                                    <div className="text-sm text-muted-foreground">Total Tickets</div>
                                    <div className="text-3xl font-bold text-foreground">{analytics.totalTickets}</div>
                                </div>
                                <div className="bg-card rounded-xl border p-4 shadow-sm">
                                    <div className="text-sm text-muted-foreground">Open</div>
                                    <div className="text-3xl font-bold text-info">{analytics.openTickets}</div>
                                </div>
                                <div className="bg-card rounded-xl border p-4 shadow-sm">
                                    <div className="text-sm text-muted-foreground">Avg Resolution</div>
                                    <div className="text-3xl font-bold text-foreground">{analytics.avgResolutionHours.toFixed(1)}h</div>
                                </div>
                                <div className="bg-card rounded-xl border p-4 shadow-sm">
                                    <div className="text-sm text-muted-foreground">Urgent</div>
                                    <div className={cn('text-3xl font-bold', analytics.urgentTickets > 0 ? 'text-destructive' : 'text-success')}>
                                        {analytics.urgentTickets}
                                    </div>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                {/* By Category */}
                                <div className="bg-card rounded-xl border p-6 shadow-sm">
                                    <h3 className="font-semibold mb-4">Tickets by Category</h3>
                                    <div className="space-y-3">
                                        {Object.entries(analytics.ticketsByCategory).sort((a, b) => b[1] - a[1]).map(([cat, count]) => {
                                            const cfg = CATEGORY_CONFIG[cat] ?? { label: cat, icon: '📝' };
                                            const pct = analytics.totalTickets > 0 ? (count / analytics.totalTickets) * 100 : 0;
                                            return (
                                                <div key={cat}>
                                                    <div className="flex items-center justify-between text-sm mb-1">
                                                        <span>{cfg.icon} {cfg.label}</span>
                                                        <span className="font-medium">{count} ({pct.toFixed(0)}%)</span>
                                                    </div>
                                                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                                                        <svg width="100%" height="100%" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true">
                                                            <rect x="0" y="0" width={Math.max(0, Math.min(100, pct))} height="8" className="fill-primary" />
                                                        </svg>
                                                    </div>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>

                                {/* By Priority */}
                                <div className="bg-card rounded-xl border p-6 shadow-sm">
                                    <h3 className="font-semibold mb-4">Tickets by Priority</h3>
                                    <div className="space-y-3">
                                        {Object.entries(analytics.ticketsByPriority).sort((a, b) => {
                                            const order = ['urgent', 'high', 'medium', 'low'];
                                            return order.indexOf(a[0]) - order.indexOf(b[0]);
                                        }).map(([pri, count]) => {
                                            const cfg = PRIORITY_CONFIG[pri] ?? { label: pri, color: 'text-muted-foreground', bgColor: 'bg-muted' };
                                            const pct = analytics.totalTickets > 0 ? (count / analytics.totalTickets) * 100 : 0;
                                            return (
                                                <div key={pri}>
                                                    <div className="flex items-center justify-between text-sm mb-1">
                                                        <span className={cfg.color}>{cfg.label}</span>
                                                        <span className="font-medium">{count} ({pct.toFixed(0)}%)</span>
                                                    </div>
                                                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                                                        <svg width="100%" height="100%" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true">
                                                            <rect
                                                                x="0"
                                                                y="0"
                                                                width={Math.max(0, Math.min(100, pct))}
                                                                height="8"
                                                                className={cn(cfg.bgColor === 'bg-muted' ? 'fill-gray-400' : cfg.color.replace('text-', 'fill-'))}
                                                            />
                                                        </svg>
                                                    </div>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>

                                {/* Status Distribution */}
                                <div className="bg-card rounded-xl border p-6 shadow-sm">
                                    <h3 className="font-semibold mb-4">Status Distribution</h3>
                                    <div className="grid grid-cols-2 gap-3">
                                        {Object.entries(STATUS_CONFIG).map(([status, cfg]) => {
                                            const count = status === 'open' ? analytics.openTickets
                                                : status === 'in_progress' ? analytics.inProgressTickets
                                                : status === 'waiting_on_customer' ? analytics.waitingTickets
                                                : status === 'resolved' ? analytics.resolvedTickets
                                                : analytics.closedTickets;
                                            return (
                                                <div key={status} className={cn('p-3 rounded-lg', cfg.bgColor)}>
                                                    <div className={cn('text-xl font-bold', cfg.color)}>{count}</div>
                                                    <div className="text-xs text-muted-foreground">{cfg.label}</div>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>

                                {/* Top Tenants */}
                                <div className="bg-card rounded-xl border p-6 shadow-sm">
                                    <h3 className="font-semibold mb-4">Top Tenants by Tickets</h3>
                                    {analytics.topTenants.length === 0 ? (
                                        <p className="text-sm text-muted-foreground">No data yet</p>
                                    ) : (
                                        <div className="space-y-2">
                                            {analytics.topTenants.map((t, i) => (
                                                <div key={i} className="flex items-center justify-between py-1.5 border-b border-border last:border-0">
                                                    <span className="text-sm">{t.tenantName}</span>
                                                    <span className="font-medium text-sm">{t.count}</span>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>

                                {/* Ticket Timeline */}
                                <div className="bg-card rounded-xl border p-6 shadow-sm lg:col-span-2">
                                    <h3 className="font-semibold mb-4">Tickets Over Time (Last 30 Days)</h3>
                                    {analytics.ticketsOverTime.length === 0 ? (
                                        <p className="text-sm text-muted-foreground">No data yet</p>
                                    ) : (
                                        <div className="flex items-end gap-1 h-40">
                                            {analytics.ticketsOverTime.map((d, i) => {
                                                const maxCount = Math.max(...analytics.ticketsOverTime.map(x => x.count), 1);
                                                const height = (d.count / maxCount) * 100;
                                                return (
                                                    <div key={i} className="flex-1 flex flex-col items-center gap-1" title={`${d.date}: ${d.count} tickets`}>
                                                        <div className="w-full h-full rounded-t overflow-hidden">
                                                            <svg width="100%" height="100%" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
                                                                <rect
                                                                    x="0"
                                                                    y={100 - Math.max(4, Math.min(100, height))}
                                                                    width="100"
                                                                    height={Math.max(4, Math.min(100, height))}
                                                                    className="fill-primary/80 transition-all duration-300 hover:fill-primary"
                                                                />
                                                            </svg>
                                                        </div>
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    )}
                                </div>

                                {/* Response Time Buckets */}
                                <div className="bg-card rounded-xl border p-6 shadow-sm lg:col-span-2">
                                    <h3 className="font-semibold mb-4">Resolution Time Distribution</h3>
                                    <div className="grid grid-cols-5 gap-3">
                                        {['< 1h', '1-4h', '4-24h', '1-3d', '> 3d'].map(bucket => {
                                            const count = analytics.responseTimeBuckets[bucket] ?? 0;
                                            return (
                                                <div key={bucket} className="text-center p-3 bg-muted/50 rounded-lg">
                                                    <div className="text-xl font-bold text-foreground">{count}</div>
                                                    <div className="text-xs text-muted-foreground">{bucket}</div>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>

                                {/* Recent Tickets Table */}
                                <div className="bg-card rounded-xl border p-6 shadow-sm lg:col-span-2">
                                    <h3 className="font-semibold mb-4">Recent Tickets</h3>
                                    <div className="overflow-x-auto">
                                        <table className="w-full text-sm">
                                            <thead>
                                                <tr className="border-b border-border">
                                                    <th className="text-left py-2 font-medium text-muted-foreground">Subject</th>
                                                    <th className="text-left py-2 font-medium text-muted-foreground">Tenant</th>
                                                    <th className="text-left py-2 font-medium text-muted-foreground">Category</th>
                                                    <th className="text-left py-2 font-medium text-muted-foreground">Priority</th>
                                                    <th className="text-left py-2 font-medium text-muted-foreground">Status</th>
                                                    <th className="text-left py-2 font-medium text-muted-foreground">Created</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {analytics.recentTickets.map(t => {
                                                    const sCfg = STATUS_CONFIG[t.status] ?? STATUS_CONFIG.open;
                                                    const pCfg = PRIORITY_CONFIG[t.priority] ?? PRIORITY_CONFIG.medium;
                                                    const cCfg = CATEGORY_CONFIG[t.category] ?? CATEGORY_CONFIG.general;
                                                    return (
                                                        <tr key={t.id} className="border-b border-border last:border-0 hover:bg-muted/30 cursor-pointer"
                                                            onClick={() => {
                                                                const found = tickets.find(tk => tk.id === t.id);
                                                                if (found) { setSelectedTicket(found); setActiveView('tickets'); }
                                                            }}>
                                                            <td className="py-2 pr-4 max-w-[200px] truncate font-medium">{t.subject}</td>
                                                            <td className="py-2 pr-4">{t.tenantName}</td>
                                                            <td className="py-2 pr-4">{cCfg.icon} {cCfg.label}</td>
                                                            <td className="py-2 pr-4"><span className={cn('px-2 py-0.5 rounded text-xs font-medium', pCfg.bgColor, pCfg.color)}>{pCfg.label}</span></td>
                                                            <td className="py-2 pr-4"><span className={cn('px-2 py-0.5 rounded text-xs font-medium', sCfg.bgColor, sCfg.color)}>{sCfg.label}</span></td>
                                                            <td className="py-2 text-muted-foreground">{timeAgo(t.createdAt)}</td>
                                                        </tr>
                                                    );
                                                })}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="text-center py-12 text-muted-foreground">No analytics data available</div>
                    )}
                </div>
            )}

            {/* Tickets View */}
            {activeView === 'tickets' && (
                <>
                    {/* Urgent Alert */}
                    {urgentCount > 0 && (
                        <div className="bg-destructive/10 border border-destructive/20 rounded-xl p-4 mb-6">
                            <div className="flex items-center gap-2 text-destructive font-medium">
                                <span>⚠️</span>
                                <span>{urgentCount} urgent ticket(s) require immediate attention</span>
                            </div>
                        </div>
                    )}

                    {/* Stats */}
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                        {Object.entries(STATUS_CONFIG).map(([status, config]) => {
                            const count = tickets.filter(t => t.status === status).length;
                            return (
                                <button
                                    key={status}
                                    onClick={() => setFilterStatus(filterStatus === status ? '' : status)}
                                    className={cn(
                                        'bg-card rounded-xl border p-4 shadow-sm transition-all text-left',
                                        filterStatus === status ? 'border-primary ring-2 ring-primary/20' : 'border-border hover:border-input'
                                    )}
                                >
                                    <div className="text-sm text-muted-foreground font-medium">{config.label}</div>
                                    <div className={cn('text-2xl font-bold', config.color)}>{count}</div>
                                </button>
                            );
                        })}
                    </div>

                    {/* Filters */}
                    <div className="flex flex-wrap gap-2 mb-6">
                        <input
                            type="text"
                            placeholder="Search tickets..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="px-3 py-2 border border-input rounded-lg text-sm focus:ring-2 focus:ring-primary/20 focus:border-primary outline-none bg-background text-foreground w-60"
                        />
                        <select value={filterPriority} onChange={(e) => setFilterPriority(e.target.value)}
                            className="px-3 py-2 border border-input rounded-lg text-sm focus:ring-2 focus:ring-primary/20 focus:border-primary outline-none bg-background text-foreground">
                            <option value="">All Priorities</option>
                            {Object.entries(PRIORITY_CONFIG).map(([key, config]) => (
                                <option key={key} value={key}>{config.label}</option>
                            ))}
                        </select>
                        <select value={filterCategory} onChange={(e) => setFilterCategory(e.target.value)}
                            className="px-3 py-2 border border-input rounded-lg text-sm focus:ring-2 focus:ring-primary/20 focus:border-primary outline-none bg-background text-foreground">
                            <option value="">All Categories</option>
                            {Object.entries(CATEGORY_CONFIG).map(([key, config]) => (
                                <option key={key} value={key}>{config.icon} {config.label}</option>
                            ))}
                        </select>
                        {(filterStatus || filterPriority || filterCategory || searchQuery) && (
                            <button
                                onClick={() => { setFilterStatus(''); setFilterPriority(''); setFilterCategory(''); setSearchQuery(''); setTriageShortcut('none'); }}
                                className="px-3 py-2 text-sm text-muted-foreground hover:text-foreground"
                            >
                                Clear Filters
                            </button>
                        )}
                    </div>

                    <div className="flex flex-wrap gap-2 mb-6">
                        <button
                            onClick={() => setTriageShortcut(triageShortcut === 'urgent_unassigned' ? 'none' : 'urgent_unassigned')}
                            className={cn(
                                'px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors',
                                triageShortcut === 'urgent_unassigned'
                                    ? 'bg-destructive/10 text-destructive border-destructive/30'
                                    : 'bg-muted text-muted-foreground border-border hover:text-foreground'
                            )}
                        >
                            Urgent + Unassigned
                        </button>
                        <button
                            onClick={() => setTriageShortcut(triageShortcut === 'sla_breach' ? 'none' : 'sla_breach')}
                            className={cn(
                                'px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors',
                                triageShortcut === 'sla_breach'
                                    ? 'bg-warning/10 text-warning border-warning/30'
                                    : 'bg-muted text-muted-foreground border-border hover:text-foreground'
                            )}
                        >
                            SLA Breach (24h+)
                        </button>
                        <button
                            onClick={() => setTriageShortcut(triageShortcut === 'my_queue' ? 'none' : 'my_queue')}
                            className={cn(
                                'px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors',
                                triageShortcut === 'my_queue'
                                    ? 'bg-primary/10 text-primary border-primary/30'
                                    : 'bg-muted text-muted-foreground border-border hover:text-foreground'
                            )}
                        >
                            My Queue
                        </button>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        {/* Ticket List */}
                        <div className="lg:col-span-1 space-y-3 max-h-[calc(100vh-320px)] overflow-y-auto">
                            {filteredTickets.length === 0 ? (
                                <div className="text-center py-12 text-muted-foreground">
                                    No tickets found. If this is a new admin account, tickets will appear after your first tenant opens support conversations.
                                </div>
                            ) : (
                                filteredTickets.map(ticket => {
                                    const statusConfig = STATUS_CONFIG[ticket.status];
                                    const priorityConfig = PRIORITY_CONFIG[ticket.priority];
                                    const categoryConfig = CATEGORY_CONFIG[ticket.category] ?? CATEGORY_CONFIG.general;
                                    const openHours = (Date.now() - new Date(ticket.createdAt).getTime()) / (1000 * 60 * 60);
                                    const isSlaBreached = (ticket.status !== 'resolved' && ticket.status !== 'closed') && openHours >= 24;

                                    return (
                                        <button
                                            key={ticket.id}
                                            onClick={() => setSelectedTicket(ticket)}
                                            className={cn(
                                                'w-full text-left bg-card rounded-xl border p-4 transition-all',
                                                selectedTicket?.id === ticket.id ? 'border-primary ring-2 ring-primary/20' : 'border-border hover:border-input',
                                                isSlaBreached && 'border-warning/40 bg-warning/5'
                                            )}
                                        >
                                            <div className="flex items-start justify-between gap-2 mb-2">
                                                <span className="text-lg">{categoryConfig.icon}</span>
                                                <span className={cn('px-2.5 py-0.5 rounded text-xs font-medium', priorityConfig.bgColor, priorityConfig.color)}>
                                                    {priorityConfig.label}
                                                </span>
                                            </div>
                                            <h3 className="font-medium text-foreground mb-1 line-clamp-1">{ticket.subject}</h3>
                                            <p className="text-sm text-muted-foreground mb-2">{ticket.tenantName}</p>
                                            <div className="flex items-center justify-between">
                                                <span className={cn('px-2.5 py-0.5 rounded text-xs font-medium', getStatusChipClasses(ticket.status))}>
                                                    {statusConfig.label}
                                                </span>
                                                <span className="text-xs text-muted-foreground">{timeAgo(ticket.updatedAt)}</span>
                                            </div>
                                            {isSlaBreached && (
                                                <div className="mt-2 text-[11px] text-warning font-medium">
                                                    SLA breach: open for {Math.floor(openHours)}h
                                                </div>
                                            )}
                                        </button>
                                    );
                                })
                            )}
                        </div>

                        {/* Ticket Detail */}
                        <div className="lg:col-span-2">
                            {selectedTicket ? (
                                <div className="bg-card rounded-xl border border-border overflow-hidden shadow-sm">
                                    {/* Header */}
                                    <div className="p-4 border-b border-border bg-muted/30">
                                        <div className="flex items-start justify-between gap-4">
                                            <div>
                                                <h2 className="text-lg font-semibold text-foreground">{selectedTicket.subject}</h2>
                                                <p className="text-sm text-muted-foreground mt-1">
                                                    {selectedTicket.tenantName} • {selectedTicket.tenantEmail}
                                                </p>
                                            </div>
                                            <button onClick={() => setSelectedTicket(null)}
                                                className="text-muted-foreground hover:text-foreground lg:hidden">Close</button>
                                        </div>
                                        <div className="flex flex-wrap gap-2 mt-3">
                                            <span className={cn('px-2.5 py-0.5 rounded-full text-xs font-medium', getStatusChipClasses(selectedTicket.status))}>
                                                {STATUS_CONFIG[selectedTicket.status].label}
                                            </span>
                                            <span className={cn('px-2.5 py-0.5 rounded-full text-xs font-medium', PRIORITY_CONFIG[selectedTicket.priority].bgColor, PRIORITY_CONFIG[selectedTicket.priority].color)}>
                                                {PRIORITY_CONFIG[selectedTicket.priority].label}
                                            </span>
                                            <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-muted text-muted-foreground">
                                                {(CATEGORY_CONFIG[selectedTicket.category] ?? CATEGORY_CONFIG.general).icon} {(CATEGORY_CONFIG[selectedTicket.category] ?? CATEGORY_CONFIG.general).label}
                                            </span>
                                        </div>
                                    </div>

                                    {/* Actions Bar */}
                                    <div className="p-3 border-b border-border bg-muted/30 flex flex-wrap gap-2">
                                        <select value={selectedTicket.status}
                                            onChange={(e) => updateTicketStatus(selectedTicket.id, e.target.value as Ticket['status'])}
                                            className="px-3 py-1.5 border border-input rounded-lg text-sm focus:ring-2 focus:ring-primary/20 focus:border-primary outline-none bg-background text-foreground">
                                            {Object.entries(STATUS_CONFIG).map(([key, config]) => (
                                                <option key={key} value={key}>{config.label}</option>
                                            ))}
                                        </select>
                                        <select value={selectedTicket.priority}
                                            onChange={(e) => updateTicketPriority(selectedTicket.id, e.target.value)}
                                            className="px-3 py-1.5 border border-input rounded-lg text-sm focus:ring-2 focus:ring-primary/20 focus:border-primary outline-none bg-background text-foreground">
                                            {Object.entries(PRIORITY_CONFIG).map(([key, config]) => (
                                                <option key={key} value={key}>{config.label}</option>
                                            ))}
                                        </select>
                                        <select value={selectedTicket.assignee || ''}
                                            onChange={(e) => assignTicket(selectedTicket.id, e.target.value || null)}
                                            className="px-3 py-1.5 border border-input rounded-lg text-sm focus:ring-2 focus:ring-primary/20 focus:border-primary outline-none bg-background text-foreground">
                                            <option value="">Unassigned</option>
                                            {TEAM_MEMBERS.map(member => (
                                                <option key={member} value={member}>{member}</option>
                                            ))}
                                        </select>
                                        <button
                                            onClick={() => {
                                                const impersonateUrl = `${process.env.NEXT_PUBLIC_CONSOLE_URL || 'http://localhost:3000'}?impersonate=${selectedTicket.tenantId}`;
                                                window.open(impersonateUrl, '_blank');
                                            }}
                                            className="px-3 py-1.5 bg-warning/10 text-warning rounded-lg text-sm font-medium hover:bg-warning/20 transition-colors"
                                        >
                                            Impersonate
                                        </button>
                                    </div>

                                    {/* Messages */}
                                    <div className="p-4 space-y-4 max-h-[400px] overflow-y-auto">
                                        {selectedTicket.messages.map(message => (
                                            <div
                                                key={message.id}
                                                className={cn(
                                                    'rounded-lg p-4',
                                                    message.authorType === 'support' ? 'bg-primary/5 border border-primary/10 ml-8'
                                                      : message.authorType === 'bot' ? 'bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/20 mr-8'
                                                      : 'bg-muted/50 border border-border mr-8'
                                                )}
                                            >
                                                <div className="flex items-center justify-between mb-2">
                                                    <span className={cn(
                                                        'text-sm font-medium',
                                                        message.authorType === 'support' ? 'text-primary'
                                                          : message.authorType === 'bot' ? 'text-amber-600'
                                                          : 'text-muted-foreground'
                                                    )}>
                                                        {message.authorType === 'bot' ? '🤖 ' : ''}{message.author}
                                                    </span>
                                                    <span className="text-xs text-muted-foreground">{timeAgo(message.createdAt)}</span>
                                                </div>
                                                <p className="text-sm text-foreground whitespace-pre-wrap">{message.content}</p>
                                                {message.attachments && message.attachments.length > 0 && (
                                                    <div className="mt-2 flex flex-wrap gap-2">
                                                        {message.attachments.map(attachment => (
                                                            <span key={attachment} className="px-2.5 py-1 bg-muted rounded text-xs text-muted-foreground">
                                                                📎 {attachment}
                                                            </span>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>
                                        ))}
                                        <div ref={messagesEndRef} />
                                    </div>

                                    {/* Reply Box */}
                                    <div className="p-4 border-t border-border">
                                        <textarea
                                            value={replyContent}
                                            onChange={(e) => setReplyContent(e.target.value)}
                                            placeholder="Type your reply..."
                                            rows={3}
                                            className="w-full px-3 py-2 border border-input rounded-lg text-sm focus:ring-2 focus:ring-primary/20 focus:border-primary outline-none resize-none bg-background text-foreground placeholder:text-muted-foreground"
                                        />
                                        <div className="flex justify-end gap-2 mt-3">
                                            <button
                                                onClick={() => sendReply('waiting_on_customer')}
                                                disabled={!replyContent.trim() || sendingReply}
                                                className="px-4 py-2 bg-muted text-foreground/70 rounded-lg text-sm font-medium hover:bg-muted/80 transition-colors disabled:opacity-50"
                                            >
                                                Reply & Wait
                                            </button>
                                            <button
                                                onClick={() => sendReply()}
                                                disabled={!replyContent.trim() || sendingReply}
                                                className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
                                            >
                                                {sendingReply ? 'Sending...' : 'Send Reply'}
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            ) : (
                                <div className="bg-card rounded-xl border border-border p-12 text-center">
                                    <h3 className="text-lg font-medium text-foreground mb-2">Select a Ticket</h3>
                                    <p className="text-muted-foreground text-sm">Choose a ticket from the list to view details and respond</p>
                                </div>
                            )}
                        </div>
                    </div>
                </>
            )}
        </div>
    );
}

export default function SupportPage() {
    return (
        <Suspense fallback={<div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div></div>}>
            <SupportPageContent />
        </Suspense>
    );
}
