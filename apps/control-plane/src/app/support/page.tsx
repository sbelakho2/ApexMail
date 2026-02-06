'use client';

import { useState, useEffect, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { cn, timeAgo } from '../../lib/utils';

export const dynamic = 'force-dynamic';

/**
 * Support Tickets - Customer support helpdesk
 * 
 * The owner can:
 * - View all support tickets across tenants
 * - Reply to tickets
 * - Assign tickets to team members
 * - Escalate or close tickets
 * - Filter by status, priority, and tenant
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
    authorType: 'customer' | 'support';
    createdAt: string;
    attachments: string[];
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
    general: { label: 'General', icon: '💬' },
};



const TEAM_MEMBERS = ['Alex (Support)', 'Jordan (Support)', 'Sam (Engineering)', 'Taylor (Billing)'];

function SupportPageContent() {
    const searchParams = useSearchParams();
    const tenantFilter = searchParams.get('tenant');
    
    const [tickets, setTickets] = useState<Ticket[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedTicket, setSelectedTicket] = useState<Ticket | null>(null);
    const [filterStatus, setFilterStatus] = useState<string>('');
    const [filterPriority, setFilterPriority] = useState<string>('');
    const [replyContent, setReplyContent] = useState('');
    const [sendingReply, setSendingReply] = useState(false);

    useEffect(() => {
        loadTickets();
    }, []);

    async function loadTickets() {
        try {
            const response = await fetch('/api/support', { credentials: 'include' });
            if (!response.ok) throw new Error(`Failed to fetch tickets: ${response.status}`);
            const data = await response.json();
            setTickets(data);
        } catch (err) {
            console.error('Failed to load tickets:', err);
        } finally {
            setLoading(false);
        }
    }

    function updateTicketStatus(ticketId: string, status: Ticket['status']) {
        setTickets(prev => prev.map(t => 
            t.id === ticketId ? { ...t, status, updatedAt: new Date().toISOString() } : t
        ));
        if (selectedTicket?.id === ticketId) {
            setSelectedTicket(prev => prev ? { ...prev, status, updatedAt: new Date().toISOString() } : null);
        }
    }

    function assignTicket(ticketId: string, assignee: string | null) {
        setTickets(prev => prev.map(t => 
            t.id === ticketId ? { ...t, assignee, updatedAt: new Date().toISOString() } : t
        ));
        if (selectedTicket?.id === ticketId) {
            setSelectedTicket(prev => prev ? { ...prev, assignee, updatedAt: new Date().toISOString() } : null);
        }
    }

    async function sendReply() {
        if (!selectedTicket || !replyContent.trim()) return;
        
        setSendingReply(true);
        try {
            // In production: POST to Support API
            await new Promise(resolve => setTimeout(resolve, 500));
            
            const newMessage: TicketMessage = {
                id: `m-${Date.now()}`,
                content: replyContent,
                author: 'You (Support)',
                authorType: 'support',
                createdAt: new Date().toISOString(),
                attachments: [],
            };
            
            setTickets(prev => prev.map(t => 
                t.id === selectedTicket.id 
                    ? { ...t, messages: [...t.messages, newMessage], updatedAt: new Date().toISOString() }
                    : t
            ));
            setSelectedTicket(prev => prev 
                ? { ...prev, messages: [...prev.messages, newMessage], updatedAt: new Date().toISOString() }
                : null
            );
            setReplyContent('');
        } finally {
            setSendingReply(false);
        }
    }

    const filteredTickets = tickets.filter(t => {
        if (tenantFilter && t.tenantId !== tenantFilter) return false;
        if (filterStatus && t.status !== filterStatus) return false;
        if (filterPriority && t.priority !== filterPriority) return false;
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
                        {openCount} open tickets • {urgentCount} urgent
                    </p>
                </div>
            </div>

            {/* Urgent Alert */}
            {urgentCount > 0 && (
                <div className="bg-destructive/10 border border-destructive/20 rounded-xl p-4 mb-6">
                    <div className="flex items-center gap-2 text-destructive font-medium">
                        <span>🚨</span>
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
                                filterStatus === status
                                    ? 'border-primary ring-2 ring-primary/20'
                                    : 'border-border hover:border-input'
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
                <select
                    value={filterPriority}
                    onChange={(e) => setFilterPriority(e.target.value)}
                    className="px-3 py-2 border border-input rounded-lg text-sm focus:ring-2 focus:ring-primary/20 focus:border-primary outline-none bg-background text-foreground"
                >
                    <option value="">All Priorities</option>
                    {Object.entries(PRIORITY_CONFIG).map(([key, config]) => (
                        <option key={key} value={key}>{config.label}</option>
                    ))}
                </select>
                {(filterStatus || filterPriority || tenantFilter) && (
                    <button
                        onClick={() => {
                            setFilterStatus('');
                            setFilterPriority('');
                        }}
                        className="px-3 py-2 text-sm text-muted-foreground hover:text-foreground"
                    >
                        Clear Filters
                    </button>
                )}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Ticket List */}
                <div className="lg:col-span-1 space-y-3 max-h-[calc(100vh-320px)] overflow-y-auto">
                    {filteredTickets.length === 0 ? (
                        <div className="text-center py-12 text-muted-foreground">
                            No tickets found
                        </div>
                    ) : (
                        filteredTickets.map(ticket => {
                            const statusConfig = STATUS_CONFIG[ticket.status];
                            const priorityConfig = PRIORITY_CONFIG[ticket.priority];
                            const categoryConfig = CATEGORY_CONFIG[ticket.category];
                            
                            return (
                                <button
                                    key={ticket.id}
                                    onClick={() => setSelectedTicket(ticket)}
                                    className={cn(
                                        'w-full text-left bg-card rounded-xl border p-4 transition-all',
                                        selectedTicket?.id === ticket.id
                                            ? 'border-primary ring-2 ring-primary/20'
                                            : 'border-border hover:border-input'
                                    )}
                                >
                                    <div className="flex items-start justify-between gap-2 mb-2">
                                        <span className="text-lg">{categoryConfig.icon}</span>
                                        <span className={cn(
                                            'px-2.5 py-0.5 rounded text-xs font-medium',
                                            priorityConfig.bgColor,
                                            priorityConfig.color
                                        )}>
                                            {priorityConfig.label}
                                        </span>
                                    </div>
                                    <h3 className="font-medium text-foreground mb-1 line-clamp-1">{ticket.subject}</h3>
                                    <p className="text-sm text-muted-foreground mb-2">{ticket.tenantName}</p>
                                    <div className="flex items-center justify-between">
                                        <span className={cn(
                                            'px-2.5 py-0.5 rounded text-xs font-medium',
                                            statusConfig.bgColor,
                                            statusConfig.color
                                        )}>
                                            {statusConfig.label}
                                        </span>
                                        <span className="text-xs text-muted-foreground">{timeAgo(ticket.updatedAt)}</span>
                                    </div>
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
                                    <button
                                        onClick={() => setSelectedTicket(null)}
                                        className="text-muted-foreground hover:text-foreground lg:hidden"
                                    >
                                        ✕
                                    </button>
                                </div>
                                <div className="flex flex-wrap gap-2 mt-3">
                                    <span className={cn(
                                        'px-2.5 py-0.5 rounded-full text-xs font-medium',
                                        STATUS_CONFIG[selectedTicket.status].bgColor,
                                        STATUS_CONFIG[selectedTicket.status].color
                                    )}>
                                        {STATUS_CONFIG[selectedTicket.status].label}
                                    </span>
                                    <span className={cn(
                                        'px-2.5 py-0.5 rounded-full text-xs font-medium',
                                        PRIORITY_CONFIG[selectedTicket.priority].bgColor,
                                        PRIORITY_CONFIG[selectedTicket.priority].color
                                    )}>
                                        {PRIORITY_CONFIG[selectedTicket.priority].label}
                                    </span>
                                    <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-muted text-muted-foreground">
                                        {CATEGORY_CONFIG[selectedTicket.category].icon} {CATEGORY_CONFIG[selectedTicket.category].label}
                                    </span>
                                </div>
                            </div>

                            {/* Actions Bar */}
                            <div className="p-3 border-b border-border bg-muted/30 flex flex-wrap gap-2">
                                <select
                                    value={selectedTicket.status}
                                    onChange={(e) => updateTicketStatus(selectedTicket.id, e.target.value as Ticket['status'])}
                                    className="px-3 py-1.5 border border-input rounded-lg text-sm focus:ring-2 focus:ring-primary/20 focus:border-primary outline-none bg-background text-foreground"
                                >
                                    {Object.entries(STATUS_CONFIG).map(([key, config]) => (
                                        <option key={key} value={key}>{config.label}</option>
                                    ))}
                                </select>
                                <select
                                    value={selectedTicket.assignee || ''}
                                    onChange={(e) => assignTicket(selectedTicket.id, e.target.value || null)}
                                    className="px-3 py-1.5 border border-input rounded-lg text-sm focus:ring-2 focus:ring-primary/20 focus:border-primary outline-none bg-background text-foreground"
                                >
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
                                    👁️ Impersonate
                                </button>
                            </div>

                            {/* Messages */}
                            <div className="p-4 space-y-4 max-h-[400px] overflow-y-auto">
                                {selectedTicket.messages.map(message => (
                                    <div
                                        key={message.id}
                                        className={cn(
                                            'rounded-lg p-4',
                                            message.authorType === 'support'
                                                ? 'bg-primary/5 border border-primary/10 ml-8'
                                                : 'bg-muted/50 border border-border mr-8'
                                        )}
                                    >
                                        <div className="flex items-center justify-between mb-2">
                                            <span className={cn(
                                                'text-sm font-medium',
                                                message.authorType === 'support' ? 'text-primary' : 'text-muted-foreground'
                                            )}>
                                                {message.author}
                                            </span>
                                            <span className="text-xs text-muted-foreground">{timeAgo(message.createdAt)}</span>
                                        </div>
                                        <p className="text-sm text-foreground whitespace-pre-wrap">{message.content}</p>
                                        {message.attachments.length > 0 && (
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
                                        onClick={() => {
                                            sendReply();
                                            updateTicketStatus(selectedTicket.id, 'waiting_on_customer');
                                        }}
                                        disabled={!replyContent.trim() || sendingReply}
                                        className="px-4 py-2 bg-muted text-foreground/70 rounded-lg text-sm font-medium hover:bg-muted/80 transition-colors disabled:opacity-50"
                                    >
                                        Reply & Wait
                                    </button>
                                    <button
                                        onClick={sendReply}
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
                            <div className="text-4xl mb-4">🎫</div>
                            <h3 className="text-lg font-medium text-foreground mb-2">Select a Ticket</h3>
                            <p className="text-muted-foreground text-sm">
                                Choose a ticket from the list to view details and respond
                            </p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

export default function SupportPage() {
    return (
        <Suspense fallback={<div>Loading...</div>}>
            <SupportPageContent />
        </Suspense>
    );
}
