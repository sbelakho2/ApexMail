'use client';

import { useState, useEffect } from 'react';
import { useSearchParams } from 'next/navigation';
import { cn, timeAgo } from '../../lib/utils';

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
    open: { label: 'Open', color: 'text-blue-700', bgColor: 'bg-blue-100' },
    in_progress: { label: 'In Progress', color: 'text-amber-700', bgColor: 'bg-amber-100' },
    waiting_on_customer: { label: 'Waiting on Customer', color: 'text-violet-700', bgColor: 'bg-violet-100' },
    resolved: { label: 'Resolved', color: 'text-emerald-700', bgColor: 'bg-emerald-100' },
    closed: { label: 'Closed', color: 'text-surface-500', bgColor: 'bg-surface-100' },
};

const PRIORITY_CONFIG: Record<string, { label: string; color: string; bgColor: string }> = {
    low: { label: 'Low', color: 'text-surface-600', bgColor: 'bg-surface-100' },
    medium: { label: 'Medium', color: 'text-blue-700', bgColor: 'bg-blue-100' },
    high: { label: 'High', color: 'text-orange-700', bgColor: 'bg-orange-100' },
    urgent: { label: 'Urgent', color: 'text-red-700', bgColor: 'bg-red-100' },
};

const CATEGORY_CONFIG: Record<string, { label: string; icon: string }> = {
    billing: { label: 'Billing', icon: '💳' },
    technical: { label: 'Technical', icon: '🔧' },
    feature_request: { label: 'Feature Request', icon: '💡' },
    bug: { label: 'Bug Report', icon: '🐛' },
    general: { label: 'General', icon: '💬' },
};

const DEMO_TICKETS: Ticket[] = [
    {
        id: 'ticket-1',
        subject: 'Cannot access API dashboard',
        description: 'I\'ve been trying to access the API dashboard but keep getting a 403 error. I\'ve checked my permissions and everything seems correct.',
        tenantId: 'tenant-1',
        tenantName: 'TechCorp Solutions',
        tenantEmail: 'admin@techcorp.io',
        status: 'open',
        priority: 'high',
        category: 'technical',
        assignee: null,
        createdAt: new Date(Date.now() - 3600000).toISOString(),
        updatedAt: new Date(Date.now() - 3600000).toISOString(),
        messages: [
            { id: 'm1', content: 'I\'ve been trying to access the API dashboard but keep getting a 403 error. I\'ve checked my permissions and everything seems correct.', author: 'John Smith', authorType: 'customer', createdAt: new Date(Date.now() - 3600000).toISOString(), attachments: [] },
        ],
    },
    {
        id: 'ticket-2',
        subject: 'Billing discrepancy on last invoice',
        description: 'Our last invoice shows charges for 150k emails but our tracking shows only 120k sent. Can you please review?',
        tenantId: 'tenant-2',
        tenantName: 'Newsletter Pro',
        tenantEmail: 'billing@newsletter.pro',
        status: 'in_progress',
        priority: 'medium',
        category: 'billing',
        assignee: 'Alex (Support)',
        createdAt: new Date(Date.now() - 86400000).toISOString(),
        updatedAt: new Date(Date.now() - 7200000).toISOString(),
        messages: [
            { id: 'm2', content: 'Our last invoice shows charges for 150k emails but our tracking shows only 120k sent. Can you please review?', author: 'Jane Doe', authorType: 'customer', createdAt: new Date(Date.now() - 86400000).toISOString(), attachments: ['invoice-dec.pdf'] },
            { id: 'm3', content: 'Hi Jane, thank you for reaching out. I\'m looking into this now and will get back to you shortly.', author: 'Alex (Support)', authorType: 'support', createdAt: new Date(Date.now() - 72000000).toISOString(), attachments: [] },
        ],
    },
    {
        id: 'ticket-3',
        subject: 'Request: Custom webhook headers',
        description: 'We need the ability to add custom headers to our webhooks for authentication with our backend. Is this on the roadmap?',
        tenantId: 'tenant-3',
        tenantName: 'E-Commerce Store',
        tenantEmail: 'dev@shop.example.com',
        status: 'waiting_on_customer',
        priority: 'low',
        category: 'feature_request',
        assignee: 'Alex (Support)',
        createdAt: new Date(Date.now() - 259200000).toISOString(),
        updatedAt: new Date(Date.now() - 172800000).toISOString(),
        messages: [
            { id: 'm4', content: 'We need the ability to add custom headers to our webhooks for authentication with our backend. Is this on the roadmap?', author: 'Mike Chen', authorType: 'customer', createdAt: new Date(Date.now() - 259200000).toISOString(), attachments: [] },
            { id: 'm5', content: 'Great suggestion! This is actually something we\'re considering. Could you share more about your specific use case?', author: 'Alex (Support)', authorType: 'support', createdAt: new Date(Date.now() - 172800000).toISOString(), attachments: [] },
        ],
    },
    {
        id: 'ticket-4',
        subject: 'Emails going to spam for gmail recipients',
        description: 'Starting yesterday, our transactional emails are landing in spam for Gmail users. We haven\'t changed anything on our end.',
        tenantId: 'tenant-1',
        tenantName: 'TechCorp Solutions',
        tenantEmail: 'admin@techcorp.io',
        status: 'open',
        priority: 'urgent',
        category: 'bug',
        assignee: null,
        createdAt: new Date(Date.now() - 1800000).toISOString(),
        updatedAt: new Date(Date.now() - 1800000).toISOString(),
        messages: [
            { id: 'm6', content: 'Starting yesterday, our transactional emails are landing in spam for Gmail users. We haven\'t changed anything on our end.', author: 'John Smith', authorType: 'customer', createdAt: new Date(Date.now() - 1800000).toISOString(), attachments: ['email-headers.txt'] },
        ],
    },
    {
        id: 'ticket-5',
        subject: 'How to set up DKIM for subdomain?',
        description: 'We want to send emails from a subdomain. What DKIM records do we need to add?',
        tenantId: 'tenant-4',
        tenantName: 'StartupXYZ',
        tenantEmail: 'founder@startupxyz.com',
        status: 'resolved',
        priority: 'medium',
        category: 'general',
        assignee: 'Alex (Support)',
        createdAt: new Date(Date.now() - 604800000).toISOString(),
        updatedAt: new Date(Date.now() - 518400000).toISOString(),
        messages: [
            { id: 'm7', content: 'We want to send emails from a subdomain. What DKIM records do we need to add?', author: 'Sarah Lee', authorType: 'customer', createdAt: new Date(Date.now() - 604800000).toISOString(), attachments: [] },
            { id: 'm8', content: 'Here\'s a guide for setting up DKIM on subdomains:\n\n1. Go to Settings > Domains\n2. Click "Add Domain" and enter your subdomain\n3. Follow the DNS record instructions\n\nLet me know if you need any clarification!', author: 'Alex (Support)', authorType: 'support', createdAt: new Date(Date.now() - 518400000).toISOString(), attachments: [] },
            { id: 'm9', content: 'That worked perfectly, thank you!', author: 'Sarah Lee', authorType: 'customer', createdAt: new Date(Date.now() - 518400000).toISOString(), attachments: [] },
        ],
    },
];

const TEAM_MEMBERS = ['Alex (Support)', 'Jordan (Support)', 'Sam (Engineering)', 'Taylor (Billing)'];

export default function SupportPage() {
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
            // In production: fetch from Support API
            setTickets(DEMO_TICKETS);
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
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    return (
        <div className="max-w-7xl mx-auto">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                <div>
                    <h1 className="text-2xl font-bold text-surface-900">Support Tickets</h1>
                    <p className="text-surface-600 mt-1">
                        {openCount} open tickets • {urgentCount} urgent
                    </p>
                </div>
            </div>

            {/* Urgent Alert */}
            {urgentCount > 0 && (
                <div className="bg-red-50 border border-red-200 rounded-xl p-4 mb-6">
                    <div className="flex items-center gap-2 text-red-700 font-medium">
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
                                'bg-surface-0 rounded-xl border p-4 shadow-sm transition-all text-left',
                                filterStatus === status
                                    ? 'border-blue-500 ring-2 ring-blue-100'
                                    : 'border-surface-200 hover:border-surface-300'
                            )}
                        >
                            <div className="text-sm text-surface-500 font-medium">{config.label}</div>
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
                    className="px-3 py-2 border border-surface-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
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
                        className="px-3 py-2 text-sm text-surface-600 hover:text-surface-900"
                    >
                        Clear Filters
                    </button>
                )}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Ticket List */}
                <div className="lg:col-span-1 space-y-3 max-h-[calc(100vh-320px)] overflow-y-auto">
                    {filteredTickets.length === 0 ? (
                        <div className="text-center py-12 text-surface-500">
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
                                        'w-full text-left bg-surface-0 rounded-xl border p-4 transition-all',
                                        selectedTicket?.id === ticket.id
                                            ? 'border-blue-500 ring-2 ring-blue-100'
                                            : 'border-surface-200 hover:border-surface-300'
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
                                    <h3 className="font-medium text-surface-900 mb-1 line-clamp-1">{ticket.subject}</h3>
                                    <p className="text-sm text-surface-500 mb-2">{ticket.tenantName}</p>
                                    <div className="flex items-center justify-between">
                                        <span className={cn(
                                            'px-2.5 py-0.5 rounded text-xs font-medium',
                                            statusConfig.bgColor,
                                            statusConfig.color
                                        )}>
                                            {statusConfig.label}
                                        </span>
                                        <span className="text-xs text-surface-400">{timeAgo(ticket.updatedAt)}</span>
                                    </div>
                                </button>
                            );
                        })
                    )}
                </div>

                {/* Ticket Detail */}
                <div className="lg:col-span-2">
                    {selectedTicket ? (
                        <div className="bg-surface-0 rounded-xl border border-surface-200 overflow-hidden shadow-sm">
                            {/* Header */}
                            <div className="p-4 border-b border-surface-200 bg-surface-50">
                                <div className="flex items-start justify-between gap-4">
                                    <div>
                                        <h2 className="text-lg font-semibold text-surface-900">{selectedTicket.subject}</h2>
                                        <p className="text-sm text-surface-500 mt-1">
                                            {selectedTicket.tenantName} • {selectedTicket.tenantEmail}
                                        </p>
                                    </div>
                                    <button
                                        onClick={() => setSelectedTicket(null)}
                                        className="text-surface-400 hover:text-surface-600 lg:hidden"
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
                                    <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-surface-100 text-surface-600">
                                        {CATEGORY_CONFIG[selectedTicket.category].icon} {CATEGORY_CONFIG[selectedTicket.category].label}
                                    </span>
                                </div>
                            </div>

                            {/* Actions Bar */}
                            <div className="p-3 border-b border-surface-200 bg-surface-50 flex flex-wrap gap-2">
                                <select
                                    value={selectedTicket.status}
                                    onChange={(e) => updateTicketStatus(selectedTicket.id, e.target.value as Ticket['status'])}
                                    className="px-3 py-1.5 border border-surface-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
                                >
                                    {Object.entries(STATUS_CONFIG).map(([key, config]) => (
                                        <option key={key} value={key}>{config.label}</option>
                                    ))}
                                </select>
                                <select
                                    value={selectedTicket.assignee || ''}
                                    onChange={(e) => assignTicket(selectedTicket.id, e.target.value || null)}
                                    className="px-3 py-1.5 border border-surface-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
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
                                    className="px-3 py-1.5 bg-amber-100 text-amber-700 rounded-lg text-sm font-medium hover:bg-amber-200 transition-colors"
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
                                                ? 'bg-blue-50 border border-blue-100 ml-8'
                                                : 'bg-surface-50 border border-surface-100 mr-8'
                                        )}
                                    >
                                        <div className="flex items-center justify-between mb-2">
                                            <span className={cn(
                                                'text-sm font-medium',
                                                message.authorType === 'support' ? 'text-blue-700' : 'text-surface-700'
                                            )}>
                                                {message.author}
                                            </span>
                                            <span className="text-xs text-surface-400">{timeAgo(message.createdAt)}</span>
                                        </div>
                                        <p className="text-sm text-surface-700 whitespace-pre-wrap">{message.content}</p>
                                        {message.attachments.length > 0 && (
                                            <div className="mt-2 flex flex-wrap gap-2">
                                                {message.attachments.map(attachment => (
                                                    <span key={attachment} className="px-2.5 py-1 bg-surface-100 rounded text-xs text-surface-600">
                                                        📎 {attachment}
                                                    </span>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                ))}
                            </div>

                            {/* Reply Box */}
                            <div className="p-4 border-t border-surface-200">
                                <textarea
                                    value={replyContent}
                                    onChange={(e) => setReplyContent(e.target.value)}
                                    placeholder="Type your reply..."
                                    rows={3}
                                    className="w-full px-3 py-2 border border-surface-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none resize-none"
                                />
                                <div className="flex justify-end gap-2 mt-3">
                                    <button
                                        onClick={() => {
                                            sendReply();
                                            updateTicketStatus(selectedTicket.id, 'waiting_on_customer');
                                        }}
                                        disabled={!replyContent.trim() || sendingReply}
                                        className="px-4 py-2 bg-surface-100 text-surface-700 rounded-lg text-sm font-medium hover:bg-surface-200 transition-colors disabled:opacity-50"
                                    >
                                        Reply & Wait
                                    </button>
                                    <button
                                        onClick={sendReply}
                                        disabled={!replyContent.trim() || sendingReply}
                                        className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors disabled:opacity-50"
                                    >
                                        {sendingReply ? 'Sending...' : 'Send Reply'}
                                    </button>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="bg-surface-0 rounded-xl border border-surface-200 p-12 text-center">
                            <div className="text-4xl mb-4">🎫</div>
                            <h3 className="text-lg font-medium text-surface-900 mb-2">Select a Ticket</h3>
                            <p className="text-surface-500 text-sm">
                                Choose a ticket from the list to view details and respond
                            </p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
