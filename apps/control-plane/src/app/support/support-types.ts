export interface Ticket {
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

export interface TicketMessage {
    id: string;
    content: string;
    author: string;
    authorType: 'customer' | 'support' | 'bot';
    createdAt: string;
    attachments: string[];
}

export interface TicketAnalytics {
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

export const STATUS_CONFIG: Record<string, { label: string; color: string; bgColor: string }> = {
    open: { label: 'Open', color: 'text-info', bgColor: 'bg-info/10' },
    in_progress: { label: 'In Progress', color: 'text-warning', bgColor: 'bg-warning/10' },
    waiting_on_customer: { label: 'Waiting on Customer', color: 'text-purple-600', bgColor: 'bg-purple-500/10' },
    resolved: { label: 'Resolved', color: 'text-success', bgColor: 'bg-success/10' },
    closed: { label: 'Closed', color: 'text-muted-foreground', bgColor: 'bg-muted' },
};

export const PRIORITY_CONFIG: Record<string, { label: string; color: string; bgColor: string }> = {
    low: { label: 'Low', color: 'text-muted-foreground', bgColor: 'bg-muted' },
    medium: { label: 'Medium', color: 'text-info', bgColor: 'bg-info/10' },
    high: { label: 'High', color: 'text-orange-600', bgColor: 'bg-orange-500/10' },
    urgent: { label: 'Urgent', color: 'text-destructive', bgColor: 'bg-destructive/10' },
};

export const CATEGORY_CONFIG: Record<string, { label: string; icon: string }> = {
    billing: { label: 'Billing', icon: '💳' },
    technical: { label: 'Technical', icon: '🔧' },
    feature_request: { label: 'Feature Request', icon: '💡' },
    bug: { label: 'Bug Report', icon: '🐛' },
    general: { label: 'General', icon: '📝' },
};
