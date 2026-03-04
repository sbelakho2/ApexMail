export interface Campaign {
    id: string;
    name: string;
    subject: string;
    fromName: string;
    fromEmail: string;
    status: 'draft' | 'scheduled' | 'sending' | 'sent' | 'paused';
    listId: string;
    templateId?: string;
    content?: string;
    scheduledAt?: string;
    sentAt?: string;
    stats?: CampaignStats;
    createdAt: string;
    updatedAt: string;
}

export interface CampaignStats {
    sent: number;
    delivered: number;
    opens: number;
    uniqueOpens: number;
    clicks: number;
    uniqueClicks: number;
    bounces: number;
    complaints: number;
    unsubscribes: number;
    openRate: number;
    clickRate: number;
    bounceRate: number;
}

export interface Contact {
    id: string;
    email: string;
    firstName?: string;
    lastName?: string;
    phone?: string;
    company?: string;
    status: 'subscribed' | 'unsubscribed' | 'bounced' | 'complained';
    tags: string[];
    customFields: Record<string, string | number | boolean | null | string[] | number[] | boolean[]>;
    score?: number;
    createdAt: string;
    updatedAt: string;
}

export interface PaginatedResponse<T> {
    data: T[];
    total: number;
    page: number;
    pageSize: number;
    totalPages: number;
}

export interface List {
    id: string;
    name: string;
    description?: string;
    subscriberCount: number;
    unsubscribedCount: number;
    bouncedCount: number;
    createdAt: string;
    updatedAt: string;
}

export interface Template {
    id: string;
    name: string;
    subject?: string;
    content: string;
    type: 'html' | 'mjml' | 'text';
    thumbnail?: string;
    createdAt: string;
    updatedAt: string;
}

export interface DashboardStats {
    totalContacts: number;
    totalCampaigns: number;
    totalSent: number;
    avgOpenRate: number;
    avgClickRate: number;
    recentCampaigns: Campaign[];
    sendingTrend: { date: string; sent: number }[];
    engagementTrend: { date: string; opens: number; clicks: number }[];
}

export interface SupportTicket {
    id: string;
    subject: string;
    description: string;
    status: 'open' | 'in_progress' | 'waiting_on_customer' | 'resolved' | 'closed';
    priority: 'low' | 'medium' | 'high' | 'urgent';
    category: 'billing' | 'technical' | 'feature_request' | 'bug' | 'general';
    createdAt: string;
    updatedAt: string;
    messages: SupportTicketMessage[];
}

export interface SupportTicketMessage {
    id: string;
    content: string;
    author: string;
    authorType: 'customer' | 'support' | 'bot';
    createdAt: string;
    attachments: string[];
}

export interface TicketsResponse {
    tickets: SupportTicket[];
    pagination: { total: number; limit: number; offset: number; hasMore: boolean };
}
