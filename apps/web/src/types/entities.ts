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
