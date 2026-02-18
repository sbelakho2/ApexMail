import useSWR, { SWRConfiguration, mutate as globalMutate } from 'swr';
import useSWRMutation from 'swr/mutation';

// Base API URL from environment
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

// Custom error class for API errors
export class APIError extends Error {
    status: number;
    info?: unknown;

    constructor(message: string, status: number, info?: unknown) {
        super(message);
        this.name = 'APIError';
        this.status = status;
        this.info = info;
    }
}

// Type-safe fetcher function
async function fetcher<T>(url: string): Promise<T> {
    const response = await fetch(`${API_BASE_URL}${url}`, {
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
        },
    });

    if (!response.ok) {
        const info = await response.json().catch(() => null);
        throw new APIError(
            info?.message || `API error: ${response.statusText}`,
            response.status,
            info
        );
    }

    return response.json();
}

// Mutator functions for POST/PUT/DELETE
async function postFetcher<T, D = unknown>(
    url: string,
    { arg }: { arg: D }
): Promise<T> {
    const response = await fetch(`${API_BASE_URL}${url}`, {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(arg),
    });

    if (!response.ok) {
        const info = await response.json().catch(() => null);
        throw new APIError(
            info?.message || `API error: ${response.statusText}`,
            response.status,
            info
        );
    }

    return response.json();
}

async function putFetcher<T, D = unknown>(
    url: string,
    { arg }: { arg: D }
): Promise<T> {
    const response = await fetch(`${API_BASE_URL}${url}`, {
        method: 'PUT',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(arg),
    });

    if (!response.ok) {
        const info = await response.json().catch(() => null);
        throw new APIError(
            info?.message || `API error: ${response.statusText}`,
            response.status,
            info
        );
    }

    return response.json();
}

async function deleteFetcher<T>(url: string): Promise<T> {
    const response = await fetch(`${API_BASE_URL}${url}`, {
        method: 'DELETE',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
        },
    });

    if (!response.ok) {
        const info = await response.json().catch(() => null);
        throw new APIError(
            info?.message || `API error: ${response.statusText}`,
            response.status,
            info
        );
    }

    return response.json();
}

// Default SWR configuration
const defaultConfig: SWRConfiguration = {
    revalidateOnFocus: false,
    revalidateOnReconnect: true,
    shouldRetryOnError: true,
    errorRetryCount: 3,
    dedupingInterval: 2000,
};

// Generic GET hook
export function useAPI<T>(
    endpoint: string | null,
    config?: SWRConfiguration<T, APIError>
) {
    return useSWR<T, APIError>(
        endpoint,
        fetcher,
        { ...defaultConfig, ...config }
    );
}

// Generic POST mutation hook
export function useAPIMutation<T, D = unknown>(
    endpoint: string,
    config?: { onSuccess?: (data: T) => void; onError?: (error: APIError) => void }
) {
    return useSWRMutation<T, APIError, string, D>(
        endpoint,
        postFetcher,
        {
            onSuccess: config?.onSuccess,
            onError: config?.onError,
        }
    );
}

// Generic PUT mutation hook
export function useAPIPut<T, D = unknown>(
    endpoint: string,
    config?: { onSuccess?: (data: T) => void; onError?: (error: APIError) => void }
) {
    return useSWRMutation<T, APIError, string, D>(
        endpoint,
        putFetcher,
        {
            onSuccess: config?.onSuccess,
            onError: config?.onError,
        }
    );
}

// Generic DELETE mutation hook
export function useAPIDelete<T>(
    endpoint: string,
    config?: { onSuccess?: (data: T) => void; onError?: (error: APIError) => void }
) {
    return useSWRMutation<T, APIError, string, void>(
        endpoint,
        () => deleteFetcher<T>(endpoint),
        {
            onSuccess: config?.onSuccess,
            onError: config?.onError,
        }
    );
}

// Type definitions for API responses
export interface PaginatedResponse<T> {
    data: T[];
    total: number;
    page: number;
    pageSize: number;
    totalPages: number;
}

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
    customFields: Record<string, unknown>;
    score?: number;
    createdAt: string;
    updatedAt: string;
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

// Specific API hooks for campaigns
export function useCampaigns(page = 1, pageSize = 20) {
    return useAPI<PaginatedResponse<Campaign>>(
        `/api/campaigns?page=${page}&pageSize=${pageSize}`
    );
}

export function useCampaign(id: string | null) {
    return useAPI<Campaign>(id ? `/api/campaigns/${id}` : null);
}

export function useCreateCampaign() {
    return useAPIMutation<Campaign, Partial<Campaign>>('/api/campaigns', {
        onSuccess: () => {
            globalMutate((key) => typeof key === 'string' && key.startsWith('/api/campaigns'));
        },
    });
}

export function useUpdateCampaign(id: string) {
    return useAPIPut<Campaign, Partial<Campaign>>(`/api/campaigns/${id}`, {
        onSuccess: () => {
            globalMutate((key) => typeof key === 'string' && key.startsWith('/api/campaigns'));
        },
    });
}

export function useDeleteCampaign(id: string) {
    return useAPIDelete<void>(`/api/campaigns/${id}`, {
        onSuccess: () => {
            globalMutate((key) => typeof key === 'string' && key.startsWith('/api/campaigns'));
        },
    });
}

// Specific API hooks for contacts
export function useContacts(page = 1, pageSize = 50, listId?: string) {
    const params = new URLSearchParams({
        page: String(page),
        pageSize: String(pageSize),
    });
    if (listId) params.set('listId', listId);
    return useAPI<PaginatedResponse<Contact>>(`/api/contacts?${params}`);
}

export function useContact(id: string | null) {
    return useAPI<Contact>(id ? `/api/contacts/${id}` : null);
}

export function useCreateContact() {
    return useAPIMutation<Contact, Partial<Contact>>('/api/contacts', {
        onSuccess: () => {
            globalMutate((key) => typeof key === 'string' && key.startsWith('/api/contacts'));
        },
    });
}

// Specific API hooks for lists
export function useLists() {
    return useAPI<List[]>('/api/lists');
}

export function useList(id: string | null) {
    return useAPI<List>(id ? `/api/lists/${id}` : null);
}

// Specific API hooks for templates
export function useTemplates() {
    return useAPI<Template[]>('/api/templates');
}

export function useTemplate(id: string | null) {
    return useAPI<Template>(id ? `/api/templates/${id}` : null);
}

// Dashboard stats hook
export function useDashboardStats() {
    return useAPI<DashboardStats>('/api/dashboard/stats');
}

// Support tickets types & hooks
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

export function useTickets(limit = 50, offset = 0) {
    return useAPI<TicketsResponse>(`/v1/support/tickets?limit=${limit}&offset=${offset}`);
}

export function useTicket(id: string | null) {
    return useAPI<{ ticket: SupportTicket }>(id ? `/v1/support/tickets/${id}` : null);
}

export function useCreateTicket() {
    return useAPIMutation<{ ticket: SupportTicket }, {
        subject: string;
        description: string;
        category: string;
        priority?: string;
    }>('/v1/support/tickets', {
        onSuccess: () => {
            globalMutate((key) => typeof key === 'string' && key.includes('/support/tickets'));
        },
    });
}

export function useAddTicketMessage(ticketId: string) {
    return useAPIMutation<
        { message: SupportTicketMessage; botReply?: SupportTicketMessage },
        { content: string; attachments?: string[] }
    >(`/v1/support/tickets/${ticketId}/messages`, {
        onSuccess: () => {
            globalMutate((key) => typeof key === 'string' && key.includes('/support/tickets'));
        },
    });
}

export {
    fetcher,
    postFetcher,
    putFetcher,
    deleteFetcher,
    defaultConfig,
    API_BASE_URL,
    globalMutate,
};
