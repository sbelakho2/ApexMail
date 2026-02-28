import useSWR, { SWRConfiguration, mutate as globalMutate } from 'swr';
import useSWRMutation from 'swr/mutation';
import type { Campaign, CampaignStats, Contact } from '@/types/entities';

// Always use same-origin relative paths; Next.js rewrites proxy /v1/* to API_URL server-side.
const API_BASE_URL = '';
const CSRF_HEADER = 'X-CSRF-Token';
const CSRF_COOKIE = 'csrf_token';
const CSRF_CACHE_TTL_MS = 10 * 60 * 1000;

let cachedCsrfToken: string | null = null;
let cachedCsrfAt = 0;
let inflightCsrfRequest: Promise<string | null> | null = null;

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

function readCookie(name: string): string | null {
    if (typeof document === 'undefined') {
        return null;
    }

    const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const match = document.cookie.match(new RegExp(`(?:^|; )${escapedName}=([^;]*)`));
    return match ? decodeURIComponent(match[1]) : null;
}

async function fetchCsrfToken(): Promise<string | null> {
    if (typeof window === 'undefined') {
        return null;
    }

    const response = await fetch('/api/csrf', {
        method: 'GET',
        credentials: 'include',
        cache: 'no-store',
    });

    if (!response.ok) {
        return null;
    }

    const payload = await response.json().catch(() => null) as { token?: unknown } | null;
    const token = typeof payload?.token === 'string' ? payload.token : null;
    if (!token) {
        return null;
    }

    cachedCsrfToken = token;
    cachedCsrfAt = Date.now();
    return token;
}

async function getCsrfToken(): Promise<string | null> {
    const cookieToken = readCookie(CSRF_COOKIE);
    if (cookieToken) {
        cachedCsrfToken = cookieToken;
        cachedCsrfAt = Date.now();
        return cookieToken;
    }

    const isFresh = cachedCsrfToken && (Date.now() - cachedCsrfAt) < CSRF_CACHE_TTL_MS;
    if (isFresh && cachedCsrfToken) {
        return cachedCsrfToken;
    }

    if (!inflightCsrfRequest) {
        inflightCsrfRequest = fetchCsrfToken().finally(() => {
            inflightCsrfRequest = null;
        });
    }

    return inflightCsrfRequest;
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
    const csrfToken = await getCsrfToken();
    if (!csrfToken) {
        throw new APIError('Unable to initialize CSRF token', 403);
    }

    const response = await fetch(`${API_BASE_URL}${url}`, {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            [CSRF_HEADER]: csrfToken,
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
    const csrfToken = await getCsrfToken();
    if (!csrfToken) {
        throw new APIError('Unable to initialize CSRF token', 403);
    }

    const response = await fetch(`${API_BASE_URL}${url}`, {
        method: 'PUT',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            [CSRF_HEADER]: csrfToken,
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
    const csrfToken = await getCsrfToken();
    if (!csrfToken) {
        throw new APIError('Unable to initialize CSRF token', 403);
    }

    const response = await fetch(`${API_BASE_URL}${url}`, {
        method: 'DELETE',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            [CSRF_HEADER]: csrfToken,
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

async function putByIdFetcher<T, D>(
    baseUrl: string,
    { arg }: { arg: { id: string; data: D } }
): Promise<T> {
    if (!arg?.id) {
        throw new APIError('Resource ID is required', 400);
    }

    return putFetcher<T, D>(`${baseUrl}/${arg.id}`, { arg: arg.data });
}

async function deleteByIdFetcher<T>(
    baseUrl: string,
    { arg }: { arg: string }
): Promise<T> {
    if (!arg) {
        throw new APIError('Resource ID is required', 400);
    }

    return deleteFetcher<T>(`${baseUrl}/${arg}`);
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
        deleteFetcher,
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

export type { Campaign, CampaignStats, Contact };

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
        `/v1/campaigns?page=${page}&pageSize=${pageSize}`
    );
}

export function useCampaign(id: string | null) {
    return useAPI<Campaign>(id ? `/v1/campaigns/${id}` : null);
}

export function useCreateCampaign() {
    return useAPIMutation<Campaign, Partial<Campaign>>('/v1/campaigns', {
        onSuccess: () => {
            globalMutate((key) => typeof key === 'string' && key.startsWith('/v1/campaigns'));
        },
    });
}

export function useUpdateCampaign(id: string) {
    return useAPIPut<Campaign, Partial<Campaign>>(`/v1/campaigns/${id}`, {
        onSuccess: () => {
            globalMutate((key) => typeof key === 'string' && key.startsWith('/v1/campaigns'));
        },
    });
}

export function useDeleteCampaign() {
    return useSWRMutation<void, APIError, string, string>(
        '/v1/campaigns',
        deleteByIdFetcher,
        {
            onSuccess: () => {
                globalMutate((key) => typeof key === 'string' && key.startsWith('/v1/campaigns'));
            },
        }
    );
}

// Specific API hooks for contacts
export function useContacts(
    page = 1,
    pageSize = 50,
    listId?: string,
    options?: {
        status?: string;
        search?: string;
        sortField?: 'name' | 'score' | 'lastActivity';
        sortOrder?: 'asc' | 'desc';
    }
) {
    const params = new URLSearchParams({
        page: String(page),
        pageSize: String(pageSize),
    });
    if (listId) params.set('listId', listId);
    if (options?.status && options.status !== 'all') params.set('status', options.status);
    if (options?.search) params.set('search', options.search);
    if (options?.sortField) params.set('sortField', options.sortField);
    if (options?.sortOrder) params.set('sortOrder', options.sortOrder);
    return useAPI<PaginatedResponse<Contact>>(`/v1/contacts?${params}`);
}

export function useContact(id: string | null) {
    return useAPI<Contact>(id ? `/v1/contacts/${id}` : null);
}

export function useCreateContact() {
    return useAPIMutation<Contact, Partial<Contact>>('/v1/contacts', {
        onSuccess: () => {
            globalMutate((key) => typeof key === 'string' && key.startsWith('/v1/contacts'));
        },
    });
}

export function useUpdateContact() {
    return useSWRMutation<Contact, APIError, string, { id: string; data: Partial<Contact> }>(
        '/v1/contacts',
        putByIdFetcher,
        {
            onSuccess: () => {
                globalMutate((key) => typeof key === 'string' && key.startsWith('/v1/contacts'));
            },
        }
    );
}

export function useDeleteContact() {
    return useSWRMutation<void, APIError, string, string>(
        '/v1/contacts',
        deleteByIdFetcher,
        {
            onSuccess: () => {
                globalMutate((key) => typeof key === 'string' && key.startsWith('/v1/contacts'));
            },
        }
    );
}

// Specific API hooks for lists
export function useLists() {
    return useAPI<List[]>('/v1/lists');
}

export function useCreateList() {
    return useAPIMutation<List, Partial<List>>('/v1/lists', {
        onSuccess: () => {
            globalMutate((key) => typeof key === 'string' && key.startsWith('/v1/lists'));
        },
    });
}

export function useList(id: string | null) {
    return useAPI<List>(id ? `/v1/lists/${id}` : null);
}

// Specific API hooks for templates
export function useTemplates() {
    return useAPI<Template[]>('/v1/templates');
}

export function useTemplate(id: string | null) {
    return useAPI<Template>(id ? `/v1/templates/${id}` : null);
}

// Dashboard stats hook
export function useDashboardStats() {
    return useAPI<DashboardStats>('/v1/dashboard/stats');
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
