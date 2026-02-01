import { create } from 'zustand';
import { persist, devtools } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';

// User store
interface User {
    id: string;
    email: string;
    name: string;
    avatar?: string;
    role: 'admin' | 'member' | 'viewer';
    tenantId: string;
    tenantName: string;
    plan: 'free' | 'starter' | 'pro' | 'enterprise';
}

interface UserState {
    user: User | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    setUser: (user: User | null) => void;
    setLoading: (loading: boolean) => void;
    logout: () => void;
}

export const useUserStore = create<UserState>()(
    devtools(
        persist(
            immer((set) => ({
                user: null,
                isAuthenticated: false,
                isLoading: true,
                setUser: (user) =>
                    set((state) => {
                        state.user = user;
                        state.isAuthenticated = !!user;
                    }),
                setLoading: (loading) =>
                    set((state) => {
                        state.isLoading = loading;
                    }),
                logout: () =>
                    set((state) => {
                        state.user = null;
                        state.isAuthenticated = false;
                    }),
            })),
            { name: 'apexmail-user' }
        ),
        { name: 'UserStore' }
    )
);

// UI preferences store
interface UIState {
    sidebarCollapsed: boolean;
    theme: 'light' | 'dark' | 'system';
    reducedMotion: boolean;
    toggleSidebar: () => void;
    setSidebarCollapsed: (collapsed: boolean) => void;
    setTheme: (theme: 'light' | 'dark' | 'system') => void;
    setReducedMotion: (reduced: boolean) => void;
}

export const useUIStore = create<UIState>()(
    devtools(
        persist(
            immer((set) => ({
                sidebarCollapsed: false,
                theme: 'system',
                reducedMotion: false,
                toggleSidebar: () =>
                    set((state) => {
                        state.sidebarCollapsed = !state.sidebarCollapsed;
                    }),
                setSidebarCollapsed: (collapsed) =>
                    set((state) => {
                        state.sidebarCollapsed = collapsed;
                    }),
                setTheme: (theme) =>
                    set((state) => {
                        state.theme = theme;
                    }),
                setReducedMotion: (reduced) =>
                    set((state) => {
                        state.reducedMotion = reduced;
                    }),
            })),
            { name: 'apexmail-ui' }
        ),
        { name: 'UIStore' }
    )
);

// Campaign store
interface Campaign {
    id: string;
    name: string;
    subject: string;
    status: 'draft' | 'scheduled' | 'sending' | 'sent' | 'paused';
    listId: string;
    templateId?: string;
    scheduledAt?: string;
    sentAt?: string;
    stats?: {
        sent: number;
        delivered: number;
        opens: number;
        clicks: number;
        bounces: number;
        unsubscribes: number;
    };
    createdAt: string;
    updatedAt: string;
}

interface CampaignState {
    campaigns: Campaign[];
    currentCampaign: Campaign | null;
    isLoading: boolean;
    error: string | null;
    setCampaigns: (campaigns: Campaign[]) => void;
    addCampaign: (campaign: Campaign) => void;
    updateCampaign: (id: string, updates: Partial<Campaign>) => void;
    deleteCampaign: (id: string) => void;
    setCurrentCampaign: (campaign: Campaign | null) => void;
    setLoading: (loading: boolean) => void;
    setError: (error: string | null) => void;
}

export const useCampaignStore = create<CampaignState>()(
    devtools(
        immer((set) => ({
            campaigns: [],
            currentCampaign: null,
            isLoading: false,
            error: null,
            setCampaigns: (campaigns) =>
                set((state) => {
                    state.campaigns = campaigns;
                }),
            addCampaign: (campaign) =>
                set((state) => {
                    state.campaigns.push(campaign);
                }),
            updateCampaign: (id, updates) =>
                set((state) => {
                    const index = state.campaigns.findIndex((c) => c.id === id);
                    if (index !== -1) {
                        state.campaigns[index] = { ...state.campaigns[index], ...updates };
                    }
                }),
            deleteCampaign: (id) =>
                set((state) => {
                    state.campaigns = state.campaigns.filter((c) => c.id !== id);
                }),
            setCurrentCampaign: (campaign) =>
                set((state) => {
                    state.currentCampaign = campaign;
                }),
            setLoading: (loading) =>
                set((state) => {
                    state.isLoading = loading;
                }),
            setError: (error) =>
                set((state) => {
                    state.error = error;
                }),
        })),
        { name: 'CampaignStore' }
    )
);

// Contact store
interface Contact {
    id: string;
    email: string;
    firstName?: string;
    lastName?: string;
    phone?: string;
    company?: string;
    status: 'subscribed' | 'unsubscribed' | 'bounced' | 'complained';
    tags: string[];
    customFields: Record<string, string | number | boolean>;
    score?: number;
    createdAt: string;
    updatedAt: string;
}

interface ContactState {
    contacts: Contact[];
    totalCount: number;
    currentPage: number;
    pageSize: number;
    isLoading: boolean;
    error: string | null;
    selectedContactIds: string[];
    setContacts: (contacts: Contact[], totalCount: number) => void;
    addContact: (contact: Contact) => void;
    updateContact: (id: string, updates: Partial<Contact>) => void;
    deleteContacts: (ids: string[]) => void;
    setCurrentPage: (page: number) => void;
    setPageSize: (size: number) => void;
    setLoading: (loading: boolean) => void;
    setError: (error: string | null) => void;
    selectContact: (id: string) => void;
    deselectContact: (id: string) => void;
    selectAll: () => void;
    deselectAll: () => void;
}

export const useContactStore = create<ContactState>()(
    devtools(
        immer((set) => ({
            contacts: [],
            totalCount: 0,
            currentPage: 1,
            pageSize: 50,
            isLoading: false,
            error: null,
            selectedContactIds: [],
            setContacts: (contacts, totalCount) =>
                set((state) => {
                    state.contacts = contacts;
                    state.totalCount = totalCount;
                }),
            addContact: (contact) =>
                set((state) => {
                    state.contacts.unshift(contact);
                    state.totalCount += 1;
                }),
            updateContact: (id, updates) =>
                set((state) => {
                    const index = state.contacts.findIndex((c) => c.id === id);
                    if (index !== -1) {
                        state.contacts[index] = { ...state.contacts[index], ...updates };
                    }
                }),
            deleteContacts: (ids) =>
                set((state) => {
                    state.contacts = state.contacts.filter((c) => !ids.includes(c.id));
                    state.totalCount -= ids.length;
                    state.selectedContactIds = state.selectedContactIds.filter(
                        (id) => !ids.includes(id)
                    );
                }),
            setCurrentPage: (page) =>
                set((state) => {
                    state.currentPage = page;
                }),
            setPageSize: (size) =>
                set((state) => {
                    state.pageSize = size;
                    state.currentPage = 1;
                }),
            setLoading: (loading) =>
                set((state) => {
                    state.isLoading = loading;
                }),
            setError: (error) =>
                set((state) => {
                    state.error = error;
                }),
            selectContact: (id) =>
                set((state) => {
                    if (!state.selectedContactIds.includes(id)) {
                        state.selectedContactIds.push(id);
                    }
                }),
            deselectContact: (id) =>
                set((state) => {
                    state.selectedContactIds = state.selectedContactIds.filter((i) => i !== id);
                }),
            selectAll: () =>
                set((state) => {
                    state.selectedContactIds = state.contacts.map((c) => c.id);
                }),
            deselectAll: () =>
                set((state) => {
                    state.selectedContactIds = [];
                }),
        })),
        { name: 'ContactStore' }
    )
);

// Notification store
interface Notification {
    id: string;
    type: 'info' | 'success' | 'warning' | 'error';
    title: string;
    message?: string;
    read: boolean;
    createdAt: string;
    link?: string;
}

interface NotificationState {
    notifications: Notification[];
    unreadCount: number;
    addNotification: (notification: Omit<Notification, 'id' | 'read' | 'createdAt'>) => void;
    markAsRead: (id: string) => void;
    markAllAsRead: () => void;
    removeNotification: (id: string) => void;
    clearAll: () => void;
}

export const useNotificationStore = create<NotificationState>()(
    devtools(
        immer((set) => ({
            notifications: [],
            unreadCount: 0,
            addNotification: (notification) =>
                set((state) => {
                    const newNotification: Notification = {
                        ...notification,
                        id: crypto.randomUUID(),
                        read: false,
                        createdAt: new Date().toISOString(),
                    };
                    state.notifications.unshift(newNotification);
                    state.unreadCount += 1;
                }),
            markAsRead: (id) =>
                set((state) => {
                    const notification = state.notifications.find((n) => n.id === id);
                    if (notification && !notification.read) {
                        notification.read = true;
                        state.unreadCount -= 1;
                    }
                }),
            markAllAsRead: () =>
                set((state) => {
                    state.notifications.forEach((n) => {
                        n.read = true;
                    });
                    state.unreadCount = 0;
                }),
            removeNotification: (id) =>
                set((state) => {
                    const index = state.notifications.findIndex((n) => n.id === id);
                    if (index !== -1) {
                        if (!state.notifications[index].read) {
                            state.unreadCount -= 1;
                        }
                        state.notifications.splice(index, 1);
                    }
                }),
            clearAll: () =>
                set((state) => {
                    state.notifications = [];
                    state.unreadCount = 0;
                }),
        })),
        { name: 'NotificationStore' }
    )
);
