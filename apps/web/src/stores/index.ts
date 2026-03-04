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
    hasRole: (role: User['role'] | User['role'][]) => boolean;
    canAccess: (feature: 'team' | 'billing' | 'settings' | 'api' | 'compliance' | 'dedicated-ips') => boolean;
}

export const useUserStore = create<UserState>()(
    devtools(
        immer((set, get) => ({
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
            hasRole: (role) => {
                const user = get().user;
                if (!user) return false;
                if (Array.isArray(role)) return role.includes(user.role);
                return user.role === role;
            },
            canAccess: (feature) => {
                const user = get().user;
                if (!user) return false;
                const roleHierarchy: Record<User['role'], number> = { viewer: 0, member: 1, admin: 2 };
                const userLevel = roleHierarchy[user.role] ?? 0;
                const featureMinLevel: Record<string, number> = {
                    team: 2,        // admin only
                    billing: 2,     // admin only
                    settings: 1,    // member+
                    api: 1,         // member+
                    compliance: 1,  // member+
                    'dedicated-ips': 2, // admin only
                };
                return userLevel >= (featureMinLevel[feature] ?? 0);
            },
        })),
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

const NOTIFICATION_LIMIT = 200;

export const useNotificationStore = create<NotificationState>()(
    devtools(
        persist(
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
                        if (state.notifications.length > NOTIFICATION_LIMIT) {
                            state.notifications = state.notifications.slice(0, NOTIFICATION_LIMIT);
                        }
                        state.unreadCount += 1;
                    }),
                markAsRead: (id) =>
                    set((state) => {
                        const notification = state.notifications.find((n: Notification) => n.id === id);
                        if (notification && !notification.read) {
                            notification.read = true;
                            state.unreadCount -= 1;
                        }
                    }),
                markAllAsRead: () =>
                    set((state) => {
                        state.notifications.forEach((n: Notification) => {
                            n.read = true;
                        });
                        state.unreadCount = 0;
                    }),
                removeNotification: (id) =>
                    set((state) => {
                        const index = state.notifications.findIndex((n: Notification) => n.id === id);
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
            { name: 'apexmail-notifications', version: 1 }
        ),
        { name: 'NotificationStore' }
    )
);
