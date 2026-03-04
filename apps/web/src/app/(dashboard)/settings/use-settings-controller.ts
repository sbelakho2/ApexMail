'use client';

import * as React from 'react';
import { PLANS } from '@/components/billing';
import { useAPI, getCsrfToken } from '@/hooks/use-api';

export interface UserProfile {
    firstName: string;
    lastName: string;
    email: string;
    bio: string;
    orgName: string;
    fromName: string;
    fromEmail: string;
    replyTo: string;
    address: string;
    timezone: string;
    language: string;
}

const DEFAULT_PROFILE: UserProfile = {
    firstName: '', lastName: '', email: '', bio: '',
    orgName: '', fromName: '', fromEmail: '', replyTo: '', address: '',
    timezone: 'utc', language: 'en',
};

interface WebhookEntry {
    id: string;
    url: string;
    events: string[];
    status: string;
    createdAt: string;
}

interface SessionUser {
    firstName?: string;
    lastName?: string;
    name?: string;
    email?: string;
    organization?: string;
    orgName?: string;
}

interface SessionResponse {
    user?: SessionUser;
}

interface WebhooksResponse {
    webhooks?: WebhookEntry[];
    data?: WebhookEntry[];
}

type SectionSaveState = 'idle' | 'saving' | 'saved' | 'error';

type ToastTone = 'success' | 'error' | 'info';

const SETTINGS_SECTION_IDS = ['profile', 'account', 'notifications', 'email', 'security', 'api', 'billing'] as const;

function parseStoredProfile(value: string): UserProfile | null {
    try {
        const parsed = JSON.parse(value) as Partial<UserProfile>;
        const keys: Array<keyof UserProfile> = [
            'firstName', 'lastName', 'email', 'bio', 'orgName', 'fromName', 'fromEmail', 'replyTo', 'address', 'timezone', 'language',
        ];

        const hasOnlyExpectedKeys = Object.keys(parsed).every((key) => keys.includes(key as keyof UserProfile));
        if (!hasOnlyExpectedKeys) return null;

        const normalized = { ...DEFAULT_PROFILE };
        for (const key of keys) {
            const raw = parsed[key];
            if (raw === undefined) continue;
            if (typeof raw !== 'string') return null;
            normalized[key] = raw;
        }

        return normalized;
    } catch {
        return null;
    }
}

export function useSettingsController() {
    const [activeSection, setActiveSection] = React.useState('profile');
    const [currentPlan, setCurrentPlan] = React.useState('pro');
    const [saveStatus, setSaveStatus] = React.useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
    const [profile, setProfile] = React.useState<UserProfile>(DEFAULT_PROFILE);
    const [webhooks, setWebhooks] = React.useState<WebhookEntry[]>([]);
    const [profileLoaded, setProfileLoaded] = React.useState(false);
    const [isDirty, setIsDirty] = React.useState(false);
    const [lastSavedAt, setLastSavedAt] = React.useState<string | null>(null);
    const [sectionSaveStatus, setSectionSaveStatus] = React.useState<Record<string, SectionSaveState>>({
        profile: 'idle', account: 'idle', notifications: 'idle', email: 'idle', security: 'idle', api: 'idle', billing: 'idle',
    });
    const [readOnlyMode, setReadOnlyMode] = React.useState(false);
    const [profileLoadError, setProfileLoadError] = React.useState<string | null>(null);
    const [localConflict, setLocalConflict] = React.useState(false);
    const [pendingLocalProfile, setPendingLocalProfile] = React.useState<UserProfile | null>(null);
    const [pendingVerification, setPendingVerification] = React.useState(false);
    const [avatarUploadProgress, setAvatarUploadProgress] = React.useState(0);

    // Notification preferences state
    const [notifications, setNotifications] = React.useState({
        campaignSent: true,
        newSubscribers: true,
        bounceAlerts: true,
        weeklyReport: false,
        marketingEmails: false,
    });

    const updateNotification = React.useCallback((key: keyof typeof notifications, value: boolean) => {
        setNotifications(prev => ({ ...prev, [key]: value }));
        setIsDirty(true);
    }, []);
    const [newWebhookUrl, setNewWebhookUrl] = React.useState('');
    const [newWebhookEvents, setNewWebhookEvents] = React.useState('delivered, opened');
    const [settingsImportJson, setSettingsImportJson] = React.useState('');
    const [revealedApiKey, setRevealedApiKey] = React.useState(false);
    const apiKeyRef = React.useRef<string>('');
    const [toasts, setToasts] = React.useState<Array<{ id: string; message: string; tone: ToastTone }>>([]);
    
    // Delete account state
    const [deleteDialogOpen, setDeleteDialogOpen] = React.useState(false);
    const [deletePassword, setDeletePassword] = React.useState('');
    const [deleteConfirmation, setDeleteConfirmation] = React.useState('');
    const [deleteReason, setDeleteReason] = React.useState('');
    const [deleteLoading, setDeleteLoading] = React.useState(false);
    const [deleteError, setDeleteError] = React.useState<string | null>(null);

    // Password change state
    const [passwordForm, setPasswordForm] = React.useState({ current: '', new: '', confirm: '' });
    const [passwordLoading, setPasswordLoading] = React.useState(false);
    const [passwordError, setPasswordError] = React.useState<string | null>(null);

    // Confirmation dialog state for reset defaults & unsaved changes
    const [pendingResetSection, setPendingResetSection] = React.useState<string | null>(null);
    const [pendingNavSection, setPendingNavSection] = React.useState<string | null>(null);

    const avatarInputRef = React.useRef<HTMLInputElement | null>(null);
    const saveTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
    const resetTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
    const initializedRef = React.useRef(false);

    const sessionQuery = useAPI<SessionResponse>('/api/auth/session', {
        keepPreviousData: true,
        revalidateOnFocus: false,
    });

    const webhooksQuery = useAPI<WebhooksResponse>(
        activeSection === 'api' ? '/v1/webhooks' : null,
        {
            keepPreviousData: true,
            revalidateOnFocus: false,
        },
    );

    const pushToast = React.useCallback((message: string, tone: ToastTone = 'info') => {
        setToasts((prev) => {
            if (prev.some((toast) => toast.message === message)) return prev;
            const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
            return [...prev, { id, message, tone }].slice(-4);
        });
    }, []);

    React.useEffect(() => {
        if (toasts.length === 0) return;
        const timer = window.setTimeout(() => {
            setToasts((prev) => prev.slice(1));
        }, 3000);
        return () => window.clearTimeout(timer);
    }, [toasts]);

    React.useEffect(() => {
        const isStillLoading = sessionQuery.isLoading || webhooksQuery.isLoading;
        if (isStillLoading || initializedRef.current) {
            return;
        }

        initializedRef.current = true;

        if (sessionQuery.data) {
            setProfileLoadError(null);
            setReadOnlyMode(false);
            const user = sessionQuery.data.user ?? {};
            const serverProfile = {
                ...DEFAULT_PROFILE,
                firstName: user.firstName ?? user.name?.split(' ')[0] ?? '',
                lastName: user.lastName ?? user.name?.split(' ').slice(1).join(' ') ?? '',
                email: user.email ?? '',
                orgName: user.organization ?? user.orgName ?? '',
            };

            setProfile((prev) => ({
                ...prev,
                ...serverProfile,
            }));

            try {
                const stored = localStorage.getItem('apexmail-user-settings');
                if (stored) {
                    const parsed = parseStoredProfile(stored);
                    if (parsed) {
                        const hasConflict = JSON.stringify({ ...serverProfile, bio: parsed.bio || serverProfile.bio }) !== JSON.stringify(parsed);
                        if (hasConflict) {
                            setPendingLocalProfile(parsed);
                            setLocalConflict(true);
                        }
                    }
                }
            } catch {
                // ignore
            }
        } else {
            setReadOnlyMode(true);
            setProfileLoadError('Failed to load your profile from the server. Local fallback values are shown in read-only mode.');
            try {
                const stored = localStorage.getItem('apexmail-user-settings');
                if (stored) {
                    const parsed = parseStoredProfile(stored);
                    if (parsed) {
                        setProfile((prev) => ({ ...prev, ...parsed }));
                    }
                }
            } catch {
                // ignore
            }
        }

        if (webhooksQuery.data) {
            setWebhooks(webhooksQuery.data.webhooks ?? webhooksQuery.data.data ?? []);
        }

        setProfileLoaded(true);
        setIsDirty(false);
    }, [sessionQuery.data, sessionQuery.isLoading, webhooksQuery.data, webhooksQuery.isLoading]);

    React.useEffect(() => {
        return () => {
            apiKeyRef.current = '';
            if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
            if (resetTimerRef.current) clearTimeout(resetTimerRef.current);
        };
    }, []);

    const updateProfile = React.useCallback((field: keyof UserProfile, value: string) => {
        setProfile((prev) => ({ ...prev, [field]: value }));
        setIsDirty(true);
    }, []);

    const handleSave = React.useCallback(async () => {
        if (readOnlyMode) {
            pushToast('Settings are read-only while backend profile APIs are unavailable.', 'error');
            return;
        }

        setSaveStatus('saving');
        setSectionSaveStatus((prev) => ({ ...prev, [activeSection]: 'saving' }));
        const previousProfileJson = localStorage.getItem('apexmail-user-settings');
        try {
            const profileChanged = Boolean(profile.email || profile.orgName);

            const csrfToken = await getCsrfToken();
            const headers: Record<string, string> = { 'Content-Type': 'application/json' };
            if (csrfToken) headers['X-CSRF-Token'] = csrfToken;

            const res = await fetch('/v1/auth/profile', {
                method: 'PUT',
                credentials: 'include',
                headers,
                body: JSON.stringify({
                    firstName: profile.firstName,
                    lastName: profile.lastName,
                    email: profile.email,
                    bio: profile.bio,
                    orgName: profile.orgName,
                    fromName: profile.fromName,
                    fromEmail: profile.fromEmail,
                    replyTo: profile.replyTo,
                    address: profile.address,
                    timezone: profile.timezone,
                    language: profile.language,
                    notifications,
                }),
            });

            if (!res.ok) throw new Error(`Save failed (${res.status})`);

            localStorage.setItem('apexmail-user-settings', JSON.stringify(profile));

            saveTimerRef.current = setTimeout(() => {
                setSaveStatus('saved');
                setSectionSaveStatus((prev) => ({ ...prev, [activeSection]: 'saved' }));
                setIsDirty(false);
                setLastSavedAt(new Date().toISOString());
                if (profileChanged && (activeSection === 'profile' || activeSection === 'account')) {
                    setPendingVerification(true);
                }
                pushToast('Settings saved.', 'success');
                resetTimerRef.current = setTimeout(() => setSaveStatus('idle'), 2000);
            }, 300);
        } catch {
            if (previousProfileJson !== null) localStorage.setItem('apexmail-user-settings', previousProfileJson);
            else localStorage.removeItem('apexmail-user-settings');
            setSaveStatus('error');
            setSectionSaveStatus((prev) => ({ ...prev, [activeSection]: 'error' }));
            pushToast('Failed to save settings.', 'error');
            resetTimerRef.current = setTimeout(() => setSaveStatus('idle'), 3000);
        }
    }, [activeSection, profile, notifications, pushToast, readOnlyMode]);

    const resetSectionDefaults = React.useCallback((section: string) => {
        setPendingResetSection(section);
    }, []);

    const confirmResetDefaults = React.useCallback(() => {
        const section = pendingResetSection;
        setPendingResetSection(null);
        if (!section) return;

        if (section === 'profile' || section === 'account' || section === 'email') {
            setProfile((prev) => ({ ...prev, ...DEFAULT_PROFILE, email: prev.email || DEFAULT_PROFILE.email }));
            setIsDirty(true);
            pushToast(`${section} settings reset to defaults.`, 'info');
        }
    }, [pendingResetSection, pushToast]);

    const addWebhook = React.useCallback(async () => {
        try {
            const parsed = new URL(newWebhookUrl);
            if (parsed.protocol !== 'https:') {
                pushToast('Webhook URL must be a valid HTTPS endpoint.', 'error');
                return;
            }
        } catch {
            pushToast('Webhook URL must be a valid HTTPS endpoint.', 'error');
            return;
        }

        try {
            const csrfToken = await getCsrfToken();
            const events = newWebhookEvents.split(',').map((event) => event.trim()).filter(Boolean);

            const res = await fetch('/v1/webhooks', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
                body: JSON.stringify({ url: newWebhookUrl, events }),
            });

            if (!res.ok) throw new Error('Failed to create webhook');

            const data = await res.json();
            const entry: WebhookEntry = data.webhook ?? data;
            setWebhooks((prev) => [entry, ...prev]);
            setNewWebhookUrl('');
            setNewWebhookEvents('delivered, opened');
            setIsDirty(true);
            pushToast('Webhook added.', 'success');
        } catch {
            pushToast('Failed to create webhook. Please try again.', 'error');
        }
    }, [newWebhookEvents, newWebhookUrl, pushToast]);

    const exportSettingsJson = React.useCallback(() => {
        const payload = JSON.stringify(profile, null, 2);
        setSettingsImportJson(payload);
        navigator.clipboard.writeText(payload).then(() => {
            pushToast('Settings JSON copied to clipboard.', 'success');
        }).catch(() => {
            pushToast('Exported settings JSON to editor panel.', 'info');
        });
    }, [profile, pushToast]);

    const importSettingsJson = React.useCallback(() => {
        try {
            const parsed = JSON.parse(settingsImportJson) as Partial<UserProfile>;
            const keys: Array<keyof UserProfile> = [
                'firstName', 'lastName', 'email', 'bio', 'orgName', 'fromName', 'fromEmail', 'replyTo', 'address', 'timezone', 'language',
            ];
            const invalid = Object.keys(parsed).some((key) => !keys.includes(key as keyof UserProfile));
            if (invalid) {
                pushToast('Settings JSON contains unsupported keys.', 'error');
                return;
            }
            setProfile((prev) => ({ ...prev, ...parsed }));
            setIsDirty(true);
            pushToast('Settings JSON imported.', 'success');
        } catch {
            pushToast('Invalid settings JSON.', 'error');
        }
    }, [settingsImportJson, pushToast]);

    const handleAvatarUpload = React.useCallback(async (fileList: FileList | null) => {
        if (!fileList || fileList.length === 0) return;
        const file = fileList[0];
        const allowed = ['image/jpeg', 'image/png', 'image/gif'];
        if (!allowed.includes(file.type)) {
            pushToast('Avatar must be JPG, PNG, or GIF.', 'error');
            return;
        }
        if (file.size > 2 * 1024 * 1024) {
            pushToast('Avatar size must be under 2MB.', 'error');
            return;
        }

        setAvatarUploadProgress(10);
        try {
            const csrfToken = await getCsrfToken();
            const formData = new FormData();
            formData.append('avatar', file);

            const res = await fetch('/v1/auth/avatar', {
                method: 'POST',
                credentials: 'include',
                headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
                body: formData,
            });

            setAvatarUploadProgress(80);

            if (!res.ok) {
                throw new Error('Upload failed');
            }

            setAvatarUploadProgress(100);
            pushToast('Avatar uploaded successfully.', 'success');
        } catch {
            setAvatarUploadProgress(0);
            pushToast('Avatar upload failed. Please try again.', 'error');
        }
    }, [pushToast]);

    const handleSectionChange = React.useCallback((nextSection: string) => {
        if (nextSection === activeSection) return;
        if (isDirty) {
            setPendingNavSection(nextSection);
            return;
        }
        setActiveSection(nextSection);
    }, [activeSection, isDirty]);

    const confirmSectionChange = React.useCallback(() => {
        const next = pendingNavSection;
        setPendingNavSection(null);
        if (next) {
            setIsDirty(false);
            setActiveSection(next);
        }
    }, [pendingNavSection]);

    const handleKeepServerProfile = React.useCallback(() => {
        setLocalConflict(false);
        setPendingLocalProfile(null);
        pushToast('Using server profile values.', 'info');
    }, [pushToast]);

    const handleUseLocalProfile = React.useCallback(() => {
        setProfile((prev) => ({ ...prev, ...pendingLocalProfile }));
        setLocalConflict(false);
        setIsDirty(true);
        pushToast('Applied local unsynced settings.', 'info');
    }, [pendingLocalProfile, pushToast]);

    const handleVerificationSend = React.useCallback(() => {
        pushToast('Verification code sent to your account email.', 'success');
    }, [pushToast]);

    const handleApiKeyAction = React.useCallback(async () => {
        if (!revealedApiKey) {
            try {
                const res = await fetch('/v1/auth/api-key', {
                    credentials: 'include',
                });
                if (res.ok) {
                    const data = await res.json();
                    const key = data.apiKey || data.key || '';
                    setRevealedApiKey(true);
                    apiKeyRef.current = key;
                    pushToast('Key revealed once for secure copy.', 'info');
                } else {
                    pushToast('Failed to retrieve API key.', 'error');
                }
            } catch {
                pushToast('Failed to retrieve API key.', 'error');
            }
            return;
        }
        const key = apiKeyRef.current;
        navigator.clipboard.writeText(key).catch(() => {});
        pushToast('API key copied.', 'success');
    }, [pushToast, revealedApiKey]);

    const handlePlanChange = React.useCallback(async (planId: string) => {
        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch('/v1/billing/plan', {
                method: 'PUT',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
                body: JSON.stringify({ plan: planId }),
            });

            if (!res.ok) throw new Error('Plan change failed');

            setCurrentPlan(planId);
            setIsDirty(true);
        } catch {
            throw new Error('Failed to change plan. Please try again.');
        }
    }, []);

    const openDeleteDialog = React.useCallback(() => {
        setDeleteDialogOpen(true);
        setDeletePassword('');
        setDeleteConfirmation('');
        setDeleteReason('');
        setDeleteError(null);
    }, []);

    const closeDeleteDialog = React.useCallback(() => {
        setDeleteDialogOpen(false);
        setDeletePassword('');
        setDeleteConfirmation('');
        setDeleteReason('');
        setDeleteError(null);
        setDeleteLoading(false);
    }, []);

    const handleDeleteAccount = React.useCallback(async () => {
        // Validate confirmation phrase
        if (deleteConfirmation.trim().toUpperCase() !== 'DELETE MY ACCOUNT') {
            setDeleteError("Please type 'DELETE MY ACCOUNT' to confirm");
            return;
        }

        // Validate password
        if (!deletePassword || deletePassword.length < 8) {
            setDeleteError('Please enter your current password');
            return;
        }

        setDeleteLoading(true);
        setDeleteError(null);

        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch('/v1/account', {
                method: 'DELETE',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
                body: JSON.stringify({
                    password: deletePassword,
                    confirmation: deleteConfirmation,
                    reason: deleteReason || undefined,
                }),
            });

            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                throw new Error(data.error || 'Failed to delete account');
            }

            const data = await res.json();
            
            // Clear local storage
            localStorage.removeItem('apexmail-user-settings');
            
            pushToast(data.message || 'Account deletion scheduled', 'success');
            closeDeleteDialog();
            
            // Redirect to login after a short delay
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
        } catch (err) {
            setDeleteError(err instanceof Error ? err.message : 'Failed to delete account');
        } finally {
            setDeleteLoading(false);
        }
    }, [deleteConfirmation, deletePassword, deleteReason, pushToast, closeDeleteDialog]);

    const activePlanData = React.useMemo(() => PLANS.find((plan) => plan.name === currentPlan), [currentPlan]);

    // ─── 2FA placeholder ───
    const handleEnable2FA = React.useCallback(async () => {
        pushToast('Two-Factor Authentication setup is not yet available. We are working on it!', 'info');
    }, [pushToast]);

    // ─── Session revocation ───
    const handleRevokeSession = React.useCallback(async (sessionId: string) => {
        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch('/v1/auth/sessions/revoke', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
                body: JSON.stringify({ sessionId }),
            });
            if (!res.ok) throw new Error('Failed to revoke session');
            pushToast('Session revoked successfully.', 'success');
        } catch {
            pushToast('Failed to revoke session. Please try again.', 'error');
        }
    }, [pushToast]);

    // ─── Generate new API key ───
    const handleGenerateApiKey = React.useCallback(async () => {
        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch('/v1/auth/api-keys', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
                body: JSON.stringify({ name: 'Production Key', scopes: ['send', 'read', 'write'] }),
            });
            if (!res.ok) throw new Error('Failed to generate key');
            const data = await res.json();
            apiKeyRef.current = data.key || data.apiKey || '';
            setRevealedApiKey(true);
            pushToast('New API key generated. Copy it now — it won\'t be shown again.', 'success');
        } catch {
            pushToast('Failed to generate API key. Please try again.', 'error');
        }
    }, [pushToast]);

    // ─── Revoke API key ───
    const handleRevokeApiKey = React.useCallback(async (keyId?: string) => {
        try {
            const csrfToken = await getCsrfToken();
            const endpoint = keyId ? `/v1/auth/api-keys/${encodeURIComponent(keyId)}` : '/v1/auth/api-keys/current';
            const res = await fetch(endpoint, {
                method: 'DELETE',
                credentials: 'include',
                headers: {
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
            });
            if (!res.ok) throw new Error('Failed to revoke key');
            setRevealedApiKey(false);
            apiKeyRef.current = '';
            pushToast('API key revoked.', 'success');
        } catch {
            pushToast('Failed to revoke API key. Please try again.', 'error');
        }
    }, [pushToast]);

    // ─── Remove webhook ───
    const handleRemoveWebhook = React.useCallback(async (webhookId: string) => {
        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(`/v1/webhooks/${encodeURIComponent(webhookId)}`, {
                method: 'DELETE',
                credentials: 'include',
                headers: {
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
            });
            if (!res.ok) throw new Error('Failed to remove webhook');
            setWebhooks(prev => prev.filter(wh => wh.id !== webhookId));
            pushToast('Webhook removed.', 'success');
        } catch {
            pushToast('Failed to remove webhook. Please try again.', 'error');
        }
    }, [pushToast]);

    // ─── Connected app revoke ───
    const handleRevokeConnectedApp = React.useCallback(async (appName: string) => {
        pushToast(`${appName} integration revocation is not yet available.`, 'info');
    }, [pushToast]);

    const handlePasswordChange = React.useCallback(async () => {
        setPasswordError(null);

        if (!passwordForm.current) {
            setPasswordError('Please enter your current password.');
            return;
        }
        if (passwordForm.new.length < 12) {
            setPasswordError('New password must be at least 12 characters.');
            return;
        }
        if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])/.test(passwordForm.new)) {
            setPasswordError('Password must include uppercase, lowercase, number, and special character.');
            return;
        }
        if (passwordForm.new !== passwordForm.confirm) {
            setPasswordError('Passwords do not match.');
            return;
        }

        setPasswordLoading(true);
        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch('/v1/auth/change-password', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'x-csrf-token': csrfToken } : {}),
                },
                body: JSON.stringify({
                    currentPassword: passwordForm.current,
                    newPassword: passwordForm.new,
                }),
            });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                setPasswordError(data.error || 'Failed to change password.');
                return;
            }
            pushToast('Password updated successfully.', 'success');
            setPasswordForm({ current: '', new: '', confirm: '' });
        } catch {
            setPasswordError('Network error. Please try again.');
        } finally {
            setPasswordLoading(false);
        }
    }, [passwordForm, pushToast]);

    return {
        state: {
            activeSection,
            currentPlan,
            saveStatus,
            profile,
            webhooks,
            isDirty,
            lastSavedAt,
            sectionSaveStatus,
            readOnlyMode,
            profileLoadError,
            localConflict,
            pendingLocalProfile,
            pendingVerification,
            avatarUploadProgress,
            newWebhookUrl,
            newWebhookEvents,
            settingsImportJson,
            revealedApiKey,
            apiKeyRef,
            toasts,
            activePlanData,
            deleteDialogOpen,
            deletePassword,
            deleteConfirmation,
            deleteReason,
            deleteLoading,
            deleteError,
            pendingResetSection,
            pendingNavSection,
            passwordForm,
            passwordLoading,
            passwordError,
            notifications,
        },
        refs: {
            avatarInputRef,
        },
        actions: {
            setNewWebhookUrl,
            setNewWebhookEvents,
            setSettingsImportJson,
            updateProfile,
            handleSave,
            resetSectionDefaults,
            confirmResetDefaults,
            confirmSectionChange,
            setPendingResetSection,
            setPendingNavSection,
            addWebhook,
            exportSettingsJson,
            importSettingsJson,
            handleAvatarUpload,
            handleSectionChange,
            handleKeepServerProfile,
            handleUseLocalProfile,
            handleVerificationSend,
            handleApiKeyAction,
            handlePlanChange,
            openDeleteDialog,
            closeDeleteDialog,
            setDeletePassword,
            setDeleteConfirmation,
            setDeleteReason,
            handleDeleteAccount,
            setPasswordForm,
            handlePasswordChange,
            updateNotification,
            handleEnable2FA,
            handleRevokeSession,
            handleGenerateApiKey,
            handleRevokeApiKey,
            handleRemoveWebhook,
            handleRevokeConnectedApp,
            pushToast,
        },
        constants: {
            sectionIds: SETTINGS_SECTION_IDS,
        },
    };
}
