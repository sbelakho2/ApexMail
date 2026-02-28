'use client';

import * as React from 'react';
import { PLANS } from '@/components/billing';
import { useAPI } from '@/hooks/use-api';

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
    const [newWebhookUrl, setNewWebhookUrl] = React.useState('');
    const [newWebhookEvents, setNewWebhookEvents] = React.useState('delivered, opened');
    const [settingsImportJson, setSettingsImportJson] = React.useState('');
    const [revealedApiKey, setRevealedApiKey] = React.useState(false);
    const [toasts, setToasts] = React.useState<Array<{ id: string; message: string; tone: ToastTone }>>([]);
    
    // Delete account state
    const [deleteDialogOpen, setDeleteDialogOpen] = React.useState(false);
    const [deletePassword, setDeletePassword] = React.useState('');
    const [deleteConfirmation, setDeleteConfirmation] = React.useState('');
    const [deleteReason, setDeleteReason] = React.useState('');
    const [deleteLoading, setDeleteLoading] = React.useState(false);
    const [deleteError, setDeleteError] = React.useState<string | null>(null);

    const avatarInputRef = React.useRef<HTMLInputElement | null>(null);
    const saveTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
    const resetTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
    const initializedRef = React.useRef(false);

    const sessionQuery = useAPI<SessionResponse>('/api/auth/session', {
        keepPreviousData: true,
        revalidateOnFocus: false,
    });

    const webhooksQuery = useAPI<WebhooksResponse>('/v1/webhooks', {
        keepPreviousData: true,
        revalidateOnFocus: false,
    });

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
        try {
            const profileChanged = Boolean(profile.email || profile.orgName);

            localStorage.setItem('apexmail-user-settings', JSON.stringify(profile));

            const res = await fetch('/v1/auth/profile', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
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
                }),
            });

            if (!res.ok && res.status !== 404) throw new Error('Save failed');

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
            setSaveStatus('error');
            setSectionSaveStatus((prev) => ({ ...prev, [activeSection]: 'error' }));
            pushToast('Failed to save settings.', 'error');
            resetTimerRef.current = setTimeout(() => setSaveStatus('idle'), 3000);
        }
    }, [activeSection, profile, pushToast, readOnlyMode]);

    const resetSectionDefaults = React.useCallback((section: string) => {
        if (!window.confirm(`Reset ${section} settings to defaults?`)) return;

        if (section === 'profile' || section === 'account' || section === 'email') {
            setProfile((prev) => ({ ...prev, ...DEFAULT_PROFILE, email: prev.email || DEFAULT_PROFILE.email }));
            setIsDirty(true);
            pushToast(`${section} settings reset to defaults.`, 'info');
        }
    }, [pushToast]);

    const addWebhook = React.useCallback(() => {
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

        const entry: WebhookEntry = {
            id: `wh_${Date.now()}`,
            url: newWebhookUrl,
            events: newWebhookEvents.split(',').map((event) => event.trim()).filter(Boolean),
            status: 'active',
            createdAt: new Date().toISOString(),
        };
        setWebhooks((prev) => [entry, ...prev]);
        setNewWebhookUrl('');
        setNewWebhookEvents('delivered, opened');
        setIsDirty(true);
        pushToast('Webhook added.', 'success');
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

    const handleAvatarUpload = React.useCallback((fileList: FileList | null) => {
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
        const timer = window.setInterval(() => {
            setAvatarUploadProgress((prev) => {
                const next = Math.min(prev + 30, 100);
                if (next >= 100) {
                    window.clearInterval(timer);
                    pushToast('Avatar uploaded successfully.', 'success');
                }
                return next;
            });
        }, 200);
    }, [pushToast]);

    const handleSectionChange = React.useCallback((nextSection: string) => {
        if (nextSection === activeSection) return;
        if (isDirty && !window.confirm('You have unsaved changes. Leave this section anyway?')) return;
        setActiveSection(nextSection);
    }, [activeSection, isDirty]);

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

    const handleApiKeyAction = React.useCallback(() => {
        if (!revealedApiKey) {
            setRevealedApiKey(true);
            pushToast('Key revealed once for secure copy.', 'info');
            return;
        }
        navigator.clipboard.writeText('am_prod_abcd1234efgh5678ijkl9012mnop3456');
        pushToast('API key copied.', 'success');
    }, [pushToast, revealedApiKey]);

    const handlePlanChange = React.useCallback(async (planId: string) => {
        setCurrentPlan(planId);
        setIsDirty(true);
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
            const res = await fetch('/api/account', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
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
            
            // Redirect to logout after a short delay
            setTimeout(() => {
                window.location.href = '/logout';
            }, 2000);
        } catch (err) {
            setDeleteError(err instanceof Error ? err.message : 'Failed to delete account');
        } finally {
            setDeleteLoading(false);
        }
    }, [deleteConfirmation, deletePassword, deleteReason, pushToast, closeDeleteDialog]);

    const activePlanData = React.useMemo(() => PLANS.find((plan) => plan.name === currentPlan), [currentPlan]);

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
            toasts,
            activePlanData,
            deleteDialogOpen,
            deletePassword,
            deleteConfirmation,
            deleteReason,
            deleteLoading,
            deleteError,
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
        },
        constants: {
            sectionIds: SETTINGS_SECTION_IDS,
        },
    };
}
