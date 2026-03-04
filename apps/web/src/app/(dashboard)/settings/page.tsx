'use client';

import { useEffect } from 'react';
import {
    Key,
    Save,
    CreditCard,
    Webhook,
} from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { Badge } from '@/components/ui/badge';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogFooter,
} from '@/components/ui/dialog';
import { cn, formatDate } from '@/lib/utils';
import { PlanSelector, PaygUsageDashboard } from '@/components/billing';
import { useAPI, getCsrfToken } from '@/hooks/use-api';
import { useSettingsController } from './use-settings-controller';
import { settingsSections } from './settings-sections';

export default function SettingsPage() {
    const {
        state: {
            activeSection,
            currentPlan,
            saveStatus,
            profile,
            webhooks,
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
            isDirty,
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
    } = useSettingsController();

    // Fetch billing payment method + team member count dynamically
    const { data: billingData } = useAPI<{ paymentMethod?: { brand: string; last4: string; expMonth: number; expYear: number } }>('/v1/billing/payment-method');
    const { data: teamData } = useAPI<{ members: unknown[]; limit: number }>('/v1/team/members');
    const paymentMethod = billingData?.paymentMethod;
    const teamMemberCount = teamData?.members?.length ?? 0;
    const teamMemberLimit = teamData?.limit ?? 0;

    const openBillingPortal = async () => {
        try {
            const csrf = await getCsrfToken();
            const res = await fetch('/api/billing', {
                method: 'POST', credentials: 'include',
                headers: { 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
                body: JSON.stringify({ action: 'portal' }),
            });
            if (!res.ok) throw new Error('Failed to open billing portal');
            const data = await res.json().catch(() => ({}));
            if (data.url) {
                const u = new URL(data.url);
                if (u.hostname.endsWith('.stripe.com')) window.location.href = data.url;
            }
        } catch {
            pushToast('Failed to open billing portal. Please try again.', 'error');
        }
    };

    useEffect(() => {
        if (!isDirty) return;

        const handleBeforeUnload = (event: BeforeUnloadEvent) => {
            event.preventDefault();
            event.returnValue = '';
        };

        window.addEventListener('beforeunload', handleBeforeUnload);
        return () => window.removeEventListener('beforeunload', handleBeforeUnload);
    }, [isDirty]);

    return (
        <div className="space-y-6">
            {toasts.length > 0 ? (
                <div className="fixed right-4 top-20 z-50 space-y-2">
                    {toasts.map((toast) => (
                        <div
                            key={toast.id}
                            className={cn(
                                'rounded-lg border px-3 py-2 text-sm shadow-lg bg-card',
                                toast.tone === 'success' && 'border-success/40',
                                toast.tone === 'error' && 'border-destructive/40',
                                toast.tone === 'info' && 'border-border'
                            )}
                        >
                            {toast.message}
                        </div>
                    ))}
                </div>
            ) : null}

            <PageHeader
                title="Settings"
                description="Manage your account settings and preferences."
                breadcrumbs={[{ label: 'Settings' }]}
            />

            {readOnlyMode ? (
                <Card className="border-warning/40 bg-warning/10">
                    <CardContent className="p-3 text-sm text-foreground">
                        Settings are currently in read-only mode because profile APIs are unavailable.
                    </CardContent>
                </Card>
            ) : null}

            {profileLoadError ? (
                <Card className="border-destructive/40 bg-destructive/10">
                    <CardContent className="p-3 text-sm text-foreground">
                        {profileLoadError}
                    </CardContent>
                </Card>
            ) : null}

            {localConflict && pendingLocalProfile ? (
                <Card className="border-warning/40 bg-warning/10">
                    <CardContent className="p-3 text-sm text-foreground flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                        <span>Local unsynced settings differ from server profile. Choose which version to keep.</span>
                        <div className="flex items-center gap-2">
                            <Button
                                size="sm"
                                variant="outline"
                                onClick={handleKeepServerProfile}
                            >
                                Keep Server
                            </Button>
                            <Button
                                size="sm"
                                onClick={handleUseLocalProfile}
                            >
                                Use Local
                            </Button>
                        </div>
                    </CardContent>
                </Card>
            ) : null}

            {pendingVerification ? (
                <Card className="border-primary/30 bg-primary/5">
                    <CardContent className="p-3 text-sm text-foreground flex items-center justify-between gap-3">
                        <span>Profile identity changes pending verification. Confirm via email to finalize billing/contact updates.</span>
                        <Button size="sm" variant="outline" onClick={handleVerificationSend}>
                            Send Verification Code
                        </Button>
                    </CardContent>
                </Card>
            ) : null}

            <div className="grid gap-6 lg:grid-cols-4">
                {/* Settings Navigation */}
                <Card className="lg:col-span-1 h-fit">
                    <CardContent className="p-4">
                        <nav className="space-y-1">
                            {settingsSections.map((section) => (
                                <button
                                    key={section.id}
                                    onClick={() => handleSectionChange(section.id)}
                                    aria-label={`Open ${section.label} settings`}
                                    className={cn(
                                        'flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                                        activeSection === section.id
                                            ? 'bg-primary/10 text-primary'
                                            : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                                    )}
                                >
                                    <section.icon className="h-4 w-4" />
                                    {section.label}
                                    {sectionSaveStatus[section.id] === 'saved' ? (
                                        <Badge variant="outline" className="ml-auto text-[10px]">Saved</Badge>
                                    ) : null}
                                </button>
                            ))}
                        </nav>
                    </CardContent>
                </Card>

                {/* Settings Content */}
                <div className="space-y-6 lg:col-span-3">
                    <Card>
                        <CardContent className="p-4">
                            <div className="grid gap-3 sm:grid-cols-3 text-xs text-muted-foreground">
                                <div>
                                    <p className="font-semibold uppercase tracking-wide">Created By</p>
                                    <p className="mt-1 text-foreground">System</p>
                                </div>
                                <div>
                                    <p className="font-semibold uppercase tracking-wide">Updated By</p>
                                    <p className="mt-1 text-foreground">Current User</p>
                                </div>
                                <div>
                                    <p className="font-semibold uppercase tracking-wide">Last Updated</p>
                                    <p className="mt-1 text-foreground">{lastSavedAt ? formatDate(lastSavedAt) : 'Not saved yet'}</p>
                                </div>
                            </div>
                            <div className="mt-3 text-xs">
                                <a href={`/audit?scope=settings:${activeSection}`} className="text-primary hover:underline">
                                    View audit trail for this settings section
                                </a>
                            </div>
                        </CardContent>
                    </Card>

                    {/* Profile Settings */}
                    {activeSection === 'profile' && (
                        <Card>
                            <CardHeader>
                                <CardTitle>Profile Settings</CardTitle>
                                <CardDescription>
                                    Manage your personal information and preferences.
                                </CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-6">
                                {/* Avatar */}
                                <div className="flex items-center gap-6">
                                    <Avatar size="2xl">
                                        <AvatarImage src="/avatar.png" alt="Profile" />
                                        <AvatarFallback>JD</AvatarFallback>
                                    </Avatar>
                                    <div className="space-y-2">
                                        <input
                                            ref={avatarInputRef}
                                            type="file"
                                            accept="image/png,image/jpeg,image/gif"
                                            className="hidden"
                                            onChange={(event) => handleAvatarUpload(event.target.files)}
                                        />
                                        <Button variant="outline" onClick={() => avatarInputRef.current?.click()} disabled={readOnlyMode}>Change Avatar</Button>
                                        <p className="text-sm text-muted-foreground">
                                            JPG, PNG or GIF. Max size 2MB.
                                        </p>
                                        {avatarUploadProgress > 0 ? (
                                            <p className="text-xs text-muted-foreground">Upload progress: {avatarUploadProgress}%</p>
                                        ) : null}
                                    </div>
                                </div>

                                <Separator />

                                {/* Personal Info */}
                                <div className="grid gap-4 sm:grid-cols-2">
                                    <div className="grid gap-2">
                                        <Label htmlFor="firstName">First Name</Label>
                                        <Input id="firstName" value={profile.firstName} disabled={readOnlyMode} onChange={e => updateProfile('firstName', e.target.value)} />
                                    </div>
                                    <div className="grid gap-2">
                                        <Label htmlFor="lastName">Last Name</Label>
                                        <Input id="lastName" value={profile.lastName} disabled={readOnlyMode} onChange={e => updateProfile('lastName', e.target.value)} />
                                    </div>
                                    <div className="grid gap-2 sm:col-span-2">
                                        <Label htmlFor="email">Email Address</Label>
                                        <Input id="email" type="email" value={profile.email} disabled={readOnlyMode} onChange={e => updateProfile('email', e.target.value)} />
                                    </div>
                                    <div className="grid gap-2 sm:col-span-2">
                                        <Label htmlFor="bio">Bio</Label>
                                        <Textarea id="bio" placeholder="Tell us about yourself..." rows={3} value={profile.bio} disabled={readOnlyMode} onChange={e => updateProfile('bio', e.target.value)} />
                                    </div>
                                </div>

                                <div className="flex items-center justify-between rounded-lg border p-3 text-sm">
                                    <span>Quick links</span>
                                    <a href="/audit?scope=profile" className="text-primary hover:underline">View profile audit trail</a>
                                </div>

                                <div className="flex justify-end">
                                    <Button variant="outline" onClick={() => resetSectionDefaults('profile')} disabled={readOnlyMode}>Reset to defaults</Button>
                                    <Button onClick={handleSave} disabled={saveStatus === 'saving' || readOnlyMode} className="ml-2">
                                        <Save className="mr-2 h-4 w-4" />
                                        {saveStatus === 'saving' ? 'Saving...' : saveStatus === 'saved' ? '✓ Saved!' : 'Save Changes'}
                                    </Button>
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    {/* Account Settings */}
                    {activeSection === 'account' && (
                        <Card>
                            <CardHeader>
                                <CardTitle>Account Settings</CardTitle>
                                <CardDescription>
                                    Manage your organization and team settings.
                                </CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-6">
                                <div className="grid gap-4">
                                    <div className="grid gap-2">
                                        <Label htmlFor="orgName">Organization Name</Label>
                                        <Input id="orgName" value={profile.orgName} disabled={readOnlyMode} onChange={e => updateProfile('orgName', e.target.value)} />
                                    </div>
                                    <div className="grid gap-2">
                                        <Label htmlFor="timezone">Timezone</Label>
                                        <Select value={profile.timezone} onValueChange={v => updateProfile('timezone', v)} disabled={readOnlyMode}>
                                            <SelectTrigger>
                                                <SelectValue placeholder="Select timezone" />
                                            </SelectTrigger>
                                            <SelectContent>
                                                <SelectItem value="utc-8">
                                                    (UTC-08:00) Pacific Time
                                                </SelectItem>
                                                <SelectItem value="utc-5">
                                                    (UTC-05:00) Eastern Time
                                                </SelectItem>
                                                <SelectItem value="utc">
                                                    (UTC+00:00) UTC
                                                </SelectItem>
                                                <SelectItem value="utc+1">
                                                    (UTC+01:00) Central European Time
                                                </SelectItem>
                                            </SelectContent>
                                        </Select>
                                    </div>
                                    <div className="grid gap-2">
                                        <Label htmlFor="language">Language</Label>
                                        <Select value={profile.language} onValueChange={v => updateProfile('language', v)} disabled={readOnlyMode}>
                                            <SelectTrigger>
                                                <SelectValue placeholder="Select language" />
                                            </SelectTrigger>
                                            <SelectContent>
                                                <SelectItem value="en">English</SelectItem>
                                                <SelectItem value="es">Español</SelectItem>
                                                <SelectItem value="fr">Français</SelectItem>
                                                <SelectItem value="de">Deutsch</SelectItem>
                                            </SelectContent>
                                        </Select>
                                    </div>
                                </div>

                                <div className="space-y-2 rounded-lg border p-3">
                                    <p className="text-sm font-medium">Import / Export Settings JSON</p>
                                    <div className="flex items-center gap-2">
                                        <Button size="sm" variant="outline" onClick={exportSettingsJson}>Export JSON</Button>
                                        <Button size="sm" variant="outline" onClick={importSettingsJson} disabled={readOnlyMode}>Import JSON</Button>
                                        <Button size="sm" variant="outline" onClick={() => resetSectionDefaults('account')} disabled={readOnlyMode}>Reset Defaults</Button>
                                    </div>
                                    <Textarea value={settingsImportJson} onChange={(event) => setSettingsImportJson(event.target.value)} rows={4} placeholder="Paste settings JSON here" disabled={readOnlyMode} />
                                </div>

                                <Separator />

                                <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
                                    <h3 className="font-medium text-destructive">Danger Zone</h3>
                                    <p className="mt-1 text-sm text-muted-foreground">
                                        Permanently delete your account and all associated data.
                                    </p>
                                    <Button 
                                        variant="destructive" 
                                        size="sm" 
                                        className="mt-4 min-h-[44px]"
                                        onClick={openDeleteDialog}
                                    >
                                        Delete Account
                                    </Button>
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    {/* Notification Settings */}
                    {activeSection === 'notifications' && (
                        <Card>
                            <CardHeader>
                                <CardTitle>Notification Settings</CardTitle>
                                <CardDescription>
                                    Choose how you want to be notified about activity.
                                </CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-6">
                                <div className="space-y-4">
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <p className="font-medium">Campaign Sent</p>
                                            <p className="text-sm text-muted-foreground">
                                                Notify when a campaign is sent successfully
                                            </p>
                                        </div>
                                        <Switch checked={notifications.campaignSent} onCheckedChange={(v) => updateNotification('campaignSent', v)} />
                                    </div>
                                    <Separator />
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <p className="font-medium">New Subscribers</p>
                                            <p className="text-sm text-muted-foreground">
                                                Daily summary of new subscribers
                                            </p>
                                        </div>
                                        <Switch checked={notifications.newSubscribers} onCheckedChange={(v) => updateNotification('newSubscribers', v)} />
                                    </div>
                                    <Separator />
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <p className="font-medium">Bounce Alerts</p>
                                            <p className="text-sm text-muted-foreground">
                                                Alert when bounce rate exceeds threshold
                                            </p>
                                        </div>
                                        <Switch checked={notifications.bounceAlerts} onCheckedChange={(v) => updateNotification('bounceAlerts', v)} />
                                    </div>
                                    <Separator />
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <p className="font-medium">Weekly Report</p>
                                            <p className="text-sm text-muted-foreground">
                                                Receive weekly performance summary
                                            </p>
                                        </div>
                                        <Switch checked={notifications.weeklyReport} onCheckedChange={(v) => updateNotification('weeklyReport', v)} />
                                    </div>
                                    <Separator />
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <p className="font-medium">Marketing Emails</p>
                                            <p className="text-sm text-muted-foreground">
                                                Product updates and tips
                                            </p>
                                        </div>
                                        <Switch checked={notifications.marketingEmails} onCheckedChange={(v) => updateNotification('marketingEmails', v)} />
                                    </div>
                                </div>

                                <div className="rounded-lg border p-3 text-sm text-muted-foreground">
                                    Privacy-impacting toggles may process engagement and event data to generate recommendations and alerts.
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    {/* Email Settings */}
                    {activeSection === 'email' && (
                        <Card>
                            <CardHeader>
                                <CardTitle>Email Settings</CardTitle>
                                <CardDescription>
                                    Configure your default email sending settings.
                                </CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-6">
                                <div className="grid gap-4 sm:grid-cols-2">
                                    <div className="grid gap-2">
                                        <Label htmlFor="fromName">Default From Name</Label>
                                        <Input id="fromName" value={profile.fromName} onChange={e => updateProfile('fromName', e.target.value)} />
                                    </div>
                                    <div className="grid gap-2">
                                        <Label htmlFor="fromEmail">Default From Email</Label>
                                        <Input id="fromEmail" type="email" value={profile.fromEmail} onChange={e => updateProfile('fromEmail', e.target.value)} />
                                    </div>
                                    <div className="grid gap-2 sm:col-span-2">
                                        <Label htmlFor="replyTo">Default Reply-To Email</Label>
                                        <Input id="replyTo" type="email" value={profile.replyTo} onChange={e => updateProfile('replyTo', e.target.value)} />
                                    </div>
                                </div>

                                <Separator />

                                <div className="space-y-4">
                                    <h3 className="font-medium">Email Footer</h3>
                                    <div className="grid gap-2">
                                        <Label htmlFor="address">Physical Address</Label>
                                        <Textarea
                                            id="address"
                                            placeholder="123 Main St, City, State 12345"
                                            rows={2}
                                            value={profile.address}
                                            onChange={e => updateProfile('address', e.target.value)}
                                        />
                                        <p className="text-xs text-muted-foreground">
                                            Required by CAN-SPAM act for commercial emails
                                        </p>
                                    </div>
                                </div>

                                <div className="flex justify-end">
                                    <Button variant="outline" onClick={() => resetSectionDefaults('email')} disabled={readOnlyMode}>Reset to defaults</Button>
                                    <Button onClick={handleSave} disabled={saveStatus === 'saving' || readOnlyMode} className="ml-2">
                                        <Save className="mr-2 h-4 w-4" />
                                        {saveStatus === 'saving' ? 'Saving...' : saveStatus === 'saved' ? '✓ Saved!' : 'Save Changes'}
                                    </Button>
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    {/* Security Settings */}
                    {activeSection === 'security' && (
                        <Card>
                            <CardHeader>
                                <CardTitle>Security Settings</CardTitle>
                                <CardDescription>
                                    Manage your account security and authentication.
                                </CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-6">
                                <div className="space-y-4">
                                    <h3 className="font-medium">Change Password</h3>
                                    <div className="grid gap-4 sm:max-w-md">
                                        {passwordError ? (
                                            <p className="text-sm text-destructive">{passwordError}</p>
                                        ) : null}
                                        <div className="grid gap-2">
                                            <Label htmlFor="currentPassword">Current Password</Label>
                                            <Input
                                                id="currentPassword"
                                                type="password"
                                                autoComplete="current-password"
                                                value={passwordForm.current}
                                                onChange={(e) => setPasswordForm(prev => ({ ...prev, current: e.target.value }))}
                                            />
                                        </div>
                                        <div className="grid gap-2">
                                            <Label htmlFor="newPassword">New Password</Label>
                                            <Input
                                                id="newPassword"
                                                type="password"
                                                autoComplete="new-password"
                                                value={passwordForm.new}
                                                onChange={(e) => setPasswordForm(prev => ({ ...prev, new: e.target.value }))}
                                            />
                                        </div>
                                        <div className="grid gap-2">
                                            <Label htmlFor="confirmPassword">
                                                Confirm New Password
                                            </Label>
                                            <Input
                                                id="confirmPassword"
                                                type="password"
                                                autoComplete="new-password"
                                                value={passwordForm.confirm}
                                                onChange={(e) => setPasswordForm(prev => ({ ...prev, confirm: e.target.value }))}
                                            />
                                        </div>
                                        <Button
                                            className="w-fit"
                                            onClick={handlePasswordChange}
                                            disabled={passwordLoading}
                                        >
                                            {passwordLoading ? 'Updating...' : 'Update Password'}
                                        </Button>
                                    </div>
                                </div>

                                <Separator />

                                <div className="space-y-4">
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <h3 className="font-medium">
                                                Two-Factor Authentication
                                            </h3>
                                            <p className="text-sm text-muted-foreground">
                                                Add an extra layer of security to your account
                                            </p>
                                        </div>
                                        <Button variant="outline" onClick={handleEnable2FA}>Enable 2FA</Button>
                                    </div>
                                </div>

                                <Separator />

                                <div className="space-y-4">
                                    <h3 className="font-medium">Active Sessions</h3>
                                    <p className="text-sm text-muted-foreground">
                                        Sessions are managed through your account security settings. Use &quot;Revoke&quot; to end a session.
                                    </p>
                                    <div className="space-y-3">
                                        <div className="flex items-center justify-between rounded-lg border p-4">
                                            <div>
                                                <p className="font-medium">Current Session</p>
                                                <p className="text-sm text-muted-foreground">
                                                    This device • Active now
                                                </p>
                                            </div>
                                            <Badge variant="success">Active</Badge>
                                        </div>
                                    </div>
                                    <Button variant="ghost" size="sm" className="text-destructive" onClick={() => handleRevokeSession('all-other')}>
                                        Revoke All Other Sessions
                                    </Button>
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    {/* API Settings */}
                    {activeSection === 'api' && (
                        <Card>
                            <CardHeader>
                                <CardTitle>API & Webhooks</CardTitle>
                                <CardDescription>
                                    Manage API keys and webhook endpoints.
                                </CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-6">
                                <div className="space-y-4">
                                    <h3 className="font-medium">API Keys</h3>
                                    <div className="space-y-3">
                                        <div className="flex items-center justify-between rounded-lg border p-4">
                                            <div>
                                                <p className="font-medium">Production Key</p>
                                                <p className="font-mono text-sm text-muted-foreground">
                                                    {revealedApiKey ? (apiKeyRef.current || 'am_prod_****************************') : 'am_prod_****************************'}
                                                </p>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <Button variant="outline" size="sm" onClick={handleApiKeyAction}>
                                                    {revealedApiKey ? 'Copy' : 'Reveal'}
                                                </Button>
                                                <Button
                                                    variant="outline"
                                                    size="sm"
                                                    className="text-destructive"
                                                    onClick={() => handleRevokeApiKey()}
                                                >
                                                    Revoke
                                                </Button>
                                            </div>
                                        </div>
                                    </div>
                                    <Button variant="outline" onClick={handleGenerateApiKey}>
                                        <Key className="mr-2 h-4 w-4" />
                                        Generate New Key
                                    </Button>
                                </div>

                                <Separator />

                                <div className="space-y-4">
                                    <h3 className="font-medium">Webhooks</h3>
                                    {webhooks.length === 0 ? (
                                        <p className="text-sm text-muted-foreground">
                                            No webhook endpoints configured. Add one to receive real-time event notifications.
                                        </p>
                                    ) : (
                                        <div className="space-y-2">
                                            {webhooks.map(wh => (
                                                <div key={wh.id} className="flex items-center justify-between rounded-lg border p-4">
                                                    <div>
                                                        <p className="font-mono text-sm">{wh.url}</p>
                                                        <p className="text-xs text-muted-foreground mt-1">
                                                            {wh.events.join(', ')} • <Badge variant={wh.status === 'active' ? 'success' : 'secondary'} className="text-xs">{wh.status}</Badge>
                                                        </p>
                                                    </div>
                                                    <Button variant="ghost" size="sm" className="text-destructive" onClick={() => handleRemoveWebhook(wh.id)}>Remove</Button>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                    <div className="rounded-lg border p-3 space-y-2">
                                        <Label htmlFor="webhook-url">Webhook URL</Label>
                                        <Input
                                            id="webhook-url"
                                            placeholder="https://example.com/webhooks/apexmail"
                                            value={newWebhookUrl}
                                            onChange={(event) => setNewWebhookUrl(event.target.value)}
                                            disabled={readOnlyMode}
                                        />
                                        <Label htmlFor="webhook-events">Events (comma-separated)</Label>
                                        <Input
                                            id="webhook-events"
                                            value={newWebhookEvents}
                                            onChange={(event) => setNewWebhookEvents(event.target.value)}
                                            disabled={readOnlyMode}
                                        />
                                        <Button variant="outline" onClick={addWebhook} disabled={readOnlyMode}>
                                            <Webhook className="mr-2 h-4 w-4" />
                                            Add Webhook
                                        </Button>
                                    </div>
                                </div>

                                <Separator />

                                <div className="space-y-3">
                                    <h3 className="font-medium">Connected Apps</h3>
                                    <div className="rounded-lg border p-4 flex items-center justify-between">
                                        <div>
                                            <p className="font-medium">Slack Workspace</p>
                                            <p className="text-xs text-muted-foreground">Read alerts, post notifications</p>
                                        </div>
                                        <Button variant="outline" size="sm" onClick={() => handleRevokeConnectedApp('Slack')}>Revoke Access</Button>
                                    </div>
                                    <div className="rounded-lg border p-4 flex items-center justify-between">
                                        <div>
                                            <p className="font-medium">Zapier Integration</p>
                                            <p className="text-xs text-muted-foreground">Webhook relay and event automation</p>
                                        </div>
                                        <Button variant="outline" size="sm" onClick={() => handleRevokeConnectedApp('Zapier')}>Manage Permissions</Button>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    {/* Billing Settings */}
                    {activeSection === 'billing' && (
                        <Card>
                            <CardHeader>
                                <CardTitle>Billing & Subscription</CardTitle>
                                <CardDescription>
                                    Manage your subscription and payment methods.
                                </CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-6">
                                <div className="rounded-lg border p-6 bg-card">
                                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                                        <div>
                                            <p className="text-sm font-medium text-muted-foreground mb-1">
                                                Current Plan
                                            </p>
                                            <div className="flex items-baseline gap-2">
                                                <h3 className="text-2xl font-semibold tracking-tight">
                                                    {currentPlan === 'payg' ? 'Pay As You Go' : activePlanData?.displayName || 'Free Plan'}
                                                </h3>
                                                {currentPlan !== 'payg' && (
                                                    <Badge variant="secondary" className="font-normal">
                                                        Monthly
                                                    </Badge>
                                                )}
                                            </div>
                                            <p className="text-sm text-muted-foreground mt-1">
                                                {currentPlan === 'payg' 
                                                    ? 'Usage-based billing' 
                                                    : `$${(activePlanData?.priceMonthly || 0) / 100}/month • Renews on ${formatDate('2026-02-15T00:00:00Z')}`
                                                }
                                            </p>
                                        </div>
                                        <PlanSelector 
                                            currentPlan={currentPlan}
                                            onPlanChange={handlePlanChange}
                                        />
                                    </div>
                                    
                                    <Separator className="my-6" />
                                    
                                    {currentPlan === 'payg' ? (
                                        <PaygUsageDashboard 
                                            initialData={{
                                                period: {
                                                    start: '2026-01-01T00:00:00Z',
                                                    end: '2026-01-15T10:00:00Z'
                                                },
                                                usage: {
                                                    emailsSent: 45231,
                                                    apiCalls: 120500
                                                },
                                                cost: {
                                                    emailCost: (10000 * 0.10) + (35231 * 0.08), // tiered: first 10K at $0.10/100, rest at $0.08/100
                                                    apiCost: Math.ceil(20500 / 1000) * 10, // $0.10/1K calls above 100K free
                                                    totalCost: (10000 * 0.10) + (35231 * 0.08) + (Math.ceil(20500 / 1000) * 10)
                                                }
                                            }}
                                        />
                                    ) : (
                                        <div className="grid gap-6 sm:grid-cols-3">
                                            <div>
                                                <p className="text-sm font-medium text-muted-foreground mb-2">
                                                    Emails Sent
                                                </p>
                                                <p className="text-xl font-semibold apex-metric-number">
                                                    — <span className="text-sm text-muted-foreground font-normal">/ {activePlanData?.emailLimit.toLocaleString()}</span>
                                                </p>
                                                <p className="text-xs text-muted-foreground mt-1">Usage data loads from your billing dashboard</p>
                                            </div>
                                            <div>
                                                <p className="text-sm font-medium text-muted-foreground mb-2">
                                                    API Calls
                                                </p>
                                                <p className="text-xl font-semibold apex-metric-number">
                                                    — <span className="text-sm text-muted-foreground font-normal">/ —</span>
                                                </p>
                                                <p className="text-xs text-muted-foreground mt-1">View detailed usage in Analytics</p>
                                            </div>
                                            <div>
                                                <p className="text-sm font-medium text-muted-foreground mb-2">
                                                    Team Members
                                                </p>
                                                <p className="text-xl font-semibold apex-metric-number">{teamMemberCount} <span className="text-sm text-muted-foreground font-normal">/ {teamMemberLimit || '∞'}</span></p>
                                            </div>
                                        </div>
                                    )}
                                </div>

                                <div className="space-y-4 pt-2">
                                    <h3 className="font-medium text-sm">Payment Method</h3>
                                    <div className="flex items-center justify-between rounded-lg border p-4 bg-card hover:bg-muted/50 transition-colors">
                                        <div className="flex items-center gap-3">
                                            <div className="rounded border bg-background p-2">
                                                <CreditCard className="h-4 w-4 text-muted-foreground" />
                                            </div>
                                            <div>
                                                <p className="font-medium text-sm">{paymentMethod ? `${paymentMethod.brand} ending in ${paymentMethod.last4}` : 'No payment method'}</p>
                                                <p className="text-xs text-muted-foreground">
                                                    {paymentMethod ? `Expires ${String(paymentMethod.expMonth).padStart(2, '0')}/${String(paymentMethod.expYear).slice(-2)}` : 'Add a card in billing portal'}
                                                </p>
                                            </div>
                                        </div>
                                        <Button variant="ghost" size="sm" className="min-h-[44px]" onClick={openBillingPortal}>
                                            Update
                                        </Button>
                                    </div>
                                </div>

                                <div className="space-y-4">
                                    <h3 className="font-medium">Billing History</h3>
                                    <p className="text-sm text-muted-foreground">
                                        View and download invoices from your billing portal.
                                    </p>
                                    <Button variant="outline" size="sm" onClick={openBillingPortal}>
                                        View Invoices &amp; History
                                    </Button>
                                </div>
                            </CardContent>
                        </Card>
                    )}
                </div>
            </div>

            {/* Delete Account Confirmation Dialog */}
            <Dialog open={deleteDialogOpen} onOpenChange={(open) => !open && closeDeleteDialog()}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle className="text-destructive">Delete Account</DialogTitle>
                        <DialogDescription>
                            This action cannot be undone. Your account will be scheduled for deletion
                            and you will have 30 days to cancel before all data is permanently removed.
                        </DialogDescription>
                    </DialogHeader>

                    <div className="space-y-4 py-4">
                        {deleteError && (
                            <div className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
                                {deleteError}
                            </div>
                        )}

                        <div className="space-y-2">
                            <Label htmlFor="delete-password">Current Password</Label>
                            <Input
                                id="delete-password"
                                type="password"
                                autoComplete="current-password"
                                placeholder="Enter your current password"
                                value={deletePassword}
                                onChange={(e) => setDeletePassword(e.target.value)}
                                disabled={deleteLoading}
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="delete-confirmation">
                                Type <span className="font-mono font-bold">DELETE MY ACCOUNT</span> to confirm
                            </Label>
                            <Input
                                id="delete-confirmation"
                                type="text"
                                placeholder="DELETE MY ACCOUNT"
                                value={deleteConfirmation}
                                onChange={(e) => setDeleteConfirmation(e.target.value)}
                                disabled={deleteLoading}
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="delete-reason">Reason for leaving (optional)</Label>
                            <Textarea
                                id="delete-reason"
                                placeholder="Help us improve by telling us why you're leaving..."
                                value={deleteReason}
                                onChange={(e) => setDeleteReason(e.target.value)}
                                disabled={deleteLoading}
                                rows={3}
                            />
                        </div>
                    </div>

                    <DialogFooter>
                        <Button variant="outline" onClick={closeDeleteDialog} disabled={deleteLoading}>
                            Cancel
                        </Button>
                        <Button 
                            variant="destructive" 
                            onClick={handleDeleteAccount}
                            disabled={deleteLoading || deleteConfirmation.toUpperCase() !== 'DELETE MY ACCOUNT'}
                        >
                            {deleteLoading ? 'Deleting...' : 'Delete My Account'}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Reset Defaults Confirmation Dialog */}
            <Dialog open={pendingResetSection !== null} onOpenChange={(open) => { if (!open) setPendingResetSection(null); }}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Reset Settings</DialogTitle>
                        <DialogDescription>
                            Reset {pendingResetSection} settings to defaults? This cannot be undone.
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setPendingResetSection(null)}>Cancel</Button>
                        <Button onClick={confirmResetDefaults}>Reset to Defaults</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Unsaved Changes Navigation Dialog */}
            <Dialog open={pendingNavSection !== null} onOpenChange={(open) => { if (!open) setPendingNavSection(null); }}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Unsaved Changes</DialogTitle>
                        <DialogDescription>
                            You have unsaved changes. Leave this section anyway? Your changes will be lost.
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setPendingNavSection(null)}>Stay</Button>
                        <Button variant="destructive" onClick={confirmSectionChange}>Leave Without Saving</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}
