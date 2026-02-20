'use client';

import * as React from 'react';
import {
    User,
    Bell,
    Shield,
    CreditCard,
    Key,
    Mail,
    Webhook,
    Building2,
    Save,
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
import { cn } from '@/lib/utils';
import { PlanSelector, PaygUsageDashboard, PLANS } from '@/components/billing';

const settingsSections = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'account', label: 'Account', icon: Building2 },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'email', label: 'Email Settings', icon: Mail },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'api', label: 'API & Webhooks', icon: Webhook },
    { id: 'billing', label: 'Billing', icon: CreditCard },
];

interface UserProfile {
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

export default function SettingsPage() {
    const [activeSection, setActiveSection] = React.useState('profile');
    const [currentPlan, setCurrentPlan] = React.useState('pro');
    const [saveStatus, setSaveStatus] = React.useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
    const [profile, setProfile] = React.useState<UserProfile>(DEFAULT_PROFILE);
    const [webhooks, setWebhooks] = React.useState<WebhookEntry[]>([]);
    const [profileLoaded, setProfileLoaded] = React.useState(false);
    const saveTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
    const resetTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);

    // Load profile from API on mount
    React.useEffect(() => {
        Promise.allSettled([
            fetch('/api/v1/auth/me'),
            fetch('/api/v1/webhooks'),
        ]).then(async ([profileRes, whRes]) => {
            if (profileRes.status === 'fulfilled' && profileRes.value.ok) {
                const json = await profileRes.value.json();
                const user = json.user ?? json;
                setProfile(prev => ({
                    ...prev,
                    firstName: user.firstName ?? user.name?.split(' ')[0] ?? '',
                    lastName: user.lastName ?? user.name?.split(' ').slice(1).join(' ') ?? '',
                    email: user.email ?? '',
                    orgName: user.organization ?? user.orgName ?? '',
                }));
            } else {
                // Fallback to localStorage if API not available
                try {
                    const stored = localStorage.getItem('apexmail-user-settings');
                    if (stored) setProfile(prev => ({ ...prev, ...JSON.parse(stored) }));
                } catch { /* ignore */ }
            }
            if (whRes.status === 'fulfilled' && whRes.value.ok) {
                const json = await whRes.value.json();
                setWebhooks(json.webhooks ?? json.data ?? []);
            }
        }).finally(() => setProfileLoaded(true));

        return () => {
            if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
            if (resetTimerRef.current) clearTimeout(resetTimerRef.current);
        };
    }, []);

    function updateProfile(field: keyof UserProfile, value: string) {
        setProfile(prev => ({ ...prev, [field]: value }));
    }

    async function handleSave() {
        setSaveStatus('saving');
        try {
            // Persist to localStorage as fallback
            localStorage.setItem('apexmail-user-settings', JSON.stringify(profile));

            // Attempt real API save — fire and forget if endpoint doesn't exist yet
            const res = await fetch('/api/v1/auth/profile', {
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
                resetTimerRef.current = setTimeout(() => setSaveStatus('idle'), 2000);
            }, 300);
        } catch {
            setSaveStatus('error');
            resetTimerRef.current = setTimeout(() => setSaveStatus('idle'), 3000);
        }
    }

    const activePlanData = PLANS.find(p => p.name === currentPlan);

    return (
        <div className="space-y-6">
            <PageHeader
                title="Settings"
                description="Manage your account settings and preferences."
                breadcrumbs={[{ label: 'Settings' }]}
            />

            <div className="grid gap-6 lg:grid-cols-4">
                {/* Settings Navigation */}
                <Card className="lg:col-span-1 h-fit">
                    <CardContent className="p-4">
                        <nav className="space-y-1">
                            {settingsSections.map((section) => (
                                <button
                                    key={section.id}
                                    onClick={() => setActiveSection(section.id)}
                                    className={cn(
                                        'flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                                        activeSection === section.id
                                            ? 'bg-primary/10 text-primary'
                                            : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                                    )}
                                >
                                    <section.icon className="h-4 w-4" />
                                    {section.label}
                                </button>
                            ))}
                        </nav>
                    </CardContent>
                </Card>

                {/* Settings Content */}
                <div className="space-y-6 lg:col-span-3">
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
                                        <Button variant="outline">Change Avatar</Button>
                                        <p className="text-sm text-muted-foreground">
                                            JPG, PNG or GIF. Max size 2MB.
                                        </p>
                                    </div>
                                </div>

                                <Separator />

                                {/* Personal Info */}
                                <div className="grid gap-4 sm:grid-cols-2">
                                    <div className="grid gap-2">
                                        <Label htmlFor="firstName">First Name</Label>
                                        <Input id="firstName" value={profile.firstName} onChange={e => updateProfile('firstName', e.target.value)} />
                                    </div>
                                    <div className="grid gap-2">
                                        <Label htmlFor="lastName">Last Name</Label>
                                        <Input id="lastName" value={profile.lastName} onChange={e => updateProfile('lastName', e.target.value)} />
                                    </div>
                                    <div className="grid gap-2 sm:col-span-2">
                                        <Label htmlFor="email">Email Address</Label>
                                        <Input id="email" type="email" value={profile.email} onChange={e => updateProfile('email', e.target.value)} />
                                    </div>
                                    <div className="grid gap-2 sm:col-span-2">
                                        <Label htmlFor="bio">Bio</Label>
                                        <Textarea id="bio" placeholder="Tell us about yourself..." rows={3} value={profile.bio} onChange={e => updateProfile('bio', e.target.value)} />
                                    </div>
                                </div>

                                <div className="flex justify-end">
                                    <Button onClick={handleSave} disabled={saveStatus === 'saving'}>
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
                                        <Input id="orgName" value={profile.orgName} onChange={e => updateProfile('orgName', e.target.value)} />
                                    </div>
                                    <div className="grid gap-2">
                                        <Label htmlFor="timezone">Timezone</Label>
                                        <Select value={profile.timezone} onValueChange={v => updateProfile('timezone', v)}>
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
                                        <Select value={profile.language} onValueChange={v => updateProfile('language', v)}>
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

                                <Separator />

                                <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
                                    <h3 className="font-medium text-destructive">Danger Zone</h3>
                                    <p className="mt-1 text-sm text-muted-foreground">
                                        Permanently delete your account and all associated data.
                                    </p>
                                    <Button variant="destructive" size="sm" className="mt-4 min-h-[44px]">
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
                                        <Switch defaultChecked />
                                    </div>
                                    <Separator />
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <p className="font-medium">New Subscribers</p>
                                            <p className="text-sm text-muted-foreground">
                                                Daily summary of new subscribers
                                            </p>
                                        </div>
                                        <Switch defaultChecked />
                                    </div>
                                    <Separator />
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <p className="font-medium">Bounce Alerts</p>
                                            <p className="text-sm text-muted-foreground">
                                                Alert when bounce rate exceeds threshold
                                            </p>
                                        </div>
                                        <Switch defaultChecked />
                                    </div>
                                    <Separator />
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <p className="font-medium">Weekly Report</p>
                                            <p className="text-sm text-muted-foreground">
                                                Receive weekly performance summary
                                            </p>
                                        </div>
                                        <Switch />
                                    </div>
                                    <Separator />
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <p className="font-medium">Marketing Emails</p>
                                            <p className="text-sm text-muted-foreground">
                                                Product updates and tips
                                            </p>
                                        </div>
                                        <Switch />
                                    </div>
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
                                    <Button onClick={handleSave} disabled={saveStatus === 'saving'}>
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
                                        <div className="grid gap-2">
                                            <Label htmlFor="currentPassword">Current Password</Label>
                                            <Input id="currentPassword" type="password" />
                                        </div>
                                        <div className="grid gap-2">
                                            <Label htmlFor="newPassword">New Password</Label>
                                            <Input id="newPassword" type="password" />
                                        </div>
                                        <div className="grid gap-2">
                                            <Label htmlFor="confirmPassword">
                                                Confirm New Password
                                            </Label>
                                            <Input id="confirmPassword" type="password" />
                                        </div>
                                        <Button className="w-fit">Update Password</Button>
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
                                        <Button variant="outline">Enable 2FA</Button>
                                    </div>
                                </div>

                                <Separator />

                                <div className="space-y-4">
                                    <h3 className="font-medium">Active Sessions</h3>
                                    <div className="space-y-3">
                                        <div className="flex items-center justify-between rounded-lg border p-4">
                                            <div>
                                                <p className="font-medium">
                                                    Chrome on macOS
                                                </p>
                                                <p className="text-sm text-muted-foreground">
                                                    San Francisco, CA • Current session
                                                </p>
                                            </div>
                                            <Badge variant="success">Active</Badge>
                                        </div>
                                        <div className="flex items-center justify-between rounded-lg border p-4">
                                            <div>
                                                <p className="font-medium">Safari on iPhone</p>
                                                <p className="text-sm text-muted-foreground">
                                                    San Francisco, CA • Last active 2 hours ago
                                                </p>
                                            </div>
                                            <Button variant="ghost" size="sm">
                                                Revoke
                                            </Button>
                                        </div>
                                    </div>
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
                                                    am_prod_****************************
                                                </p>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <Button variant="outline" size="sm">
                                                    Copy
                                                </Button>
                                                <Button
                                                    variant="outline"
                                                    size="sm"
                                                    className="text-destructive"
                                                >
                                                    Revoke
                                                </Button>
                                            </div>
                                        </div>
                                    </div>
                                    <Button variant="outline">
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
                                                    <Button variant="ghost" size="sm" className="text-destructive">Remove</Button>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                    <Button variant="outline">
                                        <Webhook className="mr-2 h-4 w-4" />
                                        Add Webhook
                                    </Button>
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
                                                    : `$${(activePlanData?.priceMonthly || 0) / 100}/month • Renews on ${new Date('2026-02-15T00:00:00Z').toLocaleDateString()}`
                                                }
                                            </p>
                                        </div>
                                        <PlanSelector 
                                            currentPlan={currentPlan}
                                            onPlanChange={async (planId) => {
                                                setCurrentPlan(planId);
                                            }}
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
                                                    emailCost: 45231 * 0.08, // approx
                                                    apiCost: 20500 * 0.05, // approx
                                                    totalCost: (45231 * 0.08) + (20500 * 0.05)
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
                                                    32,456 <span className="text-sm text-muted-foreground font-normal">/ {activePlanData?.emailLimit.toLocaleString()}</span>
                                                </p>
                                                <div className="h-1.5 w-full bg-secondary mt-3 rounded-full overflow-hidden">
                                                    <div className="h-full bg-primary rounded-full" style={{ width: '65%' }} />
                                                </div>
                                            </div>
                                            <div>
                                                <p className="text-sm font-medium text-muted-foreground mb-2">
                                                    API Calls
                                                </p>
                                                <p className="text-xl font-semibold apex-metric-number">
                                                    234k <span className="text-sm text-muted-foreground font-normal">/ 500k</span>
                                                </p>
                                                <div className="h-1.5 w-full bg-secondary mt-3 rounded-full overflow-hidden">
                                                    <div className="h-full bg-blue-500 rounded-full" style={{ width: '45%' }} />
                                                </div>
                                            </div>
                                            <div>
                                                <p className="text-sm font-medium text-muted-foreground mb-2">
                                                    Team Members
                                                </p>
                                                <p className="text-xl font-semibold apex-metric-number">3 <span className="text-sm text-muted-foreground font-normal">/ 5</span></p>
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
                                                <p className="font-medium text-sm">Visa ending in 4242</p>
                                                <p className="text-xs text-muted-foreground">
                                                    Expires 12/26
                                                </p>
                                            </div>
                                        </div>
                                        <Button variant="ghost" size="sm" className="min-h-[44px]">
                                            Update
                                        </Button>
                                    </div>
                                </div>

                                <div className="space-y-4">
                                    <h3 className="font-medium">Billing History</h3>
                                    <div className="space-y-2">
                                        {[
                                            { date: 'Dec 15, 2024', amount: '$59.00' },
                                            { date: 'Nov 15, 2024', amount: '$59.00' },
                                            { date: 'Oct 15, 2024', amount: '$59.00' },
                                        ].map((invoice, i) => (
                                            <div
                                                key={i}
                                                className="flex items-center justify-between py-2"
                                            >
                                                <p className="text-sm">{invoice.date}</p>
                                                <div className="flex items-center gap-4">
                                                    <p className="font-medium apex-metric-number">{invoice.amount}</p>
                                                    <Button variant="ghost" size="sm">
                                                        Download
                                                    </Button>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    )}
                </div>
            </div>
        </div>
    );
}
