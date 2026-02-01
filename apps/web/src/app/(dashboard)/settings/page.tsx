'use client';

import * as React from 'react';
import {
    Settings,
    User,
    Bell,
    Shield,
    CreditCard,
    Key,
    Globe,
    Palette,
    Mail,
    Webhook,
    Building2,
    Save,
} from 'lucide-react';
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { cn } from '@/lib/utils';

const settingsSections = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'account', label: 'Account', icon: Building2 },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'email', label: 'Email Settings', icon: Mail },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'api', label: 'API & Webhooks', icon: Webhook },
    { id: 'billing', label: 'Billing', icon: CreditCard },
];

export default function SettingsPage() {
    const [activeSection, setActiveSection] = React.useState('profile');

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
                                        <Input id="firstName" defaultValue="John" />
                                    </div>
                                    <div className="grid gap-2">
                                        <Label htmlFor="lastName">Last Name</Label>
                                        <Input id="lastName" defaultValue="Doe" />
                                    </div>
                                    <div className="grid gap-2 sm:col-span-2">
                                        <Label htmlFor="email">Email Address</Label>
                                        <Input id="email" type="email" defaultValue="john@example.com" />
                                    </div>
                                    <div className="grid gap-2 sm:col-span-2">
                                        <Label htmlFor="bio">Bio</Label>
                                        <Textarea
                                            id="bio"
                                            placeholder="Tell us about yourself..."
                                            rows={3}
                                        />
                                    </div>
                                </div>

                                <div className="flex justify-end">
                                    <Button>
                                        <Save className="mr-2 h-4 w-4" />
                                        Save Changes
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
                                        <Input id="orgName" defaultValue="Acme Inc" />
                                    </div>
                                    <div className="grid gap-2">
                                        <Label htmlFor="timezone">Timezone</Label>
                                        <Select defaultValue="utc-8">
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
                                        <Select defaultValue="en">
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
                                    <Button variant="destructive" size="sm" className="mt-4">
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
                                        <Input id="fromName" defaultValue="Acme Inc" />
                                    </div>
                                    <div className="grid gap-2">
                                        <Label htmlFor="fromEmail">Default From Email</Label>
                                        <Input
                                            id="fromEmail"
                                            type="email"
                                            defaultValue="hello@acme.com"
                                        />
                                    </div>
                                    <div className="grid gap-2 sm:col-span-2">
                                        <Label htmlFor="replyTo">Default Reply-To Email</Label>
                                        <Input
                                            id="replyTo"
                                            type="email"
                                            defaultValue="support@acme.com"
                                        />
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
                                        />
                                        <p className="text-xs text-muted-foreground">
                                            Required by CAN-SPAM act for commercial emails
                                        </p>
                                    </div>
                                </div>

                                <div className="flex justify-end">
                                    <Button>
                                        <Save className="mr-2 h-4 w-4" />
                                        Save Changes
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
                                            <div className="flex gap-2">
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
                                    <p className="text-sm text-muted-foreground">
                                        Configure endpoints to receive real-time notifications.
                                    </p>
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
                                <div className="rounded-lg border p-6">
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <p className="text-sm text-muted-foreground">
                                                Current Plan
                                            </p>
                                            <p className="text-2xl font-bold">Pro Plan</p>
                                            <p className="text-sm text-muted-foreground">
                                                $49/month • Renews on Jan 15, 2025
                                            </p>
                                        </div>
                                        <Button variant="outline">Change Plan</Button>
                                    </div>
                                    <Separator className="my-4" />
                                    <div className="grid gap-4 sm:grid-cols-3">
                                        <div>
                                            <p className="text-sm text-muted-foreground">
                                                Subscribers
                                            </p>
                                            <p className="text-lg font-semibold">
                                                48,293 / 100,000
                                            </p>
                                        </div>
                                        <div>
                                            <p className="text-sm text-muted-foreground">
                                                Emails Sent
                                            </p>
                                            <p className="text-lg font-semibold">
                                                234,567 / 500,000
                                            </p>
                                        </div>
                                        <div>
                                            <p className="text-sm text-muted-foreground">
                                                Team Members
                                            </p>
                                            <p className="text-lg font-semibold">5 / 10</p>
                                        </div>
                                    </div>
                                </div>

                                <div className="space-y-4">
                                    <h3 className="font-medium">Payment Method</h3>
                                    <div className="flex items-center justify-between rounded-lg border p-4">
                                        <div className="flex items-center gap-3">
                                            <div className="rounded bg-muted p-2">
                                                <CreditCard className="h-4 w-4" />
                                            </div>
                                            <div>
                                                <p className="font-medium">•••• •••• •••• 4242</p>
                                                <p className="text-sm text-muted-foreground">
                                                    Expires 12/26
                                                </p>
                                            </div>
                                        </div>
                                        <Button variant="outline" size="sm">
                                            Update
                                        </Button>
                                    </div>
                                </div>

                                <div className="space-y-4">
                                    <h3 className="font-medium">Billing History</h3>
                                    <div className="space-y-2">
                                        {[
                                            { date: 'Dec 15, 2024', amount: '$49.00' },
                                            { date: 'Nov 15, 2024', amount: '$49.00' },
                                            { date: 'Oct 15, 2024', amount: '$49.00' },
                                        ].map((invoice, i) => (
                                            <div
                                                key={i}
                                                className="flex items-center justify-between py-2"
                                            >
                                                <p className="text-sm">{invoice.date}</p>
                                                <div className="flex items-center gap-4">
                                                    <p className="font-medium">{invoice.amount}</p>
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
