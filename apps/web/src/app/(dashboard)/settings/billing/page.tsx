'use client';

import Link from 'next/link';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { PlanSelector } from '@/components/billing/PlanSelector';
import { useAPI, getCsrfToken } from '@/hooks/use-api';

interface PlanInfo {
    name: string;
    displayName: string;
    priceMonthly: number;
    status: string;
    features: {
        emailsPerMonth: number;
        dedicatedIpCount: number;
        dedicatedIp: boolean;
    };
}

interface PaymentMethod {
    brand: string;
    last4: string;
    expMonth: number;
    expYear: number;
}

interface BillingInfo {
    plan: PlanInfo;
    paymentMethod: PaymentMethod | null;
    nextInvoiceDate: string | null;
    currentPeriodEnd: string | null;
}

export default function SettingsBillingPage() {
    const { data: billing, isLoading: loading, error: swrError } = useAPI<BillingInfo>('/api/billing');
    const error = swrError ? (swrError instanceof Error ? swrError.message : 'An error occurred') : null;

    if (loading) {
        return (
            <div className="space-y-6">
                <PageHeader
                    title="Billing"
                    description="Review plan details, usage, and payment methods."
                    breadcrumbs={[{ label: 'Settings', href: '/settings' }, { label: 'Billing' }]}
                />
                <div className="text-sm text-muted-foreground">Loading billing information…</div>
            </div>
        );
    }

    if (error || !billing) {
        return (
            <div className="space-y-6">
                <PageHeader
                    title="Billing"
                    description="Review plan details, usage, and payment methods."
                    breadcrumbs={[{ label: 'Settings', href: '/settings' }, { label: 'Billing' }]}
                />
                <Card>
                    <CardContent className="pt-6">
                        <p className="text-sm text-destructive">{error ?? 'Unable to load billing information.'}</p>
                    </CardContent>
                </Card>
            </div>
        );
    }

    const plan = billing.plan;
    const pm = billing.paymentMethod;
    const priceFormatted = plan.priceMonthly > 0
        ? `$${(plan.priceMonthly / 100).toLocaleString()} / month`
        : 'Free';
    const sendsFormatted = plan.features.emailsPerMonth >= 0
        ? plan.features.emailsPerMonth.toLocaleString()
        : 'Unlimited';
    const dedicatedIpLabel = plan.features.dedicatedIp
        ? plan.features.dedicatedIpCount > 0
            ? `${plan.features.dedicatedIpCount} included`
            : 'Available as add-on'
        : 'Not available';
    const nextInvoice = billing.nextInvoiceDate
        ? new Date(billing.nextInvoiceDate).toLocaleDateString('en-US', {
            month: 'long', day: 'numeric', year: 'numeric',
        })
        : null;

    return (
        <div className="space-y-6">
            <PageHeader
                title="Billing"
                description="Review plan details, usage, and payment methods."
                breadcrumbs={[{ label: 'Settings', href: '/settings' }, { label: 'Billing' }]}
                actions={
                    <PlanSelector
                        currentPlan={billing?.plan.name ?? 'free'}
                        trigger={<Button variant="outline">Manage Plan</Button>}
                    />
                }
            />

            <div className="grid gap-6 lg:grid-cols-2">
                <Card>
                    <CardHeader>
                        <CardTitle>Current Plan</CardTitle>
                        <CardDescription>{plan.displayName} · {priceFormatted}</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="flex items-center justify-between">
                            <span className="text-sm text-muted-foreground">Status</span>
                            <Badge variant="secondary">{plan.status}</Badge>
                        </div>
                        <Separator />
                        <div className="space-y-2 text-sm">
                            <div className="flex items-center justify-between">
                                <span>Monthly sends</span>
                                <span className="font-medium">{sendsFormatted}</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span>Deliverability monitoring</span>
                                <span className="font-medium">Included</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span>Dedicated IPs</span>
                                <Link href="/settings/dedicated-ips" className="font-medium text-brand-600 hover:underline">
                                    {dedicatedIpLabel}
                                </Link>
                            </div>
                        </div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader>
                        <CardTitle>Payment Method</CardTitle>
                        <CardDescription>{pm ? 'Primary card on file' : 'No payment method'}</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        {pm ? (
                            <>
                                <div className="flex items-center justify-between">
                                    <div>
                                        <div className="font-medium">{pm.brand} ending {pm.last4}</div>
                                        <div className="text-sm text-muted-foreground">
                                            Expires {String(pm.expMonth).padStart(2, '0')}/{pm.expYear}
                                        </div>
                                    </div>
                                    <Button variant="outline" size="sm" onClick={async () => {
                                        const csrf = await getCsrfToken();
                                        const res = await fetch('/api/billing', {
                                            method: 'POST', credentials: 'include',
                                            headers: { 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
                                            body: JSON.stringify({ action: 'portal' }),
                                        });
                                        const data = await res.json();
                                        if (data.url) {
                                            const u = new URL(data.url);
                                            if (u.hostname.endsWith('.stripe.com')) window.location.href = data.url;
                                        }
                                    }}>Update</Button>
                                </div>
                                <Separator />
                                {nextInvoice && (
                                    <div className="text-sm text-muted-foreground">
                                        Next invoice scheduled for {nextInvoice}.
                                    </div>
                                )}
                            </>
                        ) : (
                            <div className="text-sm text-muted-foreground">
                                Add a payment method to start a paid plan.
                                <div className="mt-2">
                                    <Button variant="outline" size="sm" onClick={async () => {
                                        const csrf = await getCsrfToken();
                                        const res = await fetch('/api/billing', {
                                            method: 'POST', credentials: 'include',
                                            headers: { 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
                                            body: JSON.stringify({ action: 'portal' }),
                                        });
                                        const data = await res.json();
                                        if (data.url) {
                                            const u = new URL(data.url);
                                            if (u.hostname.endsWith('.stripe.com')) window.location.href = data.url;
                                        }
                                    }}>Add Payment Method</Button>
                                </div>
                            </div>
                        )}
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}