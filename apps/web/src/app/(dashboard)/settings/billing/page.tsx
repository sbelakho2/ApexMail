'use client';

import * as React from 'react';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';

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
    const [billing, setBilling] = React.useState<BillingInfo | null>(null);
    const [loading, setLoading] = React.useState(true);
    const [error, setError] = React.useState<string | null>(null);

    React.useEffect(() => {
        async function fetchBilling() {
            try {
                const res = await fetch('/v1/billing');
                if (!res.ok) throw new Error('Failed to load billing info');
                const data: BillingInfo = await res.json();
                setBilling(data);
            } catch (err) {
                setError(err instanceof Error ? err.message : 'An error occurred');
            } finally {
                setLoading(false);
            }
        }
        void fetchBilling();
    }, []);

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
                actions={<Button variant="outline">Manage Plan</Button>}
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
                                <span className="font-medium">{dedicatedIpLabel}</span>
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
                                    <Button variant="outline" size="sm">Update</Button>
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
                                    <Button variant="outline" size="sm">Add Payment Method</Button>
                                </div>
                            </div>
                        )}
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}