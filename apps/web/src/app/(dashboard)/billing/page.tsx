'use client';

import * as React from 'react';
import { CreditCard, Check, Loader2 } from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { PlanSelector, PLANS } from '@/components/billing';
import { cn, getErrorMessage } from '@/lib/utils';
import { useAPI, useAPIMutation, getCsrfToken } from '@/hooks/use-api';
import { useToast } from '@/hooks/use-toast';

interface SubscriptionData {
    subscription: {
        planName: string;
        status: string;
        currentPeriodEnd?: string;
    } | null;
    message?: string;
}

export default function BillingPage() {
    const { data: billing, isLoading, mutate } = useAPI<SubscriptionData>('/api/billing');
    const { toast } = useToast();
    const [checkoutLoading, setCheckoutLoading] = React.useState(false);

    const currentPlan = billing?.subscription?.planName || 'free';
    const activePlan = PLANS.find(p => p.name === currentPlan);

    const handlePlanChange = React.useCallback(async (planName: string) => {
        if (planName === currentPlan) return;

        setCheckoutLoading(true);
        try {
            const csrfToken = await getCsrfToken();

            const res = await fetch('/api/billing', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
                body: JSON.stringify({ action: 'checkout', planName }),
            });

            const data = await res.json();

            if (!res.ok) {
                throw new Error(data.error || 'Failed to start checkout');
            }

            if (data.checkoutUrl) {
                try {
                    const url = new URL(data.checkoutUrl);
                    if (!url.hostname.endsWith('.stripe.com')) throw new Error('Untrusted redirect');
                } catch { throw new Error('Invalid checkout URL'); }
                window.location.href = data.checkoutUrl;
                return;
            }

            // If no checkout URL (e.g. downgrade to free), refresh
            toast({ title: 'Plan updated', description: `Switched to ${planName}` });
            await mutate();
        } catch (err) {
            toast({ title: 'Plan change failed', description: getErrorMessage(err), variant: 'destructive' });
        } finally {
            setCheckoutLoading(false);
        }
    }, [currentPlan, mutate, toast]);

    const handleManageBilling = React.useCallback(async () => {
        try {
            const csrfToken = await getCsrfToken();

            const res = await fetch('/api/billing', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
                },
                body: JSON.stringify({ action: 'portal' }),
            });

            const data = await res.json();

            if (!res.ok) {
                throw new Error(data.error || 'Failed to open billing portal');
            }

            if (data.url) {
                try {
                    const url = new URL(data.url);
                    if (!url.hostname.endsWith('.stripe.com')) throw new Error('Untrusted redirect');
                } catch { throw new Error('Invalid billing portal URL'); }
                window.location.href = data.url;
            }
        } catch (err) {
            toast({ title: 'Error', description: getErrorMessage(err), variant: 'destructive' });
        }
    }, [toast]);

    return (
        <div className="flex flex-col gap-6">
            <PageHeader
                title="Billing"
                description="Manage your subscription, invoices, and payment methods."
                breadcrumbs={[{ label: 'Billing' }]}
            />

            {/* Current Plan */}
            <Card>
                <CardHeader>
                    <div className="flex items-center justify-between">
                        <div>
                            <CardTitle>Current Plan</CardTitle>
                            <CardDescription>
                                {isLoading ? (
                                    <span className="flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin" /> Loading...</span>
                                ) : (
                                    <span className="apex-metric-number">{activePlan?.displayName ?? 'Free'} — {activePlan ? `$${(activePlan.priceMonthly / 100).toFixed(0)}/mo` : 'Free'}</span>
                                )}
                            </CardDescription>
                        </div>
                        <PlanSelector currentPlan={currentPlan} onPlanChange={handlePlanChange} />
                    </div>
                </CardHeader>
            </Card>

            {/* Plans comparison */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                {PLANS.filter(p => !p.isPayg && p.name !== 'enterprise').map(plan => (
                    <Card key={plan.name} className={cn(plan.name === currentPlan && 'border-primary ring-1 ring-primary')}>
                        <CardContent className="p-6">
                            <h3 className="font-semibold text-lg">{plan.displayName}</h3>
                            <p className="text-2xl apex-metric-number mt-2">${(plan.priceMonthly / 100).toFixed(0)}<span className="text-sm font-normal text-muted-foreground">/mo</span></p>
                            <p className="text-sm text-muted-foreground mt-1 apex-metric-number">{plan.emailLimit.toLocaleString()} emails/mo</p>
                            <Separator className="my-4" />
                            <ul className="space-y-2">
                                {['Email sending', 'Analytics', 'API access', ...(plan.name === 'pro' ? ['A/B testing', 'Dedicated IP add-on'] : []), ...(plan.name === 'growth' ? ['Audit logs', 'Priority support'] : []), ...(['scale'].includes(plan.name) ? ['SSO/SAML', 'Dedicated IPs', 'SLA guarantee'] : [])].map(f => (
                                    <li key={f} className="flex items-center gap-2 text-sm"><Check className="h-4 w-4 text-success" />{f}</li>
                                ))}
                            </ul>
                            <Button
                                variant={plan.name === currentPlan ? 'outline' : 'default'}
                                className="w-full mt-4"
                                disabled={plan.name === currentPlan || checkoutLoading}
                                onClick={() => handlePlanChange(plan.name)}
                            >
                                {checkoutLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : plan.name === currentPlan ? 'Current Plan' : 'Upgrade'}
                            </Button>
                        </CardContent>
                    </Card>
                ))}
            </div>

            {/* PAYG Option */}
            {(() => {
                const paygPlan = PLANS.find(p => p.isPayg);
                return paygPlan ? (
                    <Card className={cn(currentPlan === 'payg' && 'border-primary ring-1 ring-primary')}>
                        <CardContent className="p-6">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h3 className="font-semibold text-lg">{paygPlan.displayName}</h3>
                                    <p className="text-sm text-muted-foreground mt-1">No monthly commitment. Pay only for what you send.</p>
                                    <div className="flex flex-wrap gap-2 mt-2">
                                        {paygPlan.features.map(f => (
                                            <span key={f} className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                                                <Check className="h-3 w-3 text-success" />{f}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                                <Button
                                    variant={currentPlan === 'payg' ? 'outline' : 'default'}
                                    disabled={currentPlan === 'payg' || checkoutLoading}
                                    onClick={() => handlePlanChange('payg')}
                                >
                                    {currentPlan === 'payg' ? 'Current Plan' : 'Switch to PAYG'}
                                </Button>
                            </div>
                        </CardContent>
                    </Card>
                ) : null;
            })()}

            {/* Payment method */}
            <Card>
                <CardHeader><CardTitle>Payment Method</CardTitle></CardHeader>
                <CardContent>
                    <div className="flex items-center justify-between rounded-lg border p-4">
                        <div className="flex items-center gap-3">
                            <CreditCard className="h-5 w-5 text-muted-foreground" />
                            <div>
                                <p className="font-medium text-sm">Manage your payment methods</p>
                                <p className="text-xs text-muted-foreground">Add, update, or remove cards via the billing portal</p>
                            </div>
                        </div>
                        <Button variant="outline" size="sm" onClick={handleManageBilling}>
                            Manage Billing
                        </Button>
                    </div>
                </CardContent>
            </Card>

            {/* Invoices */}
            <Card>
                <CardHeader><CardTitle>Billing History</CardTitle><CardDescription>Your recent invoices</CardDescription></CardHeader>
                <CardContent>
                    <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                        <CreditCard className="h-8 w-8 mb-3" />
                        <p className="text-sm">No invoices yet</p>
                        <p className="text-sm mt-1">Invoices will appear here after your first billing cycle.</p>
                        <Button variant="link" size="sm" className="mt-2" onClick={handleManageBilling}>
                            View all invoices in billing portal
                        </Button>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
