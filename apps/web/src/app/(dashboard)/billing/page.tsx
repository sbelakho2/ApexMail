'use client';

import * as React from 'react';
import { CreditCard, Check } from 'lucide-react';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

import { Separator } from '@/components/ui/separator';
import { PlanSelector, PLANS } from '@/components/billing';
import { cn } from '@/lib/utils';

export default function BillingPage() {
    const [currentPlan, setCurrentPlan] = React.useState('free');
    const activePlan = PLANS.find(p => p.name === currentPlan);

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
                            <CardDescription><span className="tabular-nums">{activePlan?.displayName ?? 'Free'} — {activePlan ? `$${(activePlan.priceMonthly / 100).toFixed(0)}/mo` : 'Free'}</span></CardDescription>
                        </div>
                        <PlanSelector currentPlan={currentPlan} onPlanChange={async (p) => setCurrentPlan(p)} />
                    </div>
                </CardHeader>
            </Card>

            {/* Plans comparison */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                {PLANS.filter(p => p.name !== 'payg').map(plan => (
                    <Card key={plan.name} className={cn(plan.name === currentPlan && 'border-primary ring-1 ring-primary')}>
                        <CardContent className="p-6">
                            <h3 className="font-semibold text-lg">{plan.displayName}</h3>
                            <p className="text-2xl font-bold mt-2 tabular-nums">${(plan.priceMonthly / 100).toFixed(0)}<span className="text-sm font-normal text-muted-foreground">/mo</span></p>
                            <p className="text-sm text-muted-foreground mt-1 tabular-nums">{plan.emailLimit.toLocaleString()} emails/mo</p>
                            <Separator className="my-4" />
                            <ul className="space-y-2">
                                {['Email sending', 'Analytics', 'API access', ...(plan.name === 'pro' ? ['Priority support'] : []), ...(plan.name === 'enterprise' ? ['Priority support', 'Dedicated IP', 'SSO/SAML'] : [])].map(f => (
                                    <li key={f} className="flex items-center gap-2 text-sm"><Check className="h-4 w-4 text-success" />{f}</li>
                                ))}
                            </ul>
                            <Button variant={plan.name === currentPlan ? 'outline' : 'default'} className="w-full mt-4" disabled={plan.name === currentPlan} onClick={() => setCurrentPlan(plan.name)}>
                                {plan.name === currentPlan ? 'Current Plan' : 'Upgrade'}
                            </Button>
                        </CardContent>
                    </Card>
                ))}
            </div>

            {/* Payment method */}
            <Card>
                <CardHeader><CardTitle>Payment Method</CardTitle></CardHeader>
                <CardContent>
                    <div className="flex items-center justify-between rounded-lg border p-4">
                        <div className="flex items-center gap-3">
                            <CreditCard className="h-5 w-5 text-muted-foreground" />
                            <div>
                                <p className="font-medium text-sm">No payment method on file</p>
                                <p className="text-xs text-muted-foreground">Add a card to upgrade your plan</p>
                            </div>
                        </div>
                        <Button variant="outline" size="sm">Add Card</Button>
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
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
