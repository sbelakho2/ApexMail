'use client';

import { useState } from 'react';
import { CheckCircle, Zap, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';

export interface Plan {
  id: string;
  name: string;
  displayName: string;
  priceMonthly: number; // In cents
  priceYearly: number;
  emailLimit: number;
  features: string[];
  popular?: boolean;
  isPayg?: boolean;
}

const PLANS: Plan[] = [
  {
    id: 'free',
    name: 'free',
    displayName: 'Free',
    priceMonthly: 0,
    priceYearly: 0,
    emailLimit: 1000,
    features: [
      '1,000 emails/month',
      'RESTful API access',
      '1 sending domain',
      '7-day retention',
    ],
  },
  {
    id: 'starter',
    name: 'starter',
    displayName: 'Starter',
    priceMonthly: 2900,
    priceYearly: 29000,
    emailLimit: 25000,
    features: [
      '25,000 emails/month',
      'Webhooks & analytics',
      '3 sending domains',
      '3 team members',
    ],
  },
  {
    id: 'pro',
    name: 'pro',
    displayName: 'Pro',
    priceMonthly: 4900,
    priceYearly: 49000,
    emailLimit: 50000,
    features: [
      '50,000 emails/month',
      'Custom tracking domain',
      '60-day retention',
      '5 team members',
    ],
  },
  {
    id: 'growth',
    name: 'growth',
    displayName: 'Growth',
    priceMonthly: 9900,
    priceYearly: 99000,
    emailLimit: 100000,
    features: [
      '100,000 emails/month',
      '1 dedicated IP',
      'A/B testing & audit logs',
      'Priority support',
    ],
    popular: true,
  },
  {
    id: 'scale',
    name: 'scale',
    displayName: 'Scale',
    priceMonthly: 29900,
    priceYearly: 299000,
    emailLimit: 500000,
    features: [
      '500,000 emails/month',
      '3 dedicated IPs',
      'SSO/SAML & SLA (10%)',
      'Phone + dedicated CSM',
    ],
  },
  {
    id: 'payg',
    name: 'payg',
    displayName: 'Pay As You Go',
    priceMonthly: 0,
    priceYearly: 0,
    emailLimit: -1, // Unlimited
    features: [
      'No monthly commitment',
      '$0.001-$0.0003/email',
      'Volume discounts',
      '100k free API calls/mo',
    ],
    isPayg: true,
  },
];

interface PlanSelectorProps {
  currentPlan: string;
  onPlanChange?: (planId: string) => Promise<void>;
  trigger?: React.ReactNode;
}

export function PlanSelector({ currentPlan, onPlanChange, trigger }: PlanSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [billingPeriod, setBillingPeriod] = useState<'monthly' | 'yearly'>('monthly');
  const [isLoading, setIsLoading] = useState<string | null>(null);

  const handlePlanSelect = async (planId: string) => {
    if (planId === currentPlan || !onPlanChange) return;
    
    setIsLoading(planId);
    try {
      await onPlanChange(planId);
      setIsOpen(false);
    } catch (error) {
      console.error('Failed to change plan:', error);
    } finally {
      setIsLoading(null);
    }
  };

  const formatPrice = (cents: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 0,
    }).format(cents / 100);
  };

  const currentPlanData = PLANS.find(p => p.name === currentPlan);

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        {trigger || <Button variant="outline">Change Plan</Button>}
      </DialogTrigger>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto p-0">
        <DialogHeader className="p-6 pb-0">
          <DialogTitle className="text-xl font-semibold tracking-tight">Choose Your Plan</DialogTitle>
          <DialogDescription className="text-sm">
            {currentPlanData ? (
              <>Currently on <strong className="font-medium text-foreground">{currentPlanData.displayName}</strong></>
            ) : (
              'Select a plan that fits your needs'
            )}
          </DialogDescription>
        </DialogHeader>

        {/* Billing Toggle - Minimal, clear */}
        <div className="flex items-center justify-center gap-1 px-6 py-4 border-b bg-muted/30">
          <button
            onClick={() => setBillingPeriod('monthly')}
            className={cn(
              'px-4 py-2 text-sm font-medium rounded-md transition-colors',
              billingPeriod === 'monthly'
                ? 'bg-background text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            Monthly
          </button>
          <button
            onClick={() => setBillingPeriod('yearly')}
            className={cn(
              'px-4 py-2 text-sm font-medium rounded-md transition-colors flex items-center gap-2',
              billingPeriod === 'yearly'
                ? 'bg-background text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            Yearly
            <span className="text-xs text-green-600 font-semibold">-17%</span>
          </button>
        </div>

        {/* Plans Grid - Clean, functional */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4 p-6">
          {PLANS.filter(p => !p.isPayg).map((plan) => {
            const price = billingPeriod === 'monthly' ? plan.priceMonthly : plan.priceYearly / 12;
            const isCurrent = plan.name === currentPlan;
            const isUpgrade = currentPlanData && plan.priceMonthly > currentPlanData.priceMonthly;

            return (
              <div
                key={plan.id}
                className={cn(
                  'relative rounded-lg border p-5 transition-all duration-200',
                  plan.popular && 'border-primary shadow-sm',
                  isCurrent && 'bg-muted/50 border-muted-foreground/20',
                  !isCurrent && !plan.popular && 'hover:border-muted-foreground/40'
                )}
              >
                {plan.popular && (
                  <div className="absolute -top-2.5 left-4 px-2 py-0.5 bg-primary text-primary-foreground text-[10px] font-semibold uppercase tracking-wider rounded">
                    Popular
                  </div>
                )}

                <div className="mb-4">
                  <h3 className="font-medium text-base">{plan.displayName}</h3>
                  <div className="mt-1 flex items-baseline gap-1">
                    <span className="text-2xl font-semibold tabular-nums">
                      {plan.priceMonthly === 0 ? '$0' : formatPrice(price)}
                    </span>
                    <span className="text-muted-foreground text-sm">/mo</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">
                    {plan.emailLimit.toLocaleString()} emails
                  </p>
                </div>

                <ul className="space-y-1.5 mb-5 text-sm">
                  {plan.features.map((feature) => (
                    <li key={feature} className="flex items-start gap-2 text-muted-foreground">
                      <CheckCircle className="w-3.5 h-3.5 text-primary flex-shrink-0 mt-0.5" strokeWidth={2} />
                      <span>{feature}</span>
                    </li>
                  ))}
                </ul>

                <Button
                  size="sm"
                  className="w-full"
                  variant={isCurrent ? 'secondary' : plan.popular ? 'default' : 'outline'}
                  disabled={isCurrent || isLoading !== null}
                  onClick={() => handlePlanSelect(plan.name)}
                >
                  {isLoading === plan.name ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : isCurrent ? (
                    'Current'
                  ) : isUpgrade ? (
                    'Upgrade'
                  ) : (
                    'Select'
                  )}
                </Button>
              </div>
            );
          })}
        </div>

        {/* Pay As You Go - Distinct but integrated */}
        <div className="mx-6 mb-6 rounded-lg border border-amber-200/80 bg-amber-50/50 p-5">
          <div className="flex flex-col sm:flex-row sm:items-center gap-4">
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <Zap className="w-4 h-4 text-amber-600" />
                <h3 className="font-medium">Pay As You Go</h3>
              </div>
              <p className="text-sm text-muted-foreground mb-3">
                No commitment. Volume discounts from $0.001 to $0.0003/email.
              </p>
              <div className="flex flex-wrap gap-2">
                {[
                  { range: '0-10k', rate: '$0.001' },
                  { range: '10k-100k', rate: '$0.0008' },
                  { range: '100k-1M', rate: '$0.0005' },
                  { range: '1M+', rate: '$0.0003' },
                ].map((tier) => (
                  <span key={tier.range} className="inline-flex items-center gap-1 px-2 py-1 bg-white rounded text-xs border border-amber-200/60">
                    <span className="text-muted-foreground">{tier.range}:</span>
                    <span className="font-medium text-amber-700">{tier.rate}</span>
                  </span>
                ))}
              </div>
            </div>
            <Button
              size="sm"
              variant={currentPlan === 'payg' ? 'secondary' : 'outline'}
              disabled={currentPlan === 'payg' || isLoading !== null}
              onClick={() => handlePlanSelect('payg')}
              className="shrink-0"
            >
              {isLoading === 'payg' ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : currentPlan === 'payg' ? (
                'Current'
              ) : (
                'Switch'
              )}
            </Button>
          </div>
        </div>

        {/* Enterprise - Simple, clear */}
        <div className="px-6 pb-6 pt-2 border-t">
          <p className="text-sm text-muted-foreground text-center">
            Need custom infrastructure? <a href="/contact/enterprise" className="text-primary font-medium hover:underline">Contact Enterprise Sales</a>
          </p>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export { PLANS };
