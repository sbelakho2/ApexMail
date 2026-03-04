'use client';

import { CheckCircle, Zap } from '@/components/ui/icons';
import Link from 'next/link';
import { cn } from '@/lib/utils';

interface Plan {
 name: string;
 price: string;
 period: string;
 description: string;
 features: string[];
 cta: string;
 ctaLink: string;
 popular?: boolean;
}

const plans: Plan[] = [
 {
 name: 'Free',
 price: '$0',
 period: 'forever',
 description: 'Perfect for development and testing.',
 features: [
 '3,000 emails/month',
 'RESTful API access',
 '1 sending domain',
 '7-day data retention',
 'Community support',
 ],
 cta: 'Start Free',
 ctaLink: 'https://app.apexmail.ee/signup',
 },
 {
 name: 'Starter',
 price: '$25',
 period: '/month',
 description: 'For growing apps with moderate needs.',
 features: [
 '50,000 emails/month',
 'Webhooks & advanced analytics',
 'Custom templates',
 '5 sending domains',
 '5 team members',
 'Email support',
 ],
 cta: 'Start Trial',
 ctaLink: 'https://app.apexmail.ee/signup?plan=starter',
 },
 {
 name: 'Pro',
 price: '$65',
 period: '/month',
 description: 'For scaling teams with A/B testing.',
 features: [
 '150,000 emails/month',
 'A/B testing & send-time AI',
 'Custom tracking domain',
 '25 sending domains',
 '10 team members',
 'Dedicated IP add-on ($30/mo)',
 ],
 cta: 'Start Trial',
 ctaLink: 'https://app.apexmail.ee/signup?plan=pro',
 },
 {
 name: 'Growth',
 price: '$150',
 period: '/month',
 description: 'For teams serious about deliverability.',
 features: [
 '500,000 emails/month',
 '1 dedicated IP included',
 'Audit logs & priority support',
 '100 sending domains',
 '25 team members',
 '90-day data retention',
 ],
 cta: 'Start Trial',
 ctaLink: 'https://app.apexmail.ee/signup?plan=growth',
 popular: true,
 },
 {
 name: 'Scale',
 price: '$350',
 period: '/month',
 description: 'For high-volume enterprise senders.',
 features: [
 '2,000,000 emails/month',
 '3 dedicated IPs',
 'Unlimited domains',
 'SSO/SAML & 10 subaccounts',
 'SLA guarantee (99.9%, 10% credit cap)',
 'Phone support & dedicated CSM',
 ],
 cta: 'Contact Sales',
 ctaLink: '/private-cloud',
 },
];

export function PricingPlans() {
 return (
 <section className="py-20 lg:py-32 bg-white">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 {/* Plans Grid - Clean, minimal, functional */}
 <div className="grid md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4 lg:gap-5">
 {plans.map((plan, index) => (
            <div key={plan.name} className={cn( 'relative flex flex-col p-6 bg-white rounded-lg border transition-all duration-200', plan.popular ? 'border-primary-600 ring-1 ring-primary-600' : 'border-surface-200 hover:border-surface-300' )}>
              {plan.popular && (
                <div className="mb-4">
                  <span className="inline-block px-2 py-0.5 bg-primary-50 text-primary-700 text-xs font-medium rounded border border-primary-100">
                    Most Popular
                  </span>
                </div>
              )}

              <div className="mb-5">
                <h3 className="text-base font-semibold text-surface-900 mb-2">{plan.name}</h3>
                <div className="flex items-baseline gap-1">
                  <span className="text-3xl font-semibold text-surface-900 tabular-nums">{plan.price}</span>
                  <span className="text-sm text-surface-500">{plan.period}</span>
                </div>
                <p className="text-sm text-surface-500 mt-2 leading-relaxed">{plan.description}</p>
              </div>

              <ul className="space-y-2 mb-6 flex-1">
                {plan.features.map((feature) => (
                  <li key={feature} className="flex items-start gap-2 text-sm text-surface-600">
                    <CheckCircle className="w-4 h-4 text-primary-500 flex-shrink-0 mt-0.5" strokeWidth={2} />
                    <span>{feature}</span>
                  </li>
                ))}
              </ul>

              <Link
                href={plan.ctaLink}
                aria-label={`${plan.cta} - ${plan.name} plan at ${plan.price}${plan.period}`}
                className={cn(
                  'block w-full py-2.5 rounded-md text-sm font-medium text-center transition-colors',
                  plan.popular
                    ? 'bg-primary-600 text-white hover:bg-primary-700'
                    : 'bg-surface-100 text-surface-900 hover:bg-surface-200'
                )}
              >
                {plan.cta}
              </Link>
            </div>
          ))}
        </div>

        {/* Pay As You Go - Distinct, honest */}
        <div className="animate-in delay-500 mt-10 rounded-lg border border-amber-200 bg-amber-50/50 overflow-hidden">
          <div className="p-6 lg:p-8 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
            <div className="flex-1">
              <div className="inline-flex items-center gap-1.5 text-amber-700 mb-3">
                <Zap className="w-4 h-4" />
                <span className="text-xs font-semibold">Pay As You Go</span>
              </div>
              <p className="text-surface-600 text-sm mb-4 max-w-lg">
                No monthly commitment. Volume discounts from $0.001 to $0.0003 per email.
              </p>
              <div className="flex flex-wrap gap-2">
                {[
                  { label: '0-10k', price: '$0.001' },
                  { label: '10k-100k', price: '$0.0008' },
                  { label: '100k-1M', price: '$0.0005' },
                  { label: '1M+', price: '$0.0003' },
                ].map((tier) => (
                  <span key={tier.label} className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-white rounded-md border border-amber-200 text-xs">
                    <span className="text-surface-500">{tier.label}:</span>
                    <span className="font-medium text-amber-700">{tier.price}</span>
                  </span>
                ))}
              </div>
            </div>
            <Link
              href="/signup?plan=payg"
              className="shrink-0 px-5 py-2.5 text-sm font-medium bg-amber-500 text-white rounded-md hover:bg-amber-600 transition-colors"
            >
              Get Started
            </Link>
          </div>
        </div>

        {/* Enterprise - Clear, confident */}
        <div className="animate-in delay-500 mt-10 rounded-lg bg-surface-900 overflow-hidden">
          <div className="p-6 lg:p-8 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
            <div className="flex-1">
              <h3 className="text-lg font-semibold text-white mb-2">Enterprise — from $800/mo</h3>
              <p className="text-surface-400 text-sm mb-4 max-w-lg">
                5,000,000+ emails/month, custom SLA, HIPAA/SOC 2 compliance, and dedicated support.
              </p>
              <div className="flex flex-wrap gap-x-4 gap-y-1">
                {['10 dedicated IPs', 'SSO/SAML & SCIM', 'HIPAA & SOC 2', 'White-label & BYOIP', 'Custom SLA (99.9%, 25% credit cap)', 'Dedicated account manager'].map((feature) => (
                  <span key={feature} className="flex items-center gap-1.5 text-sm text-surface-300">
                    <CheckCircle className="w-4 h-4 text-primary-400" strokeWidth={2} />
                    {feature}
                  </span>
                ))}
              </div>
            </div>
            <Link
              href="/private-cloud"
              className="shrink-0 px-5 py-2.5 text-sm font-medium bg-white text-surface-900 rounded-md hover:bg-surface-100 transition-colors"
            >
              Contact Sales
            </Link>
          </div>
        </div>
 </div>
 </section>
 );
}
