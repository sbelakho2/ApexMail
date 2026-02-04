'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { CheckCircle, Zap } from 'lucide-react';
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
 '1,000 emails/month',
 'RESTful API access',
 '1 sending domain',
 '7-day data retention',
 'Community support',
 ],
 cta: 'Start Free',
 ctaLink: '/signup',
 },
 {
 name: 'Starter',
 price: '$29',
 period: '/month',
 description: 'For growing apps with moderate needs.',
 features: [
 '25,000 emails/month',
 'Webhooks & advanced analytics',
 'Custom templates',
 '3 sending domains',
 '3 team members',
 'Email support',
 ],
 cta: 'Start Trial',
 ctaLink: '/signup?plan=starter',
 },
 {
 name: 'Pro',
 price: '$59',
 period: '/month',
 description: 'For scaling teams needing custom tracking.',
 features: [
 '50,000 emails/month',
 'Custom tracking domain',
 '60-day data retention',
 '5 sending domains',
 '5 team members',
 'Priority onboarding',
 ],
 cta: 'Start Trial',
 ctaLink: '/signup?plan=pro',
 },
 {
 name: 'Growth',
 price: '$129',
 period: '/month',
 description: 'For teams serious about deliverability.',
 features: [
 '100,000 emails/month',
 '1 dedicated IP',
 'A/B testing & time-travel debug',
 '10 sending domains',
 '10 team members',
 'Audit logs',
 'Priority support',
 ],
 cta: 'Start Trial',
 ctaLink: '/signup?plan=growth',
 popular: true,
 },
 {
 name: 'Scale',
 price: '$399',
 period: '/month',
 description: 'For high-volume enterprise senders.',
 features: [
 '500,000 emails/month',
 '3 dedicated IPs',
 'Unlimited domains',
 'SSO/SAML & 10 subaccounts',
 'SLA guarantee (10% credit)',
 'Phone support & dedicated CSM',
 ],
 cta: 'Contact Sales',
 ctaLink: '/contact/sales',
 },
];

export function PricingPlans() {
 const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

 return (
 <section ref={ref} className="py-16 lg:py-24 bg-white">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 {/* Plans Grid - Clean, minimal, functional */}
 <div className="grid md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4 lg:gap-5">
 {plans.map((plan, index) => (
            <motion.div
              key={plan.name}
              initial={{ opacity: 0, y: 16 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ delay: index * 0.08, duration: 0.4 }}
              className={cn(
                'relative flex flex-col p-6 bg-white rounded-xl border transition-all duration-200',
                plan.popular 
                  ? 'border-primary-600 ring-1 ring-primary-600' 
                  : 'border-surface-200 hover:border-surface-300'
              )}
            >
              {plan.popular && (
                <div className="mb-4">
                  <span className="inline-block px-2 py-0.5 bg-primary-50 text-primary-700 text-[11px] font-medium uppercase tracking-wide rounded border border-primary-100">
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
                  'block w-full py-2.5 rounded-lg text-sm font-medium text-center transition-colors',
                  plan.popular
                    ? 'bg-primary-600 text-white hover:bg-primary-700'
                    : 'bg-surface-100 text-surface-900 hover:bg-surface-200'
                )}
              >
                {plan.cta}
              </Link>
            </motion.div>
          ))}
        </div>

        {/* Pay As You Go - Distinct, honest */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.5, duration: 0.4 }}
          className="mt-10 rounded-xl border border-amber-200 bg-amber-50/50 overflow-hidden"
        >
          <div className="p-6 lg:p-8 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
            <div className="flex-1">
              <div className="inline-flex items-center gap-1.5 text-amber-700 mb-3">
                <Zap className="w-4 h-4" />
                <span className="text-xs font-semibold uppercase tracking-wide">Pay As You Go</span>
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
              className="shrink-0 px-5 py-2.5 text-sm font-medium bg-amber-500 text-white rounded-lg hover:bg-amber-600 transition-colors"
            >
              Get Started
            </Link>
          </div>
        </motion.div>

        {/* Enterprise - Clear, confident */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.6, duration: 0.4 }}
          className="mt-10 rounded-xl bg-surface-900 overflow-hidden"
        >
          <div className="p-6 lg:p-8 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
            <div className="flex-1">
              <h3 className="text-lg font-semibold text-white mb-2">Enterprise</h3>
              <p className="text-surface-400 text-sm mb-4 max-w-lg">
                Private cloud, custom SLA, HIPAA/SOC2 compliance, and dedicated support.
              </p>
              <div className="flex flex-wrap gap-x-4 gap-y-1">
                {['Dedicated infrastructure', 'Custom integrations', 'Priority support'].map((feature) => (
                  <span key={feature} className="flex items-center gap-1.5 text-sm text-surface-300">
                    <CheckCircle className="w-3.5 h-3.5 text-primary-400" strokeWidth={2} />
                    {feature}
                  </span>
                ))}
              </div>
            </div>
            <Link
              href="/contact/enterprise"
              className="shrink-0 px-5 py-2.5 text-sm font-medium bg-white text-surface-900 rounded-lg hover:bg-surface-100 transition-colors"
            >
              Contact Sales
            </Link>
          </div>
        </motion.div>
 </div>
 </section>
 );
}
