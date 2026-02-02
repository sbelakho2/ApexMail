'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { CheckCircle } from 'lucide-react';
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
 description: 'Perfect for development and personal projects.',
 features: [
 '1,000 emails/month',
 'RESTful API access',
 'Standard analytics',
 'Community support',
 'Single sending domain',
 'Standard templates',
 ],
 cta: 'Start Free',
 ctaLink: '/signup',
 },
 {
 name: 'Starter',
 price: '$29',
 period: '/month',
 description: 'For growing apps with moderate email needs.',
 features: [
 '25,000 emails/month',
 'Everything in Free',
 'Custom templates',
 'Webhooks',
 '3 sending domains',
 'Email support',
 'Advanced analytics',
 ],
 cta: 'Start Trial',
 ctaLink: '/signup?plan=starter',
 },
 {
 name: 'Growth',
 price: '$99',
 period: '/month',
 description: 'For companies serious about deliverability.',
 features: [
 '100,000 emails/month',
 'Everything in Starter',
 'Dedicated IP',
 'Time-travel debugging',
 '10 sending domains',
 'Priority support',
 'Custom DKIM',
 'A/B testing',
 ],
 cta: 'Start Trial',
 ctaLink: '/signup?plan=growth',
 popular: true,
 },
 {
 name: 'Scale',
 price: '$299',
 period: '/month',
 description: 'For high-volume senders needing isolation.',
 features: [
 '500,000 emails/month',
 'Everything in Growth',
 'Multiple dedicated IPs',
 'Unlimited domains',
 'Phone support',
 'SLA guarantee',
 'SSO/SAML included',
 'Dedicated CSM',
 ],
 cta: 'Contact Sales',
 ctaLink: '/contact/sales',
 },
];

export function PricingPlans() {
 const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

 return (
 <section ref={ref} className="py-12 lg:py-20 relative bg-white">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
 {plans.map((plan, index) => (
            <motion.div
              key={plan.name}
              initial={{ opacity: 0, y: 20 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ delay: index * 0.1 }}
              className={cn(
                'premium-card p-10 bg-white relative flex flex-col group hover:-translate-y-2 transition-all duration-300',
                plan.popular && 'ring-2 ring-primary-500 z-10 shadow-2xl shadow-primary-500/10'
              )}
            >
              {plan.popular && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-4 py-1.5 bg-primary-600 text-white text-[11px] font-bold uppercase tracking-widest rounded-md shadow-lg shadow-primary-600/30">
                  Recommended
                </div>
              )}

              <div className="text-center mb-10">
                <h3 className="text-[13px] font-bold text-surface-400 uppercase tracking-[0.2em] mb-4">{plan.name}</h3>
                <div className="flex items-baseline justify-center gap-1">
                  <span className="text-5xl font-bold text-surface-900 tabular-nums tracking-tighter">{plan.price}</span>
                  <span className="text-[11px] font-bold text-surface-400 uppercase tracking-widest">{plan.period}</span>
                </div>
                <p className="text-[14px] font-medium text-surface-500 mt-6 leading-relaxed h-12">{plan.description}</p>
              </div>

              <div className="h-px w-full bg-surface-100 mb-8" />

              <ul className="space-y-4 mb-10 flex-1">
                {plan.features.map((feature) => (
                  <li key={feature} className="flex items-start gap-3 text-[14px] text-surface-700 font-medium group-hover:text-surface-900 transition-colors">
                    <CheckCircle className="w-4 h-4 text-primary-500 flex-shrink-0 mt-0.5" strokeWidth={2.5} />
                    {feature}
                  </li>
                ))}
              </ul>

              <Link
                href={plan.ctaLink}
                className={cn(
                  'block w-full py-4 rounded-xl font-bold text-[14px] text-center transition-all shadow-sm active:scale-[0.98]',
                  plan.popular
                    ? 'bg-primary-600 text-white hover:bg-primary-700 shadow-lg shadow-primary-600/20'
                    : 'bg-white text-surface-900 border border-surface-200 hover:border-surface-300 hover:bg-surface-50'
                )}
              >
                {plan.cta}
              </Link>
            </motion.div>
          ))}
        </div>

        {/* Enterprise */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.5 }}
          className="mt-20 premium-card p-1 bg-surface-900 overflow-hidden border-surface-800"
        >
          <div className="p-10 lg:p-14 flex flex-col lg:flex-row items-center justify-between gap-12 bg-gradient-to-br from-surface-900 via-surface-900 to-surface-800">
            <div className="flex-1">
              <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-md bg-primary-500/10 text-primary-400 border border-primary-500/20 text-[11px] font-bold uppercase tracking-widest mb-8">
                Enterprise Infrastructure
              </div>
              <h3 className="text-3xl md:text-4xl font-bold text-white mb-6 tracking-tight leading-tight">Scale Without Compromise</h3>
              <p className="text-surface-400 text-lg font-medium mb-10 leading-relaxed max-w-2xl">
                Dedicated infrastructure for organizations with mission-critical email requirements. 
                Private clouds, extreme isolation, and white-glove support.
              </p>
              <div className="grid sm:grid-cols-2 gap-x-12 gap-y-5">
                {[
                  'Private cloud deployment',
                  'Custom SLA (99.99%+)',
                  'Dedicated account team',
                  'Custom integrations',
                  'HIPAA/SOC2 compliance',
                  'Priority feature requests',
                ].map((feature) => (
                  <div key={feature} className="flex items-center gap-3 text-[15px] text-surface-300 font-semibold group">
                    <CheckCircle className="w-5 h-5 text-primary-400 flex-shrink-0 group-hover:scale-110 transition-transform" strokeWidth={2.5} />
                    {feature}
                  </div>
                ))}
              </div>
            </div>
            <div className="w-full lg:w-[400px] text-center bg-white/5 backdrop-blur-sm p-10 rounded-2xl border border-white/10 shadow-2xl">
              <div className="text-[12px] font-bold text-surface-500 uppercase tracking-widest mb-3">Custom pricing</div>
              <div className="text-6xl font-bold text-white mb-10 tracking-tighter tabular-nums">Tailored</div>
              <Link
                href="/contact/enterprise"
                className="block w-full py-5 text-[16px] font-bold bg-white text-surface-900 rounded-xl hover:bg-surface-50 transition-all shadow-xl active:scale-[0.98]"
              >
                Request Access
              </Link>
              <p className="mt-6 text-[11px] text-surface-500 font-medium">Talk to an infrastructure expert today.</p>
            </div>
          </div>
        </motion.div>
 </div>
 </section>
 );
}
