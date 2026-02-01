'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { CheckCircle } from 'lucide-react';
import Link from 'next/link';

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
    description: 'Perfect for getting started and testing the API.',
    features: [
      '10,000 emails/month',
      'RESTful API access',
      'Basic analytics',
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
    description: 'For growing businesses with moderate email needs.',
    features: [
      '100,000 emails/month',
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
    name: 'Pro',
    price: '$99',
    period: '/month',
    description: 'For companies serious about email deliverability.',
    features: [
      '500,000 emails/month',
      'Everything in Starter',
      'Dedicated IP',
      'Time-travel debugging',
      '10 sending domains',
      'Priority support',
      'Custom DKIM',
      'A/B testing',
    ],
    cta: 'Start Trial',
    ctaLink: '/signup?plan=pro',
    popular: true,
  },
  {
    name: 'Business',
    price: '$199',
    period: '/month',
    description: 'For high-volume senders who need more power.',
    features: [
      '1,000,000 emails/month',
      'Everything in Pro',
      'Multiple dedicated IPs',
      'Unlimited domains',
      'Phone support',
      'Custom integrations',
      'SLA guarantee',
      'Dedicated CSM',
    ],
    cta: 'Contact Sales',
    ctaLink: '/contact/sales',
  },
];

export function PricingPlans() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-12 lg:py-20 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          {plans.map((plan, index) => (
            <motion.div
              key={plan.name}
              initial={{ opacity: 0, y: 20 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ delay: index * 0.1 }}
              className={`glass-card p-6 relative ${
                plan.popular ? 'border-primary-500/50 ring-1 ring-primary-500/20' : ''
              }`}
            >
              {plan.popular && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 bg-primary-600 text-white text-xs font-medium rounded-full">
                  Most Popular
                </div>
              )}

              <div className="text-center mb-6">
                <h3 className="text-xl font-semibold text-white mb-2">{plan.name}</h3>
                <div className="flex items-baseline justify-center gap-1">
                  <span className="text-4xl font-bold text-white">{plan.price}</span>
                  <span className="text-surface-400">{plan.period}</span>
                </div>
                <p className="text-sm text-surface-400 mt-2">{plan.description}</p>
              </div>

              <ul className="space-y-3 mb-6">
                {plan.features.map((feature) => (
                  <li key={feature} className="flex items-start gap-2 text-sm text-surface-300">
                    <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                    {feature}
                  </li>
                ))}
              </ul>

              <Link
                href={plan.ctaLink}
                className={`block w-full py-3 rounded-lg font-medium text-center transition-colors ${
                  plan.popular
                    ? 'bg-primary-600 text-white hover:bg-primary-500'
                    : 'bg-surface-800 text-white hover:bg-surface-700'
                }`}
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
          className="mt-12 glass-card p-8"
        >
          <div className="grid lg:grid-cols-2 gap-8 items-center">
            <div>
              <h3 className="text-2xl font-bold text-white mb-2">Enterprise</h3>
              <p className="text-surface-400 mb-4">
                Custom solutions for organizations with unique requirements. 
                Private cloud, custom SLAs, dedicated support, and more.
              </p>
              <ul className="grid grid-cols-2 gap-2">
                {[
                  'Private cloud deployment',
                  'Custom SLA (99.99%+)',
                  'Dedicated account team',
                  'Custom integrations',
                  'HIPAA/SOC2 compliance',
                  'Priority feature requests',
                ].map((feature) => (
                  <li key={feature} className="flex items-center gap-2 text-sm text-surface-300">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    {feature}
                  </li>
                ))}
              </ul>
            </div>
            <div className="text-center lg:text-right">
              <div className="text-surface-400 mb-2">Starting at</div>
              <div className="text-4xl font-bold text-white mb-4">Custom</div>
              <Link
                href="/contact/enterprise"
                className="inline-flex items-center justify-center px-8 py-3 bg-primary-600 text-white font-medium rounded-lg hover:bg-primary-500 transition-colors"
              >
                Contact Sales
              </Link>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
