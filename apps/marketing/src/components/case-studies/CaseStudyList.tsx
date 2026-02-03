'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Mail, TrendingUp, Shield, Clock, Building2, Users } from 'lucide-react';
import { cn } from '@/lib/utils';

const caseStudies = [
  {
    slug: 'fintech-startup',
    company: 'FinanceFlow',
    industry: 'FinTech',
    logo: '/logos/financeflow.svg',
    title: 'How FinanceFlow Achieved 99.9% Email Delivery for Payment Notifications',
    summary:
      'A fast-growing payment platform needed bulletproof transactional email delivery for critical payment notifications while meeting strict financial compliance requirements.',
    stats: [
      { value: '99.9%', label: 'Delivery Rate', icon: Mail },
      { value: '50M+', label: 'Emails/Month', icon: TrendingUp },
      { value: '<2s', label: 'Avg. Delivery', icon: Clock },
      { value: '100%', label: 'PCI Compliant', icon: Shield },
    ],
    challenge:
      'Payment notifications require 100% reliability. Any delay or failure can result in customer complaints and regulatory issues.',
    solution:
      'ApexMail\'s dedicated IP pool with automatic reputation monitoring ensured consistent delivery. The GDPR automation tools simplified compliance.',
    results: [
      'Reduced bounce rate from 3.2% to 0.1%',
      'Cut time-to-delivery from 15s to under 2s',
      'Automated GDPR compliance for EU customers',
      'Saved $15,000/month vs previous provider',
    ],
    quote: {
      text: 'ApexMail gave us the reliability we needed for payment notifications. Our customers now receive instant confirmation, and we sleep better at night.',
      author: 'Sarah Chen',
      role: 'CTO, FinanceFlow',
    },
    color: 'bg-blue-600',
    iconColor: 'text-blue-600',
    bgLight: 'bg-blue-50',
  },
  {
    slug: 'healthcare-saas',
    company: 'MedConnect',
    industry: 'Healthcare',
    logo: '/logos/medconnect.svg',
    title: 'MedConnect Scales HIPAA-Compliant Email to 100+ Healthcare Providers',
    summary:
      'A healthcare SaaS platform needed to send appointment reminders and lab results while maintaining strict HIPAA compliance across multiple healthcare providers.',
    stats: [
      { value: '100+', label: 'Healthcare Providers', icon: Building2 },
      { value: '2M+', label: 'Patients Reached', icon: Users },
      { value: 'HIPAA', label: 'Compliant', icon: Shield },
      { value: '45%', label: 'Cost Reduction', icon: TrendingUp },
    ],
    challenge:
      'Healthcare email requires HIPAA BAA, encrypted PHI handling, and complete audit trails. Most email providers don\'t offer this.',
    solution:
      'ApexMail\'s HIPAA-ready infrastructure with BAA, encrypted storage, and comprehensive audit logging met all compliance requirements.',
    results: [
      'Deployed to 100+ healthcare providers in 3 months',
      '45% reduction in email infrastructure costs',
      'Zero HIPAA violations in 18 months',
      'Complete audit trail for all communications',
    ],
    quote: {
      text: 'Finding an email provider that truly understands healthcare compliance was a game-changer. ApexMail\'s HIPAA features are built-in, not bolted on.',
      author: 'Dr. Michael Torres',
      role: 'VP of Engineering, MedConnect',
    },
    color: 'bg-emerald-600',
    iconColor: 'text-emerald-600',
    bgLight: 'bg-emerald-50',
  },
  {
    slug: 'ecommerce-platform',
    company: 'ShopScale',
    industry: 'E-Commerce',
    logo: '/logos/shopscale.svg',
    title: 'ShopScale Increases Order Confirmation Open Rates by 34% with AI',
    summary:
      'A multi-brand e-commerce platform wanted to optimize email delivery timing and improve engagement across their order lifecycle emails.',
    stats: [
      { value: '34%', label: 'Open Rate Increase', icon: TrendingUp },
      { value: '12M', label: 'Orders/Month', icon: Mail },
      { value: '25+', label: 'Brands Managed', icon: Building2 },
      { value: '1.1s', label: 'Delivery Time', icon: Clock },
    ],
    challenge:
      'Managing email for 25+ brands with different audiences meant generic send times weren\'t optimal. Each brand needed personalized optimization.',
    solution:
      'ApexMail\'s ML-powered Send-Time Optimization analyzed engagement patterns per brand and automatically scheduled emails for peak engagement windows.',
    results: [
      '34% increase in order confirmation open rates',
      '22% increase in review request click-through',
      'Unified analytics across all 25+ brands',
      'White-label setup for each brand in under 1 hour',
    ],
    quote: {
      text: 'The AI send-time optimization paid for itself in the first month. Our customers engage more because they receive emails when they\'re actually checking their inbox.',
      author: 'Jessica Park',
      role: 'Head of Growth, ShopScale',
    },
    color: 'bg-purple-600',
    iconColor: 'text-purple-600',
    bgLight: 'bg-purple-50',
  },
  {
    slug: 'developer-tools',
    company: 'DevPipeline',
    industry: 'Developer Tools',
    logo: '/logos/devpipeline.svg',
    title: 'DevPipeline Self-Hosts ApexMail for Complete Data Sovereignty',
    summary:
      'A CI/CD platform for enterprise clients needed complete control over their email infrastructure to meet Fortune 500 security requirements.',
    stats: [
      { value: '$0', label: 'Per-Email Cost', icon: TrendingUp },
      { value: '100%', label: 'Data Sovereignty', icon: Shield },
      { value: '5M+', label: 'Build Notifications', icon: Mail },
      { value: '<1s', label: 'Notification Latency', icon: Clock },
    ],
    challenge:
      'Fortune 500 clients demanded that no email data leave their private cloud environment. SaaS email providers were not an option.',
    solution:
      'ApexMail\'s self-hosted deployment with Docker Compose gave DevPipeline complete control. Zero per-email costs meant predictable budgeting.',
    results: [
      'Won 3 Fortune 500 contracts with self-hosted deployment',
      'Zero per-email costs after initial setup',
      'Full audit trail within client\'s infrastructure',
      'SOC 2 compliance maintained with internal controls',
    ],
    quote: {
      text: 'Self-hosting ApexMail was the difference between winning and losing enterprise deals. Our clients\' security teams approve it because the data never leaves their environment.',
      author: 'Alex Rivera',
      role: 'Founder & CEO, DevPipeline',
    },
    color: 'bg-orange-600',
    iconColor: 'text-orange-600',
    bgLight: 'bg-orange-50',
  },
];

export function CaseStudyList() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 bg-surface-50">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="space-y-16">
          {caseStudies.map((study, index) => (
            <motion.article
              key={study.slug}
              initial={{ opacity: 0, y: 20 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ delay: index * 0.1 }}
              className="bg-white rounded-xl border border-surface-200 shadow-sm overflow-hidden"
            >
              {/* Header */}
              <div className="border-b border-surface-100 flex flex-col md:flex-row md:items-center justify-between p-6 bg-white">
                <div className="flex items-center gap-3 mb-4 md:mb-0">
                  <div className={cn("w-10 h-10 rounded-lg flex items-center justify-center", study.bgLight)}>
                     <Building2 className={cn("w-5 h-5", study.iconColor)} />
                  </div>
                   <div>
                    <h3 className="font-bold text-lg text-surface-900 leading-tight">{study.company}</h3>
                    <div className="text-sm text-surface-500">{study.industry}</div>
                   </div>
                </div>
              </div>

              <div className="p-6 lg:p-10">
                {/* Title */}
                <h2 className="text-2xl font-bold text-surface-900 mb-4 leading-tight">
                  {study.title}
                </h2>
                <p className="text-lg text-surface-600 mb-10 max-w-4xl">{study.summary}</p>

                {/* Stats Grid */}
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-10">
                  {study.stats.map((stat) => (
                    <div key={stat.label} className="p-4 rounded-lg bg-surface-50 border border-surface-100">
                      <stat.icon className="w-5 h-5 mb-2 text-primary-600" />
                      <div className="text-xl font-bold text-surface-900">{stat.value}</div>
                      <div className="text-xs font-medium text-surface-500">{stat.label}</div>
                    </div>
                  ))}
                </div>

                {/* Challenge & Solution */}
                <div className="grid lg:grid-cols-2 gap-8 lg:gap-12 mb-10">
                  <div>
                    <h3 className="text-sm font-bold text-surface-900 flex items-center gap-2 mb-3">
                      <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
                      The Challenge
                    </h3>
                    <p className="text-surface-600 leading-relaxed">{study.challenge}</p>
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-surface-900 flex items-center gap-2 mb-3">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                      The Solution
                    </h3>
                    <p className="text-surface-600 leading-relaxed">{study.solution}</p>
                  </div>
                </div>

                <div className="grid lg:grid-cols-2 gap-8 lg:gap-12 pt-10 border-t border-surface-100">
                   {/* Results */}
                  <div>
                    <h3 className="text-sm font-bold text-surface-900 mb-4">
                      Key Results
                    </h3>
                    <ul className="space-y-3">
                      {study.results.map((result) => (
                        <li key={result} className="flex items-start gap-3">
                          <TrendingUp className="w-4 h-4 text-emerald-600 mt-1 flex-shrink-0" />
                          <span className="text-surface-700 text-sm">{result}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Quote */}
                  <div className={cn("p-6 rounded-xl border border-surface-100", study.bgLight)}>
                     <p className="text-lg text-surface-800 italic mb-4 leading-relaxed">&ldquo;{study.quote.text}&rdquo;</p>
                      <footer className="text-sm flex items-center gap-2">
                        <span className="font-semibold text-surface-900">{study.quote.author}</span>
                        <span className="w-1 h-1 rounded-full bg-surface-300" />
                        <span className="text-surface-600">{study.quote.role}</span>
                      </footer>
                  </div>
                </div>

              </div>
            </motion.article>
          ))}
        </div>
      </div>
    </section>
  );
}
