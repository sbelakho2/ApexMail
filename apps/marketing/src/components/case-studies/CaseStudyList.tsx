'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import Link from 'next/link';
import { ArrowRight, Building2, Users, Mail, TrendingUp, Shield, Clock } from 'lucide-react';
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
    color: 'bg-blue-500',
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
    color: 'bg-green-500',
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
    color: 'bg-purple-500',
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
    color: 'bg-orange-500',
  },
];

export function CaseStudyList() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 bg-white">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="space-y-24">
          {caseStudies.map((study, index) => (
            <motion.article
              key={study.slug}
              initial={{ opacity: 0, y: 40 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ delay: index * 0.1 }}
              className="premium-card overflow-hidden bg-white"
            >
              {/* Header */}
              <div className={cn('px-8 py-4', study.color)}>
                <div className="flex items-center justify-between">
                  <span className="text-white/80 text-sm font-medium">{study.industry}</span>
                  <span className="text-white font-bold text-lg">{study.company}</span>
                </div>
              </div>

              <div className="p-8 lg:p-10">
                {/* Title */}
                <h2 className="text-2xl lg:text-3xl font-bold text-surface-900 mb-4">
                  {study.title}
                </h2>
                <p className="text-lg text-surface-600 mb-8">{study.summary}</p>

                {/* Stats Grid */}
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
                  {study.stats.map((stat) => (
                    <div key={stat.label} className="text-center p-4 rounded-xl bg-surface-50">
                      <stat.icon className="w-6 h-6 mx-auto mb-2 text-primary-600" />
                      <div className="text-2xl font-bold text-surface-900">{stat.value}</div>
                      <div className="text-sm text-surface-600">{stat.label}</div>
                    </div>
                  ))}
                </div>

                {/* Challenge & Solution */}
                <div className="grid lg:grid-cols-2 gap-8 mb-10">
                  <div>
                    <h3 className="text-sm font-bold text-surface-500 uppercase tracking-wider mb-3">
                      The Challenge
                    </h3>
                    <p className="text-surface-700">{study.challenge}</p>
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-surface-500 uppercase tracking-wider mb-3">
                      The Solution
                    </h3>
                    <p className="text-surface-700">{study.solution}</p>
                  </div>
                </div>

                {/* Results */}
                <div className="mb-10">
                  <h3 className="text-sm font-bold text-surface-500 uppercase tracking-wider mb-4">
                    Key Results
                  </h3>
                  <ul className="grid sm:grid-cols-2 gap-3">
                    {study.results.map((result) => (
                      <li key={result} className="flex items-start gap-2">
                        <span className="w-5 h-5 rounded-full bg-primary-100 flex items-center justify-center flex-shrink-0 mt-0.5">
                          <TrendingUp className="w-3 h-3 text-primary-600" />
                        </span>
                        <span className="text-surface-700">{result}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Quote */}
                <blockquote className="border-l-4 border-primary-500 pl-6 py-2">
                  <p className="text-lg text-surface-700 italic mb-4">&ldquo;{study.quote.text}&rdquo;</p>
                  <footer className="text-sm">
                    <span className="font-semibold text-surface-900">{study.quote.author}</span>
                    <span className="text-surface-500"> — {study.quote.role}</span>
                  </footer>
                </blockquote>
              </div>
            </motion.article>
          ))}
        </div>
      </div>
    </section>
  );
}
