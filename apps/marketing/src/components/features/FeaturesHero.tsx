'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';
import { ArrowRight, Zap } from 'lucide-react';

const stats = [
  { value: '99.9%', label: 'Delivery Rate' },
  { value: '<1.2s', label: 'Avg. Delivery' },
  { value: '100%', label: 'GDPR Compliant' },
  { value: '0', label: 'Paid AI APIs' },
];

export function FeaturesHero() {
  return (
    <section className="pt-32 pb-20 lg:pb-32 bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="text-center max-w-4xl mx-auto"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-100 border border-surface-200 text-sm text-surface-700 mb-6 font-medium">
            <Zap className="w-4 h-4" />
            Complete Email Infrastructure
          </div>

          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-6 text-surface-900">
            Every Feature You Need,
            <span className="text-primary-600 block sm:inline sm:ml-3">Zero You Don&apos;t</span>
          </h1>

          <p className="text-xl text-surface-600 mb-10 max-w-2xl mx-auto leading-relaxed">
            From send to delivery, ApexMail handles everything: authentication, deliverability, 
            compliance, analytics, and AI optimization—all without external dependencies.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-20">
            <Link
              href="https://app.apexmail.ee/signup"
              className="btn-primary flex items-center gap-2 group px-8 py-3.5 text-lg"
            >
              Start Free Trial
              <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
            </Link>
            <Link href="/pricing" className="btn-secondary flex items-center gap-2 px-8 py-3.5 text-lg">
              View Pricing
            </Link>
          </div>

          {/* Stats Grid */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-8 pt-8 border-t border-surface-100">
            {stats.map((stat, index) => (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 + index * 0.1 }}
                className="text-center"
              >
                <div className="text-3xl lg:text-4xl font-bold text-surface-900 mb-2 tracking-tight">
                  {stat.value}
                </div>
                <div className="text-sm text-surface-500 font-medium">{stat.label}</div>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  );
}
