'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';
import { ArrowRight, Zap, Shield, Brain, Gauge } from 'lucide-react';

const stats = [
  { value: '99.9%', label: 'Delivery Rate' },
  { value: '<1.2s', label: 'Avg. Delivery' },
  { value: '100%', label: 'GDPR Compliant' },
  { value: '0', label: 'Paid AI APIs' },
];

export function FeaturesHero() {
  return (
    <section className="relative pt-32 pb-20 lg:pb-32 overflow-hidden bg-surface-50">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 right-0 w-1/3 h-full bg-primary-50 [clip-path:polygon(100%_0,0%_0,100%_100%)]" />
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="text-center max-w-4xl mx-auto"
        >
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-xl bg-white border border-surface-200 text-sm text-primary-700 mb-6">
            <Zap className="w-4 h-4" />
            Complete Email Infrastructure
          </div>

          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-6">
            <span className="text-surface-900">Every Feature You Need,</span>
            <br />
            <span className="text-primary-500">Zero You Don&apos;t</span>
          </h1>

          <p className="text-lg lg:text-xl text-surface-600 mb-10 max-w-2xl mx-auto leading-relaxed">
            From send to delivery, ApexMail handles everything: authentication, deliverability, 
            compliance, analytics, and AI optimization—all without external dependencies.
          </p>

          <div className="flex flex-wrap justify-center gap-4 mb-16">
            <Link
              href="https://app.apexmail.ee/signup"
              className="btn-primary flex items-center gap-2 group"
            >
              Start Free Trial
              <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
            </Link>
            <Link href="/pricing" className="btn-secondary flex items-center gap-2">
              View Pricing
            </Link>
          </div>

          {/* Stats Grid */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
            {stats.map((stat, index) => (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 + index * 0.1 }}
                className="text-center"
              >
                <div className="text-3xl lg:text-4xl font-bold text-primary-600 mb-2">
                  {stat.value}
                </div>
                <div className="text-sm text-surface-600 font-medium">{stat.label}</div>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  );
}
