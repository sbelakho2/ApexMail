'use client';

import { motion } from 'framer-motion';
import { DollarSign } from 'lucide-react';
import Link from 'next/link';

export function PricingHero() {
  return (
    <section className="relative min-h-[40vh] flex items-center pt-20">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-b from-surface-950 via-surface-900 to-surface-950" />
      <div className="absolute inset-0 opacity-30">
        <div className="absolute top-1/3 left-1/4 w-96 h-96 bg-primary-500/20 rounded-full blur-3xl" />
        <div className="absolute bottom-1/3 right-1/4 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl" />
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <div className="text-center max-w-3xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-500/10 text-primary-400 text-sm mb-6"
          >
            <DollarSign className="w-4 h-4" />
            Simple Pricing
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="text-4xl lg:text-5xl font-bold text-white mb-6"
          >
            Start Free. Scale Predictably.
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="text-xl text-surface-400 mb-8"
          >
            No hidden fees. No surprise charges. Just simple, transparent pricing 
            that grows with your business.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
          >
            <Link
              href="/pricing/calculator"
              className="text-primary-400 hover:text-primary-300 underline"
            >
              Compare with competitors →
            </Link>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
