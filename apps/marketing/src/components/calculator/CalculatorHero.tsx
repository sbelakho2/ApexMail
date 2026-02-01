'use client';

import { motion } from 'framer-motion';
import { Calculator, DollarSign, TrendingDown } from 'lucide-react';

export function CalculatorHero() {
  return (
    <section className="relative min-h-[50vh] flex items-center pt-20">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-b from-surface-950 via-surface-900 to-surface-950" />
      <div className="absolute inset-0 opacity-30">
        <div className="absolute top-1/3 left-1/3 w-96 h-96 bg-green-500/20 rounded-full blur-3xl" />
        <div className="absolute bottom-1/3 right-1/3 w-96 h-96 bg-emerald-500/20 rounded-full blur-3xl" />
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <div className="text-center max-w-3xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-green-500/10 text-green-400 text-sm mb-6"
          >
            <Calculator className="w-4 h-4" />
            Pricing Calculator
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="text-4xl lg:text-5xl font-bold text-white mb-6"
          >
            Calculate Your Savings
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="text-xl text-surface-400 mb-8"
          >
            See exactly how ApexMail stacks up against SendGrid, Mailchimp, and AWS SES. 
            Enter your volume and watch the numbers speak for themselves.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="flex flex-wrap justify-center gap-6"
          >
            <div className="flex items-center gap-2 text-surface-400">
              <DollarSign className="w-5 h-5 text-green-400" />
              <span>Transparent pricing</span>
            </div>
            <div className="flex items-center gap-2 text-surface-400">
              <TrendingDown className="w-5 h-5 text-green-400" />
              <span>Up to 60% savings</span>
            </div>
            <div className="flex items-center gap-2 text-surface-400">
              <Calculator className="w-5 h-5 text-green-400" />
              <span>No hidden fees</span>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
