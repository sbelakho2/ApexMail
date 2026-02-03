'use client';

import { motion } from 'framer-motion';
import { Calculator, DollarSign, TrendingDown } from 'lucide-react';

export function CalculatorHero() {
 return (
 <section className="relative min-h-[40vh] flex items-center pt-32 pb-20 bg-surface-50">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
 <div className="text-center max-w-3xl mx-auto">
 <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-primary-50 text-primary-700 border border-primary-100 text-[10px] font-bold uppercase tracking-widest mb-6"
          >
            <Calculator className="w-4 h-4" />
            Pricing Calculator
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="text-4xl lg:text-6xl font-bold text-surface-900 mb-6 tracking-tight"
          >
            Calculate Your <span className="text-primary-600">Savings</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="text-xl text-surface-600 mb-10 leading-relaxed font-medium"
          >
            See exactly how ApexMail stacks up against SendGrid, Mailchimp, and AWS SES. 
            Enter your volume and watch the numbers speak for themselves.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="flex flex-wrap justify-center gap-8"
          >
            <div className="flex items-center gap-2 text-surface-600 font-bold text-[10px] uppercase tracking-widest">
              <DollarSign className="w-5 h-5 text-primary-600" />
              <span>Transparent pricing</span>
            </div>
            <div className="flex items-center gap-2 text-surface-600 font-bold text-[10px] uppercase tracking-widest">
              <TrendingDown className="w-5 h-5 text-primary-600" />
              <span>Up to 60% savings</span>
            </div>
            <div className="flex items-center gap-2 text-surface-600 font-bold text-[10px] uppercase tracking-widest">
              <Calculator className="w-5 h-5 text-primary-600" />
              <span>No hidden fees</span>
            </div>
          </motion.div>
 </div>
 </div>
 </section>
 );
}
