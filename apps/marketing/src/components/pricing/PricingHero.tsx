'use client';

import { motion } from 'framer-motion';
import { DollarSign } from 'lucide-react';
import Link from 'next/link';

export function PricingHero() {
 return (
 <section className="relative flex items-center pt-24 pb-12 bg-white">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full">
 <div className="text-center max-w-2xl mx-auto">
 <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            className="inline-flex items-center gap-2 mb-6"
          >
           <span className="text-sm font-semibold text-primary-600 tracking-wide uppercase">Simple Pricing</span>
          </motion.div>

 <motion.h1
 initial={{ opacity: 0, y: 16 }}
 animate={{ opacity: 1, y: 0 }}
 transition={{ delay: 0.1 }}
 className="text-4xl lg:text-5xl font-bold text-surface-900 mb-4 tracking-tight"
 >
 Start Free. <span className="text-surface-500">Scale Predictably.</span>
 </motion.h1>

 <motion.p
 initial={{ opacity: 0, y: 16 }}
 animate={{ opacity: 1, y: 0 }}
 transition={{ delay: 0.2 }}
 className="text-lg text-surface-500 mb-8 leading-relaxed max-w-xl mx-auto"
 >
 Transparent pricing that grows with your business. No hidden fees or surprise charges.
 </motion.p>
 </div>
 </div>
 </section>
 );
}

