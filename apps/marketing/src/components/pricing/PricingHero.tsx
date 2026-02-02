'use client';

import { motion } from 'framer-motion';
import { DollarSign } from 'lucide-react';
import Link from 'next/link';

export function PricingHero() {
 return (
 <section className="relative min-h-[40vh] flex items-center pt-32 pb-20 bg-surface-50">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
 <div className="text-center max-w-3xl mx-auto">
 <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-primary-50 text-primary-700 border border-primary-100 text-[10px] font-bold uppercase tracking-widest mb-6"
          >
            <DollarSign className="w-4 h-4" />
            Simple Pricing
          </motion.div>

 <motion.h1
 initial={{ opacity: 0, y: 20 }}
 animate={{ opacity: 1, y: 0 }}
 transition={{ delay: 0.1 }}
 className="text-4xl lg:text-6xl font-bold text-surface-900 mb-6 tracking-tight leading-tight"
 >
 Start Free.
 <br />
 Scale <span className="text-primary-600">Predictably.</span>
 </motion.h1>

 <motion.p
 initial={{ opacity: 0, y: 20 }}
 animate={{ opacity: 1, y: 0 }}
 transition={{ delay: 0.2 }}
 className="text-xl text-surface-600 mb-10 leading-relaxed font-medium"
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
 className="text-primary-600 font-bold hover:underline flex items-center justify-center gap-2"
 >
 Compare with competitors
 <span className="text-lg">→</span>
 </Link>
 </motion.div>
 </div>
 </div>
 </section>
 );
}
