'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ArrowRight, MessageCircle, Calculator } from 'lucide-react';
import Link from 'next/link';

export function PricingCTA() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 relative">
      <div className="absolute inset-0 bg-gradient-to-t from-primary-900/20 to-transparent" />

      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="glass-card p-8 lg:p-12 text-center"
        >
          <h2 className="text-3xl lg:text-4xl font-bold text-white mb-4">
            Still Have Questions?
          </h2>
          <p className="text-lg text-surface-400 mb-8 max-w-2xl mx-auto">
            Our team is here to help you find the perfect plan for your needs. 
            Schedule a call or calculate your costs with our pricing calculator.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              href="/signup"
              className="inline-flex items-center justify-center gap-2 px-8 py-4 bg-primary-600 text-white font-semibold rounded-xl hover:bg-primary-500 transition-colors"
            >
              Start Free
              <ArrowRight className="w-5 h-5" />
            </Link>
            <Link
              href="/pricing/calculator"
              className="inline-flex items-center justify-center gap-2 px-8 py-4 border border-surface-600 text-white font-semibold rounded-xl hover:border-surface-500 hover:bg-surface-800/50 transition-all"
            >
              <Calculator className="w-5 h-5" />
              Price Calculator
            </Link>
            <Link
              href="/contact/sales"
              className="inline-flex items-center justify-center gap-2 px-8 py-4 border border-surface-600 text-white font-semibold rounded-xl hover:border-surface-500 hover:bg-surface-800/50 transition-all"
            >
              <MessageCircle className="w-5 h-5" />
              Talk to Sales
            </Link>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
