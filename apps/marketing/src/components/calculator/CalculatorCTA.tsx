'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ArrowRight, Calculator, MessageCircle } from 'lucide-react';
import Link from 'next/link';

export function CalculatorCTA() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 relative">
      <div className="absolute inset-0 bg-gradient-to-t from-green-900/20 to-transparent" />

      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="glass-card p-8 lg:p-12 text-center"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-green-500/10 text-green-400 text-sm mb-6">
            <Calculator className="w-4 h-4" />
            Start Saving Today
          </div>

          <h2 className="text-3xl lg:text-4xl font-bold text-white mb-4">
            Ready to Cut Your Email Costs?
          </h2>
          <p className="text-lg text-surface-400 mb-8 max-w-2xl mx-auto">
            Join thousands of companies saving money with ApexMail. 
            Start free with 10,000 emails per month—no credit card required.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
            <Link
              href="/signup"
              className="inline-flex items-center justify-center gap-2 px-8 py-4 bg-primary-600 text-white font-semibold rounded-xl hover:bg-primary-500 transition-colors"
            >
              Start Free
              <ArrowRight className="w-5 h-5" />
            </Link>
            <Link
              href="/contact/sales"
              className="inline-flex items-center justify-center gap-2 px-8 py-4 border border-surface-600 text-white font-semibold rounded-xl hover:border-surface-500 hover:bg-surface-800/50 transition-all"
            >
              <MessageCircle className="w-5 h-5" />
              Talk to Sales
            </Link>
          </div>

          {/* Trust Signals */}
          <div className="grid grid-cols-3 gap-6 pt-8 border-t border-surface-700">
            {[
              { value: '10K', label: 'Free emails/month' },
              { value: '$0', label: 'Setup fees' },
              { value: '60%', label: 'Average savings' },
            ].map((item) => (
              <div key={item.label}>
                <div className="text-2xl font-bold text-white">{item.value}</div>
                <div className="text-sm text-surface-500">{item.label}</div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* FAQ Note */}
        <motion.p
          initial={{ opacity: 0 }}
          animate={inView ? { opacity: 1 } : {}}
          transition={{ delay: 0.3 }}
          className="text-center text-sm text-surface-500 mt-8"
        >
          Have questions about pricing?{' '}
          <Link href="/pricing/faq" className="text-primary-400 hover:underline">
            Check our FAQ
          </Link>{' '}
          or{' '}
          <Link href="/contact" className="text-primary-400 hover:underline">
            contact us
          </Link>
          .
        </motion.p>
      </div>
    </section>
  );
}
