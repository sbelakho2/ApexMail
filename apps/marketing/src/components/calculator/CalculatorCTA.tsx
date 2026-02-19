'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ArrowRight, Calculator, MessageCircle } from '@/components/ui/icons';
import Link from 'next/link';

export function CalculatorCTA() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 relative bg-surface-50">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="bg-white border border-surface-200 shadow-sm rounded-lg p-8 lg:p-12 text-center"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-50 text-primary-700 border border-primary-100/50 text-xs font-medium mb-6">
            <Calculator className="w-4 h-4" />
            <span>Start saving today</span>
          </div>

          <h2 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-4 tracking-tight">
            Ready to cut your email costs?
          </h2>
          <p className="text-lg text-surface-600 mb-10 max-w-2xl mx-auto leading-relaxed">
            Join thousands of companies saving money with ApexMail. 
            Start free with 10,000 emails per month—no credit card required.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
            <Link
              href="/signup"
              className="btn-primary text-base px-6 py-3"
            >
              Start Free
              <ArrowRight className="w-4 h-4 ml-2" />
            </Link>
            <Link
              href="/contact/sales"
              className="btn-secondary text-base px-6 py-3 bg-white"
            >
              <MessageCircle className="w-4 h-4 mr-2" />
              Talk to Sales
            </Link>
          </div>

          {/* Trust Signals */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 pt-10 border-t border-surface-100">
            {[
              { value: '10K', label: 'Free emails/month' },
              { value: '$0', label: 'Setup fees' },
              { value: '60%', label: 'Average savings' },
            ].map((item) => (
              <div key={item.label}>
                <div className="text-2xl font-bold text-surface-900 tabular-nums mb-1">{item.value}</div>
                <div className="text-xs font-medium text-surface-500">{item.label}</div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* FAQ Note */}
        <motion.p
          initial={{ opacity: 0 }}
          animate={inView ? { opacity: 1 } : {}}
          transition={{ delay: 0.3 }}
          className="text-center text-sm font-medium text-surface-500 mt-10"
        >
          Have questions about pricing?{' '}
          <Link href="/pricing/faq" className="text-primary-600 font-semibold hover:text-primary-700 transition-colors">
            Check our FAQ
          </Link>{' '}
          or{' '}
          <Link href="/contact" className="text-primary-600 font-semibold hover:text-primary-700 transition-colors">
            contact us
          </Link>
          .
        </motion.p>
      </div>
    </section>
  );
}
