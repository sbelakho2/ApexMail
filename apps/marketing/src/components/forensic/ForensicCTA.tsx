'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ArrowRight, Bug, Zap } from '@/components/ui/icons';
import Link from 'next/link';

export function ForensicCTA() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });
  
  return (
    <section ref={ref} className="py-20 lg:py-32 relative bg-white">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="bg-white border border-surface-200 shadow-sm rounded-2xl p-8 lg:p-12 text-center"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-100/50 text-surface-900 border border-surface-200 text-xs font-medium mb-6">
            <Bug className="w-4 h-4 text-surface-500" />
            Never Debug Blind Again
          </div>

          <h2 className="text-3xl lg:text-4xl font-semibold text-surface-900 mb-4 tracking-tight">
            Stop Guessing. Start Knowing.
          </h2>
          <p className="text-lg text-surface-600 mb-10 max-w-2xl mx-auto leading-relaxed font-medium">
            Every email you send with ApexMail includes full forensic debugging capabilities. 
            See what your customers see, instantly.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
            <Link
              href="/signup"
              className="btn-primary text-lg px-8 py-4"
            >
              Start Free Trial
              <ArrowRight className="w-5 h-5 ml-2" />
            </Link>
            <Link
              href="/api-console"
              className="btn-secondary text-lg px-8 py-4 bg-white"
            >
              <Zap className="w-5 h-5 mr-2" />
              Try Live Demo
            </Link>
          </div>

          {/* Feature Highlights */}
          <div className="grid md:grid-cols-3 gap-8 pt-10 border-t border-surface-100">
            {[
              { value: '90 days', label: 'Render retention' },
              { value: '50+', label: 'Email clients' },
              { value: 'Real-time', label: 'Render tracking' },
            ].map((item) => (
              <div key={item.label}>
                <div className="text-2xl font-semibold text-surface-900 tabular-nums mb-1">{item.value}</div>
                <div className="text-xs font-medium text-surface-500">{item.label}</div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  );
}
