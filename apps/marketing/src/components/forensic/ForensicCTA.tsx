'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ArrowRight, Bug, Zap } from 'lucide-react';
import Link from 'next/link';

export function ForensicCTA() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 relative">
      <div className="absolute inset-0 bg-gradient-to-t from-orange-900/20 to-transparent" />

      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="glass-card p-8 lg:p-12 text-center"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-orange-500/10 text-orange-400 text-sm mb-6">
            <Bug className="w-4 h-4" />
            Never Debug Blind Again
          </div>

          <h2 className="text-3xl lg:text-4xl font-bold text-white mb-4">
            Stop Guessing. Start Knowing.
          </h2>
          <p className="text-lg text-surface-400 mb-8 max-w-2xl mx-auto">
            Every email you send with ApexMail includes full forensic debugging capabilities. 
            See what your customers see, instantly.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
            <Link
              href="/signup"
              className="inline-flex items-center justify-center gap-2 px-8 py-4 bg-primary-600 text-white font-semibold rounded-xl hover:bg-primary-500 transition-colors"
            >
              Start Free Trial
              <ArrowRight className="w-5 h-5" />
            </Link>
            <Link
              href="/api-console"
              className="inline-flex items-center justify-center gap-2 px-8 py-4 border border-surface-600 text-white font-semibold rounded-xl hover:border-surface-500 hover:bg-surface-800/50 transition-all"
            >
              <Zap className="w-5 h-5" />
              Try Live Demo
            </Link>
          </div>

          {/* Feature Highlights */}
          <div className="grid md:grid-cols-3 gap-6 pt-8 border-t border-surface-700">
            {[
              { value: '90 days', label: 'Render retention' },
              { value: '50+', label: 'Email clients' },
              { value: 'Real-time', label: 'Render tracking' },
            ].map((item) => (
              <div key={item.label}>
                <div className="text-2xl font-bold text-white">{item.value}</div>
                <div className="text-sm text-surface-500">{item.label}</div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  );
}
