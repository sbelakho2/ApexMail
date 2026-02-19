'use client';

import { motion } from 'framer-motion';
import { Terminal, Zap, Lock } from '@/components/ui/icons';

export function APIConsoleHero() {
  return (
    <section className="relative min-h-[40vh] flex items-center pt-32 pb-20 bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <div className="text-center max-w-3xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-100/50 text-surface-900 border border-surface-200 text-xs font-medium mb-6"
          >
            <Terminal className="w-4 h-4 text-surface-500" />
            Live API Console
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="text-4xl lg:text-6xl font-semibold text-surface-900 mb-6 tracking-tight"
          >
            Try Before You <span className="text-primary-600">Sign Up</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="text-xl text-surface-600 mb-10 leading-relaxed font-medium"
          >
            Send real test emails, see webhooks fire, and explore the full API—all 
            without creating an account. No credit card, no commitment.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="flex flex-wrap justify-center gap-8"
          >
            <div className="flex items-center gap-2 text-surface-600 font-medium text-xs">
              <Zap className="w-5 h-5 text-surface-400" />
              <span>Real API responses</span>
            </div>
            <div className="flex items-center gap-2 text-surface-600 font-medium text-xs">
              <Lock className="w-5 h-5 text-surface-400" />
              <span>Sandboxed environment</span>
            </div>
            <div className="flex items-center gap-2 text-surface-600 font-medium text-xs">
              <Terminal className="w-5 h-5 text-surface-400" />
              <span>Copy code snippets</span>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
