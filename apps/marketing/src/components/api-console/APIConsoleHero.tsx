'use client';

import { motion } from 'framer-motion';
import { Terminal, Zap, Lock } from 'lucide-react';
import Link from 'next/link';

export function APIConsoleHero() {
  return (
    <section className="relative min-h-[60vh] flex items-center pt-20">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-b from-surface-950 via-surface-900 to-surface-950" />
      <div className="absolute inset-0 opacity-30">
        <div className="absolute top-1/3 right-1/4 w-96 h-96 bg-cyan-500/20 rounded-full blur-3xl" />
        <div className="absolute bottom-1/3 left-1/4 w-96 h-96 bg-blue-500/20 rounded-full blur-3xl" />
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <div className="text-center max-w-3xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 text-cyan-400 text-sm mb-6"
          >
            <Terminal className="w-4 h-4" />
            Live API Console
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="text-4xl lg:text-5xl font-bold text-white mb-6"
          >
            Try Before You Sign Up
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="text-xl text-surface-400 mb-8"
          >
            Send real test emails, see webhooks fire, and explore the full API—all 
            without creating an account. No credit card, no commitment.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="flex flex-wrap justify-center gap-4"
          >
            <div className="flex items-center gap-2 text-surface-400">
              <Zap className="w-5 h-5 text-cyan-400" />
              <span>Real API responses</span>
            </div>
            <div className="flex items-center gap-2 text-surface-400">
              <Lock className="w-5 h-5 text-cyan-400" />
              <span>Sandboxed environment</span>
            </div>
            <div className="flex items-center gap-2 text-surface-400">
              <Terminal className="w-5 h-5 text-cyan-400" />
              <span>Copy code snippets</span>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
