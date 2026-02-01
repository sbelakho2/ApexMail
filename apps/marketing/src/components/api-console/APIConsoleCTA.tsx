'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ArrowRight, Terminal, Book } from 'lucide-react';
import Link from 'next/link';

export function APIConsoleCTA() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 relative">
      <div className="absolute inset-0 bg-gradient-to-t from-cyan-900/20 to-transparent" />

      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="glass-card p-8 lg:p-12 text-center"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 text-cyan-400 text-sm mb-6">
            <Terminal className="w-4 h-4" />
            Ready to Build?
          </div>

          <h2 className="text-3xl lg:text-4xl font-bold text-white mb-4">
            Go from Playground to Production
          </h2>
          <p className="text-lg text-surface-400 mb-8 max-w-2xl mx-auto">
            Sign up for free and get 10,000 emails per month at no cost. 
            Same API, same reliability, your own API keys.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
            <Link
              href="/signup"
              className="inline-flex items-center justify-center gap-2 px-8 py-4 bg-primary-600 text-white font-semibold rounded-xl hover:bg-primary-500 transition-colors"
            >
              Create Free Account
              <ArrowRight className="w-5 h-5" />
            </Link>
            <Link
              href="/docs"
              className="inline-flex items-center justify-center gap-2 px-8 py-4 border border-surface-600 text-white font-semibold rounded-xl hover:border-surface-500 hover:bg-surface-800/50 transition-all"
            >
              <Book className="w-5 h-5" />
              Read Documentation
            </Link>
          </div>

          {/* SDK Options */}
          <div className="pt-8 border-t border-surface-700">
            <div className="text-sm text-surface-500 mb-4">Available SDKs</div>
            <div className="flex flex-wrap justify-center gap-4">
              {['Node.js', 'Python', 'Ruby', 'Go', 'PHP', 'Java', '.NET', 'Rust'].map((sdk) => (
                <span
                  key={sdk}
                  className="px-3 py-1 bg-surface-800 text-surface-400 text-sm rounded-lg"
                >
                  {sdk}
                </span>
              ))}
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
