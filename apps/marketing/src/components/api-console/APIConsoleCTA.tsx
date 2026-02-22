'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ArrowRight, Terminal, Book } from '@/components/ui/icons';
import Link from 'next/link';

export function APIConsoleCTA() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });
  
  return (
    <section ref={ref} className="py-20 lg:py-32 relative bg-white">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="bg-white border border-surface-200 shadow-sm rounded-lg p-8 lg:p-12 text-center"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-100/50 text-surface-900 border border-surface-200 text-xs font-medium mb-6">
            <Terminal className="w-4 h-4 text-surface-500" />
            Ready to Build?
          </div>

          <h2 className="text-3xl lg:text-4xl font-semibold text-surface-900 mb-4 tracking-tight">
            Go from Playground to Production
          </h2>
          <p className="text-lg text-surface-600 mb-10 max-w-2xl mx-auto leading-relaxed font-medium">
            Sign up for free and get 3,000 emails per month at no cost.
            Same API, same reliability, your own API keys.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
            <Link
              href="/signup"
              className="btn-primary text-lg px-8 py-4"
            >
              Create Free Account
              <ArrowRight className="w-5 h-5 ml-2" />
            </Link>
            <Link
              href="/docs"
              className="btn-secondary text-lg px-8 py-4 bg-white"
            >
              <Book className="w-5 h-5 mr-2" />
              Read Documentation
            </Link>
          </div>

          {/* SDK Options */}
          <div className="pt-10 border-t border-surface-100">
            <div className="text-xs font-medium text-surface-500 mb-6">Available SDKs</div>
            <div className="flex flex-wrap justify-center gap-3">
              {['Node.js', 'Python', 'Ruby', 'Go', 'PHP', 'Java', '.NET', 'Rust'].map((sdk) => (
                <span
                  key={sdk}
                  className="px-3 py-1.5 bg-surface-50 text-surface-700 text-xs font-medium rounded-md border border-surface-200"
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
