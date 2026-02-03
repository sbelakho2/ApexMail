'use client';

import { motion } from 'framer-motion';
import { BookOpen } from 'lucide-react';

export function CaseStudiesHero() {
  return (
    <section className="relative pt-32 pb-20 overflow-hidden bg-surface-50">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 right-0 w-1/3 h-full bg-primary-50 [clip-path:polygon(100%_0,0%_0,100%_100%)]" />
      </div>

      <div className="relative max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="text-center"
        >
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-xl bg-white border border-surface-200 text-sm text-primary-700 mb-6">
            <BookOpen className="w-4 h-4" />
            Customer Success
          </div>

          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-6">
            <span className="text-surface-900">Real Results From</span>
            <br />
            <span className="text-primary-500">Real Companies</span>
          </h1>

          <p className="text-lg text-surface-600 max-w-2xl mx-auto">
            See how engineering teams at startups and enterprises use ApexMail 
            to deliver millions of transactional emails with confidence.
          </p>
        </motion.div>
      </div>
    </section>
  );
}
