'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';
import { ArrowRight, ArrowLeftRight } from '@/components/ui/icons';

interface CompareHeroProps {
  competitor: {
    name: string;
    logo: string;
    description: string;
  };
}

export function CompareHero({ competitor }: CompareHeroProps) {
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
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-lg bg-white border border-surface-200 text-sm text-primary-700 mb-6">
            <ArrowLeftRight className="w-4 h-4" />
            Feature Comparison
          </div>

          <h1 className="text-3xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-6 break-words">
            <span className="text-primary-500">ApexMail</span>
            <span className="text-surface-400 mx-2 sm:mx-4">vs</span>
            <span className="text-surface-900">{competitor.name}</span>
          </h1>

          <p className="text-lg text-surface-600 mb-10 max-w-2xl mx-auto">
            See how ApexMail compares to {competitor.name}. {competitor.description}
          </p>

          <div className="flex flex-wrap justify-center gap-4">
            <Link
              href="https://app.apexmail.ee/signup"
              className="btn-primary flex items-center gap-2 group"
            >
              Try ApexMail Free
              <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
            </Link>
            <Link href="#comparison" className="btn-secondary">
              See Full Comparison
            </Link>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
