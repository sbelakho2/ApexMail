'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import Link from 'next/link';
import { ArrowRight, Check } from 'lucide-react';

interface CompareCTAProps {
  verdict: {
    title: string;
    points: string[];
  };
}

export function CompareCTA({ verdict }: CompareCTAProps) {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 bg-surface-50">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="premium-card p-8 lg:p-12 bg-white"
        >
          <h2 className="text-2xl lg:text-3xl font-bold text-surface-900 mb-8">
            {verdict.title}
          </h2>

          <ul className="space-y-4 mb-10">
            {verdict.points.map((point, index) => (
              <motion.li
                key={index}
                initial={{ opacity: 0, x: -20 }}
                animate={inView ? { opacity: 1, x: 0 } : {}}
                transition={{ delay: 0.1 + index * 0.1 }}
                className="flex items-start gap-3"
              >
                <span className="w-6 h-6 rounded-full bg-primary-100 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <Check className="w-4 h-4 text-primary-600" />
                </span>
                <span className="text-surface-700">{point}</span>
              </motion.li>
            ))}
          </ul>

          <div className="flex flex-wrap gap-4">
            <Link
              href="https://app.apexmail.ee/signup"
              className="btn-primary flex items-center gap-2 group"
            >
              Start Free Trial
              <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
            </Link>
            <Link href="/pricing" className="btn-secondary">
              View Pricing
            </Link>
          </div>

          <p className="text-sm text-surface-500 mt-6">
            No credit card required • 1,000 free emails per month • Setup in 5 minutes
          </p>
        </motion.div>

        {/* Other Comparisons */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.4 }}
          className="mt-12 text-center"
        >
          <p className="text-sm text-surface-600 mb-4">Compare ApexMail to other providers:</p>
          <div className="flex flex-wrap justify-center gap-4">
            <Link
              href="/compare/sendgrid"
              className="text-sm text-primary-600 hover:text-primary-700 font-medium"
            >
              vs SendGrid
            </Link>
            <Link
              href="/compare/resend"
              className="text-sm text-primary-600 hover:text-primary-700 font-medium"
            >
              vs Resend
            </Link>
            <Link
              href="/compare/postmark"
              className="text-sm text-primary-600 hover:text-primary-700 font-medium"
            >
              vs Postmark
            </Link>
            <Link
              href="/compare/amazon-ses"
              className="text-sm text-primary-600 hover:text-primary-700 font-medium"
            >
              vs Amazon SES
            </Link>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
