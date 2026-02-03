'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import Link from 'next/link';
import { ArrowRight, MessageCircle } from 'lucide-react';

export function CaseStudiesCTA() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 bg-primary-600">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
        >
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-xl bg-primary-500 text-white text-sm mb-6">
            <MessageCircle className="w-4 h-4" />
            Your Story Next?
          </div>

          <h2 className="text-3xl lg:text-4xl font-bold text-white mb-6">
            Ready to Write Your Success Story?
          </h2>

          <p className="text-lg text-primary-100 mb-10 max-w-2xl mx-auto">
            Join companies that trust ApexMail for their critical email infrastructure.
            Start free and scale when you&apos;re ready.
          </p>

          <div className="flex flex-wrap justify-center gap-4">
            <Link
              href="https://app.apexmail.ee/signup"
              className="bg-white text-primary-600 px-6 py-3 rounded-lg font-semibold hover:bg-primary-50 transition-colors flex items-center gap-2 group"
            >
              Get Started Free
              <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
            </Link>
            <Link
              href="/contact"
              className="border border-primary-400 text-white px-6 py-3 rounded-lg font-semibold hover:bg-primary-500 transition-colors"
            >
              Talk to Sales
            </Link>
          </div>

          <p className="text-primary-200 text-sm mt-8">
            No credit card required • Free tier includes 1,000 emails/month
          </p>
        </motion.div>
      </div>
    </section>
  );
}
