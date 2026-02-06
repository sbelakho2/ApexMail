'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import Link from 'next/link';
import { ArrowRight, Zap, MessageCircle } from 'lucide-react';

export function FeatureCTA() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 relative bg-surface-50">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="bg-white border border-surface-200 shadow-sm rounded-lg p-8 lg:p-12 text-center"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-50 text-primary-700 border border-primary-100/50 text-xs font-medium mb-6">
            <Zap className="w-4 h-4" />
            <span>Start in 5 Minutes</span>
          </div>

          <h2 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-6 tracking-tight">
            Ready to Ship Better Email?
          </h2>

          <p className="text-lg text-surface-600 mb-10 max-w-2xl mx-auto leading-relaxed">
            Join thousands of developers who trust ApexMail for their transactional email.
            Start free with 1,000 emails per month.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center">
             <Link
              href="https://app.apexmail.ee/signup"
              className="inline-flex items-center justify-center gap-2 bg-primary-600 hover:bg-primary-700 text-white px-6 py-3 rounded-md font-semibold transition-colors group"
            >
              Get Started Free
              <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
            </Link>
            <Link
              href="/contact"
              className="inline-flex items-center justify-center gap-2 bg-white text-surface-900 border border-surface-200 hover:bg-surface-50 px-6 py-3 rounded-md font-semibold transition-colors"
            >
               <MessageCircle className="w-4 h-4 text-surface-500" />
              Talk to Sales
            </Link>
          </div>

          <p className="text-surface-500 text-sm mt-8 font-medium">
            No credit card required • Free tier includes 1,000 emails/month
          </p>
        </motion.div>
      </div>
    </section>
  );
}
