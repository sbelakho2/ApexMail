'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import Link from 'next/link';
import { ArrowRight, Zap, Clock, Shield, Headphones } from 'lucide-react';

const ctaFeatures = [
  { icon: Zap, text: 'Send your first email in < 60 seconds' },
  { icon: Clock, text: '1,000 free emails every month, forever' },
  { icon: Shield, text: 'No credit card required to start' },
  { icon: Headphones, text: 'Free migration assistance available' },
];

export function CTASection() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 relative overflow-hidden">
      {/* Background Effects */}
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-gradient-to-t from-surface-950 via-surface-900 to-surface-950" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[1000px] h-[600px] bg-gradient-to-r from-primary-600/10 via-accent-600/10 to-primary-600/10 rounded-full blur-3xl" />
        <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-primary-500/50 to-transparent" />
      </div>

      <div className="relative max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="text-center"
        >
          {/* Headline */}
          <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold tracking-tight mb-6">
            <span className="text-white">Ready to Ship</span>
            <br />
            <span className="gradient-text">Better Email?</span>
          </h2>

          {/* Subheadline */}
          <p className="text-xl text-surface-300 max-w-2xl mx-auto mb-8">
            Join thousands of developers who trust ApexMail for their 
            mission-critical email infrastructure. Start free, scale infinitely.
          </p>

          {/* Features List */}
          <div className="grid sm:grid-cols-2 gap-4 max-w-xl mx-auto mb-10">
            {ctaFeatures.map((feature, index) => (
              <motion.div
                key={feature.text}
                initial={{ opacity: 0, x: -20 }}
                animate={inView ? { opacity: 1, x: 0 } : {}}
                transition={{ delay: 0.2 + index * 0.1 }}
                className="flex items-center gap-3 text-left"
              >
                <div className="w-8 h-8 rounded-lg bg-primary-500/20 flex items-center justify-center flex-shrink-0">
                  <feature.icon className="w-4 h-4 text-primary-400" />
                </div>
                <span className="text-surface-300 text-sm">{feature.text}</span>
              </motion.div>
            ))}
          </div>

          {/* CTA Buttons */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.4 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-12"
          >
            <Link
              href="https://app.apexmail.ee/signup"
              className="btn-primary text-lg px-8 py-4 flex items-center gap-2 group w-full sm:w-auto justify-center"
            >
              Start Sending Free
              <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </Link>
            <Link
              href="/contact"
              className="btn-secondary text-lg px-8 py-4 w-full sm:w-auto justify-center"
            >
              Talk to Sales
            </Link>
          </motion.div>

          {/* Trust Badges */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={inView ? { opacity: 1 } : {}}
            transition={{ delay: 0.6 }}
            className="flex flex-wrap items-center justify-center gap-6 text-surface-500 text-sm"
          >
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-accent-500"></span>
              99.99% Uptime SLA
            </span>
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-accent-500"></span>
              SOC 2 Certified
            </span>
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-accent-500"></span>
              GDPR Compliant
            </span>
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-accent-500"></span>
              24/7 Support
            </span>
          </motion.div>
        </motion.div>

        {/* Bottom Wave Effect */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={inView ? { opacity: 1 } : {}}
          transition={{ delay: 0.8 }}
          className="absolute bottom-0 left-0 right-0 h-32 overflow-hidden pointer-events-none"
        >
          <svg
            viewBox="0 0 1200 120"
            preserveAspectRatio="none"
            className="absolute bottom-0 w-full h-full fill-surface-950"
          >
            <path d="M321.39,56.44c58-10.79,114.16-30.13,172-41.86,82.39-16.72,168.19-17.73,250.45-.39C823.78,31,906.67,72,985.66,92.83c70.05,18.48,146.53,26.09,214.34,3V120H0V95.8C59.71,118.11,140.52,94.45,200.69,81,239.21,72.39,280.61,65.35,321.39,56.44Z" />
          </svg>
        </motion.div>
      </div>
    </section>
  );
}
