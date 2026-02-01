'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ArrowRight, Calendar, Cloud, Phone } from 'lucide-react';
import Link from 'next/link';

export function PrivateCloudCTA() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 relative bg-surface-900/50">
      <div className="absolute inset-0 bg-gradient-to-t from-primary-900/20 to-transparent" />

      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="glass-card p-8 lg:p-12 text-center"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 text-blue-400 text-sm mb-6">
            <Cloud className="w-4 h-4" />
            Enterprise Ready
          </div>

          <h2 className="text-3xl lg:text-4xl font-bold text-white mb-4">
            Deploy in Your Cloud This Week
          </h2>
          <p className="text-lg text-surface-400 mb-8 max-w-2xl mx-auto">
            Our solutions architects will work with your team to design and deploy 
            a private ApexMail instance tailored to your security requirements.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
            <Link
              href="/contact/enterprise"
              className="inline-flex items-center justify-center gap-2 px-8 py-4 bg-primary-600 text-white font-semibold rounded-xl hover:bg-primary-500 transition-colors"
            >
              Talk to Sales
              <ArrowRight className="w-5 h-5" />
            </Link>
            <Link
              href="/docs/private-cloud/architecture"
              className="inline-flex items-center justify-center gap-2 px-8 py-4 border border-surface-600 text-white font-semibold rounded-xl hover:border-surface-500 hover:bg-surface-800/50 transition-all"
            >
              <Calendar className="w-5 h-5" />
              Schedule Architecture Review
            </Link>
          </div>

          {/* Deployment Timeline */}
          <div className="grid md:grid-cols-4 gap-4 pt-8 border-t border-surface-700">
            {[
              { day: 'Day 1', title: 'Architecture Review', description: 'Design deployment' },
              { day: 'Day 2-3', title: 'Infrastructure', description: 'Provision resources' },
              { day: 'Day 4', title: 'Deployment', description: 'Install ApexMail' },
              { day: 'Day 5', title: 'Go Live', description: 'Production ready' },
            ].map((step, index) => (
              <div key={step.day} className="text-center">
                <div className="text-primary-400 font-semibold mb-1">{step.day}</div>
                <div className="text-white font-medium">{step.title}</div>
                <div className="text-xs text-surface-500">{step.description}</div>
                {index < 3 && (
                  <div className="hidden md:block absolute right-0 top-1/2 transform translate-x-1/2 -translate-y-1/2">
                    <ArrowRight className="w-4 h-4 text-surface-600" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </motion.div>

        {/* Contact Options */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.2 }}
          className="grid md:grid-cols-2 gap-6 mt-8"
        >
          <div className="glass-card p-6 flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-green-500/10 flex items-center justify-center flex-shrink-0">
              <Phone className="w-6 h-6 text-green-400" />
            </div>
            <div>
              <div className="text-white font-medium">Talk to an Engineer</div>
              <div className="text-sm text-surface-400">
                Get a technical deep-dive with our solutions team
              </div>
            </div>
          </div>
          <div className="glass-card p-6 flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-purple-500/10 flex items-center justify-center flex-shrink-0">
              <Calendar className="w-6 h-6 text-purple-400" />
            </div>
            <div>
              <div className="text-white font-medium">Proof of Concept</div>
              <div className="text-sm text-surface-400">
                Deploy a trial instance in your staging environment
              </div>
            </div>
          </div>
        </motion.div>

        {/* Enterprise Customers */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={inView ? { opacity: 1 } : {}}
          transition={{ delay: 0.4 }}
          className="text-center mt-12"
        >
          <p className="text-sm text-surface-500 mb-4">
            Trusted by security-conscious enterprises
          </p>
          <div className="flex flex-wrap justify-center gap-8 opacity-50">
            {['Fortune 500 Bank', 'Healthcare Provider', 'Government Agency', 'Defense Contractor'].map(
              (customer) => (
                <span key={customer} className="text-surface-500 text-sm">
                  {customer}
                </span>
              )
            )}
          </div>
        </motion.div>
      </div>
    </section>
  );
}
