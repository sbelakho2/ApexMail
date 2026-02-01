'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ArrowRight, Calendar, Shield, FileText } from 'lucide-react';
import Link from 'next/link';

export function ComplianceCTA() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 relative">
      <div className="absolute inset-0 bg-gradient-to-t from-primary-900/20 to-transparent" />
      
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="glass-card p-8 lg:p-12 text-center"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-500/10 text-primary-400 text-sm mb-6">
            <Shield className="w-4 h-4" />
            Enterprise Compliance
          </div>

          <h2 className="text-3xl lg:text-4xl font-bold text-white mb-4">
            Ready to Sleep Better at Night?
          </h2>
          <p className="text-lg text-surface-400 mb-8 max-w-2xl mx-auto">
            Join 2,000+ companies that trust ApexMail for their compliance-critical email infrastructure. 
            Get a personalized compliance assessment from our DPO team.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
            <Link
              href="/signup"
              className="inline-flex items-center justify-center gap-2 px-8 py-4 bg-primary-600 text-white font-semibold rounded-xl hover:bg-primary-500 transition-colors"
            >
              Start Free Trial
              <ArrowRight className="w-5 h-5" />
            </Link>
            <Link
              href="/contact/compliance"
              className="inline-flex items-center justify-center gap-2 px-8 py-4 border border-surface-600 text-white font-semibold rounded-xl hover:border-surface-500 hover:bg-surface-800/50 transition-all"
            >
              <Calendar className="w-5 h-5" />
              Talk to Compliance Team
            </Link>
          </div>

          {/* Trust Signals */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6 pt-8 border-t border-surface-700">
            {[
              { icon: Shield, label: 'SOC 2 Type II', sublabel: 'Certified' },
              { icon: FileText, label: 'GDPR', sublabel: 'Compliant' },
              { icon: Shield, label: 'HIPAA', sublabel: 'BAA Available' },
              { icon: FileText, label: 'ISO 27001', sublabel: 'Certified' },
            ].map((item) => (
              <div key={item.label} className="text-center">
                <item.icon className="w-6 h-6 text-primary-400 mx-auto mb-2" />
                <div className="text-white font-medium">{item.label}</div>
                <div className="text-xs text-surface-500">{item.sublabel}</div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Bottom Note */}
        <motion.p
          initial={{ opacity: 0 }}
          animate={inView ? { opacity: 1 } : {}}
          transition={{ delay: 0.3 }}
          className="text-center text-sm text-surface-500 mt-8"
        >
          All compliance documentation, audit reports, and certifications available upon request.
          <br />
          Contact{' '}
          <a href="mailto:compliance@apexmail.io" className="text-primary-400 hover:underline">
            compliance@apexmail.io
          </a>{' '}
          for custom security questionnaires.
        </motion.p>
      </div>
    </section>
  );
}
