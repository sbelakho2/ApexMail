'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { FileText, Download, CheckCircle } from 'lucide-react';

export function AutoDPA() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 relative bg-surface-900/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
          {/* Left - Copy */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={inView ? { opacity: 1, x: 0 } : {}}
          >
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-green-500/10 text-green-400 text-sm mb-4">
              <FileText className="w-4 h-4" />
              Auto-DPA
            </div>
            <h2 className="text-3xl lg:text-4xl font-bold text-white mb-4">
              Data Processing Agreements on Autopilot
            </h2>
            <p className="text-lg text-surface-400 mb-6">
              No more back-and-forth with legal teams. Generate compliant DPAs instantly, 
              customized to your jurisdiction and processing activities.
            </p>

            <ul className="space-y-4 mb-8">
              {[
                'Pre-approved by EU data protection authorities',
                'Automatically includes your processing activities',
                'Standard Contractual Clauses (SCCs) included',
                'Versioned and timestamped for audit trails',
                'Digital signatures with legal validity',
              ].map((item) => (
                <li key={item} className="flex items-start gap-3 text-surface-300">
                  <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                  {item}
                </li>
              ))}
            </ul>
          </motion.div>

          {/* Right - Visual */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={inView ? { opacity: 1, x: 0 } : {}}
            transition={{ delay: 0.2 }}
          >
            <div className="glass-card p-6">
              {/* Document Preview */}
              <div className="bg-white rounded-lg p-6 mb-4">
                <div className="flex items-center gap-3 mb-4">
                  <FileText className="w-8 h-8 text-blue-600" />
                  <div>
                    <div className="font-semibold text-gray-900">Data Processing Agreement</div>
                    <div className="text-sm text-gray-500">Generated: Feb 15, 2024</div>
                  </div>
                </div>
                <div className="space-y-2 text-sm text-gray-600">
                  <div className="h-2 bg-gray-200 rounded w-full" />
                  <div className="h-2 bg-gray-200 rounded w-5/6" />
                  <div className="h-2 bg-gray-200 rounded w-4/5" />
                </div>
                <div className="mt-4 pt-4 border-t border-gray-200">
                  <div className="text-xs text-gray-500 mb-2">Includes:</div>
                  <div className="flex flex-wrap gap-2">
                    {['GDPR Art. 28', 'SCCs', 'Sub-processors', 'Security Measures'].map((item) => (
                      <span key={item} className="px-2 py-1 bg-blue-50 text-blue-700 text-xs rounded">
                        {item}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Actions */}
              <div className="flex gap-3">
                <button className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-500 transition-colors">
                  <Download className="w-4 h-4" />
                  Download PDF
                </button>
                <button className="flex-1 flex items-center justify-center gap-2 px-4 py-2 border border-surface-600 text-surface-300 rounded-lg hover:border-surface-500 transition-colors">
                  Send for Signature
                </button>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
