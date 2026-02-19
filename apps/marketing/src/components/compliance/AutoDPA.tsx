'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { FileText, Download, CheckCircle } from '@/components/ui/icons';

export function AutoDPA() {
 const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

 return (
 <section ref={ref} className="py-24 relative bg-white">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
 {/* Left - Copy */}
 <motion.div
 initial={{ opacity: 0, y: 16 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 >
 <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-50 border border-emerald-100/50 text-xs font-medium text-emerald-700 mb-6">
            <FileText className="w-4 h-4" />
            Auto-DPA
          </div>
 <h2 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-surface-900 mb-6 tracking-tight break-words">
 Data Processing Agreements on Autopilot
 </h2>
 <p className="text-lg text-surface-600 mb-8 leading-relaxed">
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
 <li key={item} className="flex items-start gap-3 text-surface-700 text-sm leading-relaxed">
 <CheckCircle className="w-5 h-5 text-surface-900 flex-shrink-0 mt-0.5" strokeWidth={1.5} />
 {item}
 </li>
 ))}
 </ul>
 </motion.div>

 {/* Right - Visual */}
 <motion.div
 initial={{ opacity: 0, y: 16 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.2 }}
 >
 <div className="bg-white rounded-lg border border-surface-200 p-6 sm:p-8 shadow-sm">
 {/* Document Preview */}
 <div className="bg-surface-50/50 rounded-lg p-6 mb-6 border border-surface-200">
 <div className="flex items-center gap-4 mb-6">
 <div className="w-10 h-10 rounded-lg bg-white flex items-center justify-center border border-surface-200 shadow-sm">
 <FileText className="w-5 h-5 text-surface-900" strokeWidth={1.5} />
 </div>
 <div>
 <div className="font-semibold text-surface-900 text-sm mb-0.5">Data Processing Agreement</div>
 <div className="text-xs text-surface-500">Generated: Feb 15, 2024</div>
 </div>
 </div>
 <div className="space-y-3 mb-6 opacity-60">
 <div className="h-1.5 bg-surface-200 rounded-full w-full" />
 <div className="h-1.5 bg-surface-200 rounded-full w-5/6" />
 <div className="h-1.5 bg-surface-200 rounded-full w-4/5" />
 </div>
 <div className="mt-6 pt-6 border-t border-surface-200">
 <div className="text-xs font-semibold text-surface-900 mb-3">Included Clauses:</div>
 <div className="flex flex-wrap gap-2">
 {['GDPR Art. 28', 'SCCs', 'Sub-processors', 'Security Measures'].map((item) => (
 <span key={item} className="px-2 py-1 bg-white text-surface-600 text-xs font-medium rounded border border-surface-200">
 {item}
 </span>
 ))}
 </div>
 </div>
 </div>

 {/* Actions */}
 <div className="flex gap-4">
 <button className="flex-1 py-2.5 px-4 text-sm font-semibold text-white bg-primary-600 rounded-md hover:bg-primary-700 transition-colors flex items-center justify-center">
 <Download className="w-4 h-4 mr-2" />
 Download PDF
 </button>
 <button className="flex-1 py-2.5 px-4 text-sm font-semibold text-surface-700 bg-white border border-surface-200 rounded-md hover:bg-surface-50 transition-colors">
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
