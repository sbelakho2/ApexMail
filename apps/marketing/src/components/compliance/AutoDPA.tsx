'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { FileText, Download, CheckCircle } from 'lucide-react';

export function AutoDPA() {
 const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

 return (
 <section ref={ref} className="py-20 lg:py-32 relative bg-white">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
 {/* Left - Copy */}
 <motion.div
 initial={{ opacity: 0, x: -20 }}
 animate={inView ? { opacity: 1, x: 0 } : {}}
 >
 <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-green-50 text-green-700 border border-green-100 text-[10px] font-bold uppercase tracking-widest mb-4">
            <FileText className="w-4 h-4" />
            Auto-DPA
          </div>
 <h2 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-4 tracking-tight">
 Data Processing Agreements on Autopilot
 </h2>
 <p className="text-lg text-surface-600 mb-8 font-medium leading-relaxed">
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
 <li key={item} className="flex items-start gap-3 text-surface-700 font-bold text-sm">
 <CheckCircle className="w-5 h-5 text-primary-600 flex-shrink-0 mt-0.5" strokeWidth={3} />
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
 <div className="premium-card p-8 bg-surface-50">
 {/* Document Preview */}
 <div className="bg-white rounded-xl p-8 mb-6 border border-surface-200 ">
 <div className="flex items-center gap-4 mb-6">
 <div className="w-12 h-12 rounded-lg bg-primary-50 flex items-center justify-center border border-primary-100">
 <FileText className="w-7 h-7 text-primary-600" />
 </div>
 <div>
 <div className="font-bold text-surface-900">Data Processing Agreement</div>
 <div className="text-[10px] font-bold text-surface-400 uppercase tracking-widest">Generated: Feb 15, 2024</div>
 </div>
 </div>
 <div className="space-y-3 mb-6">
 <div className="h-2 bg-surface-50 rounded-full w-full" />
 <div className="h-2 bg-surface-50 rounded-full w-5/6" />
 <div className="h-2 bg-surface-50 rounded-full w-4/5" />
 </div>
 <div className="mt-6 pt-6 border-t border-surface-100">
 <div className="text-[10px] font-bold text-surface-400 mb-3 uppercase tracking-widest">Included Clauses:</div>
 <div className="flex flex-wrap gap-2">
 {['GDPR Art. 28', 'SCCs', 'Sub-processors', 'Security Measures'].map((item) => (
 <span key={item} className="px-2 py-1 bg-surface-100 text-surface-600 text-[10px] font-bold uppercase tracking-tight rounded-md border border-surface-200">
 {item}
 </span>
 ))}
 </div>
 </div>
 </div>

 {/* Actions */}
 <div className="flex gap-4">
 <button className="btn-primary flex-1 py-3 text-xs font-bold uppercase tracking-widest">
 <Download className="w-4 h-4 mr-2" />
 Download PDF
 </button>
 <button className="btn-secondary flex-1 py-3 bg-white text-xs font-bold uppercase tracking-widest">
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
