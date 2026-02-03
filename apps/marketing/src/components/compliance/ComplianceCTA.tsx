'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ArrowRight, Calendar, Shield, FileText } from 'lucide-react';
import Link from 'next/link';

export function ComplianceCTA() {
 const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

 return (
 <section ref={ref} className="py-20 lg:py-32 relative bg-surface-50">
 <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative">
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 className="premium-card p-8 lg:p-12 text-center bg-white "
 >
 <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-50 text-primary-700 border border-primary-100 text-[10px] font-bold uppercase tracking-widest mb-6">
 <Shield className="w-4 h-4" />
 Enterprise Compliance
 </div>

 <h2 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-4 tracking-tight">
 Ready to Sleep Better at Night?
 </h2>
 <p className="text-lg text-surface-600 mb-10 max-w-2xl mx-auto leading-relaxed font-medium">
 Join 2,000+ companies that trust ApexMail for their compliance-critical email infrastructure. 
 Get a personalized compliance assessment from our DPO team.
 </p>

 <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
 <Link
 href="/signup"
 className="btn-primary text-lg px-8 py-4"
 >
 Start Free Trial
 <ArrowRight className="w-5 h-5 ml-2" />
 </Link>
 <Link
 href="/contact/compliance"
 className="btn-secondary text-lg px-8 py-4 bg-white"
 >
 <Calendar className="w-5 h-5 mr-2" />
 Talk to Compliance Team
 </Link>
 </div>

 {/* Trust Signals */}
 <div className="grid grid-cols-2 md:grid-cols-4 gap-8 pt-10 border-t border-surface-100">
 {[
 { icon: Shield, label: 'SOC 2 Type II', sublabel: 'Certified' },
 { icon: FileText, label: 'GDPR', sublabel: 'Compliant' },
 { icon: Shield, label: 'HIPAA', sublabel: 'BAA Available' },
 { icon: FileText, label: 'ISO 27001', sublabel: 'Certified' },
 ].map((item) => (
 <div key={item.label} className="text-center">
 <div className="w-10 h-10 rounded-full bg-primary-50 flex items-center justify-center mx-auto mb-3 border border-primary-100">
 <item.icon className="w-5 h-5 text-primary-600" />
 </div>
 <div className="text-surface-900 font-bold text-sm mb-1">{item.label}</div>
 <div className="text-[10px] text-surface-600 font-bold uppercase tracking-tight">{item.sublabel}</div>
 </div>
 ))}
 </div>
 </motion.div>

 {/* Bottom Note */}
 <motion.p
 initial={{ opacity: 0 }}
 animate={inView ? { opacity: 1 } : {}}
 transition={{ delay: 0.3 }}
 className="text-center text-sm font-medium text-surface-500 mt-10"
 >
 All compliance documentation, audit reports, and certifications available upon request.
 <br />
 Contact{' '}
 <a href="mailto:compliance@apexmail.ee" className="text-primary-600 font-bold hover:underline">
 compliance@apexmail.ee
 </a>{' '}
 for custom security questionnaires.
 </motion.p>
 </div>
 </section>
 );
}
