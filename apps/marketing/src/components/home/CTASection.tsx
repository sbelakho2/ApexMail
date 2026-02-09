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
 <section ref={ref} className="py-20 lg:py-32 relative overflow-hidden bg-white">
 <div className="relative max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 className="text-center"
 >
 {/* Headline */}
 <h2 className="mb-6">
 <span className="text-surface-900">Ready to Ship</span>
 <br />
 <span className="text-primary-500">Better Email?</span>
 </h2>

 {/* Subheadline */}
 <p className="text-xl text-surface-600 max-w-2xl mx-auto mb-10 leading-relaxed font-medium">
   Join thousands of developers who trust ApexMail for their 
   mission-critical email infrastructure. Start free, scale infinitely.
 </p>

 {/* Features List */}
 <div className="grid sm:grid-cols-2 gap-x-8 gap-y-4 max-w-2xl mx-auto mb-12">
   {ctaFeatures.map((feature, index) => (
     <motion.div
       key={feature.text}
       initial={{ opacity: 0, x: -20 }}
       animate={inView ? { opacity: 1, x: 0 } : {}}
       transition={{ delay: 0.2 + index * 0.1 }}
       className="flex items-center gap-3 text-left"
     >
       <div className="w-6 h-6 rounded bg-surface-100 flex items-center justify-center flex-shrink-0 text-surface-600">
         <feature.icon className="w-4 h-4" />
       </div>
       <span className="text-surface-600 text-sm font-bold uppercase tracking-wide">{feature.text}</span>
     </motion.div>
   ))}
 </div>

 {/* CTA Buttons */}
 <motion.div
   initial={{ opacity: 0, y: 20 }}
   animate={inView ? { opacity: 1, y: 0 } : {}}
   transition={{ delay: 0.4 }}
   className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16"
 >
   <Link
     href="https://app.apexmail.ee/signup"
     className="inline-flex items-center justify-center px-8 py-4 text-base font-bold text-white bg-primary-600 rounded-md hover:bg-primary-700 transition-colors w-full sm:w-auto shadow-lg shadow-primary-500/20"
   >
     Deploy to Production
     <ArrowRight className="w-4 h-4 ml-2" />
   </Link>
   <Link
     href="/contact"
     className="inline-flex items-center justify-center px-8 py-4 text-base font-bold text-surface-900 bg-white border border-surface-200 rounded-md hover:bg-surface-50 transition-colors w-full sm:w-auto"
   >
     Book Architecture Review
   </Link>
 </motion.div>

 {/* Trust Badges */}
 <motion.div
 initial={{ opacity: 0 }}
 animate={inView ? { opacity: 1 } : {}}
 transition={{ delay: 0.6 }}
 className="flex flex-wrap items-center justify-center gap-6 text-surface-600 text-xs font-bold uppercase tracking-widest"
 >
 <span className="flex items-center gap-2">
 <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)]"></span>
 99.99% Uptime SLA
 </span>
 <span className="flex items-center gap-2">
 <span className="w-1.5 h-1.5 rounded-full bg-primary-500 shadow-[0_0_8px_rgba(37,99,235,0.4)]"></span>
 SOC 2 Certified
 </span>
 <span className="flex items-center gap-2">
 <span className="w-1.5 h-1.5 rounded-full bg-primary-500 shadow-[0_0_8px_rgba(37,99,235,0.4)]"></span>
 GDPR Compliant
 </span>
 <span className="flex items-center gap-2">
 <span className="w-1.5 h-1.5 rounded-full bg-surface-400"></span>
 24/7 Support
 </span>
 </motion.div>
 </motion.div>
 </div>
 </section>
 );
}
