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
 <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold tracking-tight mb-6">
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
 <div className="grid sm:grid-cols-2 gap-4 max-w-2xl mx-auto mb-12 p-6 rounded-2xl bg-surface-50 border border-surface-100/60">
   {ctaFeatures.map((feature, index) => (
     <motion.div
       key={feature.text}
       initial={{ opacity: 0, x: -20 }}
       animate={inView ? { opacity: 1, x: 0 } : {}}
       transition={{ delay: 0.2 + index * 0.1 }}
       className="flex items-center gap-3 text-left"
     >
       <div className="w-8 h-8 rounded-lg bg-white flex items-center justify-center flex-shrink-0 border border-surface-200 shadow-sm">
         <feature.icon className="w-4 h-4 text-primary-600" />
       </div>
       <span className="text-surface-700 text-[15px] font-medium">{feature.text}</span>
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
     className="btn-primary text-[17px] font-bold px-8 py-4 flex items-center gap-2 group w-full sm:w-auto justify-center rounded-xl shadow-xl shadow-primary-500/20 hover:shadow-2xl hover:shadow-primary-500/30 active:scale-[0.98] transition-all"
   >
     Start Sending Free
     <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
   </Link>
   <Link
     href="/contact"
     className="btn-secondary text-[17px] font-bold px-8 py-4 w-full sm:w-auto justify-center bg-white hover:bg-surface-50 rounded-xl border-surface-200 active:scale-[0.98] transition-all"
   >
     Talk to Sales
   </Link>
 </motion.div>

 {/* Trust Badges */}
 <motion.div
 initial={{ opacity: 0 }}
 animate={inView ? { opacity: 1 } : {}}
 transition={{ delay: 0.6 }}
 className="flex flex-wrap items-center justify-center gap-6 text-surface-500 text-sm font-medium"
 >
 <span className="flex items-center gap-2">
 <span className="w-2 h-2 rounded-full bg-green-500"></span>
 99.99% Uptime SLA
 </span>
 <span className="flex items-center gap-2">
 <span className="w-2 h-2 rounded-full bg-primary-500"></span>
 SOC 2 Certified
 </span>
 <span className="flex items-center gap-2">
 <span className="w-2 h-2 rounded-full bg-primary-500"></span>
 GDPR Compliant
 </span>
 <span className="flex items-center gap-2">
 <span className="w-2 h-2 rounded-full bg-orange-500"></span>
 24/7 Support
 </span>
 </motion.div>
 </motion.div>
 </div>
 </section>
 );
}
