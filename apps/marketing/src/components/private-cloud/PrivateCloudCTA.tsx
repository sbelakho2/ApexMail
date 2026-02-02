'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ArrowRight, Calendar, Cloud, Phone } from 'lucide-react';
import Link from 'next/link';

export function PrivateCloudCTA() {
 const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

 return (
 <section ref={ref} className="py-20 lg:py-32 relative bg-white">
 <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative">
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 className="premium-card p-8 lg:p-12 text-center bg-surface-50"
 >
 <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-primary-50 text-primary-700 border border-primary-100 text-[10px] font-bold uppercase tracking-widest mb-6">
            <Cloud className="w-4 h-4" />
            Enterprise Ready
          </div>

 <h2 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-4 tracking-tight">
 Deploy in Your Cloud This Week
 </h2>
 <p className="text-lg text-surface-600 mb-10 max-w-2xl mx-auto leading-relaxed font-medium">
 Our solutions architects will work with your team to design and deploy 
 a private ApexMail instance tailored to your security requirements.
 </p>

 <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
 <Link
 href="/contact/enterprise"
 className="btn-primary text-lg px-8 py-4"
 >
 Talk to Sales
 <ArrowRight className="w-5 h-5 ml-2" />
 </Link>
 <Link
 href="/docs/private-cloud/architecture"
 className="btn-secondary text-lg px-8 py-4 bg-white"
 >
 <Calendar className="w-5 h-5 mr-2" />
 Architecture Review
 </Link>
 </div>

 {/* Deployment Timeline */}
 <div className="grid md:grid-cols-4 gap-6 pt-10 border-t border-surface-200">
 {[
 { day: 'Day 1', title: 'Architecture Review', description: 'Design deployment' },
 { day: 'Day 2-3', title: 'Infrastructure', description: 'Provision resources' },
 { day: 'Day 4', title: 'Deployment', description: 'Install ApexMail' },
 { day: 'Day 5', title: 'Go Live', description: 'Production ready' },
 ].map((step) => (
 <div key={step.day} className="text-center relative">
 <div className="text-primary-600 font-bold text-[10px] uppercase tracking-widest mb-1">{step.day}</div>
 <div className="text-surface-900 font-bold text-sm mb-1">{step.title}</div>
 <div className="text-[10px] text-surface-500 font-bold uppercase tracking-tight">{step.description}</div>
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
 <div className="premium-card p-6 flex items-center gap-4 bg-white">
 <div className="w-12 h-12 rounded-md bg-primary-50 flex items-center justify-center flex-shrink-0 border border-primary-100">
 <Phone className="w-6 h-6 text-primary-600" />
 </div>
 <div>
 <div className="text-surface-900 font-bold">Talk to an Engineer</div>
 <div className="text-xs text-surface-500 font-medium">
 Get a technical deep-dive with our solutions team
 </div>
 </div>
 </div>
 <div className="premium-card p-6 flex items-center gap-4 bg-white">
 <div className="w-12 h-12 rounded-md bg-primary-50 flex items-center justify-center flex-shrink-0 border border-primary-100">
 <Calendar className="w-6 h-6 text-primary-600" />
 </div>
 <div>
 <div className="text-surface-900 font-bold">Proof of Concept</div>
 <div className="text-xs text-surface-500 font-medium">
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
 <p className="text-[10px] font-bold text-surface-400 uppercase tracking-widest mb-6">
 Trusted by security-conscious enterprises
 </p>
 <div className="flex flex-wrap justify-center gap-12 opacity-40 grayscale">
 {['Fortune 500 Bank', 'Healthcare Provider', 'Government Agency', 'Defense Contractor'].map(
 (customer) => (
 <span key={customer} className="text-surface-900 font-bold text-sm">
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
