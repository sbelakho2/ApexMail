'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ArrowRight, Calendar, Cloud, Phone } from '@/components/ui/icons';
import Link from 'next/link';

export function PrivateCloudCTA() {
 const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

 return (
 <section ref={ref} className="py-24 relative bg-white">
 <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 relative">
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 className="bg-surface-50/50 rounded-2xl border border-surface-200 p-8 md:p-12 text-center"
 >
 <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-white border border-surface-200 text-xs font-medium text-surface-900 mb-6 shadow-sm">
            <Cloud className="w-4 h-4" />
            Enterprise Ready
          </div>

 <h2 className="text-3xl md:text-4xl font-bold text-surface-900 mb-6 tracking-tight">
 Deploy in Your Cloud This Week
 </h2>
 <p className="text-lg text-surface-600 mb-10 max-w-2xl mx-auto leading-relaxed">
 Our solutions architects will work with your team to design and deploy 
 a private ApexMail instance tailored to your security requirements.
 </p>

 <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
 <Link
 href="/contact/enterprise"
 className="inline-flex items-center justify-center px-6 py-3 text-sm font-semibold text-white bg-primary-600 rounded-md hover:bg-primary-700 transition-colors"
 >
 Talk to Sales
 <ArrowRight className="w-4 h-4 ml-2" />
 </Link>
 <Link
 href="/docs/private-cloud/architecture"
 className="inline-flex items-center justify-center px-6 py-3 text-sm font-semibold text-surface-900 bg-white border border-surface-200 rounded-md hover:bg-surface-50 transition-colors"
 >
 <Calendar className="w-4 h-4 mr-2" />
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
 <div className="text-surface-500 font-medium text-xs mb-1">{step.day}</div>
 <div className="text-surface-900 font-semibold text-sm mb-1">{step.title}</div>
 <div className="text-xs text-surface-500">{step.description}</div>
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
 <div className="bg-white rounded-lg border border-surface-200 p-6 flex items-center gap-4 hover:border-surface-300 transition-colors cursor-pointer">
 <div className="w-10 h-10 rounded-lg bg-surface-50 flex items-center justify-center flex-shrink-0 border border-surface-200">
 <Phone className="w-5 h-5 text-surface-900" strokeWidth={1.5} />
 </div>
 <div>
 <div className="text-surface-900 font-semibold text-sm">Talk to an Engineer</div>
 <div className="text-xs text-surface-500 mt-0.5">
 Get a technical deep-dive with our solutions team
 </div>
 </div>
 </div>
 <div className="bg-white rounded-lg border border-surface-200 p-6 flex items-center gap-4 hover:border-surface-300 transition-colors cursor-pointer">
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
 <p className="text-xs font-bold text-surface-600 mb-6">
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
