'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Check, X, ArrowRight } from 'lucide-react';
import Link from 'next/link';
import { cn } from '@/lib/utils';

const comparisonData = {
 categories: [
 {
 name: 'Deliverability',
 features: [
 { name: 'Delivery Rate', apexmail: '99.9%', sendgrid: '97%', mailchimp: '92%', ses: '95%' },
 { name: 'Dedicated IP Included', apexmail: 'Growth+', sendgrid: 'Pro+', mailchimp: 'Premium', ses: 'Manual' },
 { name: 'IP Warming Automation', apexmail: true, sendgrid: true, mailchimp: false, ses: false },
 { name: 'Reputation Circuit Breaker', apexmail: true, sendgrid: false, mailchimp: false, ses: false },
 ],
 },
 {
 name: 'Compliance',
 features: [
 { name: 'GDPR Compliance Tools', apexmail: 'Native', sendgrid: 'Basic', mailchimp: 'Basic', ses: 'None' },
 { name: 'HIPAA BAA', apexmail: true, sendgrid: 'Enterprise', mailchimp: false, ses: true },
 { name: 'Cryptographic Proof of Delivery', apexmail: true, sendgrid: false, mailchimp: false, ses: false },
 { name: 'Auto-Generated DPA', apexmail: true, sendgrid: false, mailchimp: false, ses: false },
 { name: 'Right-to-be-Forgotten Cascade', apexmail: true, sendgrid: false, mailchimp: false, ses: false },
 ],
 },
 {
 name: 'Infrastructure',
 features: [
 { name: 'True Single-Tenant Option', apexmail: true, sendgrid: false, mailchimp: false, ses: false },
 { name: 'Private Cloud Deploy', apexmail: true, sendgrid: false, mailchimp: false, ses: 'N/A' },
 { name: 'BYOIP Support', apexmail: true, sendgrid: false, mailchimp: false, ses: true },
 { name: 'Air-Gapped AI', apexmail: true, sendgrid: false, mailchimp: false, ses: false },
 ],
 },
 {
 name: 'Developer Experience',
 features: [
 { name: 'Time to First Email', apexmail: '< 10 sec', sendgrid: '5 min', mailchimp: '10+ min', ses: '30+ min' },
 { name: 'No Credit Card Trial', apexmail: true, sendgrid: true, mailchimp: true, ses: false },
 { name: 'Webhook Signatures', apexmail: true, sendgrid: true, mailchimp: true, ses: false },
 { name: 'Idempotency Keys', apexmail: true, sendgrid: false, mailchimp: false, ses: false },
 { name: 'Forensic Render History', apexmail: true, sendgrid: false, mailchimp: false, ses: false },
 ],
 },
 ],
};

const renderValue = (value: boolean | string) => {
 if (typeof value === 'boolean') {
 return value ? (
 <Check className="w-5 h-5 text-primary-600" />
 ) : (
 <X className="w-5 h-5 text-surface-400" />
 );
 }
 return <span className="text-sm tabular-nums">{value}</span>;
};

export function ComparisonSection() {
 const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

 return (
 <section ref={ref} className="py-20 lg:py-32 relative bg-surface-50">
 <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 {/* Header */}
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 className="text-center mb-12"
 >
 <h2 className="section-title mb-4">
 <span className="text-surface-900">See How We</span>{' '}
 <span className="text-primary-500">Stack Up</span>
 </h2>
 <p className="text-surface-600 text-[17px] max-w-2xl mx-auto leading-relaxed">
 We built ApexMail because we were tired of email providers that treat 
 compliance as an afterthought and developers as an inconvenience.
 </p>
 </motion.div>

 {/* Comparison Table */}
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.2 }}
 className="premium-card overflow-hidden bg-white"
 >
 {/* Table Header */}
 <div className="grid grid-cols-5 gap-4 p-4 lg:p-6 border-b border-surface-200 bg-surface-50">
   <div className="font-bold text-surface-400 uppercase tracking-widest text-[11px] flex items-center">Feature</div>
   <div className="text-center">
     <div className="font-bold text-primary-600">ApexMail</div>
     <div className="text-[10px] text-primary-500 uppercase font-bold tracking-tight">Recommended</div>
   </div>
   <div className="text-center text-surface-900">
     <div className="font-medium">SendGrid</div>
     <div className="text-[10px] text-surface-400 font-bold uppercase tracking-widest">Twilio</div>
   </div>
   <div className="text-center text-surface-900">
     <div className="font-medium">Mailchimp</div>
     <div className="text-[10px] text-surface-400 font-bold uppercase tracking-widest">Intuit</div>
   </div>
   <div className="text-center text-surface-900">
     <div className="font-medium">AWS SES</div>
     <div className="text-[10px] text-surface-400 font-bold uppercase tracking-widest">Amazon</div>
   </div>
 </div>

 {/* Categories */}
 {comparisonData.categories.map((category, categoryIndex) => (
 <div key={category.name}>
 {/* Category Header */}
 <div className="px-4 lg:px-6 py-3 bg-surface-50 border-b border-surface-100">
 <span className="text-[11px] font-bold text-surface-400 uppercase tracking-widest">
 {category.name}
 </span>
 </div>

 {/* Features */}
 {category.features.map((feature, featureIndex) => (
 <motion.div
 key={feature.name}
 initial={{ opacity: 0, x: -20 }}
 animate={inView ? { opacity: 1, x: 0 } : {}}
 transition={{ delay: categoryIndex * 0.1 + featureIndex * 0.05 }}
 className={cn(
 'grid grid-cols-5 gap-4 px-4 lg:px-6 py-4 items-center hover:bg-surface-50 transition-colors',
 featureIndex !== category.features.length - 1 && 'border-b border-surface-100'
 )}
 >
 <div className="text-sm font-medium text-surface-700">{feature.name}</div>
 <div className="flex justify-center font-bold text-primary-700">
 {renderValue(feature.apexmail)}
 </div>
 <div className="flex justify-center text-surface-500">
 {renderValue(feature.sendgrid)}
 </div>
 <div className="flex justify-center text-surface-500">
 {renderValue(feature.mailchimp)}
 </div>
 <div className="flex justify-center text-surface-500">
 {renderValue(feature.ses)}
 </div>
 </motion.div>
 ))}
 </div>
 ))}
 </motion.div>

 {/* Bottom CTA */}
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.4 }}
 className="mt-12 text-center"
 >
 <p className="text-surface-600 mb-6 font-medium">
 Still not convinced? See the full feature comparison or talk to our team.
 </p>
 <div className="flex flex-wrap justify-center gap-4">
 <Link href="/features" className="btn-secondary flex items-center gap-2">
 Full Feature List
 <ArrowRight className="w-4 h-4" />
 </Link>
 <Link href="/contact" className="btn-primary flex items-center gap-2">
 Talk to Sales
 <ArrowRight className="w-4 h-4" />
 </Link>
 </div>
 </motion.div>
 </div>
 </section>
 );
}
