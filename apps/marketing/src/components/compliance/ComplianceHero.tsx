'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';
import { Shield, Scale, FileCheck, Lock, ArrowRight } from 'lucide-react';

const badges = [
 { name: 'GDPR' },
 { name: 'HIPAA' },
 { name: 'SOC 2' },
 { name: 'CCPA' },
 { name: 'ISO 27001' },
];

export function ComplianceHero() {
 return (
 <section className="relative min-h-screen flex items-center pt-32 pb-20 overflow-hidden bg-surface-50">
 <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 lg:py-20">
 <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
 {/* Left Column */}
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={{ opacity: 1, y: 0 }}
 transition={{ duration: 0.5 }}
 >
 {/* Badge */}
 <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-md bg-primary-50 border border-primary-100 text-[10px] font-bold uppercase tracking-widest text-primary-700 mb-6">
            <Shield className="w-4 h-4" />
            Compliance-as-Code
          </div>

 {/* Headline */}
 <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-6 leading-tight">
 <span className="text-surface-900">The Email API That</span>
 <br />
 <span className="text-primary-600">
 Keeps You Out of Court
 </span>
 </h1>

 {/* Subheadline */}
 <p className="text-lg lg:text-xl text-surface-600 mb-10 leading-relaxed font-medium">
 Stop treating compliance as an afterthought. ApexMail bakes GDPR, HIPAA, 
 and SOC 2 requirements directly into the infrastructure layer.
 </p>

 {/* Key Points */}
 <ul className="space-y-6 mb-10">
 {[
 { icon: FileCheck, text: 'Immutable consent ledger with cryptographic proofs' },
 { icon: Scale, text: 'Auto-generated DPAs that satisfy EU regulators' },
 { icon: Lock, text: 'One-click "Right-to-be-Forgotten" cascade deletion' },
 ].map((point) => (
 <li key={point.text} className="flex items-start gap-4">
 <span className="w-10 h-10 rounded-md bg-primary-50 flex items-center justify-center flex-shrink-0 border border-primary-100">
 <point.icon className="w-5 h-5 text-primary-600" />
 </span>
 <span className="text-surface-700 font-bold text-sm leading-tight mt-2.5">{point.text}</span>
 </li>
 ))}
 </ul>

 {/* CTA */}
 <div className="flex flex-wrap gap-4">
 <Link href="https://app.apexmail.ee/signup" className="btn-primary flex items-center gap-2 text-lg px-8 py-4">
 Start Free Trial
 <ArrowRight className="w-5 h-5 ml-2" />
 </Link>
 <Link href="/contact" className="btn-secondary text-lg px-8 py-4 bg-white">
 Compliance Review
 </Link>
 </div>
 </motion.div>

 {/* Right Column - Compliance Badges */}
 <motion.div
 initial={{ opacity: 0, x: 20 }}
 animate={{ opacity: 1, x: 0 }}
 transition={{ duration: 0.5, delay: 0.2 }}
 className="relative"
 >
 <div className="premium-card p-10 bg-white">
 <h3 className="text-[10px] font-bold text-surface-400 uppercase tracking-widest mb-10 text-center">
 Compliance Certifications
 </h3>
 <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
 {badges.map((badge, index) => (
 <motion.div
 key={badge.name}
 initial={{ opacity: 0, scale: 0.8 }}
 animate={{ opacity: 1, scale: 1 }}
 transition={{ delay: 0.3 + index * 0.1 }}
 className="aspect-square rounded-lg bg-surface-50 border border-surface-100 flex flex-col items-center justify-center p-4 hover:border-primary-200 transition-all group"
 >
 <div className="w-12 h-12 rounded-md bg-primary-50 flex items-center justify-center mb-3 border border-primary-100 group-hover:bg-primary-100 transition-colors">
 <Shield className="w-6 h-6 text-primary-600" />
 </div>
 <span className="text-[10px] font-bold text-surface-900 uppercase tracking-widest">{badge.name}</span>
 </motion.div>
 ))}
 </div>
 <div className="mt-10 p-4 rounded-lg bg-emerald-50 border border-emerald-100 ">
 <div className="flex items-center gap-3 text-emerald-700 text-[10px] font-bold uppercase tracking-widest">
 <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
 Verified and Current
 </div>
 </div>
 </div>
 </motion.div>
 </div>
 </div>
 </section>
 );
}
