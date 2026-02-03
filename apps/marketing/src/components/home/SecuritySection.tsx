'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Shield, Lock, Key, Eye, Server, FileCheck, AlertTriangle, Fingerprint } from 'lucide-react';

const securityFeatures = [
 {
 icon: Lock,
 title: 'End-to-End Encryption',
 description: 'TLS 1.3 in transit, AES-256 at rest. Your email content is encrypted at every stage.',
 },
 {
 icon: Fingerprint,
 title: 'Cryptographic Signing',
 description: 'Every delivery event is cryptographically signed in an immutable hash chain. Tamper-evident by design.',
 },
 {
 icon: AlertTriangle,
 title: 'Active Threat Detection',
 description: 'Built-in honeytokens and canary tokens alert you instantly when attackers probe your system.',
 },
 {
 icon: Eye,
 title: 'Zero-Retention Mode',
 description: 'Process emails entirely in RAM. No logs, no content storage, no risk. Perfect for PII processing.',
 },
 {
 icon: Server,
 title: 'SOC 2 Type II Certified',
 description: 'Annual third-party audits verify our security controls meet the highest standards.',
 },
 {
 icon: Key,
 title: 'API Key Security',
 description: 'Scoped API keys, automatic rotation, IP allowlists, and real-time usage monitoring.',
 },
];

const complianceLogos = [
 { name: 'GDPR', description: 'EU Data Protection' },
 { name: 'HIPAA', description: 'Healthcare Ready' },
 { name: 'SOC 2', description: 'Type II Certified' },
 { name: 'CCPA', description: 'California Privacy' },
 { name: 'ISO 27001', description: 'Security Standard' },
];

export function SecuritySection() {
 const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

 return (
 <section ref={ref} className="py-20 lg:py-32 relative bg-white">
 <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 {/* Header */}
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 className="text-center mb-16"
 >
 <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-md bg-primary-50 border border-primary-100 text-sm text-primary-700 mb-6 font-medium">
          <Shield className="w-4 h-4" />
          Enterprise-Grade Security
        </div>
 <h2 className="section-title mb-4">
 <span className="text-surface-900">Security That</span>{' '}
 <span className="text-primary-500">Actually Works</span>
 </h2>
 <p className="text-surface-600 text-[17px] max-w-2xl mx-auto leading-relaxed">
 We don&apos;t just check compliance boxes. We built security into the foundation, 
 not as an afterthought.
 </p>
 </motion.div>

 {/* Security Features Grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 mb-16">
          {securityFeatures.map((feature, index) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 20 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ delay: index * 0.1 }}
              className="premium-card p-6 group bg-white hover:bg-surface-50"
            >
              <div className="w-12 h-12 rounded-lg bg-primary-50 flex items-center justify-center border border-primary-100 mb-6 group-hover:scale-110 transition-transform duration-300">
                <feature.icon className="w-6 h-6 text-primary-600" />
              </div>
              <h3 className="text-lg font-bold text-surface-900 mb-3 group-hover:text-primary-600 transition-colors">
                {feature.title}
              </h3>
              <p className="text-surface-600 text-[14px] leading-relaxed">
                {feature.description}
              </p>
            </motion.div>
          ))}
        </div>

 {/* Compliance Badges */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.6 }}
          className="premium-card p-10 bg-surface-50 border-surface-200/50"
        >
          <div className="flex flex-col lg:flex-row items-center justify-between gap-10">
            <div className="text-center lg:text-left">
              <h3 className="text-xl font-bold text-surface-900 mb-2">Compliance Certifications</h3>
              <p className="text-surface-600 leading-relaxed max-w-md">
                Verified by independent auditors and regularly renewed to ensure your data remains protected.
              </p>
            </div>
            <div className="flex flex-wrap items-center justify-center gap-8">
              {complianceLogos.map((logo) => (
                <div key={logo.name} className="flex flex-col items-center group">
                  <div className="w-20 h-20 rounded-xl bg-white border border-surface-200 flex items-center justify-center mb-3 shadow-sm group-hover:shadow-md group-hover:-translate-y-1 transition-all duration-300">
                    <span className="text-xl font-bold text-primary-600 tracking-tighter">{logo.name}</span>
                  </div>
                  <div className="text-[10px] text-surface-400 font-bold uppercase tracking-widest whitespace-nowrap">{logo.description}</div>
                </div>
              ))}
            </div>
          </div>
        </motion.div>

 {/* Security Promise */}
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.8 }}
 className="mt-12 text-center"
 >
 <div className="inline-flex items-center gap-3 premium-card px-6 py-4 bg-white">
 <FileCheck className="w-6 h-6 text-primary-600" />
 <div className="text-left">
 <div className="text-sm font-bold text-surface-900">Security Audit Reports Available</div>
 <div className="text-xs text-surface-500 font-medium">Enterprise customers receive full penetration test results</div>
 </div>
 </div>
 </motion.div>
 </div>
 </section>
 );
}
