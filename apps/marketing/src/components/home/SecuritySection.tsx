'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Shield, Lock, Key, Eye, Server, FileCheck, AlertTriangle, Fingerprint } from 'lucide-react';

const securityFeatures = [
  {
    icon: Lock,
    title: 'End-to-End Encryption',
    description: 'TLS 1.3 in transit, AES-256 at rest. Your email content is encrypted at every stage.',
    color: 'from-blue-500 to-cyan-500',
  },
  {
    icon: Fingerprint,
    title: 'Cryptographic Signing',
    description: 'Every delivery event is cryptographically signed in an immutable hash chain. Tamper-evident by design.',
    color: 'from-purple-500 to-pink-500',
  },
  {
    icon: AlertTriangle,
    title: 'Active Threat Detection',
    description: 'Built-in honeytokens and canary tokens alert you instantly when attackers probe your system.',
    color: 'from-orange-500 to-red-500',
  },
  {
    icon: Eye,
    title: 'Zero-Knowledge Architecture',
    description: 'With zero-retention mode enabled, we process your emails without ever storing content.',
    color: 'from-green-500 to-teal-500',
  },
  {
    icon: Server,
    title: 'SOC 2 Type II Certified',
    description: 'Annual third-party audits verify our security controls meet the highest standards.',
    color: 'from-indigo-500 to-blue-500',
  },
  {
    icon: Key,
    title: 'API Key Security',
    description: 'Scoped API keys, automatic rotation, IP allowlists, and real-time usage monitoring.',
    color: 'from-yellow-500 to-orange-500',
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
    <section ref={ref} className="py-20 lg:py-32 relative">
      {/* Background */}
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-surface-900/50 to-transparent" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] rounded-full bg-gradient-to-r from-primary-600/5 to-accent-600/5 blur-3xl" />
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="text-center mb-16"
        >
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full glass border border-primary-500/30 text-sm text-primary-400 mb-6">
            <Shield className="w-4 h-4" />
            Enterprise-Grade Security
          </div>
          <h2 className="section-title mb-4">
            <span className="text-white">Security That</span>{' '}
            <span className="gradient-text">Actually Works</span>
          </h2>
          <p className="section-subtitle">
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
              className="feature-card group"
            >
              <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${feature.color} p-0.5 mb-4`}>
                <div className="w-full h-full rounded-[10px] bg-surface-900 flex items-center justify-center">
                  <feature.icon className="w-6 h-6 text-white" />
                </div>
              </div>
              <h3 className="text-lg font-semibold text-white mb-2 group-hover:text-primary-400 transition-colors">
                {feature.title}
              </h3>
              <p className="text-surface-400 text-sm leading-relaxed">
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
          className="glass-card p-8"
        >
          <div className="flex items-center justify-between flex-wrap gap-6">
            <div>
              <h3 className="text-lg font-semibold text-white mb-1">Compliance Certifications</h3>
              <p className="text-sm text-surface-400">
                Verified by independent auditors and regularly renewed.
              </p>
            </div>
            <div className="flex items-center gap-6 flex-wrap">
              {complianceLogos.map((logo) => (
                <div key={logo.name} className="text-center">
                  <div className="w-16 h-16 rounded-xl bg-surface-800 border border-surface-700 flex items-center justify-center mb-2">
                    <span className="text-xl font-bold text-primary-400">{logo.name}</span>
                  </div>
                  <div className="text-xs text-surface-500">{logo.description}</div>
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
          <div className="inline-flex items-center gap-3 glass-card px-6 py-4">
            <FileCheck className="w-6 h-6 text-accent-400" />
            <div className="text-left">
              <div className="text-sm font-medium text-white">Security Audit Reports Available</div>
              <div className="text-xs text-surface-400">Enterprise customers receive full penetration test results</div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
