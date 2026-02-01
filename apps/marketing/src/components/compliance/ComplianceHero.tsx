'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';
import { Shield, Scale, FileCheck, Lock, ArrowRight } from 'lucide-react';

const badges = [
  { name: 'GDPR', color: 'from-blue-500 to-cyan-500' },
  { name: 'HIPAA', color: 'from-green-500 to-teal-500' },
  { name: 'SOC 2', color: 'from-purple-500 to-pink-500' },
  { name: 'CCPA', color: 'from-orange-500 to-red-500' },
  { name: 'ISO 27001', color: 'from-indigo-500 to-blue-500' },
];

export function ComplianceHero() {
  return (
    <section className="relative min-h-screen flex items-center pt-20 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0">
        <div className="absolute -top-1/2 right-0 w-[1000px] h-[1000px] rounded-full bg-gradient-to-br from-blue-600/10 to-transparent blur-3xl" />
        <div className="absolute bottom-0 left-0 w-[600px] h-[600px] rounded-full bg-gradient-to-tr from-green-600/10 to-transparent blur-3xl" />
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 lg:py-20">
        <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
          {/* Left Column */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            {/* Badge */}
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full glass border border-blue-500/30 text-sm text-blue-400 mb-6">
              <Shield className="w-4 h-4" />
              Compliance-as-Code
            </div>

            {/* Headline */}
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-6">
              <span className="text-white">The Email API That</span>
              <br />
              <span className="bg-clip-text text-transparent bg-gradient-to-r from-blue-400 via-cyan-400 to-green-400">
                Keeps You Out of Court
              </span>
            </h1>

            {/* Subheadline */}
            <p className="text-lg lg:text-xl text-surface-300 mb-8 max-w-xl">
              Stop treating compliance as an afterthought. ApexMail bakes GDPR, HIPAA, 
              and SOC 2 requirements directly into the email infrastructure layer.
            </p>

            {/* Key Points */}
            <ul className="space-y-4 mb-8">
              {[
                { icon: FileCheck, text: 'Immutable consent ledger with cryptographic proofs' },
                { icon: Scale, text: 'Auto-generated DPAs that satisfy EU regulators' },
                { icon: Lock, text: 'One-click "Right-to-be-Forgotten" cascade deletion' },
              ].map((point) => (
                <li key={point.text} className="flex items-start gap-3">
                  <span className="w-6 h-6 rounded-lg bg-blue-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <point.icon className="w-4 h-4 text-blue-400" />
                  </span>
                  <span className="text-surface-300">{point.text}</span>
                </li>
              ))}
            </ul>

            {/* CTA */}
            <div className="flex flex-wrap gap-4">
              <Link href="https://app.apexmail.ee/signup" className="btn-primary flex items-center gap-2 group">
                Start Free Trial
                <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
              </Link>
              <Link href="/contact" className="btn-secondary">
                Request Compliance Review
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
            <div className="glass-card p-8">
              <h3 className="text-lg font-semibold text-white mb-6 text-center">
                Compliance Certifications
              </h3>
              <div className="grid grid-cols-3 gap-4">
                {badges.map((badge, index) => (
                  <motion.div
                    key={badge.name}
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: 0.3 + index * 0.1 }}
                    className="aspect-square rounded-2xl bg-surface-800/50 border border-surface-700 flex flex-col items-center justify-center p-4 hover:border-surface-600 transition-colors"
                  >
                    <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${badge.color} flex items-center justify-center mb-2`}>
                      <Shield className="w-6 h-6 text-white" />
                    </div>
                    <span className="text-sm font-medium text-white">{badge.name}</span>
                  </motion.div>
                ))}
              </div>
              <div className="mt-6 p-4 rounded-lg bg-green-500/10 border border-green-500/30">
                <div className="flex items-center gap-2 text-green-400 text-sm">
                  <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span>
                  All certifications current and independently verified
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
