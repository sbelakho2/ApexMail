'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import {
 Shield,
 Zap,
 Cloud,
 Lock,
 BarChart3,
 FileCheck,
 Cpu,
 AlertTriangle,
 History,
} from 'lucide-react';

const features = [
 {
 category: 'Compliance & Security',
 items: [
 {
 icon: Shield,
 title: 'Automated Compliance Ledger',
      description: 'Automated GDPR & HIPAA compliance. Native consent ledgers, auto-generated DPAs, and instant deletion cascades make you audit-ready in minutes.',
 badge: 'GDPR / HIPAA',
 gradient: 'bg-primary-500',
 },
 {
 icon: FileCheck,
 title: 'Cryptographic Proof of Delivery',
      description: 'Court-admissible delivery logs. Every email event is cryptographically signed, proving exactly when and what was delivered.',
 badge: 'Verifiable',
 gradient: 'bg-primary-500',
 },
 {
 icon: Lock,
 title: 'Active Defense Security',
 description: 'Built-in honeytokens and canary tokens detect intrusion attempts in real-time. Know when attackers are inside.',
 badge: 'Zero-Trust',
 gradient: 'bg-primary-500',
 },
 ],
 },
 {
 category: 'Performance & Reliability',
 items: [
 {
 icon: Zap,
 title: 'Priority Pass Traffic Shaping',
      description: 'Deliver OTPs in < 500ms. Intelligent traffic isolation ensures your password resets never get blocked by your marketing blasts.',
 badge: '< 2s OTP',
 gradient: 'bg-primary-500',
 },
 {
 icon: AlertTriangle,
 title: 'Reputation Circuit Breaker',
 description: 'Pre-flight checks pause your queue before you hit provider ban limits. Stop shooting yourself in the foot.',
 badge: 'Auto-Protect',
 gradient: 'bg-primary-500',
 },
 {
 icon: BarChart3,
 title: 'Real-Time Analytics',
 description: 'Track opens, clicks, bounces, and complaints with millisecond precision. See engagement as it happens.',
 badge: 'Live',
 gradient: 'bg-primary-500',
 },
 ],
 },
 {
 category: 'Enterprise Infrastructure',
 items: [
 {
 icon: Cloud,
 title: 'True Single-Tenant',
 description: 'ApexMail Private deploys completely isolated infrastructure - your VPC, your DB, our code. Zero noisy neighbors.',
 badge: 'Private Cloud',
 gradient: 'bg-primary-500',
 },
 {
 icon: Cpu,
 title: 'Air-Gapped AI',
 description: 'CPU-only ONNX models run locally on ARM64. Smart features without sending data to third parties.',
 badge: 'Privacy-First',
 gradient: 'bg-primary-500',
 },
 {
 icon: History,
 title: 'Forensic Render History',
 description: 'Store the exact rendered HTML of every email. See precisely what users saw, pixel-perfect time travel.',
 badge: '7-Day Replay',
 gradient: 'bg-primary-500',
 },
 ],
 },
];

export function FeaturesSection() {
 const [ref, inView] = useInView({
 triggerOnce: true,
 threshold: 0.1,
 });

 return (
 <section ref={ref} className="py-20 lg:py-32 relative bg-white" id="features">
      <div className="relative max-w-[1200px] mx-auto px-4 sm:px-6 lg:px-8">
 {/* Section Header */}
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ duration: 0.5 }}
 className="text-center mb-16"
 >
 <h2 className="section-title mb-4">
            <span className="text-surface-900">Features That</span>{' '}
            <span className="text-brand-500">Actually Matter</span>
          </h2>
 <p className="text-surface-600 text-[17px] max-w-2xl mx-auto leading-relaxed">
 Not another SendGrid clone. Every feature is built to solve real problems 
 that make developers and compliance officers lose sleep.
 </p>
 </motion.div>

 {/* Feature Categories */}
 <div className="space-y-20">
 {features.map((category, categoryIndex) => (
 <div key={category.category}>
 <motion.h3
 initial={{ opacity: 0, x: -20 }}
 animate={inView ? { opacity: 1, x: 0 } : {}}
 transition={{ delay: categoryIndex * 0.1 }}
 className="text-sm font-bold uppercase tracking-widest text-surface-600 mb-8 flex items-center gap-3"
 >
 <span className="w-8 h-px bg-surface-200" />
 {category.category}
 </motion.h3>

 <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
 {category.items.map((feature, index) => (
 <motion.div
 key={feature.title}
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: categoryIndex * 0.1 + index * 0.1 }}
              className="p-6 bg-white rounded-lg border border-surface-200 hover:border-surface-300 transition-colors"
            >
              {/* Icon & Badge */}
              <div className="flex items-start justify-between mb-5">
                <div className="w-10 h-10 rounded-sm bg-surface-50 flex items-center justify-center border border-surface-200 text-surface-900">
                  <feature.icon className="w-5 h-5" strokeWidth={1.5} />
                </div>
                <span className="inline-flex items-center px-2 py-1 rounded-sm bg-surface-50 text-surface-600 border border-surface-200 text-[14px] font-bold uppercase tracking-wider">
                  {feature.badge}
                </span>
              </div>

              {/* Content */}
              <h4 className="text-base font-semibold text-surface-900 mb-2">
                {feature.title}
              </h4>
              <p className="text-surface-600 text-sm leading-relaxed">
                {feature.description}
              </p>
            </motion.div>
          ))}
        </div>
      </div>
    ))}
  </div>

  {/* Bottom Stats */}
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={inView ? { opacity: 1, y: 0 } : {}}
    transition={{ delay: 0.6 }}
    className="mt-20 grid grid-cols-2 md:grid-cols-4 gap-px bg-surface-200 border border-surface-200 rounded-lg overflow-hidden"
  >
    {[
      { value: '99.9%', label: 'Delivery Rate' },
      { value: '<1.5s', label: 'Avg Delivery Time' },
      { value: '50M+', label: 'Emails/Month' },
      { value: '24/7', label: 'Support Response' },
    ].map((stat) => (
      <div key={stat.label} className="text-center py-8 bg-white">
        <div className="text-3xl font-semibold text-surface-900 mb-1 tabular-nums tracking-tight">{stat.value}</div>
        <div className="text-[14px] font-medium text-surface-500">{stat.label}</div>
      </div>
    ))}
  </motion.div>
 </div>
 </section>
 );
}
