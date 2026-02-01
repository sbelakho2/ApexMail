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
  Globe,
  Clock,
  Target,
  AlertTriangle,
  History,
} from 'lucide-react';

const features = [
  {
    category: 'Compliance & Security',
    items: [
      {
        icon: Shield,
        title: 'Compliance-as-Code',
        description: 'Native GDPR consent ledger, auto-generated DPAs, instant "Right-to-be-Forgotten" cascades. Be audit-ready in minutes, not months.',
        badge: 'GDPR / HIPAA',
        gradient: 'from-blue-500 to-purple-500',
      },
      {
        icon: FileCheck,
        title: 'Cryptographic Proof of Delivery',
        description: 'Every log entry is cryptographically signed in an immutable hash chain. Prove delivery in court, not just claim it.',
        badge: 'Verifiable',
        gradient: 'from-purple-500 to-pink-500',
      },
      {
        icon: Lock,
        title: 'Active Defense Security',
        description: 'Built-in honeytokens and canary tokens detect intrusion attempts in real-time. Know when attackers are inside.',
        badge: 'Zero-Trust',
        gradient: 'from-red-500 to-orange-500',
      },
    ],
  },
  {
    category: 'Performance & Reliability',
    items: [
      {
        icon: Zap,
        title: 'Priority Pass Traffic Shaping',
        description: 'Automatic classification puts transactional mail in a fast lane. Your OTPs never wait for your newsletter.',
        badge: '< 2s OTP',
        gradient: 'from-yellow-500 to-orange-500',
      },
      {
        icon: AlertTriangle,
        title: 'Reputation Circuit Breaker',
        description: 'Pre-flight checks pause your queue before you hit provider ban limits. Stop shooting yourself in the foot.',
        badge: 'Auto-Protect',
        gradient: 'from-orange-500 to-red-500',
      },
      {
        icon: BarChart3,
        title: 'Real-Time Analytics',
        description: 'Track opens, clicks, bounces, and complaints with millisecond precision. See engagement as it happens.',
        badge: 'Live',
        gradient: 'from-green-500 to-teal-500',
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
        gradient: 'from-cyan-500 to-blue-500',
      },
      {
        icon: Cpu,
        title: 'Air-Gapped AI',
        description: 'CPU-only ONNX models run locally on ARM64. Smart features without sending data to third parties.',
        badge: 'Privacy-First',
        gradient: 'from-indigo-500 to-purple-500',
      },
      {
        icon: History,
        title: 'Forensic Render History',
        description: 'Store the exact rendered HTML of every email. See precisely what users saw, pixel-perfect time travel.',
        badge: '7-Day Replay',
        gradient: 'from-pink-500 to-rose-500',
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
    <section ref={ref} className="py-20 lg:py-32 relative" id="features">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-surface-900/50 to-transparent" />

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.5 }}
          className="text-center mb-16"
        >
          <h2 className="section-title mb-4">
            <span className="text-white">Features That</span>{' '}
            <span className="gradient-text">Actually Matter</span>
          </h2>
          <p className="section-subtitle">
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
                className="text-lg font-semibold text-surface-400 mb-8 flex items-center gap-3"
              >
                <span className="w-8 h-px bg-gradient-to-r from-primary-500 to-transparent" />
                {category.category}
              </motion.h3>

              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                {category.items.map((feature, index) => (
                  <motion.div
                    key={feature.title}
                    initial={{ opacity: 0, y: 20 }}
                    animate={inView ? { opacity: 1, y: 0 } : {}}
                    transition={{ delay: categoryIndex * 0.1 + index * 0.1 }}
                    className="feature-card group"
                  >
                    {/* Icon & Badge */}
                    <div className="flex items-start justify-between mb-4">
                      <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${feature.gradient} p-0.5`}>
                        <div className="w-full h-full rounded-[10px] bg-surface-900 flex items-center justify-center">
                          <feature.icon className="w-6 h-6 text-white" />
                        </div>
                      </div>
                      <span className="text-xs px-2 py-1 rounded-full bg-surface-800 text-surface-400 border border-surface-700">
                        {feature.badge}
                      </span>
                    </div>

                    {/* Content */}
                    <h4 className="text-lg font-semibold text-white mb-2 group-hover:text-primary-400 transition-colors">
                      {feature.title}
                    </h4>
                    <p className="text-surface-400 text-sm leading-relaxed">
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
          className="mt-20 grid grid-cols-2 md:grid-cols-4 gap-6"
        >
          {[
            { value: '99.9%', label: 'Delivery Rate' },
            { value: '<1.5s', label: 'Avg Delivery Time' },
            { value: '50M+', label: 'Emails/Month' },
            { value: '24/7', label: 'Support Response' },
          ].map((stat) => (
            <div key={stat.label} className="text-center glass-card py-6">
              <div className="text-3xl lg:text-4xl font-bold gradient-text mb-1">{stat.value}</div>
              <div className="text-sm text-surface-400">{stat.label}</div>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
