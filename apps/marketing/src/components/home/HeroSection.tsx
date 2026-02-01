'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';
import { ArrowRight, Play, Check } from 'lucide-react';
import { CodeBlock } from '@/components/ui/CodeBlock';

const heroCode = `// Send your first email in 3 lines
const response = await fetch('https://api.apexmail.ee/v1/send', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer YOUR_API_KEY',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    from: 'hello@yourcompany.com',
    to: 'customer@example.com',
    subject: 'Welcome to Our Platform!',
    html: '<h1>Hello World!</h1>',
    type: 'transactional' // or 'marketing'
  })
});

// That's it. Email delivered with full tracking.
console.log(await response.json());
// { id: "msg_abc123", status: "queued" }`;

const benefits = [
  '99.9% delivery rate',
  'GDPR & HIPAA compliant',
  'Cryptographic proof of delivery',
  'No credit card required',
];

export function HeroSection() {
  return (
    <section className="relative min-h-screen flex items-center pt-20 lg:pt-0 overflow-hidden">
      {/* Background Effects */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-1/2 -right-1/4 w-[800px] h-[800px] rounded-full bg-gradient-to-br from-primary-600/20 to-transparent blur-3xl" />
        <div className="absolute -bottom-1/2 -left-1/4 w-[600px] h-[600px] rounded-full bg-gradient-to-tr from-accent-600/10 to-transparent blur-3xl" />
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 lg:py-20">
        <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
          {/* Left Column - Copy */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            {/* Badge */}
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.1 }}
              className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full glass border border-primary-500/30 text-sm text-primary-400 mb-6"
            >
              <span className="w-2 h-2 rounded-full bg-accent-500 animate-pulse" />
              Now with Private Cloud deployments
            </motion.div>

            {/* Headline */}
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-6">
              <span className="text-white">The Email API That</span>
              <br />
              <span className="gradient-text">Keeps You Out of Court</span>
            </h1>

            {/* Subheadline */}
            <p className="text-lg lg:text-xl text-surface-300 mb-8 max-w-xl">
              EU-compliant email infrastructure with cryptographic proof of delivery, 
              private cloud options, and a developer experience so good you&apos;ll actually 
              enjoy reading the docs.
            </p>

            {/* Benefits List */}
            <ul className="grid grid-cols-2 gap-3 mb-8">
              {benefits.map((benefit, index) => (
                <motion.li
                  key={benefit}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.2 + index * 0.1 }}
                  className="flex items-center gap-2 text-surface-300"
                >
                  <span className="w-5 h-5 rounded-full bg-accent-500/20 flex items-center justify-center flex-shrink-0">
                    <Check className="w-3 h-3 text-accent-400" />
                  </span>
                  {benefit}
                </motion.li>
              ))}
            </ul>

            {/* CTA Buttons */}
            <div className="flex flex-wrap gap-4">
              <Link href="https://app.apexmail.ee/signup" className="btn-primary flex items-center gap-2 group">
                Start Sending Free
                <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
              </Link>
              <Link href="#demo" className="btn-secondary flex items-center gap-2">
                <Play className="w-4 h-4" />
                Watch Demo
              </Link>
            </div>

            {/* Trust Signals */}
            <div className="mt-10 pt-8 border-t border-surface-800">
              <p className="text-sm text-surface-500 mb-4">Trusted by developers at</p>
              <div className="flex items-center gap-8 opacity-60 grayscale hover:grayscale-0 hover:opacity-100 transition-all">
                {/* Placeholder for company logos */}
                {['TechCorp', 'StartupX', 'ScaleUp', 'DevHub'].map((company) => (
                  <span key={company} className="text-surface-400 font-medium text-sm">{company}</span>
                ))}
              </div>
            </div>
          </motion.div>

          {/* Right Column - Code Block */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="relative"
          >
            {/* Floating elements */}
            <div className="absolute -top-6 -left-6 w-24 h-24 bg-gradient-to-br from-primary-500/20 to-transparent rounded-2xl blur-xl" />
            <div className="absolute -bottom-6 -right-6 w-32 h-32 bg-gradient-to-tl from-accent-500/20 to-transparent rounded-2xl blur-xl" />
            
            {/* Code block */}
            <div className="relative glass-card p-1">
              {/* Window header */}
              <div className="flex items-center gap-2 px-4 py-3 border-b border-surface-700/50">
                <div className="flex gap-1.5">
                  <span className="w-3 h-3 rounded-full bg-red-500/80" />
                  <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
                  <span className="w-3 h-3 rounded-full bg-green-500/80" />
                </div>
                <span className="text-sm text-surface-500 ml-2 font-mono">send-email.ts</span>
              </div>
              
              <CodeBlock code={heroCode} language="typescript" />
            </div>

            {/* Floating stat card */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.6 }}
              className="absolute -bottom-8 -left-8 glass-card px-4 py-3"
            >
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-accent-500/20 flex items-center justify-center">
                  <span className="text-accent-400 text-lg">✓</span>
                </div>
                <div>
                  <div className="text-sm text-surface-400">Average delivery time</div>
                  <div className="text-xl font-bold text-white">1.2s</div>
                </div>
              </div>
            </motion.div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
