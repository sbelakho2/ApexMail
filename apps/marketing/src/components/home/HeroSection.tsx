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
 <section className="relative min-h-screen flex items-center pt-20 lg:pt-0 overflow-hidden bg-surface-50">
 {/* Background Effects - Removed for Rams-grade minimalism */}
 <div className="absolute inset-0 overflow-hidden pointer-events-none">
 <div className="absolute top-0 right-0 w-1/2 h-full bg-surface-100 [clip-path:polygon(100%_0,0%_0,100%_100%)]" />
 </div>

 <div className="relative max-w-[1200px] mx-auto px-4 sm:px-6 lg:px-8 py-12 lg:py-20">
 <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
 {/* Left Column - Copy */}
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={{ opacity: 1, y: 0 }}
 transition={{ duration: 0.5 }}
 >
 {/* Badge */}
 <div
   className="inline-flex items-center gap-2 px-4 py-1.5 rounded-xl bg-white border border-surface-200 text-sm text-primary-700 mb-6"
 >
   <span className="w-2 h-2 rounded-full bg-primary-500" />
   Now with Private Cloud deployments
 </div>

 {/* Headline */}
 <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-6">
 <span className="text-surface-900">The Email API That</span>
 <br />
 <span className="text-primary-500">Keeps You Out of Court</span>
 </h1>

 {/* subheadline */}
 <p className="text-[17px] lg:text-xl text-surface-600 mb-8 max-w-xl leading-relaxed">
 EU-compliant email infrastructure with cryptographic proof of delivery, 
 private cloud options, and a developer experience so good you&apos;ll actually 
 enjoy reading the docs.
 </p>

 {/* Benefits List */}
 <ul className="grid grid-cols-2 gap-4 mb-8">
   {benefits.map((benefit) => (
     <li
       key={benefit}
       className="flex items-center gap-3 text-surface-600 text-[14px] font-medium"
     >
       <span className="w-5 h-5 rounded-md bg-primary-50 flex items-center justify-center flex-shrink-0 border border-primary-100">
         <Check className="w-3 h-3 text-primary-600" />
       </span>
       {benefit}
     </li>
   ))}
 </ul>

 {/* CTA Buttons */}
        <div className="flex flex-wrap gap-4">
          <Link 
            href="https://app.apexmail.ee/signup" 
            className="btn-primary flex items-center gap-2 group shadow-lg shadow-primary-500/20 active:scale-[0.98] transition-all"
          >
            Start Sending Free
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </Link>
          <Link 
            href="#demo" 
            className="btn-secondary flex items-center gap-2 hover:bg-surface-50 active:scale-[0.98] transition-all"
          >
            <Play className="w-4 h-4 fill-current" />
            Watch Demo
          </Link>
        </div>

        {/* Trust Signals */}
        <div className="mt-12 pt-8 border-t border-surface-200">
          <p className="text-[13px] font-semibold uppercase tracking-widest text-surface-400 mb-6">Trusted by developers at</p>
          <div className="flex flex-wrap items-center gap-x-10 gap-y-6 opacity-40 grayscale contrast-125 hover:grayscale-0 hover:opacity-100 transition-all duration-500">
            {['TechCorp', 'StartupX', 'ScaleUp', 'DevHub', 'GlobalNet'].map((company) => (
              <span key={company} className="text-surface-900 font-bold text-lg tracking-tight">{company}</span>
            ))}
          </div>
        </div>
 </motion.div>

 {/* Right Column - Code Block */}
 <div
 className="relative"
 >
 {/* Code block */}
 <div className="relative premium-card p-1 bg-surface-900 overflow-hidden border-surface-700">
 {/* Window header */}
 <div className="flex items-center gap-2 px-4 py-3 border-b border-surface-800">
 <div className="flex gap-1.5">
 <span className="w-3 h-3 rounded-full bg-surface-700" />
 <span className="w-3 h-3 rounded-full bg-surface-700" />
 <span className="w-3 h-3 rounded-full bg-surface-700" />
 </div>
 <span className="text-sm text-surface-500 ml-2 font-mono">send-email.ts</span>
 </div>
 
 <CodeBlock code={heroCode} language="typescript" />
 </div>

 {/* Floating stat card */}
 <div
 className="absolute -bottom-8 -left-8 premium-card px-4 py-3 bg-white"
 >
 <div className="flex items-center gap-3">
 <div className="w-10 h-10 rounded-full bg-primary-50 flex items-center justify-center border border-primary-100">
 <span className="text-primary-600 text-lg font-bold">✓</span>
 </div>
 <div>
 <div className="text-xs font-semibold uppercase tracking-wider text-surface-500">Average delivery</div>
 <div className="text-xl font-bold text-surface-900 tabular-nums">1.2s</div>
 </div>
 </div>
 </div>
 </div>
 </div>
 </div>
 </section>
 );
}
