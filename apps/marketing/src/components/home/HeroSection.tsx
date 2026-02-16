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
 <section className="relative min-h-[90vh] flex items-center pt-24 pb-16 lg:pt-0 overflow-hidden bg-white">
 
 <div className="relative max-w-[1200px] mx-auto px-4 sm:px-6 lg:px-8">
 <div className="grid lg:grid-cols-2 gap-12 lg:gap-20 items-center">
 {/* Left Column - Copy */}
 <motion.div
 initial={{ opacity: 0, y: 12 }}
 animate={{ opacity: 1, y: 0 }}
 transition={{ duration: 0.5 }}
 >
 {/* Badge */}
 <div
   className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-brand-50 border border-brand-100 text-sm font-semibold text-brand-700 mb-8 shadow-sm"
 >
   <span className="relative flex h-2 w-2">
     <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-brand-400 opacity-75"></span>
     <span className="relative inline-flex rounded-full h-2 w-2 bg-brand-500"></span>
   </span>
   Now with Private Cloud deployments
 </div>

 {/* Headline */}
 <h1 className="mb-6 text-surface-900 leading-[1.05]">
                The Email API That <br />
                <span className="text-brand-500">Values Your Sleep.</span>
              </h1>

 {/* subheadline */}
 <p className="text-surface-600 mb-8 max-w-xl">
                Send <strong className="text-surface-900 font-semibold">HIPAA & GDPR-ready</strong> transactional emails with clear tracking.
                Infrastructure designed for developers who prefer stability over buzzwords.
              </p>
 {/* Benefits List */}
 <ul className="grid grid-cols-1 sm:grid-cols-2 gap-y-3 gap-x-8 mb-10">
   {benefits.map((benefit) => (
     <li
       key={benefit}
       className="flex items-center gap-2.5 text-surface-600 text-[14px]"
     >
       <Check className="w-4 h-4 text-brand-500" />
       {benefit}
     </li>
   ))}
 </ul>

 {/* CTA Buttons */}
        <div className="flex flex-wrap gap-4">
          <Link 
            href="https://app.apexmail.ee/signup" 
            className="inline-flex items-center justify-center px-6 py-3 text-sm font-semibold text-white bg-brand-500 rounded-md hover:bg-brand-600 transition-colors"
            aria-label="Get API Keys - Sign up for free"
          >
            Get API Keys
            <ArrowRight className="w-4 h-4 ml-2" aria-hidden="true" />
          </Link>
          <Link 
            href="#demo" 
            className="inline-flex items-center justify-center px-6 py-3 text-sm font-semibold text-surface-900 bg-white border border-surface-200 rounded-md hover:bg-surface-50 transition-colors"
            aria-label="Watch product demo video"
          >
            <Play className="w-4 h-4 mr-2" aria-hidden="true" />
            Watch Demo
          </Link>
        </div>

        {/* Trust Signals */}
        <div className="mt-12 pt-8 border-t border-surface-200">
          <p className="text-[14px] font-semibold text-surface-400 mb-6 uppercase tracking-wider">Trusted by developers at</p>
          <div className="flex flex-wrap items-center gap-x-10 gap-y-6 opacity-40 grayscale contrast-125 hover:grayscale-0 hover:opacity-100 transition-all duration-500">
            {['TechCorp', 'StartupX', 'ScaleUp', 'DevHub', 'GlobalNet'].map((company) => (
              <span key={company} className="text-surface-900 font-bold text-lg tracking-tight">{company}</span>
            ))}
          </div>
        </div>
 </motion.div>

 {/* Right Column - Code Block */}
 <div className="relative hidden lg:block">
 {/* Code block */}
 <div className="relative bg-surface-900 rounded-xl overflow-hidden border border-surface-800 shadow-2xl">
 {/* Window header */}
 <div className="flex items-center gap-2 px-4 py-3 border-b border-surface-800 bg-surface-900">
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
                            className="absolute -bottom-8 -left-8 bg-white border border-surface-200 rounded-xl px-5 py-4 shadow-xl"
                        >
   <div className="flex items-center gap-4">
     <div className="w-12 h-12 rounded-full bg-brand-50 flex items-center justify-center border border-brand-100">
       <span className="text-brand-500 text-xl font-bold">✓</span>
     </div>
 <div>
 <div className="text-xs font-bold text-surface-500 mb-0.5">Average delivery</div>
 <div className="text-2xl font-bold text-surface-900 tabular-nums">1.2s</div>
 </div>
 </div>
 </div>
 </div>
 </div>
 </div>
 </section>
 );
}
