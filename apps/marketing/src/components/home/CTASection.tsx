import Link from 'next/link';
import { ArrowRight, Zap, Clock, Shield, Headphones } from '@/components/ui/icons';

const ctaFeatures = [
 { icon: Zap, text: 'Send your first email in < 60 seconds' },
 { icon: Clock, text: '3,000 free emails every month, forever' },
 { icon: Shield, text: 'No credit card required to start' },
 { icon: Headphones, text: 'Free migration assistance available' },
];

export function CTASection() {
 return (
 <section className="py-20 lg:py-32 relative overflow-hidden bg-white">
      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 <div className="animate-in text-center">
 {/* Headline */}
 <h2 className="mb-6">
            <span className="text-surface-900">Ready to Ship</span>
            <br />
            <span className="text-brand-500">Better Email?</span>
          </h2>

 {/* Subheadline */}
 <p className="text-xl text-surface-600 max-w-2xl mx-auto mb-10 leading-relaxed font-medium">
   Join thousands of developers who trust ApexMail for their 
   mission-critical email infrastructure. Start free, scale infinitely.
 </p>

 {/* Features List */}
 <div className="grid sm:grid-cols-2 gap-x-8 gap-y-4 max-w-2xl mx-auto mb-12">
   {ctaFeatures.map((feature, index) => (
     <div key={feature.text} className="animate-in flex items-center gap-3 text-left">
       <div className="w-6 h-6 rounded-sm bg-surface-100 flex items-center justify-center flex-shrink-0 text-surface-600">
         <feature.icon className="w-4 h-4" />
       </div>
       <span className="text-surface-600 text-[14px] font-bold uppercase tracking-wide">{feature.text}</span>
     </div>
   ))}
 </div>

 {/* CTA Buttons */}
 <div className="animate-in delay-400 flex flex-col sm:flex-row items-center justify-center gap-4 mb-16">
   <Link
     href="https://app.apexmail.ee/signup"
     className="inline-flex items-center justify-center px-8 py-4 text-base font-bold text-white bg-brand-500 rounded-md border border-brand-500 hover:bg-brand-600 transition-colors w-full sm:w-auto"
   >
     Deploy to Production
     <ArrowRight className="w-4 h-4 ml-2" />
   </Link>
   <Link
     href="/private-cloud"
     className="inline-flex items-center justify-center px-8 py-4 text-base font-bold text-surface-900 bg-white border border-surface-200 rounded-md hover:bg-surface-50 transition-colors w-full sm:w-auto"
   >
     Book Architecture Review
   </Link>
 </div>

 {/* Trust Badges */}
 <div className="animate-in delay-500 flex flex-wrap items-center justify-center gap-6 text-[14px] font-bold uppercase tracking-widest text-surface-600">
      <span className="flex items-center gap-2">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)]"></span>
        99.9% Uptime SLA (Scale+)
      </span>
      <span className="flex items-center gap-2">
        <span className="w-1.5 h-1.5 rounded-full bg-brand-500 shadow-[0_0_8px_rgba(37,99,235,0.4)]"></span>
        SOC 2 Controls (Enterprise)
      </span>
      <span className="flex items-center gap-2">
        <span className="w-1.5 h-1.5 rounded-full bg-brand-500 shadow-[0_0_8px_rgba(37,99,235,0.4)]"></span>
        GDPR Compliant
      </span>
      <span className="flex items-center gap-2">
        <span className="w-1.5 h-1.5 rounded-full bg-surface-400"></span>
        Priority Support (Growth+)
      </span>
    </div>
 </div>
 </div>
 </section>
 );
}
