import Link from 'next/link';
import { Shield, Scale, FileCheck, Lock, ArrowRight, Check } from '@/components/ui/icons';

const badges = [
 { name: 'GDPR' },
 { name: 'HIPAA (Enterprise)' },
 { name: 'SOC 2 (Enterprise)' },
 { name: 'CCPA' },
 { name: 'ISO 27001' },
];

export function ComplianceHero() {
 return (
 <section className="relative min-h-screen flex items-center pt-32 pb-20 overflow-hidden bg-surface-50">
      <div className="relative max-w-7xl mx-auto px-5 sm:px-6 lg:px-8 py-12 lg:py-20">
 <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
 {/* Left Column */}
 <div className="animate-in">
 {/* Badge */}
 <div className="inline-flex items-center gap-2 px-3 py-1 rounded-sm bg-white border border-surface-200 text-[14px] font-medium text-surface-600 mb-8 p-1 pr-3">
          <span className="w-6 h-6 rounded-sm bg-surface-100 flex items-center justify-center">
            <Shield className="w-4 h-4" />
          </span>
          Compliance-as-Code
        </div>

 {/* Headline */}
 <h1 className="text-3xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-6 leading-tight text-surface-900 break-words">
            The Email API That <br />
            <span className="text-surface-500">Keeps You Out of Court.</span>
          </h1>

 {/* Subheadline */}
 <p className="text-lg text-surface-600 mb-10 leading-relaxed max-w-lg">
 Stop treating compliance as an afterthought. ApexMail bakes GDPR requirements into
 the platform and provides HIPAA/SOC 2 controls for Enterprise plans.
 </p>

 {/* Key Points */}
 <ul className="space-y-4 mb-10">
 {[
 { icon: FileCheck, text: 'Immutable consent ledger with cryptographic proofs' },
 { icon: Scale, text: 'Auto-generated DPAs that satisfy EU regulators' },
 { icon: Lock, text: 'One-click "Right-to-be-Forgotten" cascade deletion' },
 ].map((point) => (
 <li key={point.text} className="flex items-start gap-3">
 <Check className="w-5 h-5 text-brand-500 mt-0.5 flex-shrink-0" />
 <span className="text-surface-700 font-medium text-[14px] leading-relaxed">{point.text}</span>
 </li>
 ))}
 </ul>

 {/* CTA */}
 <div className="flex flex-wrap gap-4">
 <Link href="https://app.apexmail.ee/signup" className="inline-flex items-center justify-center px-6 py-3 text-sm font-semibold text-white bg-brand-500 rounded-md hover:bg-brand-600 transition-colors">
 Start Free Trial
 <ArrowRight className="w-4 h-4 ml-2" />
 </Link>
 <Link href="/contact" className="inline-flex items-center justify-center px-6 py-3 text-sm font-semibold text-surface-900 bg-white border border-surface-200 rounded-md hover:bg-surface-50 transition-colors">
 Compliance Review
 </Link>
 </div>
 </div>

 {/* Right Column - Compliance Badges */}
 <div className="animate-in delay-200 relative">
 <div className="p-6 sm:p-8 bg-white rounded-lg border border-surface-200">
 <h3 className="text-[14px] font-semibold text-surface-500 mb-8 text-center">
 Compliance Certifications
 </h3>
 <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
 {badges.map((badge, index) => (
 <div key={badge.name} className="animate-in aspect-square rounded-sm bg-surface-50 border border-surface-200 flex flex-col items-center justify-center p-4 hover:border-surface-300 transition-colors">
 <div className="w-10 h-10 rounded-sm bg-white flex items-center justify-center mb-3 border border-surface-200 text-surface-900">
 <Shield className="w-5 h-5" strokeWidth={1.5} />
 </div>
 <span className="text-[14px] font-semibold text-surface-900">{badge.name}</span>
 </div>
 ))}
 </div>
 <div className="mt-10 p-4 rounded-sm bg-emerald-50 border border-emerald-100 ">
 <div className="flex items-center gap-3 text-emerald-700 text-[14px] font-bold">
 <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
 Enterprise compliance controls available on request
 </div>
 </div>
 </div>
 </div>
 </div>
 </div>
 </section>
 );
}
