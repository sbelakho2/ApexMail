import { ArrowRight, Calendar, Shield, FileText } from '@/components/ui/icons';
import Link from 'next/link';

export function ComplianceCTA() {
 return (
 <section className="py-20 lg:py-32 relative bg-surface-50">
 <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 relative">
 <div className="animate-in bg-white rounded-2xl border border-surface-200 p-8 md:p-12 text-center">
 <h2 className="text-3xl md:text-4xl font-bold text-surface-900 mb-6 tracking-tight">
 Ready to Sleep Better at Night?
 </h2>
 <p className="text-lg text-surface-600 mb-8 max-w-2xl mx-auto leading-relaxed">
 Join 2,000+ companies that trust ApexMail for their compliance-critical email infrastructure. 
 Get a personalized compliance assessment from our DPO team.
 </p>

 <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
 <Link
 href="/signup"
 className="inline-flex items-center justify-center px-6 py-3 text-sm font-semibold text-white bg-primary-600 rounded-md hover:bg-primary-700 transition-colors"
 >
 Start Free Trial
 <ArrowRight className="w-4 h-4 ml-2" />
 </Link>
 <Link
 href="/contact/compliance"
 className="inline-flex items-center justify-center px-6 py-3 text-sm font-semibold text-surface-900 bg-white border border-surface-200 rounded-md hover:bg-surface-50 transition-colors"
 >
 <Calendar className="w-4 h-4 mr-2" />
 Talk to Compliance Team
 </Link>
 </div>

 {/* Trust Signals */}
 <div className="grid grid-cols-2 md:grid-cols-4 gap-6 pt-8 border-t border-surface-100">
 {[
 { icon: Shield, label: 'SOC 2 Controls', sublabel: 'Enterprise plan' },
 { icon: FileText, label: 'GDPR', sublabel: 'Compliant' },
 { icon: Shield, label: 'HIPAA', sublabel: 'BAA (Enterprise)' },
 { icon: FileText, label: 'ISO 27001', sublabel: 'In progress' },
 ].map((item) => (
 <div key={item.label} className="flex flex-col items-center">
 <div className="w-10 h-10 rounded-full bg-surface-50 flex items-center justify-center mb-3 border border-surface-200 text-surface-900">
 <item.icon className="w-5 h-5" strokeWidth={1.5} />
 </div>
 <div className="text-surface-900 font-medium text-sm mb-0.5">{item.label}</div>
 <div className="text-xs text-surface-500 font-normal">{item.sublabel}</div>
 </div>
 ))}
 </div>
 </div>

 {/* Bottom Note */}
 <p className="animate-in delay-300 text-center text-sm font-medium text-surface-500 mt-8">
 All compliance documentation, audit reports, and certifications available upon request.
 <br />
 Contact{' '}
 <a href="mailto:compliance@apexmail.ee" className="text-primary-600 hover:text-primary-700 transition-colors">
 compliance@apexmail.ee
 </a>{' '}
 for custom security questionnaires.
 </p>
 </div>
 </section>
 );
}
