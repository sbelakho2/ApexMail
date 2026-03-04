import { ArrowRight, MessageCircle, Calculator } from '@/components/ui/icons';
import Link from 'next/link';

export function PricingCTA() {
 return (
 <section className="py-20 lg:py-32 bg-surface-50">
 <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
 <div className="animate-in">
 <h2 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-6 tracking-tight">
 Still have questions?
 </h2>
 <p className="text-lg text-surface-500 mb-10 max-w-2xl mx-auto leading-relaxed">
 Our team is here to help you find the perfect plan for your needs.
 </p>

 <div className="flex flex-col sm:flex-row gap-4 justify-center">
 <Link
 href="/signup"
 className="inline-flex items-center justify-center px-6 py-3 text-base font-semibold text-white bg-primary-600 rounded-md border border-primary-600 hover:bg-primary-700 transition-colors"
 >
 Start Free
 <ArrowRight className="w-4 h-4 ml-2" />
 </Link>
 <Link
 href="/pricing/calculator"
 className="inline-flex items-center justify-center px-6 py-3 text-base font-semibold text-surface-900 bg-white border border-surface-200 rounded-md hover:bg-surface-50 transition-colors"
 >
 <Calculator className="w-4 h-4 mr-2 text-surface-500" />
 Price Calculator
 </Link>
 <Link
 href="/contact/sales"
 className="inline-flex items-center justify-center px-6 py-3 text-base font-semibold text-surface-900 bg-white border border-surface-200 rounded-md hover:bg-surface-50 transition-colors"
 >
 <MessageCircle className="w-4 h-4 mr-2 text-surface-500" />
 Talk to Sales
 </Link>
 </div>
 </div>
 </div>
 </section>
 );
}
