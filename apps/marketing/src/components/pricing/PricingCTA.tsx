'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ArrowRight, MessageCircle, Calculator } from 'lucide-react';
import Link from 'next/link';

export function PricingCTA() {
 const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

 return (
 <section ref={ref} className="py-20 lg:py-32 relative bg-surface-50">
 <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative">
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 className="premium-card p-8 lg:p-12 text-center bg-white "
 >
 <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-primary-50 text-primary-700 border border-primary-100 text-[10px] font-bold uppercase tracking-widest mb-6">
            <Calculator className="w-4 h-4" />
            Pricing Support
          </div>

 <h2 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-4 tracking-tight">
 Still Have Questions?
 </h2>
 <p className="text-lg text-surface-600 mb-10 max-w-2xl mx-auto leading-relaxed font-medium">
 Our team is here to help you find the perfect plan for your needs. 
 Schedule a call or calculate your costs with our pricing calculator.
 </p>

 <div className="flex flex-col sm:flex-row gap-4 justify-center">
 <Link
 href="/signup"
 className="btn-primary text-lg px-8 py-4 rounded-md"
 >
 Start Free
 <ArrowRight className="w-5 h-5 ml-2" />
 </Link>
 <Link
 href="/pricing/calculator"
 className="btn-secondary text-lg px-8 py-4 bg-white rounded-md"
 >
 <Calculator className="w-5 h-5 mr-2" />
 Price Calculator
 </Link>
 <Link
 href="/contact/sales"
 className="btn-secondary text-lg px-8 py-4 bg-white rounded-md"
 >
 <MessageCircle className="w-5 h-5 mr-2" />
 Talk to Sales
 </Link>
 </div>
 </motion.div>
 </div>
 </section>
 );
}
