'use client';

import { useState } from 'react';
import { ChevronDown } from '@/components/ui/icons';
import { cn } from '@/lib/utils';

interface FAQ {
 question: string;
 answer: string;
}

const faqs: FAQ[] = [
 {
 question: 'What happens if I exceed my monthly email limit?',
 answer:
 "We'll notify you when you reach 80% and 100% of your limit. You can upgrade your plan or switch to Pay As You Go for overages (starting at $0.40 per 1,000 emails). We never cut off your sending mid-campaign.",
 },
 {
 question: 'Can I change plans at any time?',
 answer:
 "Yes! You can upgrade or downgrade immediately. Prorated adjustments are applied automatically to your next invoice.",
 },
 {
 question: 'Do unused emails roll over?',
 answer:
 'For monthly plans, unused emails do not roll over. Pay As You Go credits never expire.',
 },
 {
 question: 'What payment methods do you accept?',
 answer:
 'We accept all major credit cards. ACH and wire transfers are available for Enterprise plans.',
 },
 {
 question: 'Is there a contract?',
 answer:
 'No. Monthly plans are cancel-anytime. Annual plans offer a discount in exchange for a one-year commitment.',
 },
 {
 question: 'How can I reach billing for urgent invoice issues?',
 answer:
 'Use billing@apexmail.ee first. For legal invoice escalations, phone support is available at: plus-three-seven-two, five-six-three, eight-zero-nine, two-seven.',
 },
];

export function PricingFAQ() {
 const [openIndex, setOpenIndex] = useState<number | null>(null);

 return (
 <section className="py-20 lg:py-32 bg-white border-t border-surface-100">
 <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
 <div className="text-center mb-16">
 <h2 className="animate-in text-3xl font-bold text-surface-900 tracking-tight">
 Frequently Asked Questions
 </motion.h2>
 </div>

 <div className="animate-in delay-100 space-y-4">
 {faqs.map((faq, index) => (
 <div key={faq.question} className="border-b border-surface-100 last:border-0">
 <button
 onClick={() => setOpenIndex(openIndex === index ? null : index)}
 aria-expanded={openIndex === index}
 aria-controls={`faq-panel-${index}`}
 id={`faq-button-${index}`}
 className="w-full flex items-center justify-between py-6 text-left group"
 >
 <span className="text-lg font-medium text-surface-900 group-hover:text-primary-600 transition-colors">{faq.question}</span>
 <ChevronDown
 className={cn(
 'w-5 h-5 text-surface-400 transition-transform duration-200',
 openIndex === index ? 'rotate-180 text-primary-600' : ''
 )}
 />
 </button>
 {openIndex === index && (
 <div id={`faq-panel-${index}`} role="region" aria-labelledby={`faq-button-${index}`} className="animate-in">
 <div className="pb-6 pr-12">
 <p className="text-surface-600 leading-relaxed">{faq.answer}</p>
 </div>
 </div>
 )}
 
 </div>
 ))}
 </div>
 </div>
 </section>
 );
}
