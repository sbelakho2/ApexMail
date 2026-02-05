'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ChevronLeft, ChevronRight, Quote } from 'lucide-react';
import { cn } from '@/lib/utils';

const testimonials = [
 {
 quote: "We switched from SendGrid after our third compliance audit nightmare. ApexMail's cryptographic proof of delivery saved us during our SOC 2 audit. The auditors were impressed we could prove exactly when emails were delivered.",
 author: 'Sarah Chen',
 role: 'CTO',
 company: 'FinanceFlow',
 industry: 'FinTech',
 image: '/testimonials/sarah.jpg',
 stats: { metric: 'Audit Time', before: '3 weeks', after: '2 days' },
 },
 {
 quote: "The forensic render history feature alone is worth the switch. Last month a customer claimed they never got an email - we showed them exactly what they received, pixel for pixel. Case closed.",
 author: 'Marcus Rodriguez',
 role: 'Head of Engineering',
 company: 'SupportHero',
 industry: 'SaaS',
 image: '/testimonials/marcus.jpg',
 stats: { metric: 'Support Disputes', before: '15/month', after: '2/month' },
 },
 {
 quote: "As a healthcare startup, HIPAA compliance was non-negotiable. Other providers either didn't offer it or wanted $10k/month. ApexMail gave us enterprise-grade compliance at a fraction of the cost.",
 author: 'Dr. Emily Watson',
 role: 'Founder',
 company: 'MedConnect',
 industry: 'Healthcare',
 image: '/testimonials/emily.jpg',
 stats: { metric: 'Compliance Cost', before: '$10k/mo', after: '$399/mo' },
 },
 {
 quote: "The API is so clean that our junior devs had email sending working in their first hour. The TypeScript SDK with full type inference made it feel like a native part of our stack.",
 author: 'James Liu',
 role: 'Lead Developer',
 company: 'DevStack',
 industry: 'Developer Tools',
 image: '/testimonials/james.jpg',
 stats: { metric: 'Integration Time', before: '2 days', after: '45 minutes' },
 },
 {
 quote: "During Black Friday, we sent 2M emails in 4 hours. Not a single OTP or password reset was delayed thanks to the priority lane feature. Our competitors' customers were complaining about slow emails.",
 author: 'Amanda Foster',
 role: 'VP of Engineering',
 company: 'ShopFast',
 industry: 'E-commerce',
 image: '/testimonials/amanda.jpg',
 stats: { metric: 'OTP Delivery', before: '8-15 seconds', after: '<2 seconds' },
 },
];

export function TestimonialsSection() {
 const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });
 const [activeIndex, setActiveIndex] = useState(0);

 const nextTestimonial = () => {
 setActiveIndex((prev) => (prev + 1) % testimonials.length);
 };

 const prevTestimonial = () => {
 setActiveIndex((prev) => (prev - 1 + testimonials.length) % testimonials.length);
 };

 // Guard against empty testimonials array
 if (!testimonials.length) return null;

 const activeTestimonial = testimonials[activeIndex];

 return (
 <section ref={ref} className="py-20 lg:py-32 relative overflow-hidden bg-surface-50">
 <div className="relative max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
 {/* Header */}
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 className="text-center mb-12"
 >
 <h2 className="section-title mb-4">
 <span className="text-surface-900">Trusted by</span>{' '}
 <span className="text-primary-500">Developers Who Ship</span>
 </h2>
 <p className="text-surface-600 text-[17px] max-w-2xl mx-auto leading-relaxed">
 Don&apos;t take our word for it. Here&apos;s what our customers have to say.
 </p>
 </motion.div>

 {/* Main Testimonial */}
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.2 }}
 className="p-8 lg:p-12 mb-10 bg-white rounded-xl border border-surface-200"
 >
 <AnimatePresence mode="wait">
 <motion.div
 key={activeIndex}
 initial={{ opacity: 0, x: 20 }}
 animate={{ opacity: 1, x: 0 }}
 exit={{ opacity: 0, x: -20 }}
 transition={{ duration: 0.3 }}
 >
 <div className="flex flex-col lg:flex-row gap-8 lg:gap-16">
 {/* Quote */}
 <div className="flex-1">
 <Quote className="w-8 h-8 text-surface-200 mb-6" fill="currentColor" />
 <blockquote className="text-xl lg:text-2xl text-surface-900 font-medium leading-relaxed mb-8">
 &ldquo;{activeTestimonial.quote}&rdquo;
 </blockquote>
 <div className="flex items-center gap-4">
 <div className="w-12 h-12 rounded-full bg-surface-50 flex items-center justify-center text-surface-900 font-semibold text-sm border border-surface-200" aria-hidden="true">
 {activeTestimonial.author?.split(' ').map(n => n?.[0] ?? '').join('') ?? 'U'}
 </div>
 <div>
 <div className="font-semibold text-surface-900">{activeTestimonial.author}</div>
 <div className="text-sm text-surface-500">
 {activeTestimonial.role}, {activeTestimonial.company}
 </div>
 </div>
 </div>
 </div>

 {/* Stats Card */}
 <div className="lg:w-64 flex-shrink-0">
 <div className="bg-surface-50 rounded-lg p-6 border border-surface-200">
 <div className="text-xs font-semibold text-surface-500 mb-4 uppercase tracking-wide">{activeTestimonial.stats.metric}</div>
 <div className="space-y-4">
 <div>
 <div className="text-[10px] text-surface-400 mb-1 uppercase font-medium">Before</div>
 <div className="text-lg font-mono text-surface-700 font-semibold tabular-nums line-through decoration-surface-400/50">{activeTestimonial.stats.before}</div>
 </div>
 <div>
 <div className="text-[10px] text-surface-400 mb-1 uppercase font-medium">After</div>
 <div className="text-2xl font-mono text-primary-600 font-bold tabular-nums">{activeTestimonial.stats.after}</div>
 </div>
 </div>
 <div className="mt-6 pt-4 border-t border-surface-200 text-xs text-surface-500 font-medium">
 Industry: {activeTestimonial.industry}
 </div>
 </div>
 </div>
 </div>
 </motion.div>
 </AnimatePresence>
 </motion.div>

 {/* Navigation */}
 <div className="flex items-center justify-between">
 {/* Dots */}
 <div className="flex items-center gap-2">
 {testimonials.map((_, index) => (
 <button
 key={index}
 onClick={() => setActiveIndex(index)}
 className={cn(
 'h-1.5 rounded-full transition-all duration-300',
 index === activeIndex
 ? 'w-6 bg-surface-900'
 : 'w-1.5 bg-surface-200 hover:bg-surface-300'
 )}
 aria-label={`Go to testimonial ${index + 1}`}
 />
 ))}
 </div>

 {/* Arrows */}
 <div className="flex items-center gap-2">
 <button
 onClick={prevTestimonial}
 className="w-9 h-9 rounded-lg border border-surface-200 bg-white flex items-center justify-center text-surface-500 hover:text-surface-900 hover:border-surface-300 transition-colors"
 aria-label="Previous testimonial"
 >
 <ChevronLeft className="w-5 h-5" />
 </button>
 <button
 onClick={nextTestimonial}
 className="w-9 h-9 rounded-lg border border-surface-200 bg-white flex items-center justify-center text-surface-500 hover:text-surface-900 hover:border-surface-300 transition-colors"
 aria-label="Next testimonial"
 >
 <ChevronRight className="w-5 h-5" />
 </button>
 </div>
 </div>

 {/* Logos Strip */}
 <motion.div
 initial={{ opacity: 0 }}
 animate={inView ? { opacity: 1 } : {}}
 transition={{ delay: 0.4 }}
 className="mt-16 pt-12 border-t border-surface-200"
 >
 <p className="text-center text-xs font-bold text-surface-600 uppercase tracking-widest mb-8">
 Powering email for innovative companies worldwide
 </p>
 <div className="flex items-center justify-center gap-12 flex-wrap opacity-40 grayscale">
 {['TechCorp', 'ScaleUp', 'DevTools', 'CloudBase', 'DataFlow', 'AppStack'].map((company) => (
 <span key={company} className="text-surface-900 font-bold text-lg">
 {company}
 </span>
 ))}
 </div>
 </motion.div>
 </div>
 </section>
 );
}
