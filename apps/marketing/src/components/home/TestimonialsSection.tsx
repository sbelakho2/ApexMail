'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ChevronLeft, ChevronRight, Quote, Star } from 'lucide-react';
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
 stats: { metric: 'Compliance Cost', before: '$10k/mo', after: '$299/mo' },
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
 className="premium-card p-8 lg:p-12 mb-8 bg-white"
 >
 <AnimatePresence mode="wait">
 <motion.div
 key={activeIndex}
 initial={{ opacity: 0, x: 20 }}
 animate={{ opacity: 1, x: 0 }}
 exit={{ opacity: 0, x: -20 }}
 transition={{ duration: 0.3 }}
 >
 <div className="flex flex-col lg:flex-row gap-8 lg:gap-12">
 {/* Quote */}
 <div className="flex-1">
 <Quote className="w-10 h-10 text-primary-200 mb-4" />
 <blockquote className="text-xl lg:text-2xl text-surface-900 font-medium leading-relaxed mb-6">
 &ldquo;{activeTestimonial.quote}&rdquo;
 </blockquote>
 <div className="flex items-center gap-4">
 <div className="w-14 h-14 rounded-full bg-primary-50 flex items-center justify-center text-primary-600 font-bold text-lg border border-primary-100">
 {activeTestimonial.author.split(' ').map(n => n[0]).join('')}
 </div>
 <div>
 <div className="font-bold text-surface-900">{activeTestimonial.author}</div>
 <div className="text-sm text-surface-500 font-medium">
 {activeTestimonial.role} at {activeTestimonial.company}
 </div>
 </div>
 <div className="ml-auto hidden sm:flex items-center gap-0.5">
 {[...Array(5)].map((_, i) => (
 <Star key={i} className="w-4 h-4 fill-amber-400 text-amber-400" />
 ))}
 </div>
 </div>
 </div>

 {/* Stats Card */}
 <div className="lg:w-64 flex-shrink-0">
 <div className="bg-surface-50 rounded-lg p-6 border border-surface-200">
 <div className="text-xs font-bold text-surface-600 mb-4 uppercase tracking-widest">{activeTestimonial.stats.metric}</div>
 <div className="space-y-3">
 <div>
 <div className="text-[10px] text-surface-600 mb-1 uppercase font-bold">Before</div>
 <div className="text-lg font-mono text-red-600 font-bold tabular-nums">{activeTestimonial.stats.before}</div>
 </div>
 <div className="w-full h-px bg-surface-200" />
 <div>
 <div className="text-[10px] text-surface-600 mb-1 uppercase font-bold">After</div>
 <div className="text-2xl font-mono text-primary-600 font-bold tabular-nums">{activeTestimonial.stats.after}</div>
 </div>
 </div>
 <div className="mt-4 text-[10px] text-surface-600 font-bold uppercase tracking-tight">
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
 'w-2 h-2 rounded-full transition-all',
 index === activeIndex
 ? 'w-8 bg-primary-600'
 : 'bg-surface-300 hover:bg-surface-400'
 )}
 aria-label={`Go to testimonial ${index + 1}`}
 />
 ))}
 </div>

 {/* Arrows */}
 <div className="flex items-center gap-2">
 <button
 onClick={prevTestimonial}
 className="w-10 h-10 rounded-md border border-surface-200 bg-white flex items-center justify-center text-surface-500 hover:text-primary-600 hover:border-primary-200 transition-colors "
 aria-label="Previous testimonial"
 >
 <ChevronLeft className="w-5 h-5" />
 </button>
 <button
 onClick={nextTestimonial}
 className="w-10 h-10 rounded-md border border-surface-200 bg-white flex items-center justify-center text-surface-500 hover:text-primary-600 hover:border-primary-200 transition-colors "
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
