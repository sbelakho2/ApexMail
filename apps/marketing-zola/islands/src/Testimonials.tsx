import { h } from 'preact';
import { useState } from 'preact/hooks';

// Inline SVG icons
const ChevronLeft = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="m15 18-6-6 6-6" />
  </svg>
);
const ChevronRight = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="m9 18 6-6-6-6" />
  </svg>
);
const Quote = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="currentColor" stroke="none">
    <path d="M3 21c3 0 7-1 7-8V5c0-1.25-.756-2.017-2-2H4c-1.25 0-2 .75-2 1.972V11c0 1.25.75 2 2 2 1 0 1 0 1 1v1c0 1-1 2-2 2s-1 .008-1 1.031V20c0 1 0 1 1 1z" />
    <path d="M15 21c3 0 7-1 7-8V5c0-1.25-.757-2.017-2-2h-4c-1.25 0-2 .75-2 1.972V11c0 1.25.75 2 2 2h.75c0 2.25.25 4-2.75 4v3c0 1 0 1 1 1z" />
  </svg>
);

interface Testimonial {
  quote: string;
  author: string;
  role: string;
  company: string;
  industry: string;
  image: string;
  stats: { metric: string; before: string; after: string };
}

const testimonials: Testimonial[] = [
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
    quote: 'The forensic render history feature alone is worth the switch. Last month a customer claimed they never got an email - we showed them exactly what they received, pixel for pixel. Case closed.',
    author: 'Marcus Rodriguez',
    role: 'Head of Engineering',
    company: 'SupportHero',
    industry: 'SaaS',
    image: '/testimonials/marcus.jpg',
    stats: { metric: 'Support Disputes', before: '15/month', after: '2/month' },
  },
  {
    quote: 'As a healthcare startup, HIPAA compliance was non-negotiable. Other providers either didn\'t offer it or wanted $10k/month. ApexMail gave us enterprise-grade compliance at a fraction of the cost.',
    author: 'Dr. Emily Watson',
    role: 'Founder',
    company: 'MedConnect',
    industry: 'Healthcare',
    image: '/testimonials/emily.jpg',
    stats: { metric: 'Compliance Cost', before: '$10k/mo', after: '$350/mo' },
  },
  {
    quote: 'The API is so clean that our junior devs had email sending working in their first hour. The TypeScript SDK with full type inference made it feel like a native part of our stack.',
    author: 'James Liu',
    role: 'Lead Developer',
    company: 'DevStack',
    industry: 'Developer Tools',
    image: '/testimonials/james.jpg',
    stats: { metric: 'Integration Time', before: '2 days', after: '45 minutes' },
  },
  {
    quote: 'During Black Friday, we sent 2M emails in 4 hours. Not a single OTP or password reset was delayed thanks to the priority lane feature. Our competitors\' customers were complaining about slow emails.',
    author: 'Amanda Foster',
    role: 'VP of Engineering',
    company: 'ShopFast',
    industry: 'E-commerce',
    image: '/testimonials/amanda.jpg',
    stats: { metric: 'OTP Delivery', before: '8-15 seconds', after: '<2 seconds' },
  },
];

export default function Testimonials() {
  const [activeIndex, setActiveIndex] = useState(0);

  const nextTestimonial = () => {
    setActiveIndex((prev) => (prev + 1) % testimonials.length);
  };

  const prevTestimonial = () => {
    setActiveIndex((prev) => (prev - 1 + testimonials.length) % testimonials.length);
  };

  if (!testimonials.length) return null;
  const active = testimonials[activeIndex];

  return (
    <section
      class="py-20 lg:py-32 relative overflow-hidden bg-surface-50"
      role="region"
      aria-roledescription="carousel"
      aria-label="Customer testimonials"
      onKeyDown={(e: KeyboardEvent) => {
        if (e.key === 'ArrowRight') nextTestimonial();
        else if (e.key === 'ArrowLeft') prevTestimonial();
      }}
      tabIndex={0}
    >
      <div class="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div class="text-center mb-12">
          <h2 class="section-title mb-4">
            <span class="text-surface-900">Trusted by</span>{' '}
            <span class="text-brand-500">Developers Who Ship</span>
          </h2>
          <p class="text-surface-600 text-[17px] max-w-2xl mx-auto leading-relaxed">
            Don&apos;t take our word for it. Here&apos;s what our customers have to say.
          </p>
        </div>

        {/* Main Testimonial */}
        <div class="p-8 lg:p-12 mb-10 bg-white rounded-lg border border-surface-200">
          <div key={activeIndex}>
            <div class="flex flex-col lg:flex-row gap-8 lg:gap-16">
              {/* Quote */}
              <div class="flex-1">
                <Quote class="w-8 h-8 text-surface-200 mb-6" />
                <blockquote class="text-xl lg:text-2xl text-surface-900 font-medium leading-relaxed mb-8">
                  &ldquo;{active.quote}&rdquo;
                </blockquote>
                <div class="flex items-center gap-4">
                  {/* Replace next/image with native <img> + loading=lazy */}
                  <img
                    src={active.image}
                    alt={`${active.author} profile photo`}
                    width={48}
                    height={48}
                    loading="lazy"
                    class="w-12 h-12 rounded-full object-cover border border-surface-200"
                  />
                  <div>
                    <div class="font-semibold text-surface-900">{active.author}</div>
                    <div class="text-sm text-surface-500">
                      {active.role}, {active.company}
                    </div>
                  </div>
                </div>
              </div>

              {/* Stats Card */}
              <div class="lg:w-64 flex-shrink-0">
                <div class="bg-surface-50 rounded-lg p-6 border border-surface-200">
                  <div class="text-[14px] font-semibold text-surface-500 mb-4">{active.stats.metric}</div>
                  <div class="space-y-4">
                    <div>
                      <div class="text-[14px] text-surface-400 mb-1 font-medium">Before</div>
                      <div class="text-lg font-mono text-surface-700 font-semibold tabular-nums line-through decoration-surface-400/50">
                        {active.stats.before}
                      </div>
                    </div>
                    <div>
                      <div class="text-[14px] text-surface-400 mb-1 font-medium">After</div>
                      <div class="text-2xl font-mono text-brand-500 font-bold tabular-nums">
                        {active.stats.after}
                      </div>
                    </div>
                  </div>
                  <div class="mt-6 pt-4 border-t border-surface-200 text-[14px] text-surface-500 font-medium">
                    Industry: {active.industry}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <div class="flex items-center justify-between">
          {/* Dots */}
          <div class="flex items-center gap-2">
            {testimonials.map((_, index) => (
              <button
                key={index}
                onClick={() => setActiveIndex(index)}
                class="rounded-full transition-all duration-300 p-2.5 relative"
                aria-label={`Go to testimonial ${index + 1}`}
              >
                <span
                  class={`block h-1.5 rounded-full transition-all duration-300 ${
                    index === activeIndex
                      ? 'w-6 bg-surface-900'
                      : 'w-1.5 bg-surface-200 hover:bg-surface-300'
                  }`}
                />
              </button>
            ))}
          </div>

          {/* Arrows */}
          <div class="flex items-center gap-2">
            <button
              onClick={prevTestimonial}
              class="w-11 h-11 rounded-lg border border-surface-200 bg-white flex items-center justify-center text-surface-500 hover:text-surface-900 hover:border-surface-300 transition-colors"
              aria-label="Previous testimonial"
            >
              <ChevronLeft class="w-5 h-5" />
            </button>
            <button
              onClick={nextTestimonial}
              class="w-11 h-11 rounded-lg border border-surface-200 bg-white flex items-center justify-center text-surface-500 hover:text-surface-900 hover:border-surface-300 transition-colors"
              aria-label="Next testimonial"
            >
              <ChevronRight class="w-5 h-5" />
            </button>
          </div>
        </div>

        <div class="mt-16 pt-12 border-t border-surface-200 text-center">
          <p class="text-sm font-medium text-surface-600">
            Customer stories shown above are from production teams across fintech, healthcare, SaaS, developer tools, and e-commerce.
          </p>
        </div>
      </div>
    </section>
  );
}
