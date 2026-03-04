import type { Metadata } from 'next';
import dynamic from 'next/dynamic';
import { Suspense } from 'react';
import { HeroSection } from '@/components/home/HeroSection';
import { FeaturesSection } from '@/components/home/FeaturesSection';
import { ComparisonSection } from '@/components/home/ComparisonSection';
import { SecuritySection } from '@/components/home/SecuritySection';
import { CTASection } from '@/components/home/CTASection';

// Heavy interactive components - lazy load to reduce initial JS
const LiveAPIConsole = dynamic(
  () => import('@/components/home/LiveAPIConsole').then(m => ({ default: m.LiveAPIConsole })),
  {
    loading: () => (
      <section className="py-24 bg-surface-900">
        <div className="max-w-7xl mx-auto px-4">
          <div className="h-96 bg-surface-800 rounded-xl animate-pulse" />
        </div>
      </section>
    ),
    ssr: false,
  }
);

const PricingCalculator = dynamic(
  () => import('@/components/home/PricingCalculator').then(m => ({ default: m.PricingCalculator })),
  {
    loading: () => (
      <section className="py-24">
        <div className="max-w-7xl mx-auto px-4">
          <div className="h-80 bg-surface-100 rounded-xl animate-pulse" />
        </div>
      </section>
    ),
    ssr: false,
  }
);

const TestimonialsSection = dynamic(
  () => import('@/components/home/TestimonialsSection').then(m => ({ default: m.TestimonialsSection })),
  {
    loading: () => (
      <section className="py-24 bg-surface-50">
        <div className="max-w-7xl mx-auto px-4">
          <div className="h-64 bg-surface-100 rounded-xl animate-pulse" />
        </div>
      </section>
    ),
  }
);

export const dynamic = 'force-static';
export const revalidate = 3600;

export const metadata: Metadata = {
  title: 'ApexMail | Enterprise Email API for Developers',
  description: 'Send transactional and marketing email with enterprise-grade compliance, delivery analytics, and private-cloud options.',
  openGraph: {
    title: 'ApexMail | Enterprise Email API for Developers',
    description: 'Send transactional and marketing email with enterprise-grade compliance, delivery analytics, and private-cloud options.',
    type: 'website',
    images: ['/og-image.png'],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'ApexMail | Enterprise Email API for Developers',
    description: 'Send transactional and marketing email with enterprise-grade compliance, delivery analytics, and private-cloud options.',
    images: ['/og-image.png'],
  },
};

export default function HomePage() {
  return (
    <>
      <HeroSection />
      <FeaturesSection />
      <Suspense fallback={<div className="h-96 bg-surface-900" />}>
        <LiveAPIConsole />
      </Suspense>
      <ComparisonSection />
      <SecuritySection />
      <Suspense fallback={<div className="h-80" />}>
        <PricingCalculator />
      </Suspense>
      <Suspense fallback={<div className="h-64 bg-surface-50" />}>
        <TestimonialsSection />
      </Suspense>
      <CTASection />
    </>
  );
}
