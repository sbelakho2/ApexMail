import type { Metadata } from 'next';
import { HeroSection } from '@/components/home/HeroSection';
import { FeaturesSection } from '@/components/home/FeaturesSection';
import { LiveAPIConsole } from '@/components/home/LiveAPIConsole';
import { ComparisonSection } from '@/components/home/ComparisonSection';
import { PricingCalculator } from '@/components/home/PricingCalculator';
import { SecuritySection } from '@/components/home/SecuritySection';
import { TestimonialsSection } from '@/components/home/TestimonialsSection';
import { CTASection } from '@/components/home/CTASection';

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
      <LiveAPIConsole />
      <ComparisonSection />
      <SecuritySection />
      <PricingCalculator />
      <TestimonialsSection />
      <CTASection />
    </>
  );
}
