import type { Metadata } from 'next';
import { PricingHero } from '@/components/pricing/PricingHero';
import { PricingPlans } from '@/components/pricing/PricingPlans';
import { PricingFAQ } from '@/components/pricing/PricingFAQ';
import { PricingCTA } from '@/components/pricing/PricingCTA';

export const metadata: Metadata = {
  title: 'Pricing | Simple, Transparent Pricing',
  description:
    'Start free with 3,000 emails per month. Scale with predictable pricing. No hidden fees, no surprises.',
  openGraph: {
    title: 'Pricing | Simple, Transparent Pricing',
    description:
      'Start free with 3,000 emails per month. Scale with predictable pricing. No hidden fees, no surprises.',
    type: 'website',
  },
};

export default function PricingPage() {
  return (
    <main className="overflow-hidden">
      <PricingHero />
      <PricingPlans />
      <PricingFAQ />
      <PricingCTA />
    </main>
  );
}
