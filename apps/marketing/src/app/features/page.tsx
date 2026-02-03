import type { Metadata } from 'next';
import { FeaturesHero } from '@/components/features/FeaturesHero';
import { FeatureGrid } from '@/components/features/FeatureGrid';
import { FeatureDetails } from '@/components/features/FeatureDetails';
import { FeatureCTA } from '@/components/features/FeatureCTA';

export const metadata: Metadata = {
  title: 'Features | Enterprise-Grade Email Infrastructure',
  description:
    'Discover all ApexMail features: deliverability tools, compliance automation, AI-powered optimization, and enterprise security.',
  openGraph: {
    title: 'Features | Enterprise-Grade Email Infrastructure',
    description:
      'Discover all ApexMail features: deliverability tools, compliance automation, AI-powered optimization, and enterprise security.',
    type: 'website',
  },
};

export default function FeaturesPage() {
  return (
    <main className="overflow-hidden">
      <FeaturesHero />
      <FeatureGrid />
      <FeatureDetails />
      <FeatureCTA />
    </main>
  );
}
