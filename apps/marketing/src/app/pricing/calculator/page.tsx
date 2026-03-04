import type { Metadata } from 'next';
import { CalculatorHero } from '@/components/calculator/CalculatorHero';
import { InteractiveCalculator } from '@/components/calculator/InteractiveCalculator';
import { CompetitorBreakdown } from '@/components/calculator/CompetitorBreakdown';
import { CalculatorCTA } from '@/components/calculator/CalculatorCTA';

export const dynamic = 'force-static';
export const revalidate = 3600;

export const metadata: Metadata = {
  title: 'Pricing Calculator | Compare vs Competitors',
  description:
    'See exactly how much you\'ll save with ApexMail. Interactive calculator compares costs against SendGrid, Mailchimp, and AWS SES.',
  openGraph: {
    title: 'Pricing Calculator | Compare vs Competitors',
    description:
      'See exactly how much you\'ll save with ApexMail. Interactive calculator compares costs against SendGrid, Mailchimp, and AWS SES.',
    type: 'website',
  },
};

export default function CalculatorPage() {
  return (
    <main className="overflow-hidden">
      <CalculatorHero />
      <InteractiveCalculator />
      <CompetitorBreakdown />
      <CalculatorCTA />
    </main>
  );
}
