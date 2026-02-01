import { HeroSection } from '@/components/home/HeroSection';
import { FeaturesSection } from '@/components/home/FeaturesSection';
import { LiveAPIConsole } from '@/components/home/LiveAPIConsole';
import { ComparisonSection } from '@/components/home/ComparisonSection';
import { PricingCalculator } from '@/components/home/PricingCalculator';
import { SecuritySection } from '@/components/home/SecuritySection';
import { TestimonialsSection } from '@/components/home/TestimonialsSection';
import { CTASection } from '@/components/home/CTASection';

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
