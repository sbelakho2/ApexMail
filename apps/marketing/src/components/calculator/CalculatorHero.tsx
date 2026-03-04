import { Calculator, DollarSign, TrendingDown } from '@/components/ui/icons';

export function CalculatorHero() {
  return (
    <section className="relative min-h-[40vh] flex items-center pt-32 pb-20 bg-surface-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <div className="text-center max-w-3xl mx-auto">
          <div className="animate-in inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-50 text-primary-700 border border-primary-100/50 text-xs font-medium mb-6">
            <Calculator className="w-4 h-4" />
            <span>Pricing Calculator</span>
          </div>

          <h1 className="animate-in delay-100 text-4xl lg:text-6xl font-bold text-surface-900 mb-6 tracking-tight">
            Calculate Your <span className="text-primary-600">Savings</span>
          </motion.h1>

          <p className="animate-in delay-200 text-xl text-surface-600 mb-10 leading-relaxed font-medium">
            See exactly how ApexMail stacks up against SendGrid, Mailchimp, and AWS SES. 
            Enter your volume and watch the numbers speak for themselves.
          </p>

          <div className="animate-in delay-300 flex flex-wrap justify-center gap-6">
            <div className="flex items-center gap-2 text-surface-600 font-medium text-sm">
              <DollarSign className="w-4 h-4 text-primary-600" />
              <span>Transparent pricing</span>
            </div>
            <div className="flex items-center gap-2 text-surface-600 font-medium text-sm">
              <TrendingDown className="w-4 h-4 text-primary-600" />
              <span>Up to 60% savings</span>
            </div>
            <div className="flex items-center gap-2 text-surface-600 font-medium text-sm">
              <Calculator className="w-4 h-4 text-primary-600" />
              <span>No hidden fees</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
