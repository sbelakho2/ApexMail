'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { useState, useMemo } from 'react';
import { Mail, CheckCircle } from '@/components/ui/icons';
import { cn } from '@/lib/utils';

interface PricingTier {
  name: string;
  calculate: (emails: number) => number;
  color: string;
}

const providers: Record<string, PricingTier> = {
  apexmail: {
    name: 'ApexMail',
    calculate: (emails: number) => {
      if (emails <= 10000) return 0;
      if (emails <= 100000) return 29;
      if (emails <= 500000) return 99;
      if (emails <= 1000000) return 199;
      if (emails <= 5000000) return 499;
      return 499 + Math.ceil((emails - 5000000) / 1000000) * 80;
    },
    color: 'bg-primary-600',
  },
  sendgrid: {
    name: 'SendGrid',
    calculate: (emails: number) => {
      if (emails <= 100) return 0;
      if (emails <= 50000) return 19.95;
      if (emails <= 100000) return 34.95;
      if (emails <= 200000) return 89.95;
      if (emails <= 500000) return 249;
      if (emails <= 1000000) return 449;
      return 449 + Math.ceil((emails - 1000000) / 100000) * 30;
    },
    color: 'bg-surface-400',
  },
  mailchimp: {
    name: 'Mailchimp',
    calculate: (emails: number) => {
      const contacts = Math.ceil(emails / 10);
      if (contacts <= 500) return 13;
      if (contacts <= 2500) return 45;
      if (contacts <= 10000) return 100;
      if (contacts <= 50000) return 350;
      if (contacts <= 100000) return 605;
      return 605 + Math.ceil((contacts - 100000) / 10000) * 50;
    },
    color: 'bg-yellow-500',
  },
  ses: {
    name: 'AWS SES',
    calculate: (emails: number) => {
      return emails * 0.0001;
    },
    color: 'bg-orange-500',
  },
};

const volumeMarks = [
  { value: 10000, label: '10K' },
  { value: 50000, label: '50K' },
  { value: 100000, label: '100K' },
  { value: 500000, label: '500K' },
  { value: 1000000, label: '1M' },
  { value: 5000000, label: '5M' },
  { value: 10000000, label: '10M' },
];

export function InteractiveCalculator() {
  const [ref, _inView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [emailVolume, setEmailVolume] = useState(100000);

  const prices = useMemo(() => {
    return Object.entries(providers).map(([id, provider]) => ({
      id,
      ...provider,
      price: provider.calculate(emailVolume),
    }));
  }, [emailVolume]);

  const sortedPrices = [...prices].sort((a, b) => a.price - b.price);
  const maxPrice = Math.max(...prices.map((p) => p.price));
  const apexmailPrice = prices.find((p) => p.id === 'apexmail')?.price || 0;
  const highestCompetitorPrice = sortedPrices[sortedPrices.length - 1]?.price || 0;
  const savings = highestCompetitorPrice - apexmailPrice;
  const savingsPercentage = highestCompetitorPrice > 0 ? (savings / highestCompetitorPrice) * 100 : 0;

  const formatPrice = (price: number) => {
    if (price === 0) return 'Free';
    return `$${price.toLocaleString('en-US', { minimumFractionDigits: 0, maximumFractionDigits: 2 })}`;
  };

  const formatVolume = (volume: number) => {
    if (volume >= 1000000) return `${(volume / 1000000).toFixed(1)}M`;
    if (volume >= 1000) return `${(volume / 1000).toFixed(0)}K`;
    return volume.toString();
  };

  return (
    <section ref={ref} className="py-12 lg:py-20 relative bg-surface-50">
      <div className="max-w-[1200px] mx-auto px-4 sm:px-6 lg:px-8">
        <div className="bg-white border border-surface-200 shadow-sm rounded-lg p-8 lg:p-10">
          {/* Volume Slider */}
          <div className="mb-12">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-2">
                <div className="p-2 bg-primary-50 text-primary-600 rounded-lg">
                  <Mail className="w-5 h-5" />
                </div>
                <span className="text-surface-900 font-semibold text-lg">Monthly Email Volume</span>
              </div>
              <div className="text-3xl font-bold text-surface-900 tabular-nums">{formatVolume(emailVolume)} <span className="text-base font-medium text-surface-500">emails</span></div>
            </div>
            
            <input
              type="range"
              min={10000}
              max={10000000}
              step={10000}
              value={emailVolume}
              onChange={(e) => setEmailVolume(Number(e.target.value))}
              className="w-full h-2 bg-surface-100 rounded-full appearance-none cursor-pointer focus:outline-none focus:ring-2 focus:ring-primary-500/20 [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-6 [&::-webkit-slider-thumb]:h-6 [&::-webkit-slider-thumb]:bg-white [&::-webkit-slider-thumb]:border-2 [&::-webkit-slider-thumb]:border-primary-600 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:cursor-pointer [&::-webkit-slider-thumb]:shadow-sm [&::-webkit-slider-thumb]:active:scale-95 [&::-webkit-slider-thumb]:transition-transform"
            />
            
            <div className="flex justify-between mt-3 px-1">
              {volumeMarks.map((mark) => (
                <span
                  key={mark.value}
                  className={cn(
                    "text-xs tabular-nums font-medium transition-colors",
                    emailVolume >= mark.value ? 'text-primary-700 font-bold' : 'text-surface-400'
                  )}
                >
                  {mark.label}
                </span>
              ))}
            </div>
          </div>

          <div className="grid lg:grid-cols-3 gap-8 lg:gap-12">
            {/* Price Comparison */}
            <div className="lg:col-span-2 space-y-6">
              <h3 className="text-sm font-semibold text-surface-900 tracking-tight mb-4">Estimated Monthly Cost</h3>
              <div className="space-y-4">
                {sortedPrices.map((provider) => (
                  <div key={provider.id} className="space-y-2 group">
                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center gap-2">
                        {provider.id === 'apexmail' ? (
                          <div className="flex items-center gap-1.5 text-primary-700 font-bold">
                            <CheckCircle className="w-4 h-4 text-emerald-500 fill-emerald-50/50" />
                            <span>{provider.name}</span>
                          </div>
                        ) : (
                          <span className="text-surface-600 font-medium group-hover:text-surface-900 transition-colors">
                            {provider.name}
                          </span>
                        )}
                      </div>
                      <span
                        className={cn(
                          "font-medium tabular-nums",
                          provider.id === 'apexmail' ? 'text-primary-700 font-bold text-lg' : 'text-surface-600'
                        )}
                      >
                        {formatPrice(provider.price)}
                      </span>
                    </div>
                    <div className="h-2.5 bg-surface-50 rounded-full overflow-hidden flex items-center">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: maxPrice > 0 ? `${(provider.price / maxPrice) * 100}%` : '0%' }}
                        transition={{ duration: 0.5, ease: "easeOut" }}
                        className={cn("h-full rounded-full transition-colors", provider.color)}
                        style={{ minWidth: provider.price > 0 ? '4px' : '0%' }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Savings Summary */}
            <div className="lg:col-span-1">
              <div className="bg-emerald-50/50 border border-emerald-100 rounded-lg p-6 h-full flex flex-col justify-center text-center">
                {savings > 0 ? (
                  <>
                    <div className="text-emerald-700 text-xs font-bold mb-3">Potential Savings</div>
                    <div className="text-4xl font-bold text-surface-900 mb-2 tabular-nums tracking-tight">
                      {formatPrice(savings)}<span className="text-lg text-surface-500 font-medium">/mo</span>
                    </div>
                    <div className="text-surface-700 text-sm font-medium mb-6">
                      <span className="text-emerald-700 font-bold">{savingsPercentage.toFixed(0)}% less</span> than {sortedPrices[sortedPrices.length - 1]?.name}
                    </div>
                    <div className="bg-white/60 rounded-lg p-3 text-sm text-surface-600 tabular-nums border border-emerald-100/50">
                      That's <span className="font-bold text-surface-900">{formatPrice(savings * 12)}</span> saved per year
                    </div>
                  </>
                ) : (
                  <>
                    <div className="text-primary-700 text-xs font-bold mb-3">Best Value</div>
                    <p className="text-surface-700 text-sm">
                      ApexMail offers the most competitive pricing for high-volume senders.
                    </p>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
