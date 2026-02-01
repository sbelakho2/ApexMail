'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { useState, useMemo } from 'react';
import { Mail, CheckCircle } from 'lucide-react';

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
    color: 'bg-primary-500',
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
    color: 'bg-blue-500',
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
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });
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
    <section ref={ref} className="py-12 lg:py-20 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="glass-card p-8"
        >
          {/* Volume Slider */}
          <div className="mb-8">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Mail className="w-5 h-5 text-primary-400" />
                <span className="text-white font-medium">Monthly Email Volume</span>
              </div>
              <div className="text-2xl font-bold text-white">{formatVolume(emailVolume)} emails</div>
            </div>
            <input
              type="range"
              min={10000}
              max={10000000}
              step={10000}
              value={emailVolume}
              onChange={(e) => setEmailVolume(Number(e.target.value))}
              className="w-full h-2 bg-surface-700 rounded-full appearance-none cursor-pointer [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-5 [&::-webkit-slider-thumb]:h-5 [&::-webkit-slider-thumb]:bg-primary-500 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:cursor-pointer"
            />
            <div className="flex justify-between mt-2">
              {volumeMarks.map((mark) => (
                <span
                  key={mark.value}
                  className={`text-xs ${
                    emailVolume >= mark.value ? 'text-primary-400' : 'text-surface-500'
                  }`}
                >
                  {mark.label}
                </span>
              ))}
            </div>
          </div>

          {/* Price Comparison */}
          <div className="space-y-4 mb-8">
            {sortedPrices.map((provider) => (
              <div key={provider.id} className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {provider.id === 'apexmail' && (
                      <CheckCircle className="w-4 h-4 text-green-400" />
                    )}
                    <span
                      className={`font-medium ${
                        provider.id === 'apexmail' ? 'text-primary-400' : 'text-white'
                      }`}
                    >
                      {provider.name}
                    </span>
                  </div>
                  <span
                    className={`font-bold ${
                      provider.id === 'apexmail' ? 'text-primary-400 text-xl' : 'text-white'
                    }`}
                  >
                    {formatPrice(provider.price)}/mo
                  </span>
                </div>
                <div className="h-3 bg-surface-800 rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: maxPrice > 0 ? `${(provider.price / maxPrice) * 100}%` : '0%' }}
                    transition={{ duration: 0.5 }}
                    className={`h-full rounded-full ${provider.color}`}
                    style={{ minWidth: provider.price > 0 ? '2%' : '0%' }}
                  />
                </div>
              </div>
            ))}
          </div>

          {/* Savings Summary */}
          {savings > 0 && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="bg-green-500/10 border border-green-500/30 rounded-xl p-6 text-center"
            >
              <div className="text-green-400 text-sm mb-2">Your potential savings with ApexMail</div>
              <div className="text-4xl font-bold text-white mb-1">
                {formatPrice(savings)}/mo
              </div>
              <div className="text-green-400">
                {savingsPercentage.toFixed(0)}% less than {sortedPrices[sortedPrices.length - 1]?.name}
              </div>
              <div className="text-sm text-surface-400 mt-2">
                That's {formatPrice(savings * 12)} saved per year
              </div>
            </motion.div>
          )}
        </motion.div>
      </div>
    </section>
  );
}
