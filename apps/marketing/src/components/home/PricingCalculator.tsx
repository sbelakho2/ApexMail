'use client';

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Check, ArrowRight } from 'lucide-react';
import Link from 'next/link';
import { formatNumber, formatCurrency } from '@/lib/utils';
import { cn } from '@/lib/utils';

interface PricingOption {
  dedicatedIP: boolean;
  sso: boolean;
  hipaa: boolean;
  privateCloud: boolean;
}

const pricingTiers = {
  apexmail: [
    { max: 1000, price: 0 },
    { max: 25000, price: 29 },
    { max: 50000, price: 59 },
    { max: 100000, price: 129 },
    { max: 500000, price: 399 },
    { max: Infinity, pricePerK: 0.45 },
  ],
  sendgrid: [
    { max: 6000, price: 0 },
    { max: 50000, price: 19.95 },
    { max: 100000, price: 34.95 },
    { max: 300000, price: 89.95 },
    { max: 700000, price: 249 },
    { max: 1500000, price: 449 },
    { max: 2500000, price: 749 },
    { max: Infinity, pricePerK: 0.45 },
  ],
  mailchimp: [
    { max: 500, price: 0 },
    { max: 5000, price: 15 },
    { max: 10000, price: 25 },
    { max: 50000, price: 80 },
    { max: 100000, price: 280 },
    { max: 200000, price: 550 },
    { max: Infinity, pricePerK: 3.5 },
  ],
  ses: [
    { max: Infinity, pricePerK: 0.10 },
  ],
};

const addons = {
  dedicatedIP: { apexmail: 50, sendgrid: 89, mailchimp: 29.95, ses: 24.95 },
  sso: { apexmail: 0, sendgrid: 900, mailchimp: 0, ses: 0 },
  hipaa: { apexmail: 100, sendgrid: 1000, mailchimp: 0, ses: 0 },
  privateCloud: { apexmail: 2000, sendgrid: 0, mailchimp: 0, ses: 0 },
};

function calculateApexMailCost(volume: number, options: PricingOption) {
  let paygCost = 0;
  if (volume <= 10000) paygCost = volume * 0.001;
  else if (volume <= 100000) paygCost = (10000 * 0.001) + ((volume - 10000) * 0.0008);
  else if (volume <= 1000000) paygCost = (10000 * 0.001) + (90000 * 0.0008) + ((volume - 100000) * 0.0005);
  else paygCost = (10000 * 0.001) + (90000 * 0.0008) + (900000 * 0.0005) + ((volume - 1000000) * 0.0003);

  if (options.dedicatedIP) paygCost += 50;
  if (options.sso) paygCost += 100;
  if (options.hipaa) paygCost += 500;
  if (options.privateCloud) paygCost += 2000;

  let planCost = Infinity;
  const plan = pricingTiers.apexmail.find(t => volume <= t.max && t.price !== undefined);
  
  if (plan && plan.price !== undefined) {
    planCost = plan.price;
    const isGrowthOrHigher = plan.price >= 129;
    const isScaleOrHigher = plan.price >= 399;

    if (options.dedicatedIP && !isGrowthOrHigher) planCost += 50;
    if (options.sso && !isScaleOrHigher) planCost += 100;
    if (options.hipaa) planCost += 500;
    if (options.privateCloud) planCost += 2000;
  }

  return Math.min(paygCost, planCost);
}

function calculatePrice(provider: keyof typeof pricingTiers, volume: number, options: PricingOption): number {
  if (provider === 'apexmail') {
    return calculateApexMailCost(volume, options);
  }

  const tiers = pricingTiers[provider];
  let basePrice = 0;

  for (const tier of tiers) {
    if (volume <= tier.max) {
      if ('price' in tier && tier.price !== undefined) {
        basePrice = tier.price;
      } else if ('pricePerK' in tier && tier.pricePerK !== undefined) {
        basePrice = (volume / 1000) * tier.pricePerK;
      }
      break;
    }
  }

  if (options.dedicatedIP && addons.dedicatedIP[provider]) {
    basePrice += addons.dedicatedIP[provider];
  }
  if (options.sso && addons.sso[provider]) {
    basePrice += addons.sso[provider];
  }
  if (options.hipaa && addons.hipaa[provider] && provider !== 'mailchimp' && provider !== 'ses') {
    basePrice += addons.hipaa[provider];
  }

  return Math.round(basePrice);
}

const volumeMarks = [
  { value: 1000, label: '1K' },
  { value: 10000, label: '10K' },
  { value: 100000, label: '100K' },
  { value: 500000, label: '500K' },
  { value: 1000000, label: '1M' },
];

export function PricingCalculator() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [volume, setVolume] = useState(100000);
  const [options, setOptions] = useState<PricingOption>({
    dedicatedIP: false,
    sso: false,
    hipaa: false,
    privateCloud: false,
  });

  const prices = useMemo(() => ({
    apexmail: calculatePrice('apexmail', volume, options),
    sendgrid: calculatePrice('sendgrid', volume, options),
    mailchimp: calculatePrice('mailchimp', volume, options),
    ses: calculatePrice('ses', volume, options),
  }), [volume, options]);

  return (
    <section ref={ref} className="py-24 bg-surface-50 relative overflow-hidden" id="pricing">
      {/* Background Decorative Elements */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-full pointer-events-none overflow-hidden">
        <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-brand-500/5 blur-[120px] rounded-full" />
        <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-brand-500/5 blur-[120px] rounded-full" />
      </div>

      <div className="relative max-w-[1200px] mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="text-center mb-16"
        >
          <h2 className="section-title mb-4">
            <span className="text-surface-900">Pricing That</span>{' '}
            <span className="text-brand-500">Scales With You</span>
          </h2>
          <p className="text-surface-600 text-lg max-w-2xl mx-auto leading-relaxed">
            Save up to 80% compared to legacy providers. No hidden fees, no enterprise tax.
          </p>
        </motion.div>

        <div className="grid lg:grid-cols-12 gap-12 items-start">
          {/* Calculator Card */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.2 }}
            className="lg:col-span-7 bg-white rounded-2xl border border-surface-200 shadow-xl overflow-hidden"
          >
            <div className="p-8 md:p-12">
              {/* Volume Slider */}
              <div className="mb-10">
                <div className="flex items-center justify-between mb-6">
                  <label className="text-lg font-bold text-surface-900">Monthly Email Volume</label>
                  <div className="text-right">
                    <span className="text-3xl font-bold text-brand-500 tabular-nums tracking-tight">{formatNumber(volume)}</span>
                    <span className="text-sm text-surface-500 font-medium ml-1">emails</span>
                  </div>
                </div>
                <input
                  type="range"
                  min="1000"
                  max="1000000"
                  step="1000"
                  value={volume}
                  onChange={(e) => setVolume(Number(e.target.value))}
                  aria-label="Email volume slider"
                  className="w-full h-2 bg-surface-100 rounded-full appearance-none cursor-pointer focus:outline-none focus:ring-2 focus:ring-brand-500/20 [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-6 [&::-webkit-slider-thumb]:h-6 [&::-webkit-slider-thumb]:bg-white [&::-webkit-slider-thumb]:border-2 [&::-webkit-slider-thumb]:border-brand-500 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:cursor-pointer [&::-webkit-slider-thumb]:shadow-sm [&::-webkit-slider-thumb]:active:scale-95 [&::-webkit-slider-thumb]:transition-transform"
                />
                <div className="flex justify-between mt-4">
                  {volumeMarks.map((mark) => (
                    <button
                      key={mark.value}
                      className={cn(
                        'text-xs font-bold tracking-tight transition-colors focus:outline-none uppercase tracking-widest',
                        Math.abs(volume - mark.value) < 50000 ? 'text-brand-500' : 'text-surface-400 hover:text-surface-600'
                      )}
                      onClick={() => setVolume(mark.value)}
                    >
                      {mark.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Options Checkboxes */}
              <div className="grid sm:grid-cols-2 gap-4 mb-10">
                {[
                  { key: 'dedicatedIP', label: 'Dedicated IP', tip: 'Improve deliverability' },
                  { key: 'sso', label: 'SSO/SAML', tip: 'Enterprise security' },
                  { key: 'hipaa', label: 'HIPAA Compliance', tip: 'Healthcare ready' },
                  { key: 'privateCloud', label: 'Private Cloud', tip: 'Isolated infrastructure' },
                ].map((option) => (
                  <label
                    key={option.key}
                    className={cn(
                      'flex flex-col p-4 rounded-xl border cursor-pointer transition-all duration-200 active:scale-[0.98]',
                      options[option.key as keyof PricingOption]
                        ? 'border-brand-500 bg-brand-50/50 shadow-md ring-1 ring-brand-500/20'
                        : 'border-surface-200 hover:border-surface-300 bg-white hover:bg-surface-50'
                    )}
                  >
                    <div className="flex justify-between items-start mb-2">
                      <span className="font-bold text-sm text-surface-900">{option.label}</span>
                      <div className={cn(
                        "w-4 h-4 border rounded flex items-center justify-center transition-colors",
                        options[option.key as keyof PricingOption] 
                          ? "bg-brand-500 border-brand-500 text-white" 
                          : "border-surface-300 bg-white"
                      )}>
                        {options[option.key as keyof PricingOption] && <Check className="w-3.5 h-3.5" strokeWidth={3} />}
                      </div>
                      <input
                        type="checkbox"
                        checked={options[option.key as keyof PricingOption]}
                        onChange={(e) => setOptions({ ...options, [option.key]: e.target.checked })}
                        className="hidden"
                      />
                    </div>
                    <span className="text-xs text-surface-500 font-medium">{option.tip}</span>
                  </label>
                ))}
              </div>

              {/* ApexMail Price Display */}
              <div className="flex flex-col sm:flex-row items-center gap-6 p-6 bg-brand-50 rounded-xl border border-brand-100">
                <div className="flex-1">
                  <div className="text-brand-700 font-bold mb-1 text-lg">Estimated Monthly Cost</div>
                  <div className="text-sm text-brand-600/80">Based on your current volume and options.</div>
                </div>
                <div className="text-4xl font-bold text-brand-700 tabular-nums">
                  {formatCurrency(prices.apexmail)}
                </div>
              </div>
            </div>
          </motion.div>

          {/* Comparison Side */}
          <div className="lg:col-span-5 space-y-8">
            <h3 className="text-xl font-bold text-surface-900 flex items-center gap-2">
              <span className="w-8 h-px bg-surface-200" />
              Savings Comparison
            </h3>
            
            <div className="space-y-4">
              <ComparisonRow name="SendGrid" price={prices.sendgrid} apexPrice={prices.apexmail} />
              <ComparisonRow name="Mailchimp" price={prices.mailchimp} apexPrice={prices.apexmail} />
              <ComparisonRow name="AWS SES" price={prices.ses} apexPrice={prices.apexmail} />
            </div>

            <div className="mt-12 p-8 bg-surface-900 rounded-2xl text-white shadow-2xl relative overflow-hidden group">
               <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
                  <ArrowRight className="w-32 h-32 -rotate-45" />
               </div>
               <h4 className="text-2xl font-bold mb-4">Ready to switch?</h4>
               <p className="text-surface-400 text-sm leading-relaxed mb-8">
                 Migration is seamless. Use our SMTP relay or API wrapper to start sending in minutes.
               </p>
               <Link href="https://app.apexmail.ee/signup" className="btn-primary w-full inline-flex items-center justify-center">
                 Start Free Trial
                 <ArrowRight className="ml-2 w-4 h-4" />
               </Link>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function ComparisonRow({ name, price, apexPrice }: { name: string; price: number; apexPrice: number }) {
  const savings = Math.max(0, price - apexPrice);
  const percentage = Math.round((savings / price) * 100);

  return (
    <div className="p-5 bg-white rounded-xl border border-surface-200 shadow-sm">
      <div className="flex justify-between items-center mb-3">
        <span className="font-bold text-surface-900">{name}</span>
        <span className="text-lg font-bold text-surface-400 tabular-nums">{formatCurrency(price)}</span>
      </div>
      <div className="relative h-2 bg-surface-100 rounded-full overflow-hidden">
        <div 
          className="absolute top-0 left-0 h-full bg-brand-500 transition-all duration-500" 
          style={{ width: `${(apexPrice / price) * 100}%` }} 
        />
      </div>
      <div className="flex justify-between mt-2">
        <span className="text-xs font-bold text-brand-600 uppercase tracking-wider">ApexMail</span>
        <span className="text-xs font-bold text-success-600 uppercase tracking-wider">Save {percentage}%</span>
      </div>
    </div>
  );
}
