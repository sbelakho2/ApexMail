'use client';

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Check, Info, ArrowRight } from 'lucide-react';
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
    { max: 100000, price: 99 },
    { max: 500000, price: 299 },
    { max: 1000000, price: 599 },
    { max: 2500000, price: 1199 },
    { max: 5000000, price: 2199 },
    { max: Infinity, pricePerK: 0.35 },
  ],
  sendgrid: [
    { max: 6000, price: 0 },
    { max: 50000, price: 14.95 },
    { max: 100000, price: 29.95 },
    { max: 300000, price: 89.95 },
    { max: 700000, price: 249 },
    { max: 1500000, price: 449 },
    { max: 2500000, price: 749 },
    { max: Infinity, pricePerK: 0.30 },
  ],
  mailchimp: [
    { max: 500, price: 0 },
    { max: 5000, price: 13 },
    { max: 10000, price: 20 },
    { max: 50000, price: 75 },
    { max: 100000, price: 270 },
    { max: 200000, price: 540 },
    { max: Infinity, pricePerK: 2.7 },
  ],
  ses: [
    { max: Infinity, pricePerK: 0.10 },
  ],
};

const addons = {
  dedicatedIP: { apexmail: 50, sendgrid: 85, mailchimp: 150, ses: 25 },
  sso: { apexmail: 0, sendgrid: 500, mailchimp: 300, ses: 0 },
  hipaa: { apexmail: 200, sendgrid: 1000, mailchimp: 0, ses: 0 },
  privateCloud: { apexmail: 3000, sendgrid: 0, mailchimp: 0, ses: 0 },
};

function calculatePrice(provider: keyof typeof pricingTiers, volume: number, options: PricingOption): number {
  const tiers = pricingTiers[provider];
  let basePrice = 0;

  for (const tier of tiers) {
    if (volume <= tier.max) {
      if (tier.price !== undefined) {
        basePrice = tier.price;
      } else if (tier.pricePerK !== undefined) {
        basePrice = (volume / 1000) * tier.pricePerK;
      }
      break;
    }
  }

  // Add addons
  if (options.dedicatedIP && addons.dedicatedIP[provider]) {
    basePrice += addons.dedicatedIP[provider];
  }
  if (options.sso && addons.sso[provider]) {
    basePrice += addons.sso[provider];
  }
  if (options.hipaa && addons.hipaa[provider] && provider !== 'mailchimp' && provider !== 'ses') {
    basePrice += addons.hipaa[provider];
  }
  if (options.privateCloud && provider === 'apexmail') {
    basePrice += addons.privateCloud[provider];
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

  const savings = useMemo(() => {
    const avgCompetitor = (prices.sendgrid + prices.mailchimp) / 2;
    return Math.max(0, Math.round(avgCompetitor - prices.apexmail));
  }, [prices]);

  return (
    <section ref={ref} className="py-20 lg:py-32 relative" id="pricing">
      <div className="absolute inset-0 bg-gradient-to-b from-surface-900/30 via-transparent to-surface-900/30" />

      <div className="relative max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="text-center mb-12"
        >
          <h2 className="section-title mb-4">
            <span className="text-white">Transparent</span>{' '}
            <span className="gradient-text">Pricing</span>
          </h2>
          <p className="section-subtitle">
            See exactly what you&apos;ll pay. No hidden fees, no surprise overages.
          </p>
        </motion.div>

        {/* Calculator Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.2 }}
          className="glass-card p-6 lg:p-8"
        >
          {/* Volume Slider */}
          <div className="mb-8">
            <div className="flex items-center justify-between mb-4">
              <label className="text-lg font-medium text-white">Monthly Email Volume</label>
              <span className="text-2xl font-bold gradient-text">{formatNumber(volume)}</span>
            </div>
            <input
              type="range"
              min="1000"
              max="1000000"
              step="1000"
              value={volume}
              onChange={(e) => setVolume(Number(e.target.value))}
              className="w-full h-2 bg-surface-700 rounded-lg appearance-none cursor-pointer"
            />
            <div className="flex justify-between mt-2">
              {volumeMarks.map((mark) => (
                <span
                  key={mark.value}
                  className={cn(
                    'text-xs cursor-pointer transition-colors',
                    Math.abs(volume - mark.value) < 50000 ? 'text-primary-400' : 'text-surface-500'
                  )}
                  onClick={() => setVolume(mark.value)}
                >
                  {mark.label}
                </span>
              ))}
            </div>
          </div>

          {/* Options Checkboxes */}
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            {[
              { key: 'dedicatedIP', label: 'Dedicated IP', tip: 'Improve deliverability with your own IP address' },
              { key: 'sso', label: 'SSO/SAML', tip: 'Enterprise single sign-on integration' },
              { key: 'hipaa', label: 'HIPAA Compliance', tip: 'Healthcare data compliance with BAA' },
              { key: 'privateCloud', label: 'Private Cloud', tip: 'Dedicated infrastructure, zero shared resources' },
            ].map((option) => (
              <label
                key={option.key}
                className={cn(
                  'flex items-center gap-3 p-4 rounded-lg border cursor-pointer transition-all',
                  options[option.key as keyof PricingOption]
                    ? 'bg-primary-500/10 border-primary-500/50'
                    : 'bg-surface-800/50 border-surface-700 hover:border-surface-600'
                )}
              >
                <input
                  type="checkbox"
                  checked={options[option.key as keyof PricingOption]}
                  onChange={(e) => setOptions({ ...options, [option.key]: e.target.checked })}
                  className="sr-only"
                />
                <div
                  className={cn(
                    'w-5 h-5 rounded border-2 flex items-center justify-center transition-colors',
                    options[option.key as keyof PricingOption]
                      ? 'bg-primary-500 border-primary-500'
                      : 'border-surface-600'
                  )}
                >
                  {options[option.key as keyof PricingOption] && <Check className="w-3 h-3 text-white" />}
                </div>
                <div>
                  <div className="text-sm font-medium text-white">{option.label}</div>
                  <div className="text-xs text-surface-500">{option.tip}</div>
                </div>
              </label>
            ))}
          </div>

          {/* Price Comparison */}
          <div className="grid md:grid-cols-4 gap-4">
            {/* ApexMail - Featured */}
            <div className="md:col-span-1 rounded-xl border-2 border-primary-500/50 bg-primary-500/5 p-6 relative overflow-hidden">
              <div className="absolute -top-10 -right-10 w-32 h-32 bg-primary-500/10 rounded-full blur-2xl" />
              <div className="relative">
                <div className="text-sm text-primary-400 font-medium mb-1">ApexMail</div>
                <div className="text-4xl font-bold text-white mb-1">
                  {formatCurrency(prices.apexmail)}
                  <span className="text-lg text-surface-400">/mo</span>
                </div>
                <div className="text-xs text-surface-400 mb-4">
                  {(prices.apexmail / (volume / 1000)).toFixed(3)}/1K emails
                </div>
                {savings > 0 && (
                  <div className="inline-flex items-center gap-1 px-2 py-1 rounded-full bg-accent-500/20 text-accent-400 text-xs font-medium">
                    Save {formatCurrency(savings)}/mo
                  </div>
                )}
              </div>
            </div>

            {/* Competitors */}
            {[
              { name: 'SendGrid', price: prices.sendgrid },
              { name: 'Mailchimp', price: prices.mailchimp },
              { name: 'AWS SES', price: prices.ses },
            ].map((competitor) => (
              <div
                key={competitor.name}
                className="rounded-xl border border-surface-700 bg-surface-800/30 p-6"
              >
                <div className="text-sm text-surface-400 font-medium mb-1">{competitor.name}</div>
                <div className="text-3xl font-bold text-surface-300 mb-1">
                  {formatCurrency(competitor.price)}
                  <span className="text-lg text-surface-500">/mo</span>
                </div>
                <div className="text-xs text-surface-500">
                  {(competitor.price / (volume / 1000)).toFixed(3)}/1K emails
                </div>
                {options.privateCloud && competitor.name !== 'ApexMail' && (
                  <div className="mt-4 text-xs text-surface-500 flex items-center gap-1">
                    <Info className="w-3 h-3" />
                    Not available
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Bottom Note */}
          <div className="mt-6 flex items-center justify-between flex-wrap gap-4">
            <p className="text-sm text-surface-400">
              * Prices shown are estimates. Enterprise plans get custom pricing.
            </p>
            <Link href="/pricing" className="btn-primary flex items-center gap-2">
              See Full Pricing
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </motion.div>

        {/* Pricing Tiers Quick View */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.4 }}
          className="mt-12 grid sm:grid-cols-2 lg:grid-cols-4 gap-6"
        >
          {[
            { name: 'Free', price: '$0', volume: '1,000 emails/mo', features: ['Shared IP', 'Basic analytics', '"Powered by" badge'] },
            { name: 'Starter', price: '$29', volume: '25,000 emails/mo', features: ['Remove branding', 'Webhooks', 'Email support'] },
            { name: 'Growth', price: '$99', volume: '100,000 emails/mo', features: ['Dedicated IP', 'Priority support', 'Custom domain'], popular: true },
            { name: 'Scale', price: '$299', volume: '500,000 emails/mo', features: ['Multiple IPs', 'SSO included', 'SLA guarantee'] },
          ].map((tier) => (
            <div
              key={tier.name}
              className={cn(
                'glass-card relative',
                tier.popular && 'border-primary-500/50'
              )}
            >
              {tier.popular && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 bg-primary-500 text-white text-xs font-medium rounded-full">
                  Most Popular
                </div>
              )}
              <div className="text-lg font-semibold text-white mb-1">{tier.name}</div>
              <div className="text-3xl font-bold gradient-text mb-1">{tier.price}</div>
              <div className="text-sm text-surface-400 mb-4">{tier.volume}</div>
              <ul className="space-y-2">
                {tier.features.map((feature) => (
                  <li key={feature} className="flex items-center gap-2 text-sm text-surface-300">
                    <Check className="w-4 h-4 text-accent-400 flex-shrink-0" />
                    {feature}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
