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
 if ('price' in tier && tier.price !== undefined) {
 basePrice = tier.price;
 } else if ('pricePerK' in tier && tier.pricePerK !== undefined) {
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
 <section ref={ref} className="py-20 lg:py-32 relative bg-white" id="pricing">
 <div className="relative max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
 {/* Header */}
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 className="text-center mb-12"
 >
 <h2 className="section-title mb-4">
 <span className="text-surface-900">Transparent</span>{' '}
 <span className="text-primary-500">Pricing</span>
 </h2>
 <p className="text-surface-600 text-[17px] max-w-2xl mx-auto leading-relaxed">
 See exactly what you&apos;ll pay. No hidden fees, no surprise overages.
 </p>
 </motion.div>

 {/* Calculator Card */}
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.2 }}
 className="premium-card p-6 lg:p-8 bg-surface-50"
 >
 {/* Volume Slider */}
 <div className="mb-8">
 <div className="flex items-center justify-between mb-4">
 <label className="text-lg font-bold text-surface-900">Monthly Email Volume</label>
 <span className="text-2xl font-bold text-primary-600 tabular-nums">{formatNumber(volume)}</span>
 </div>
 <input
 type="range"
 min="1000"
 max="1000000"
 step="1000"
 value={volume}
 onChange={(e) => setVolume(Number(e.target.value))}
 className="w-full h-2 bg-surface-200 rounded-sm appearance-none cursor-pointer accent-primary-600"
 />
 <div className="flex justify-between mt-2">
 {volumeMarks.map((mark) => (
 <span
 key={mark.value}
 className={cn(
 'text-[10px] font-bold uppercase tracking-tight cursor-pointer transition-colors',
 Math.abs(volume - mark.value) < 50000 ? 'text-primary-600' : 'text-surface-400'
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
 { key: 'dedicatedIP', label: 'Dedicated IP', tip: 'Improve deliverability' },
 { key: 'sso', label: 'SSO/SAML', tip: 'Enterprise single sign-on' },
 { key: 'hipaa', label: 'HIPAA Compliance', tip: 'Healthcare data ready' },
 { key: 'privateCloud', label: 'Private Cloud', tip: 'Isolated infrastructure' },
 ].map((option) => (
 <label
 key={option.key}
 className={cn(
 'flex items-center gap-3 p-4 rounded-md border cursor-pointer transition-all bg-white',
 options[option.key as keyof PricingOption]
 ? 'border-primary-500 ring-1 ring-primary-500'
 : 'border-surface-200 hover:border-surface-300'
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
                        'w-5 h-5 rounded-md border flex items-center justify-center transition-colors',
                        options[option.key as keyof PricingOption]
                          ? 'bg-primary-600 border-primary-600'
                          : 'border-surface-300'
                      )}
                    >
                      {options[option.key as keyof PricingOption] && <Check className="w-3 h-3 text-white" strokeWidth={3} />}
                    </div>
                    <div>
                      <div className="text-sm font-bold text-surface-900">{option.label}</div>
                      <div className="text-[10px] text-surface-500 font-medium uppercase tracking-tight">{option.tip}</div>
                    </div>
                  </label>
                ))}
              </div>

              {/* Price Comparison */}
              <div className="grid md:grid-cols-4 gap-4">
                {/* ApexMail - Featured */}
                <div className="md:col-span-1 rounded-xl border-2 border-primary-600 bg-white p-6 relative overflow-hidden shadow-xl shadow-primary-500/10">
                  <div className="relative">
                    <div className="text-[10px] text-primary-600 font-bold uppercase tracking-widest mb-1">ApexMail</div>
                    <div className="text-4xl font-bold text-surface-900 mb-1 tabular-nums">
                      {formatCurrency(prices.apexmail)}
                      <span className="text-lg text-surface-400 font-medium">/mo</span>
                    </div>
                    <div className="text-[10px] text-surface-500 font-bold uppercase tracking-tight mb-4 tabular-nums">
                      {(prices.apexmail / (volume / 1000)).toFixed(3)}/1K emails
                    </div>
                    {savings > 0 && (
                      <div className="inline-flex items-center gap-1 px-2 py-1 rounded-md bg-green-50 text-green-700 text-[10px] font-bold uppercase tracking-tight border border-green-100">
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
                    className="premium-card p-6 bg-white"
                  >
                    <div className="text-[10px] text-surface-500 font-bold uppercase tracking-widest mb-1">{competitor.name}</div>
                    <div className="text-3xl font-bold text-surface-700 mb-1 tabular-nums">
                      {formatCurrency(competitor.price)}
                      <span className="text-lg text-surface-400 font-medium">/mo</span>
                    </div>
                    <div className="text-[10px] text-surface-500 font-bold uppercase tracking-tight tabular-nums">
                      {(competitor.price / (volume / 1000)).toFixed(3)}/1K emails
                    </div>
                    {options.privateCloud && competitor.name !== 'ApexMail' && (
                      <div className="mt-4 text-[10px] text-red-500 font-bold uppercase tracking-tight flex items-center gap-1">
                        <Info className="w-3 h-3" />
                        Not available
                      </div>
                    )}
                  </div>
                ))}
              </div>

 {/* Bottom Note */}
 <div className="mt-6 flex items-center justify-between flex-wrap gap-4">
 <p className="text-xs text-surface-500 font-medium">
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
 { name: 'Free', price: '$0', volume: '1,000 emails/mo', features: ['Shared IP', 'Basic analytics', 'Community support'] },
 { name: 'Starter', price: '$29', volume: '25,000 emails/mo', features: ['Remove branding', 'Webhooks', 'Email support'] },
 { name: 'Growth', price: '$99', volume: '100,000 emails/mo', features: ['Dedicated IP', 'Priority support', 'Custom domain'], popular: true },
 { name: 'Scale', price: '$299', volume: '500,000 emails/mo', features: ['Multiple IPs', 'SSO included', 'SLA guarantee'] },
 ].map((tier) => (
 <div
 key={tier.name}
 className={cn(
 'premium-card relative bg-white p-6',
 tier.popular && 'ring-2 ring-primary-600'
 )}
 >
 {tier.popular && (
 <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 bg-primary-600 text-white text-[10px] font-bold uppercase tracking-widest rounded-md">
 Most Popular
 </div>
 )}
 <div className="text-lg font-bold text-surface-900 mb-1">{tier.name}</div>
 <div className="text-3xl font-bold text-primary-600 mb-1 tabular-nums">{tier.price}</div>
 <div className="text-xs text-surface-500 font-bold uppercase tracking-tight mb-4">{tier.volume}</div>
 <ul className="space-y-2">
 {tier.features.map((feature) => (
 <li key={feature} className="flex items-center gap-2 text-sm text-surface-600 font-medium">
 <Check className="w-4 h-4 text-primary-600 flex-shrink-0" strokeWidth={3} />
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
