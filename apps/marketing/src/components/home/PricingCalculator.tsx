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
   { max: 50000, price: 49 },
   { max: 100000, price: 99 },
   { max: 500000, price: 299 },
   // Above 500k, use PAYG rate or Enterprise custom pricing. 
   // For calculator simplicity, we'll continue with PAYG logic in the function.
   { max: Infinity, pricePerK: 0.45 }, // Fallback
 ],
 sendgrid: [
   { max: 6000, price: 0 },
   { max: 50000, price: 19.95 },   // Updated to recent standard pricing approx
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
 sso: { apexmail: 0, sendgrid: 900, mailchimp: 0, ses: 0 }, // Scale includes SSO, handled in logic
 hipaa: { apexmail: 100, sendgrid: 1000, mailchimp: 0, ses: 0 }, // Included in Enterprise
 privateCloud: { apexmail: 2000, sendgrid: 0, mailchimp: 0, ses: 0 },
};

function calculateApexMailCost(volume: number, options: PricingOption) {
  // Calculate PAYG Cost
  let paygCost = 0;
  if (volume <= 10000) paygCost = volume * 0.001;
  else if (volume <= 100000) paygCost = (10000 * 0.001) + ((volume - 10000) * 0.0008);
  else if (volume <= 1000000) paygCost = (10000 * 0.001) + (90000 * 0.0008) + ((volume - 100000) * 0.0005);
  else paygCost = (10000 * 0.001) + (90000 * 0.0008) + (900000 * 0.0005) + ((volume - 1000000) * 0.0003);

  // Addons for PAYG
  if (options.dedicatedIP) paygCost += 50;
  // SSO/HIPAA/PrivateCloud generally require Enterprise or high tier plans, 
  // but let's assume standard pricing for calculator transparency
  if (options.sso) paygCost += 100;
  if (options.hipaa) paygCost += 500;
  if (options.privateCloud) paygCost += 2000;

  // Calculate Plan Cost
  let planCost = Infinity;
  const plan = pricingTiers.apexmail.find(t => volume <= t.max && t.price !== undefined);
  
  if (plan && plan.price !== undefined) {
    planCost = plan.price;
    // Addons not included in plan
    // Growth (99) includes IP. Scale (299) includes IP + SSO.
    const isGrowthOrHigher = plan.price >= 99;
    const isScaleOrHigher = plan.price >= 299;

    if (options.dedicatedIP && !isGrowthOrHigher) planCost += 50;
    if (options.sso && !isScaleOrHigher) planCost += 100;
    if (options.hipaa) planCost += 500; // Enterprise add-on
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
 initial={{ opacity: 0, y: 16 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.2 }}
 className="rounded-2xl border border-surface-200 bg-white p-6 lg:p-10 shadow-sm"
 >
 {/* Volume Slider */}
 <div className="mb-10">
 <div className="flex items-end justify-between mb-6">
 <label className="text-sm font-semibold text-surface-900 uppercase tracking-wide">Monthly Email Volume</label>
 <div className="text-right">
 <span className="text-3xl font-bold text-primary-600 tabular-nums tracking-tight">{formatNumber(volume)}</span>
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
 className="w-full h-1.5 bg-surface-100 rounded-full appearance-none cursor-pointer accent-primary-600 hover:accent-primary-700 transition-all"
 />
 <div className="flex justify-between mt-3">
 {volumeMarks.map((mark) => (
 <button
 key={mark.value}
 className={cn(
 'text-xs font-semibold uppercase tracking-wide transition-colors focus:outline-none',
 Math.abs(volume - mark.value) < 50000 ? 'text-primary-600' : 'text-surface-400 hover:text-surface-600'
 )}
 onClick={() => setVolume(mark.value)}
 >
 {mark.label}
 </button>
 ))}
 </div>
 </div>

 {/* Options Checkboxes */}
 <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-10">
 {[
 { key: 'dedicatedIP', label: 'Dedicated IP', tip: 'Improve deliverability' },
 { key: 'sso', label: 'SSO/SAML', tip: 'Enterprise security' },
 { key: 'hipaa', label: 'HIPAA Compliance', tip: 'Healthcare ready' },
 { key: 'privateCloud', label: 'Private Cloud', tip: 'Isolated infrastructure' },
 ].map((option) => (
 <label
 key={option.key}
 className={cn(
 'flex flex-col p-4 rounded-lg border cursor-pointer transition-all duration-200',
 options[option.key as keyof PricingOption]
 ? 'border-primary-600 bg-primary-50/10'
 : 'border-surface-200 hover:border-surface-300 bg-white'
 )}
 >
 <div className="flex justify-between items-start mb-2">
 <span className="font-semibold text-sm text-surface-900">{option.label}</span>
 <input
 type="checkbox"
 checked={options[option.key as keyof PricingOption]}
 onChange={(e) => setOptions({ ...options, [option.key]: e.target.checked })}
 className="w-4 h-4 text-primary-600 border-surface-300 rounded focus:ring-primary-500 transition-colors"
 />
 </div>
 <span className="text-xs text-surface-500 font-medium">{option.tip}</span>
 </label>
                ))}
              </div>

              {/* Price Comparison */}
              <div className="grid md:grid-cols-4 gap-4">
                {/* ApexMail - Featured */}
                <div className="md:col-span-1 p-6 rounded-xl bg-surface-900 text-white relative overflow-hidden group">
                  <div className="relative z-10">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-xs font-semibold uppercase tracking-wider text-primary-400">ApexMail</span>
                      {savings > 0 && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-primary-500 text-white shadow-sm">
                          Save {formatCurrency(savings)}
                        </span>
                      )}
                    </div>
                    <div className="flex items-baseline gap-1 mb-1">
                      <span className="text-3xl font-bold tabular-nums tracking-tight">
                        {formatCurrency(prices.apexmail)}
                      </span>
                      <span className="text-sm text-surface-400 font-medium">/mo</span>
                    </div>
                    <div className="text-xs text-surface-400 font-medium tabular-nums">
                      {(prices.apexmail / (volume / 1000)).toFixed(3)} per 1K
                    </div>
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
                    className="p-6 rounded-xl border border-surface-200 bg-surface-50/50 flex flex-col justify-center"
                  >
                    <div className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-2">{competitor.name}</div>
                    <div className="flex items-baseline gap-1 mb-1">
                      <span className="text-2xl font-semibold text-surface-900 tabular-nums tracking-tight">
                        {formatCurrency(competitor.price)}
                      </span>
                    </div>
                    <div className="text-xs text-surface-400 font-medium tabular-nums">
                       {(competitor.price / (volume / 1000)).toFixed(3)} per 1K
                    </div>
                  </div>
                ))}
              </div>

 {/* Bottom Note */}
 <div className="mt-8 flex items-center justify-center">
 <Link href="/pricing" className="text-sm font-semibold text-primary-600 hover:text-primary-700 flex items-center gap-1.5 transition-colors">
 See full feature comparison <ArrowRight className="w-4 h-4" />
 </Link>
 </div>
 </motion.div>

 {/* Pricing Tiers Quick View */}
 <motion.div
 initial={{ opacity: 0, y: 16 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.3 }}
 className="mt-12 grid sm:grid-cols-2 lg:grid-cols-4 gap-4"
 >
 {[
 { name: 'Free', price: '$0', volume: '1,000/mo', features: ['1 sending domain', '7-day retention', 'REST API'] },
 { name: 'Starter', price: '$29', volume: '25,000/mo', features: ['3 sending domains', 'Advanced analytics', 'Email support'] },
 { name: 'Growth', price: '$99', volume: '100,000/mo', features: ['Dedicated IP', 'A/B testing', 'Priority support'] },
 { name: 'Scale', price: '$299', volume: '500,000/mo', features: ['3 Dedicated IPs', 'SSO/SAML', 'Phone support'] },
 ].map((tier) => (
 <Link
 href="/pricing"
 key={tier.name}
 className="group block p-5 rounded-lg border border-surface-200 bg-white hover:border-primary-200 hover:shadow-sm transition-all duration-200"
 >
 <div className="flex items-center justify-between mb-2">
 <span className="text-sm font-semibold text-surface-900">{tier.name}</span>
 <span className="text-sm font-bold text-primary-600">{tier.price}</span>
 </div>
 <div className="text-xs text-surface-500 font-medium uppercase tracking-wide mb-3">{tier.volume}</div>
 <ul className="space-y-1.5">
 {tier.features.map((feature) => (
 <li key={feature} className="flex items-start gap-2 text-xs text-surface-600">
 <Check className="w-3.5 h-3.5 text-primary-500 flex-shrink-0" strokeWidth={2.5} />
 {feature}
 </li>
 ))}
 </ul>
 </Link>
 ))}
 </motion.div>
 </div>
 </section>
 );
}
