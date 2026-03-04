import { h } from 'preact';
import { useState, useMemo } from 'preact/hooks';

// Inline SVG icons
const CheckIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
    <polyline points="20 6 9 17 4 12" />
  </svg>
);
const ArrowRightIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M5 12h14" /><path d="m12 5 7 7-7 7" />
  </svg>
);

// ── Pricing Data ────────────────────────────────────────────

interface PricingOption {
  dedicatedIP: boolean;
  sso: boolean;
  hipaa: boolean;
  privateCloud: boolean;
}

type Provider = 'apexmail' | 'sendgrid' | 'mailchimp' | 'ses';

interface PricingTier {
  maxVolume: number;
  price?: number;
  pricePerK?: number;
}

const pricingTiers: Record<Provider, PricingTier[]> = {
  apexmail: [
    { maxVolume: 3000, price: 0 },
    { maxVolume: 50000, price: 25 },
    { maxVolume: 150000, price: 65 },
    { maxVolume: 500000, price: 150 },
    { maxVolume: 1000000, price: 350 },
    { maxVolume: Infinity, price: 800 },
  ],
  sendgrid: [
    { maxVolume: 6000, price: 0 },
    { maxVolume: 50000, price: 20 },
    { maxVolume: 100000, price: 50 },
    { maxVolume: 300000, price: 250 },
    { maxVolume: 700000, price: 500 },
    { maxVolume: 1500000, price: 900 },
    { maxVolume: Infinity, pricePerK: 0.6 },
  ],
  mailchimp: [
    { maxVolume: 500, price: 0 },
    { maxVolume: 5000, price: 13 },
    { maxVolume: 25000, price: 67 },
    { maxVolume: 50000, price: 135 },
    { maxVolume: 100000, price: 270 },
    { maxVolume: 250000, price: 540 },
    { maxVolume: Infinity, pricePerK: 2.0 },
  ],
  ses: [
    { maxVolume: 62000, price: 0 },
    { maxVolume: Infinity, pricePerK: 0.1 },
  ],
};

const addons: Record<string, Record<Provider, number>> = {
  dedicatedIP: { apexmail: 0, sendgrid: 90, mailchimp: 30, ses: 25 },
  sso: { apexmail: 0, sendgrid: 200, mailchimp: 100, ses: 0 },
  hipaa: { apexmail: 0, sendgrid: 400, mailchimp: 0, ses: 0 },
  privateCloud: { apexmail: 200, sendgrid: 0, mailchimp: 0, ses: 0 },
};

function calculatePrice(provider: Provider, volume: number, options: PricingOption): number {
  let basePrice = 0;
  for (const tier of pricingTiers[provider]) {
    if (volume <= tier.maxVolume || tier.maxVolume === Infinity) {
      if (tier.price !== undefined) {
        basePrice = tier.price;
      } else if (tier.pricePerK !== undefined) {
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

function formatNumber(n: number): string {
  return n.toLocaleString('en-US');
}

function formatCurrency(n: number): string {
  return '$' + n.toLocaleString('en-US');
}

// ── Volume marks ────────────────────────────────────────────

const volumeMarks = [
  { value: 1000, label: '1K' },
  { value: 10000, label: '10K' },
  { value: 100000, label: '100K' },
  { value: 500000, label: '500K' },
  { value: 1000000, label: '1M' },
];

// ── ComparisonRow sub-component ─────────────────────────────

function ComparisonRow({ name, price, apexPrice }: { name: string; price: number; apexPrice: number }) {
  const savings = Math.max(0, price - apexPrice);
  const percentage = price > 0 ? Math.round((savings / price) * 100) : 0;
  const usageWidth = price > 0 ? Math.min(100, Math.max(0, (apexPrice / price) * 100)) : 100;

  return (
    <div class="p-5 bg-white rounded-xl border border-surface-200 shadow-sm">
      <div class="flex justify-between items-center mb-3">
        <span class="font-bold text-surface-900">{name}</span>
        <span class="text-lg font-bold text-surface-400 tabular-nums">{formatCurrency(price)}</span>
      </div>
      <div class="relative h-2 bg-surface-100 rounded-full overflow-hidden">
        <svg width="100%" height="100%" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true">
          <rect x="0" y="0" width={usageWidth} height="8" class="fill-brand-500" rx="999" ry="999" />
        </svg>
      </div>
      <div class="flex justify-between mt-2">
        <span class="text-xs font-bold text-brand-600 uppercase tracking-wider">ApexMail</span>
        <span class="text-xs font-bold text-success-600 uppercase tracking-wider">Save {percentage}%</span>
      </div>
    </div>
  );
}

// ── Main Component ──────────────────────────────────────────

export default function PricingCalculator() {
  const [volume, setVolume] = useState(100000);
  const [options, setOptions] = useState<PricingOption>({
    dedicatedIP: false,
    sso: false,
    hipaa: false,
    privateCloud: false,
  });

  const prices = useMemo(
    () => ({
      apexmail: calculatePrice('apexmail', volume, options),
      sendgrid: calculatePrice('sendgrid', volume, options),
      mailchimp: calculatePrice('mailchimp', volume, options),
      ses: calculatePrice('ses', volume, options),
    }),
    [volume, options],
  );

  return (
    <section class="py-20 lg:py-32 bg-surface-50 relative overflow-hidden" id="pricing">
      {/* Background Decorative Elements */}
      <div class="absolute inset-0 pointer-events-none overflow-hidden">
        <div class="absolute top-[4%] left-[4%] w-[28%] h-[28%] bg-brand-500/5 blur-[120px] rounded-full" />
        <div class="absolute bottom-[4%] right-[4%] w-[28%] h-[28%] bg-brand-500/5 blur-[120px] rounded-full" />
      </div>

      <div class="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div class="text-center mb-16">
          <h2 class="section-title mb-4">
            <span class="text-surface-900">Pricing That</span>{' '}
            <span class="text-brand-500">Scales With You</span>
          </h2>
          <p class="text-surface-600 text-lg max-w-2xl mx-auto leading-relaxed">
            Save up to 80% compared to legacy providers. No hidden fees, no enterprise tax.
          </p>
        </div>

        <div class="grid lg:grid-cols-12 gap-12 items-start">
          {/* Calculator Card */}
          <div class="lg:col-span-7 bg-white rounded-2xl border border-surface-200 shadow-xl overflow-hidden">
            <div class="p-8 md:p-12">
              {/* Volume Slider */}
              <div class="mb-10">
                <div class="flex items-center justify-between mb-6">
                  <label for="monthly-volume" class="text-lg font-bold text-surface-900">
                    Monthly Email Volume
                  </label>
                  <div class="text-right">
                    <span class="text-3xl font-bold text-brand-500 tabular-nums tracking-tight">
                      {formatNumber(volume)}
                    </span>
                    <span class="text-sm text-surface-500 font-medium ml-1">emails</span>
                  </div>
                </div>
                <input
                  id="monthly-volume"
                  type="range"
                  min="1000"
                  max="1000000"
                  step="1000"
                  value={volume}
                  onInput={(e) => setVolume(Number((e.target as HTMLInputElement).value))}
                  aria-label="Email volume slider"
                  class="w-full h-2 bg-surface-100 rounded-full appearance-none cursor-pointer focus:outline-none focus:ring-2 focus:ring-brand-500/20 [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-6 [&::-webkit-slider-thumb]:h-6 [&::-webkit-slider-thumb]:bg-white [&::-webkit-slider-thumb]:border-2 [&::-webkit-slider-thumb]:border-brand-500 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:cursor-pointer [&::-webkit-slider-thumb]:shadow-sm [&::-webkit-slider-thumb]:active:scale-95 [&::-webkit-slider-thumb]:transition-transform"
                />
                <div class="flex justify-between mt-4">
                  {volumeMarks.map((mark) => (
                    <button
                      key={mark.value}
                      class={`text-xs font-bold transition-colors focus:outline-none uppercase tracking-widest ${
                        Math.abs(volume - mark.value) < 50000 ? 'text-brand-500' : 'text-surface-400 hover:text-surface-600'
                      }`}
                      onClick={() => setVolume(mark.value)}
                      aria-label={`Set monthly email volume to ${formatNumber(mark.value)} emails`}
                    >
                      {mark.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Options Checkboxes */}
              <div class="grid sm:grid-cols-2 gap-4 mb-10">
                {([
                  { key: 'dedicatedIP' as const, label: 'Dedicated IP', tip: 'Improve deliverability' },
                  { key: 'sso' as const, label: 'SSO/SAML', tip: 'Enterprise security' },
                  { key: 'hipaa' as const, label: 'HIPAA Compliance', tip: 'Healthcare ready' },
                  { key: 'privateCloud' as const, label: 'Private Cloud', tip: 'Isolated infrastructure' },
                ]).map((option) => (
                  <label
                    key={option.key}
                    class={`flex flex-col p-4 rounded-xl border cursor-pointer transition-all duration-200 active:scale-[0.98] ${
                      options[option.key]
                        ? 'border-brand-500 bg-brand-50/50 shadow-md ring-1 ring-brand-500/20'
                        : 'border-surface-200 hover:border-surface-300 bg-white hover:bg-surface-50'
                    }`}
                  >
                    <div class="flex justify-between items-start mb-2">
                      <span class="font-bold text-sm text-surface-900">{option.label}</span>
                      <div
                        class={`w-4 h-4 border rounded flex items-center justify-center transition-colors ${
                          options[option.key]
                            ? 'bg-brand-500 border-brand-500 text-white'
                            : 'border-surface-300 bg-white'
                        }`}
                      >
                        {options[option.key] && <CheckIcon class="w-3.5 h-3.5" />}
                      </div>
                      <input
                        type="checkbox"
                        checked={options[option.key]}
                        onChange={(e) =>
                          setOptions({ ...options, [option.key]: (e.target as HTMLInputElement).checked })
                        }
                        class="sr-only"
                        aria-label={option.label}
                      />
                    </div>
                    <span class="text-xs text-surface-500 font-medium">{option.tip}</span>
                  </label>
                ))}
              </div>

              {/* ApexMail Price Display */}
              <div class="flex flex-col sm:flex-row items-center gap-6 p-6 bg-brand-50 rounded-xl border border-brand-100">
                <div class="flex-1">
                  <div class="text-brand-700 font-bold mb-1 text-lg">Estimated Monthly Cost</div>
                  <div class="text-sm text-brand-600/80">Based on your current volume and options.</div>
                </div>
                <div class="text-4xl font-bold text-brand-700 tabular-nums">
                  {formatCurrency(prices.apexmail)}
                </div>
              </div>
            </div>
          </div>

          {/* Comparison Side */}
          <div class="lg:col-span-5 space-y-8">
            <h3 class="text-xl font-bold text-surface-900 flex items-center gap-2">
              <span class="w-8 h-px bg-surface-200" />
              Savings Comparison
            </h3>

            <div class="space-y-4">
              <ComparisonRow name="SendGrid" price={prices.sendgrid} apexPrice={prices.apexmail} />
              <ComparisonRow name="Mailchimp" price={prices.mailchimp} apexPrice={prices.apexmail} />
              <ComparisonRow name="AWS SES" price={prices.ses} apexPrice={prices.apexmail} />
            </div>

            <div class="mt-12 p-8 bg-surface-900 rounded-2xl text-white shadow-2xl relative overflow-hidden group">
              <div class="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
                <ArrowRightIcon class="w-32 h-32 -rotate-45" />
              </div>
              <h4 class="text-2xl font-bold mb-4">Ready to switch?</h4>
              <p class="text-surface-400 text-sm leading-relaxed mb-8">
                Migration is seamless. Use our SMTP relay or API wrapper to start sending in minutes.
              </p>
              <a href="https://app.apexmail.ee/signup" class="btn-primary w-full inline-flex items-center justify-center">
                Start Free Trial
                <ArrowRightIcon class="ml-2 w-4 h-4" />
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
