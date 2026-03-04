import { h } from 'preact';
import { useState } from 'preact/hooks';

// Inline SVG icons (no lucide-react dependency)
const ChevronDown = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="m6 9 6 6 6-6" />
  </svg>
);

interface FAQ {
  question: string;
  answer: string;
}

const faqs: FAQ[] = [
  {
    question: 'What happens if I exceed my monthly email limit?',
    answer:
      "We'll notify you when you reach 80% and 100% of your limit. You can upgrade your plan or switch to Pay As You Go for overages (starting at $0.40 per 1,000 emails). We never cut off your sending mid-campaign.",
  },
  {
    question: 'Can I change plans at any time?',
    answer:
      "Yes! You can upgrade or downgrade immediately. Prorated adjustments are applied automatically to your next invoice.",
  },
  {
    question: 'Do unused emails roll over?',
    answer:
      'For monthly plans, unused emails do not roll over. Pay As You Go credits never expire.',
  },
  {
    question: 'What payment methods do you accept?',
    answer:
      'We accept all major credit cards. ACH and wire transfers are available for Enterprise plans.',
  },
  {
    question: 'Is there a contract?',
    answer:
      'No. Monthly plans are cancel-anytime. Annual plans offer a discount in exchange for a one-year commitment.',
  },
  {
    question: 'How can I reach billing for urgent invoice issues?',
    answer:
      'Use billing@apexmail.ee first. For legal invoice escalations, phone support is available at: plus-three-seven-two, five-six-three, eight-zero-nine, two-seven.',
  },
];

export default function PricingFaq() {
  const [openIndex, setOpenIndex] = useState<number | null>(null);

  return (
    <section class="py-20 lg:py-32 bg-white border-t border-surface-100">
      <div class="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <h2 class="text-3xl font-bold text-surface-900 tracking-tight">
            Frequently Asked Questions
          </h2>
        </div>

        <div class="space-y-4">
          {faqs.map((faq, index) => (
            <div key={faq.question} class="border-b border-surface-100 last:border-0">
              <button
                onClick={() => setOpenIndex(openIndex === index ? null : index)}
                aria-expanded={openIndex === index}
                aria-controls={`faq-panel-${index}`}
                id={`faq-button-${index}`}
                class="w-full flex items-center justify-between py-6 text-left group"
              >
                <span class="text-lg font-medium text-surface-900 group-hover:text-primary-600 transition-colors">
                  {faq.question}
                </span>
                <ChevronDown
                  class={`w-5 h-5 text-surface-400 transition-transform duration-200 ${
                    openIndex === index ? 'rotate-180 text-primary-600' : ''
                  }`}
                />
              </button>
              {openIndex === index && (
                <div id={`faq-panel-${index}`} role="region" aria-labelledby={`faq-button-${index}`}>
                  <div class="pb-6 pr-12">
                    <p class="text-surface-600 leading-relaxed">{faq.answer}</p>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
