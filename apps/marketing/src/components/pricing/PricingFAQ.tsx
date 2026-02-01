'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { useState } from 'react';
import { ChevronDown, HelpCircle } from 'lucide-react';

interface FAQ {
  question: string;
  answer: string;
}

const faqs: FAQ[] = [
  {
    question: 'What happens if I exceed my monthly email limit?',
    answer:
      "We'll notify you when you reach 80% and 100% of your limit. You can upgrade your plan at any time, or purchase additional emails at $0.10 per 1,000 emails. We never cut off your sending mid-campaign.",
  },
  {
    question: 'Can I change plans at any time?',
    answer:
      "Yes! You can upgrade or downgrade your plan at any time. When upgrading, you'll be charged the prorated difference immediately. When downgrading, the change takes effect at the start of your next billing cycle.",
  },
  {
    question: 'Do unused emails roll over?',
    answer:
      'For monthly plans, unused emails do not roll over. For annual plans, you get your full allocation upfront and can use them throughout the year.',
  },
  {
    question: 'What payment methods do you accept?',
    answer:
      'We accept all major credit cards (Visa, Mastercard, American Express), ACH bank transfers for US customers, and wire transfers for Enterprise plans. All payments are processed securely through Stripe.',
  },
  {
    question: 'Is there a contract or commitment?',
    answer:
      'Monthly plans are pay-as-you-go with no long-term commitment—cancel anytime. Annual plans offer a 20% discount and are billed yearly. Enterprise plans have custom terms.',
  },
  {
    question: 'What counts as an email?',
    answer:
      'Each recipient counts as one email. So if you send to 100 recipients, that counts as 100 emails. Bounced emails and emails blocked by our spam filter do not count against your quota.',
  },
  {
    question: "What's included in the free tier?",
    answer:
      "The free tier includes 10,000 emails per month, full API access, basic analytics, and community support. It's perfect for development, testing, or low-volume production use. No credit card required.",
  },
  {
    question: 'Do you offer non-profit or startup discounts?',
    answer:
      'Yes! Registered non-profits get 50% off all plans. Startups in accelerator programs may qualify for our startup program with extended free tier limits. Contact us for details.',
  },
];

export function PricingFAQ() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [openIndex, setOpenIndex] = useState<number | null>(null);

  return (
    <section ref={ref} className="py-20 lg:py-32 relative bg-surface-900/50">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/10 text-purple-400 text-sm mb-4"
          >
            <HelpCircle className="w-4 h-4" />
            FAQ
          </motion.div>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.1 }}
            className="text-3xl lg:text-4xl font-bold text-white mb-4"
          >
            Frequently Asked Questions
          </motion.h2>
        </div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.2 }}
          className="space-y-3"
        >
          {faqs.map((faq, index) => (
            <div key={faq.question} className="glass-card overflow-hidden">
              <button
                onClick={() => setOpenIndex(openIndex === index ? null : index)}
                className="w-full flex items-center justify-between p-4 text-left"
              >
                <span className="text-white font-medium pr-4">{faq.question}</span>
                <ChevronDown
                  className={`w-5 h-5 text-surface-400 transition-transform ${
                    openIndex === index ? 'rotate-180' : ''
                  }`}
                />
              </button>
              {openIndex === index && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  className="px-4 pb-4"
                >
                  <p className="text-surface-400">{faq.answer}</p>
                </motion.div>
              )}
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
