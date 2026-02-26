'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Check, ArrowRight, Minus } from '@/components/ui/icons';
import Link from 'next/link';
import { cn } from '@/lib/utils';

const comparisonData = {
  categories: [
    {
      name: 'Deliverability',
      features: [
        { name: 'Delivery Rate', apexmail: '99.9%', sendgrid: '97%', mailchimp: '92%', ses: '95%' },
        { name: 'Dedicated IP Included', apexmail: 'Growth+', sendgrid: 'Pro+', mailchimp: 'Premium', ses: 'Manual' },
        { name: 'IP Warming Automation', apexmail: true, sendgrid: true, mailchimp: false, ses: false },
        { name: 'Reputation Circuit Breaker', apexmail: true, sendgrid: false, mailchimp: false, ses: false },
      ],
    },
    {
      name: 'Compliance',
      features: [
        { name: 'GDPR Compliance Tools', apexmail: 'Native', sendgrid: 'Basic', mailchimp: 'Basic', ses: 'None' },
        { name: 'HIPAA BAA', apexmail: true, sendgrid: 'Enterprise', mailchimp: false, ses: true },
        { name: 'Cryptographic Proof of Delivery', apexmail: true, sendgrid: false, mailchimp: false, ses: false },
        { name: 'Auto-Generated DPA', apexmail: true, sendgrid: false, mailchimp: false, ses: false },
        { name: 'Right-to-be-Forgotten Cascade', apexmail: true, sendgrid: false, mailchimp: false, ses: false },
      ],
    },
    {
      name: 'Infrastructure',
      features: [
        { name: 'True Single-Tenant Option', apexmail: true, sendgrid: false, mailchimp: false, ses: false },
        { name: 'Private Cloud Deploy', apexmail: true, sendgrid: false, mailchimp: false, ses: 'N/A' },
        { name: 'BYOIP Support', apexmail: true, sendgrid: false, mailchimp: false, ses: true },
        { name: 'Air-Gapped AI', apexmail: true, sendgrid: false, mailchimp: false, ses: false },
      ],
    },
    {
      name: 'Developer Experience',
      features: [
        { name: 'Time to First Email', apexmail: '< 10 sec', sendgrid: '5 min', mailchimp: '10+ min', ses: '30+ min' },
        { name: 'No Credit Card Trial', apexmail: true, sendgrid: true, mailchimp: true, ses: false },
        { name: 'Webhook Signatures', apexmail: true, sendgrid: true, mailchimp: true, ses: false },
        { name: 'Idempotency Keys', apexmail: true, sendgrid: false, mailchimp: false, ses: false },
        { name: 'Forensic Render History', apexmail: true, sendgrid: false, mailchimp: false, ses: false },
      ],
    },
  ],
};

const renderValue = (value: boolean | string) => {
  if (typeof value === 'boolean') {
    return value ? (
      <Check className="w-5 h-5 text-emerald-600" strokeWidth={2.5} />
    ) : (
      <Minus className="w-5 h-5 text-surface-200" />
    );
  }
  return <span className="text-sm font-medium tabular-nums text-surface-600">{value}</span>;
};

export function ComparisonSection() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 relative bg-surface-50">
      <div className="relative max-w-[1200px] mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="text-center mb-12"
        >
          <h2 className="section-title mb-4">
            <span className="text-surface-900">See How We</span>{' '}
            <span className="text-brand-500">Stack Up</span>
          </h2>
          <p className="text-surface-600 text-lg max-w-2xl mx-auto leading-relaxed">
            We built ApexMail because we were tired of email providers that treat 
            compliance as an afterthought and developers as an inconvenience.
          </p>
        </motion.div>

        {/* Comparison Table */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.2 }}
          className="overflow-x-auto bg-white rounded-lg border border-surface-200 shadow-sm"
        >
          <table className="min-w-[760px] w-full border-collapse">
            <thead>
              <tr className="border-b border-surface-200 bg-surface-50/50">
                <th scope="col" className="p-3 sm:p-4 lg:p-6 text-left font-bold text-surface-900 text-sm">Feature</th>
                <th scope="col" className="p-3 sm:p-4 lg:p-6 text-center">
                  <div className="font-bold text-brand-700 text-xs sm:text-base">ApexMail</div>
                  <div className="text-[11px] sm:text-sm text-brand-500 font-medium">Our Platform</div>
                </th>
                <th scope="col" className="p-3 sm:p-4 lg:p-6 text-center text-surface-900">
                  <div className="font-semibold text-surface-700 text-xs sm:text-base">SendGrid</div>
                  <div className="text-[11px] sm:text-sm text-surface-500 font-medium">Twilio</div>
                </th>
                <th scope="col" className="p-3 sm:p-4 lg:p-6 text-center text-surface-900">
                  <div className="font-semibold text-surface-700 text-xs sm:text-base">Mailchimp</div>
                  <div className="text-[11px] sm:text-sm text-surface-500 font-medium">Intuit</div>
                </th>
                <th scope="col" className="p-3 sm:p-4 lg:p-6 text-center text-surface-900">
                  <div className="font-semibold text-surface-700 text-xs sm:text-base">AWS SES</div>
                  <div className="text-[11px] sm:text-sm text-surface-500 font-medium">Amazon</div>
                </th>
              </tr>
            </thead>
            {comparisonData.categories.map((category) => (
              <tbody key={category.name}>
                <tr className="bg-surface-50/30 border-b border-surface-100">
                  <th colSpan={5} scope="colgroup" className="px-3 sm:px-4 lg:px-6 py-2 text-left text-sm font-bold uppercase tracking-widest text-surface-600">
                    {category.name}
                  </th>
                </tr>
                {category.features.map((feature, featureIndex) => (
                  <tr
                    key={feature.name}
                    className={cn(
                      'hover:bg-surface-50/50 transition-colors',
                      featureIndex !== category.features.length - 1 && 'border-b border-surface-100'
                    )}
                  >
                    <th scope="row" className="px-3 sm:px-4 lg:px-6 py-3 sm:py-4 text-left text-xs sm:text-sm font-semibold text-surface-700 break-words">{feature.name}</th>
                    <td className="px-3 sm:px-4 lg:px-6 py-3 sm:py-4 text-center font-bold text-brand-700">{renderValue(feature.apexmail)}</td>
                    <td className="px-3 sm:px-4 lg:px-6 py-3 sm:py-4 text-center text-surface-500">{renderValue(feature.sendgrid)}</td>
                    <td className="px-3 sm:px-4 lg:px-6 py-3 sm:py-4 text-center text-surface-500">{renderValue(feature.mailchimp)}</td>
                    <td className="px-3 sm:px-4 lg:px-6 py-3 sm:py-4 text-center text-surface-500">{renderValue(feature.ses)}</td>
                  </tr>
                ))}
              </tbody>
            ))}
          </table>
        </motion.div>

        {/* Bottom CTA */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.4 }}
          className="mt-12 text-center"
        >
          <p className="text-surface-600 mb-6 font-medium">
            Still not convinced? See the full feature comparison or talk to our team.
          </p>
          <div className="flex flex-wrap justify-center gap-4">
            <Link href="/features" className="btn-secondary flex items-center gap-2">
              Full Feature List
              <ArrowRight className="w-4 h-4" />
            </Link>
            <Link href="/private-cloud" className="btn-primary flex items-center gap-2">
              Talk to Sales
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
