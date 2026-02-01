'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { CheckCircle, XCircle, AlertCircle } from 'lucide-react';

interface FeatureComparison {
  feature: string;
  apexmail: string | boolean;
  sendgrid: string | boolean;
  mailchimp: string | boolean;
  ses: string | boolean;
}

const features: FeatureComparison[] = [
  {
    feature: 'Free tier',
    apexmail: '10K/mo',
    sendgrid: '100/day',
    mailchimp: '500 contacts',
    ses: 'None (EC2 only)',
  },
  {
    feature: 'Price per 100K emails',
    apexmail: '$29',
    sendgrid: '$34.95',
    mailchimp: '~$100',
    ses: '$10',
  },
  {
    feature: 'Dedicated IPs',
    apexmail: 'Included (Pro+)',
    sendgrid: '$90/mo extra',
    mailchimp: '$29.95/mo extra',
    ses: '$24.95/mo',
  },
  {
    feature: 'Templates included',
    apexmail: true,
    sendgrid: true,
    mailchimp: true,
    ses: false,
  },
  {
    feature: 'A/B testing',
    apexmail: true,
    sendgrid: true,
    mailchimp: 'Paid plans',
    ses: false,
  },
  {
    feature: 'Real-time analytics',
    apexmail: true,
    sendgrid: true,
    mailchimp: true,
    ses: 'Basic only',
  },
  {
    feature: 'Webhooks',
    apexmail: true,
    sendgrid: true,
    mailchimp: 'Paid plans',
    ses: true,
  },
  {
    feature: 'GDPR tools',
    apexmail: true,
    sendgrid: 'Manual',
    mailchimp: true,
    ses: false,
  },
  {
    feature: 'Time-travel debugging',
    apexmail: true,
    sendgrid: false,
    mailchimp: false,
    ses: false,
  },
  {
    feature: 'Private cloud option',
    apexmail: true,
    sendgrid: false,
    mailchimp: false,
    ses: true,
  },
  {
    feature: 'Support',
    apexmail: '24/7 (Pro+)',
    sendgrid: 'Email only',
    mailchimp: 'Email only',
    ses: 'Paid support',
  },
  {
    feature: 'Uptime SLA',
    apexmail: '99.99%',
    sendgrid: '99.95%',
    mailchimp: 'None',
    ses: '99.9%',
  },
];

const renderValue = (value: string | boolean) => {
  if (value === true) {
    return <CheckCircle className="w-5 h-5 text-green-400 mx-auto" />;
  }
  if (value === false) {
    return <XCircle className="w-5 h-5 text-red-400 mx-auto" />;
  }
  if (value.toLowerCase().includes('none') || value.toLowerCase().includes('manual')) {
    return (
      <span className="text-surface-500 flex items-center justify-center gap-1">
        <AlertCircle className="w-4 h-4" />
        <span className="text-sm">{value}</span>
      </span>
    );
  }
  return <span className="text-surface-300 text-sm">{value}</span>;
};

export function CompetitorBreakdown() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 relative bg-surface-900/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            className="text-3xl lg:text-4xl font-bold text-white mb-4"
          >
            Feature-by-Feature Comparison
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.1 }}
            className="text-lg text-surface-400 max-w-2xl mx-auto"
          >
            It's not just about price. See how ApexMail compares on features that matter.
          </motion.p>
        </div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.2 }}
          className="glass-card overflow-hidden"
        >
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-surface-700">
                  <th className="text-left py-4 px-6 text-surface-500 font-medium">Feature</th>
                  <th className="text-center py-4 px-4 font-medium">
                    <span className="text-primary-400">ApexMail</span>
                  </th>
                  <th className="text-center py-4 px-4 text-surface-400 font-medium">SendGrid</th>
                  <th className="text-center py-4 px-4 text-surface-400 font-medium">Mailchimp</th>
                  <th className="text-center py-4 px-4 text-surface-400 font-medium">AWS SES</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-700/50">
                {features.map((row) => (
                  <tr key={row.feature} className="hover:bg-surface-800/30 transition-colors">
                    <td className="py-4 px-6 text-white">{row.feature}</td>
                    <td className="py-4 px-4 text-center bg-primary-500/5">
                      {renderValue(row.apexmail)}
                    </td>
                    <td className="py-4 px-4 text-center">{renderValue(row.sendgrid)}</td>
                    <td className="py-4 px-4 text-center">{renderValue(row.mailchimp)}</td>
                    <td className="py-4 px-4 text-center">{renderValue(row.ses)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>

        {/* Legend */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={inView ? { opacity: 1 } : {}}
          transition={{ delay: 0.4 }}
          className="flex justify-center gap-8 mt-6"
        >
          <div className="flex items-center gap-2 text-sm text-surface-400">
            <CheckCircle className="w-4 h-4 text-green-400" />
            <span>Included</span>
          </div>
          <div className="flex items-center gap-2 text-sm text-surface-400">
            <XCircle className="w-4 h-4 text-red-400" />
            <span>Not available</span>
          </div>
          <div className="flex items-center gap-2 text-sm text-surface-400">
            <AlertCircle className="w-4 h-4 text-surface-500" />
            <span>Limited</span>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
