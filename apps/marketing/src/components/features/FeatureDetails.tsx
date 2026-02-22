'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Check, ArrowRight } from '@/components/ui/icons';
import Link from 'next/link';
import { CodeBlock } from '@/components/ui/CodeBlock';

const detailedFeatures = [
  {
    id: 'api',
    title: 'Developer-First API',
    subtitle: 'Build in Minutes',
    description:
      'Our RESTful API is designed for developers who value simplicity and power. TypeScript types, comprehensive SDKs, and instant feedback.',
    benefits: [
      'Send your first email in under 10 seconds',
      'Idempotency keys for safe retries',
      'Webhook signatures for security',
      'Batch sending up to 1,000 emails',
      'Real-time status updates',
    ],
    code: `import { ApexMail } from '@apexmail/node';

const apexmail = new ApexMail('am_live_xxx');

// Send with full type safety
const { id } = await apexmail.emails.send({
  from: 'hello@company.com',
  to: 'user@example.com',
  subject: 'Welcome!',
  html: '<h1>Hello {{name}}!</h1>',
  data: { name: 'John' },
  tags: [{ name: 'type', value: 'welcome' }],
});

// Track delivery
const email = await apexmail.emails.get(id);
console.log(email.status); // 'delivered'`,
    cta: { text: 'Read API Docs', href: '/docs/api' },
  },
  {
    id: 'compliance',
    title: 'Built-In Compliance',
    subtitle: 'GDPR & HIPAA',
    description:
      'Compliance is baked into every layer. Automated data subject requests, encrypted storage, and complete audit trails.',
    benefits: [
      'One-click GDPR data export & deletion',
      'Automatic consent tracking',
      'HIPAA BAA available (Enterprise plan)',
      'EU data residency option',
      'Complete audit logs',
    ],
    code: `// Handle GDPR requests automatically
await apexmail.compliance.gdpr.createRequest({
  email: 'user@example.com',
  type: 'export', // or 'delete'
});

// Check consent status
const consent = await apexmail.compliance.consent.get({
  email: 'user@example.com',
});

// Record consent
await apexmail.compliance.consent.record({
  email: 'user@example.com',
  source: 'signup_form',
  purposes: ['marketing', 'transactional'],
});`,
    cta: { text: 'Learn About Compliance', href: '/compliance' },
  },
  {
    id: 'ai',
    title: 'AI-Powered Optimization',
    subtitle: 'Automatic Intelligence',
    description:
      'AI-powered send-time optimization is included on Pro+ plans. The platform automatically learns each recipient\'s engagement patterns to maximize open rates.',
    benefits: [
      'Automatic send-time optimization per recipient (Pro+ plans)',
      'Bayesian engagement modeling with cold-start priors',
      'ML-based A/B test autopilot (Thompson Sampling)',
      'Inbox placement scoring and deliverability insights',
      'Churn prediction and re-engagement signals',
    ],
    code: `// Schedule with send-time optimization enabled
const { id } = await apexmail.emails.send({
  from: 'hello@company.com',
  to: 'user@example.com',
  subject: 'Your weekly digest',
  html: '<p>Here\'s what\'s new...</p>',
  // Platform automatically selects the optimal
  // delivery time based on recipient engagement history
  optimizeSendTime: true,
});

// Retrieve message analytics
const events = await apexmail.events.list({
  messageId: id,
});
console.log(events); // delivered, opened, clicked...`,
    cta: { text: 'View Analytics Docs', href: '/docs/analytics' },
  },
];

export function FeatureDetails() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 bg-surface-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="text-center mb-20"
        >
          <h2 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-4">
            Deep Dive Into Key Features
          </h2>
          <p className="text-lg text-surface-600 max-w-2xl mx-auto">
            See how ApexMail makes complex email infrastructure simple.
          </p>
        </motion.div>

        <div className="space-y-32">
          {detailedFeatures.map((feature, index) => (
            <motion.div
              key={feature.id}
              initial={{ opacity: 0, y: 40 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ delay: index * 0.2 }}
              className={`grid lg:grid-cols-2 gap-12 lg:gap-16 items-center ${
                index % 2 === 1 ? 'lg:flex-row-reverse' : ''
              }`}
            >
              {/* Content */}
              <div className={index % 2 === 1 ? 'lg:order-2' : ''}>
                <span className="text-sm font-bold text-primary-600 mb-2 block">
                  {feature.subtitle}
                </span>
                <h3 className="text-2xl lg:text-3xl font-bold text-surface-900 mb-4">
                  {feature.title}
                </h3>
                <p className="text-lg text-surface-600 mb-6">{feature.description}</p>

                <ul className="space-y-3 mb-8">
                  {feature.benefits.map((benefit) => (
                    <li key={benefit} className="flex items-start gap-3">
                      <span className="w-5 h-5 rounded-full bg-primary-100 flex items-center justify-center flex-shrink-0 mt-0.5">
                        <Check className="w-4 h-4 text-primary-600" />
                      </span>
                      <span className="text-surface-700">{benefit}</span>
                    </li>
                  ))}
                </ul>

                <Link
                  href={feature.cta.href}
                  className="inline-flex items-center gap-2 text-primary-600 font-semibold hover:text-primary-700 transition-colors"
                >
                  {feature.cta.text}
                  <ArrowRight className="w-4 h-4" />
                </Link>
              </div>

              {/* Code Block */}
              <div className={index % 2 === 1 ? 'lg:order-1' : ''}>
                <div className="rounded-lg border border-surface-200 bg-surface-900 overflow-hidden shadow-sm">
                  <div className="flex items-center gap-2 px-4 py-3 border-b border-surface-800 bg-surface-950/50">
                    <div className="flex gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-surface-700" />
                      <span className="w-2.5 h-2.5 rounded-full bg-surface-700" />
                      <span className="w-2.5 h-2.5 rounded-full bg-surface-700" />
                    </div>
                    <span className="text-xs text-surface-500 ml-2 font-mono font-medium">example.ts</span>
                  </div>
                  <CodeBlock code={feature.code} language="typescript" />
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
