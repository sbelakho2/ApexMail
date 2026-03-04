import {
  Mail,
  Shield,
  Brain,
  Gauge,
  Globe,
  Lock,
  BarChart3,
  Webhook,
  FileCode,
  Clock,
  Users,
  Database,
  Server,
  Zap,
  CheckCircle,
  Key,
} from '@/components/ui/icons';
import { cn } from '@/lib/utils';

const featureCategories = [
  {
    title: 'Email Delivery',
    icon: Mail,
    color: 'text-blue-600',
    bgColor: 'bg-blue-50',
    features: [
      {
        name: 'Transactional & Marketing',
        description: 'Single API for all email types with smart categorization',
        icon: Mail,
      },
      {
        name: 'Multi-Recipient Support',
        description: 'Send to up to 50 recipients per message with to/cc/bcc',
        icon: Users,
      },
      {
        name: 'Template Engine',
        description: 'Handlebars, MJML, Liquid, and EJS support with versioning',
        icon: FileCode,
      },
      {
        name: 'Scheduled Sending',
        description: 'Schedule emails up to 72 hours in advance',
        icon: Clock,
      },
      {
        name: 'Attachment Support',
        description: 'Up to 25MB per message with inline image support',
        icon: FileCode,
      },
      {
        name: 'Inbound Processing',
        description: 'Receive and parse incoming emails via webhooks (Scale+ plans)',
        icon: Webhook,
      },
    ],
  },
  {
    title: 'Deliverability',
    icon: Gauge,
    color: 'text-green-600',
    bgColor: 'bg-green-50',
    features: [
      {
        name: 'DKIM/SPF/DMARC',
        description: 'Automatic authentication with weekly key rotation',
        icon: Key,
      },
      {
        name: 'ARC & BIMI Support',
        description: 'Advanced authentication for forwarded messages and brand logos',
        icon: CheckCircle,
      },
      {
        name: 'IP Reputation Monitoring',
        description: 'Real-time RBL checks with circuit breaker protection',
        icon: Shield,
      },
      {
        name: 'Dedicated IPs',
        description: 'Isolated sending reputation with automatic warm-up',
        icon: Server,
      },
      {
        name: 'Suppression Management',
        description: 'Automatic bounce and complaint handling',
        icon: Users,
      },
      {
        name: 'MX Validation',
        description: 'Pre-send recipient validation to reduce bounces',
        icon: CheckCircle,
      },
    ],
  },
  {
    title: 'Compliance & Security',
    icon: Shield,
    color: 'text-purple-600',
    bgColor: 'bg-purple-50',
    features: [
      {
        name: 'GDPR Automation',
        description: 'Automated DSR handling with one-click data export/deletion',
        icon: Lock,
      },
      {
        name: 'HIPAA Compliance',
        description: 'BAA available with encrypted PHI handling (Enterprise plan)',
        icon: Shield,
      },
      {
        name: 'Audit Logging',
        description: 'Complete audit trail for all API operations',
        icon: Database,
      },
      {
        name: 'Data Encryption',
        description: 'AES-256 encryption at rest, TLS 1.3 in transit',
        icon: Lock,
      },
      {
        name: 'SOC 2 Controls',
        description: 'Enterprise plan controls and audit readiness',
        icon: CheckCircle,
      },
      {
        name: 'Data Residency',
        description: 'Choose EU, US, or custom data locations',
        icon: Globe,
      },
    ],
  },
  {
    title: 'AI & Intelligence',
    icon: Brain,
    color: 'text-orange-600',
    bgColor: 'bg-orange-50',
    features: [
      {
        name: 'Send-Time Optimization',
        description: 'ML-powered delivery timing for maximum engagement',
        icon: Clock,
      },
      {
        name: 'Subject Line Generator',
        description: 'AI suggestions with sentiment and spam score analysis',
        icon: Brain,
      },
      {
        name: 'Content Optimization',
        description: 'Readability scores and improvement suggestions',
        icon: FileCode,
      },
      {
        name: 'Local AI Inference',
        description: 'Zero external API calls—full privacy with ONNX models',
        icon: Server,
      },
      {
        name: 'Predictive Analytics',
        description: 'Forecast engagement and churn risk',
        icon: BarChart3,
      },
      {
        name: 'Chatbot Assistant',
        description: 'AI-powered support for email marketing questions',
        icon: Users,
      },
    ],
  },
  {
    title: 'Analytics & Tracking',
    icon: BarChart3,
    color: 'text-cyan-600',
    bgColor: 'bg-cyan-50',
    features: [
      {
        name: 'Real-Time Events',
        description: 'Track opens, clicks, bounces, and complaints instantly',
        icon: Zap,
      },
      {
        name: 'Click Heatmaps',
        description: 'Visualize where recipients engage with your emails',
        icon: BarChart3,
      },
      {
        name: 'Webhook Delivery',
        description: 'Real-time event delivery with retry and signatures',
        icon: Webhook,
      },
      {
        name: 'DuckDB Analytics',
        description: 'Sub-second queries on billions of events',
        icon: Database,
      },
      {
        name: 'Custom Dashboards',
        description: 'Build your own views with our query API',
        icon: BarChart3,
      },
      {
        name: 'Export & Reporting',
        description: 'CSV, JSON, and scheduled report delivery',
        icon: FileCode,
      },
    ],
  },
  {
    title: 'Enterprise',
    icon: Server,
    color: 'text-red-600',
    bgColor: 'bg-red-50',
    features: [
      {
        name: 'SSO/SAML/OIDC',
        description: 'Enterprise identity provider integration (Scale+ plans)',
        icon: Key,
      },
      {
        name: 'White-Label',
        description: 'Custom branding, domains, and login pages',
        icon: Globe,
      },
      {
        name: 'Sub-Accounts',
        description: 'Manage multiple brands with isolated data',
        icon: Users,
      },
      {
        name: 'Private Cloud',
        description: 'Dedicated infrastructure in your preferred region',
        icon: Server,
      },
      {
        name: 'SLA Guarantees',
        description: '99.9% uptime (Scale+ plans) with error budget tracking',
        icon: CheckCircle,
      },
      {
        name: 'Priority Support',
        description: 'Dedicated success manager and 24/7 support',
        icon: Users,
      },
    ],
  },
];

export function FeatureGrid() {
  return (
    <section className="py-20 lg:py-32 bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="animate-in text-center mb-16">
          <h2 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-4">
            Complete Feature Set
          </h2>
          <p className="text-lg text-surface-600 max-w-2xl mx-auto">
            Everything you need to send, track, and optimize transactional emails at scale.
          </p>
        </div>

        <div className="space-y-16">
          {featureCategories.map((category, categoryIndex) => (
            <div key={category.title} className="animate-in">
              <div className="flex items-center gap-3 mb-8">
                <div className={cn('w-10 h-10 rounded-lg flex items-center justify-center', category.bgColor)}>
                  <category.icon className={cn('w-5 h-5', category.color)} />
                </div>
                <h3 className="text-xl font-bold text-surface-900">{category.title}</h3>
              </div>

              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                {category.features.map((feature, featureIndex) => (
                  <div key={feature.name} className="animate-in p-6 rounded-lg border border-surface-200 hover:border-surface-300 hover:shadow-sm transition-all bg-white">
                    <div className={cn('w-8 h-8 rounded-lg flex items-center justify-center mb-4', category.bgColor)}>
                      <feature.icon className={cn('w-4 h-4', category.color)} />
                    </div>
                    <h4 className="font-semibold text-surface-900 mb-2">{feature.name}</h4>
                    <p className="text-sm text-surface-600">{feature.description}</p>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
