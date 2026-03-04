import { h } from 'preact';
import { useState } from 'preact/hooks';

// Inline SVG icons
const ServerIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <rect width="20" height="8" x="2" y="2" rx="2" ry="2" /><rect width="20" height="8" x="2" y="14" rx="2" ry="2" />
    <line x1="6" x2="6.01" y1="6" y2="6" /><line x1="6" x2="6.01" y1="18" y2="18" />
  </svg>
);
const CloudIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z" />
  </svg>
);
const BuildingIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <rect width="16" height="20" x="4" y="2" rx="2" ry="2" />
    <path d="M9 22v-4h6v4" /><path d="M8 6h.01" /><path d="M16 6h.01" /><path d="M12 6h.01" />
    <path d="M12 10h.01" /><path d="M12 14h.01" /><path d="M16 10h.01" /><path d="M16 14h.01" />
    <path d="M8 10h.01" /><path d="M8 14h.01" />
  </svg>
);
const CheckCircleIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" />
  </svg>
);

interface DeploymentOption {
  id: string;
  name: string;
  icon: (props: { class?: string }) => h.JSX.Element;
  description: string;
  features: string[];
  bestFor: string;
  availability: string;
}

const deploymentOptions: DeploymentOption[] = [
  {
    id: 'aws',
    name: 'AWS VPC',
    icon: CloudIcon,
    description: 'Deploy directly into your AWS Virtual Private Cloud with native integrations.',
    features: [
      'EKS or EC2 deployment options',
      'RDS PostgreSQL or Aurora',
      'ElastiCache Redis cluster',
      'S3 for attachments & logs',
      'CloudWatch integration',
      'AWS PrivateLink support',
    ],
    bestFor: 'Teams already on AWS',
    availability: 'Available Now',
  },
  {
    id: 'gcp',
    name: 'Google Cloud',
    icon: CloudIcon,
    description: 'Native GCP deployment with Cloud Run or GKE Autopilot options.',
    features: [
      'GKE or Cloud Run',
      'Cloud SQL PostgreSQL',
      'Memorystore Redis',
      'Cloud Storage',
      'Cloud Monitoring',
      'Private Service Connect',
    ],
    bestFor: 'Google Workspace customers',
    availability: 'Available Now',
  },
  {
    id: 'azure',
    name: 'Microsoft Azure',
    icon: CloudIcon,
    description: 'Azure deployment with AKS and managed services integration.',
    features: [
      'AKS or Container Apps',
      'Azure Database PostgreSQL',
      'Azure Cache for Redis',
      'Azure Blob Storage',
      'Azure Monitor',
      'Private Endpoints',
    ],
    bestFor: 'Microsoft 365 shops',
    availability: 'Available Now',
  },
  {
    id: 'onprem',
    name: 'On-Premises',
    icon: BuildingIcon,
    description: 'Air-gapped deployment for maximum security in your own data center.',
    features: [
      'VMware or bare metal',
      'Self-managed PostgreSQL',
      'Self-managed Redis',
      'Local S3-compatible storage',
      'Prometheus/Grafana',
      'Minimal external dependencies',
    ],
    bestFor: 'Regulated industries (ITAR, FedRAMP)',
    availability: 'Enterprise Only',
  },
];

const architectureDiagram = (name: string) => `┌─────────────────────────────────────────────────────────────┐
│ Your ${name} Environment                                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│ │ Load        │ │ ApexMail    │ │ Worker      │            │
│ │ Balancer    │──▶│ API (x3)    │──▶│ Pool (x5)   │            │
│ └─────────────┘ └─────────────┘ └─────────────┘            │
│       │               │               │                     │
│       │               ▼               │                     │
│       │         ┌─────────────┐       │                     │
│       │         │ Redis       │◀──────┘                     │
│       │         │ Cluster     │                             │
│       │         └─────────────┘                             │
│       │               │                                     │
│       ▼               ▼                                     │
│ ┌─────────────────────────────────────────────────────┐     │
│ │ PostgreSQL (Primary + Replicas)                     │     │
│ └─────────────────────────────────────────────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘`;

export default function DeploymentOptions() {
  const [selectedOption, setSelectedOption] = useState<string>('aws');
  const selected = deploymentOptions.find((o) => o.id === selectedOption) || deploymentOptions[0];

  return (
    <section class="py-20 lg:py-32 relative bg-white">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <div class="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-surface-100 border border-surface-200 text-xs font-medium text-surface-900 mb-6">
            <ServerIcon class="w-4 h-4" />
            Deployment Options
          </div>
          <h2 class="text-3xl lg:text-4xl font-bold text-surface-900 mb-6 tracking-tight">
            Deploy Anywhere
          </h2>
          <p class="text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed">
            Same code, multiple deployment targets. Choose the infrastructure
            that fits your security and compliance requirements.
          </p>
        </div>

        {/* Selector Tabs */}
        <div class="flex flex-wrap justify-center gap-2 mb-10">
          {deploymentOptions.map((option) => (
            <button
              key={option.id}
              onClick={() => setSelectedOption(option.id)}
              class={`flex items-center gap-2 px-5 py-2.5 rounded-full text-sm font-semibold transition-all ${
                selectedOption === option.id
                  ? 'bg-surface-900 text-white shadow-sm'
                  : 'bg-surface-50 text-surface-600 hover:text-surface-900 hover:bg-surface-100 border border-transparent hover:border-surface-200'
              }`}
            >
              <option.icon class="w-4 h-4" />
              {option.name}
            </button>
          ))}
        </div>

        {/* Selected Option Details */}
        <div key={selected.id} class="bg-white rounded-2xl border border-surface-200 p-8 shadow-sm">
          <div class="grid lg:grid-cols-2 gap-12">
            {/* Left - Info */}
            <div>
              <div class="flex items-center gap-5 mb-6">
                <div class="w-12 h-12 rounded-lg bg-surface-50 flex items-center justify-center border border-surface-200">
                  <selected.icon class="w-6 h-6 text-surface-900" />
                </div>
                <div>
                  <h3 class="text-xl font-bold text-surface-900">{selected.name}</h3>
                  <span class="text-xs font-medium text-emerald-600">{selected.availability}</span>
                </div>
              </div>
              <p class="text-surface-600 mb-8 leading-relaxed">{selected.description}</p>
              <div class="bg-surface-50 border border-surface-200 rounded-lg p-5">
                <div class="text-xs font-medium text-surface-500 mb-1.5">Best For</div>
                <div class="text-surface-900 font-semibold text-sm">{selected.bestFor}</div>
              </div>
            </div>

            {/* Right - Features */}
            <div>
              <div class="text-xs font-semibold text-surface-900 mb-6">Included Components</div>
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {selected.features.map((feature) => (
                  <div key={feature} class="flex items-center gap-3 text-surface-700 text-sm">
                    <CheckCircleIcon class="w-5 h-5 text-surface-900 flex-shrink-0" />
                    <span>{feature}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Architecture Preview */}
          <div class="mt-12 pt-12 border-t border-surface-200">
            <div class="text-xs font-semibold text-surface-500 mb-6 text-center">Reference Architecture</div>
            <div class="bg-surface-950 rounded-lg p-8 font-mono text-[13px] text-surface-300 shadow-sm overflow-x-auto border border-surface-900">
              <pre class="whitespace-pre-wrap break-words">{architectureDiagram(selected.name)}</pre>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
