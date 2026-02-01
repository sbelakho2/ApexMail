'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Server, Cloud, Building, CheckCircle } from 'lucide-react';
import { useState } from 'react';

interface DeploymentOption {
  id: string;
  name: string;
  icon: typeof Server;
  description: string;
  features: string[];
  bestFor: string;
  availability: string;
}

const deploymentOptions: DeploymentOption[] = [
  {
    id: 'aws',
    name: 'AWS VPC',
    icon: Cloud,
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
    icon: Cloud,
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
    icon: Cloud,
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
    icon: Building,
    description: 'Air-gapped deployment for maximum security in your own data center.',
    features: [
      'VMware or bare metal',
      'Self-managed PostgreSQL',
      'Self-managed Redis',
      'Local S3-compatible storage',
      'Prometheus/Grafana',
      'No external dependencies',
    ],
    bestFor: 'Regulated industries (ITAR, FedRAMP)',
    availability: 'Enterprise Only',
  },
];

export function DeploymentOptions() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [selectedOption, setSelectedOption] = useState<string>('aws');

  const selected = deploymentOptions.find((o) => o.id === selectedOption) || deploymentOptions[0];

  return (
    <section ref={ref} className="py-20 lg:py-32 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 text-blue-400 text-sm mb-4"
          >
            <Server className="w-4 h-4" />
            Deployment Options
          </motion.div>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.1 }}
            className="text-3xl lg:text-4xl font-bold text-white mb-4"
          >
            Deploy Anywhere
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.2 }}
            className="text-lg text-surface-400 max-w-2xl mx-auto"
          >
            Same code, multiple deployment targets. Choose the infrastructure 
            that fits your security and compliance requirements.
          </motion.p>
        </div>

        {/* Selector Tabs */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.3 }}
          className="flex flex-wrap justify-center gap-3 mb-8"
        >
          {deploymentOptions.map((option) => (
            <button
              key={option.id}
              onClick={() => setSelectedOption(option.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-all ${
                selectedOption === option.id
                  ? 'bg-primary-600 text-white'
                  : 'bg-surface-800 text-surface-400 hover:text-white hover:bg-surface-700'
              }`}
            >
              <option.icon className="w-4 h-4" />
              {option.name}
            </button>
          ))}
        </motion.div>

        {/* Selected Option Details */}
        <motion.div
          key={selected.id}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-card p-8"
        >
          <div className="grid lg:grid-cols-2 gap-8">
            {/* Left - Info */}
            <div>
              <div className="flex items-center gap-3 mb-4">
                <div className="w-12 h-12 rounded-xl bg-blue-500/10 flex items-center justify-center">
                  <selected.icon className="w-6 h-6 text-blue-400" />
                </div>
                <div>
                  <h3 className="text-xl font-semibold text-white">{selected.name}</h3>
                  <span className="text-sm text-green-400">{selected.availability}</span>
                </div>
              </div>
              <p className="text-surface-400 mb-6">{selected.description}</p>
              <div className="bg-surface-800/50 rounded-lg p-4">
                <div className="text-sm text-surface-500 mb-2">Best For</div>
                <div className="text-white">{selected.bestFor}</div>
              </div>
            </div>

            {/* Right - Features */}
            <div>
              <div className="text-sm text-surface-500 mb-4">Included Components</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {selected.features.map((feature) => (
                  <div key={feature} className="flex items-center gap-2 text-surface-300">
                    <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                    <span className="text-sm">{feature}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Architecture Preview */}
          <div className="mt-8 pt-8 border-t border-surface-700">
            <div className="text-sm text-surface-500 mb-4">Architecture Overview</div>
            <div className="bg-surface-900/50 rounded-lg p-6 font-mono text-sm text-surface-400">
              <pre className="whitespace-pre-wrap">
{`┌─────────────────────────────────────────────────────────────┐
│  Your ${selected.name} Environment                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐       │
│  │  Load       │   │  ApexMail   │   │  Worker     │       │
│  │  Balancer   │──▶│  API (x3)   │──▶│  Pool (x5)  │       │
│  └─────────────┘   └─────────────┘   └─────────────┘       │
│         │                │                  │               │
│         │                ▼                  │               │
│         │         ┌─────────────┐          │               │
│         │         │  Redis      │◀─────────┘               │
│         │         │  Cluster    │                          │
│         │         └─────────────┘                          │
│         │                │                                  │
│         ▼                ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              PostgreSQL (Primary + Replicas)        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘`}
              </pre>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
