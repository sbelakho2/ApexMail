'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Server, Cloud, Building, CheckCircle } from 'lucide-react';
import { useState } from 'react';
import { cn } from '@/lib/utils';

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
 <section ref={ref} className="py-24 relative bg-white">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 <div className="text-center mb-16">
 <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-surface-100 border border-surface-200 text-xs font-medium text-surface-900 mb-6"
          >
            <Server className="w-3.5 h-3.5" />
            Deployment Options
          </motion.div>
 <motion.h2
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.1 }}
 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-6 tracking-tight"
 >
 Deploy Anywhere
 </motion.h2>
 <motion.p
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.2 }}
 className="text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed"
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
 className="flex flex-wrap justify-center gap-2 mb-10"
 >
 {deploymentOptions.map((option) => (
 <button
 key={option.id}
 onClick={() => setSelectedOption(option.id)}
 className={cn(
 'flex items-center gap-2 px-5 py-2.5 rounded-full text-sm font-semibold transition-all',
 selectedOption === option.id
 ? 'bg-surface-900 text-white shadow-sm'
 : 'bg-surface-50 text-surface-600 hover:text-surface-900 hover:bg-surface-100 border border-transparent hover:border-surface-200'
 )}
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
 className="bg-white rounded-2xl border border-surface-200 p-8 shadow-sm"
 >
 <div className="grid lg:grid-cols-2 gap-12">
 {/* Left - Info */}
 <div>
 <div className="flex items-center gap-5 mb-6">
 <div className="w-12 h-12 rounded-lg bg-surface-50 flex items-center justify-center border border-surface-200">
 <selected.icon className="w-6 h-6 text-surface-900" strokeWidth={1.5} />
 </div>
 <div>
 <h3 className="text-xl font-bold text-surface-900">{selected.name}</h3>
 <span className="text-xs font-medium text-emerald-600">{selected.availability}</span>
 </div>
 </div>
 <p className="text-surface-600 mb-8 leading-relaxed">{selected.description}</p>
 <div className="bg-surface-50 border border-surface-200 rounded-lg p-5 ">
 <div className="text-xs font-medium text-surface-500 mb-1.5">Best For</div>
 <div className="text-surface-900 font-semibold text-sm">{selected.bestFor}</div>
 </div>
 </div>

 {/* Right - Features */}
 <div>
 <div className="text-xs font-semibold text-surface-900 mb-6">Included Components</div>
 <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
 {selected.features.map((feature) => (
 <div key={feature} className="flex items-center gap-3 text-surface-700 text-sm">
 <CheckCircle className="w-5 h-5 text-surface-900 flex-shrink-0" strokeWidth={1.5} />
 <span>{feature}</span>
 </div>
 ))}
 </div>
 </div>
 </div>

 {/* Architecture Preview */}
 <div className="mt-12 pt-12 border-t border-surface-200">
 <div className="text-xs font-semibold text-surface-500 mb-6 text-center">Reference Architecture</div>
 <div className="bg-surface-950 rounded-xl p-8 font-mono text-[13px] text-surface-300 shadow-sm overflow-x-auto border border-surface-900">
 <pre className="whitespace-pre">
{`┌─────────────────────────────────────────────────────────────┐
│ Your ${selected.name} Environment │
├─────────────────────────────────────────────────────────────┤
│ │
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│ │ Load │ │ ApexMail │ │ Worker │ │
│ │ Balancer │──▶│ API (x3) │──▶│ Pool (x5) │ │
│ └─────────────┘ └─────────────┘ └─────────────┘ │
│ │ │ │ │
│ │ ▼ │ │
│ │ ┌─────────────┐ │ │
│ │ │ Redis │◀─────────┘ │
│ │ │ Cluster │ │
│ │ └─────────────┘ │
│ │ │ │
│ ▼ ▼ │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ PostgreSQL (Primary + Replicas) │ │
│ └─────────────────────────────────────────────────────┘ │
│ │
└─────────────────────────────────────────────────────────────┘`}
 </pre>
 </div>
 </div>
 </motion.div>
 </div>
 </section>
 );
}
