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
 <section ref={ref} className="py-20 lg:py-32 relative bg-white">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 <div className="text-center mb-12">
 <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-primary-50 text-primary-700 border border-primary-100 text-[10px] font-bold uppercase tracking-widest mb-4"
          >
            <Server className="w-4 h-4" />
            Deployment Options
          </motion.div>
 <motion.h2
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.1 }}
 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-4 tracking-tight"
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
 className="flex flex-wrap justify-center gap-2 mb-8"
 >
 {deploymentOptions.map((option) => (
 <button
 key={option.id}
 onClick={() => setSelectedOption(option.id)}
 className={cn(
 'flex items-center gap-2 px-4 py-2 rounded-md font-bold text-[10px] uppercase tracking-widest transition-all',
 selectedOption === option.id
 ? 'bg-primary-600 text-white '
 : 'bg-surface-50 text-surface-500 hover:text-surface-900 hover:bg-surface-100'
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
 className="premium-card p-8 bg-surface-50"
 >
 <div className="grid lg:grid-cols-2 gap-12">
 {/* Left - Info */}
 <div>
 <div className="flex items-center gap-4 mb-6">
 <div className="w-14 h-14 rounded-md bg-primary-50 flex items-center justify-center border border-primary-100">
 <selected.icon className="w-7 h-7 text-primary-600" />
 </div>
 <div>
 <h3 className="text-2xl font-bold text-surface-900">{selected.name}</h3>
 <span className="text-[10px] font-bold text-emerald-600 uppercase tracking-widest">{selected.availability}</span>
 </div>
 </div>
 <p className="text-surface-600 font-medium mb-8 leading-relaxed">{selected.description}</p>
 <div className="bg-white border border-surface-200 rounded-md p-6 ">
 <div className="text-[10px] font-bold text-surface-600 mb-2 uppercase tracking-widest">Best For</div>
 <div className="text-surface-900 font-bold">{selected.bestFor}</div>
 </div>
 </div>

 {/* Right - Features */}
 <div>
 <div className="text-[10px] font-bold text-surface-600 mb-6 uppercase tracking-widest">Included Components</div>
 <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
 {selected.features.map((feature) => (
 <div key={feature} className="flex items-center gap-3 text-surface-700 font-bold text-sm">
 <CheckCircle className="w-5 h-5 text-primary-600 flex-shrink-0" strokeWidth={3} />
 <span>{feature}</span>
 </div>
 ))}
 </div>
 </div>
 </div>

 {/* Architecture Preview */}
 <div className="mt-12 pt-12 border-t border-surface-200">
 <div className="text-[10px] font-bold text-surface-600 mb-4 uppercase tracking-widest text-center">Reference Architecture</div>
 <div className="bg-surface-900 rounded-lg p-8 font-mono text-[13px] text-surface-300 shadow-inner overflow-x-auto">
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
