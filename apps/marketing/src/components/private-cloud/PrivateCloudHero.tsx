'use client';

import { motion } from 'framer-motion';
import { Cloud, Server, Shield, Zap } from '@/components/ui/icons';
import Link from 'next/link';

export function PrivateCloudHero() {
 return (
 <section className="relative min-h-[80vh] flex items-center pt-32 pb-20 bg-surface-50">
 <div className="max-w-7xl mx-auto px-5 sm:px-6 lg:px-8 relative">
 <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
 {/* Left - Copy */}
 <div>
 <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-100 border border-surface-200 text-xs font-medium text-surface-900 mb-6"
        >
          <Cloud className="w-4 h-4" />
          Private Cloud
        </motion.div>

 <motion.h1
 initial={{ opacity: 0, y: 20 }}
 animate={{ opacity: 1, y: 0 }}
 transition={{ delay: 0.1 }}
 className="text-3xl sm:text-4xl lg:text-6xl font-bold text-surface-900 mb-6 leading-tight tracking-tight break-words"
 >
 Your VPC.
 <br />
 Your IP.
 <br />
 <span className="text-surface-500">Our Code.</span>
 </motion.h1>

 <motion.p
 initial={{ opacity: 0, y: 20 }}
 animate={{ opacity: 1, y: 0 }}
 transition={{ delay: 0.2 }}
 className="text-lg sm:text-xl text-surface-600 mb-8 leading-relaxed"
 >
 Deploy the full ApexMail stack in your own AWS, GCP, or Azure VPC. 
 Complete data sovereignty with zero shared infrastructure.
 </motion.p>

 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={{ opacity: 1, y: 0 }}
 transition={{ delay: 0.3 }}
 className="flex flex-col sm:flex-row gap-4"
 >
 <Link
 href="/pricing"
 className="inline-flex items-center justify-center px-6 py-3 text-sm font-semibold text-white bg-primary-600 rounded-md hover:bg-primary-700 transition-colors"
 >
 Request Demo
 </Link>
 <Link
 href="https://docs.apexmail.ee"
 className="inline-flex items-center justify-center px-6 py-3 text-sm font-semibold text-surface-900 bg-white border border-surface-200 rounded-md hover:bg-surface-50 transition-colors"
 >
 View Architecture
 </Link>
 </motion.div>

 {/* Stats */}
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={{ opacity: 1, y: 0 }}
 transition={{ delay: 0.4 }}
 className="grid grid-cols-1 sm:grid-cols-3 gap-6 mt-12 pt-8 border-t border-surface-200"
 >
 {[
 { value: '< 1ms', label: 'Internal Latency' },
 { value: '100%', label: 'Data Sovereignty' },
 { value: '0', label: 'Shared Resources' },
 ].map((stat) => (
 <div key={stat.label}>
 <div className="text-2xl lg:text-3xl font-bold text-surface-900 tabular-nums mb-1">{stat.value}</div>
 <div className="text-xs font-medium text-surface-500">{stat.label}</div>
 </div>
 ))}
 </motion.div>
 </div>

 {/* Right - Visual */}
 <motion.div
 initial={{ opacity: 0, scale: 0.95 }}
 animate={{ opacity: 1, scale: 1 }}
 transition={{ delay: 0.2 }}
 className="relative"
 >
 <div className="bg-white rounded-lg border border-surface-200 p-8 shadow-sm">
 {/* VPC Diagram */}
 <div className="text-xs font-semibold text-surface-500 mb-6 text-center">Cloud VPC Architecture</div>
 
 <div className="relative bg-surface-50/50 rounded-lg p-6 border border-surface-200">
 {/* VPC Label */}
 <div className="absolute -top-3 left-4 px-2 bg-white border border-surface-200 rounded text-xs font-medium text-surface-600">
 vpc-production
 </div>

 {/* Private Subnet */}
 <div className="bg-white rounded p-4 border border-dashed border-surface-300 mb-4 ">
 <div className="text-xs font-medium text-surface-500 mb-3 text-center">Private Subnet (10.0.1.0/24)</div>
 <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
 {[
 { icon: Server, label: 'API Cluster', count: '3x' },
 { icon: Server, label: 'Workers', count: '5x' },
 { icon: Server, label: 'Database', count: '2x' },
 ].map((item) => (
 <div key={item.label} className="bg-surface-50 rounded p-3 text-center border border-surface-100">
 <item.icon className="w-5 h-5 text-surface-900 mx-auto mb-1.5" strokeWidth={1.5} />
 <div className="text-xs font-medium text-surface-900">{item.label}</div>
 <div className="text-xs text-surface-500">{item.count}</div>
 </div>
 ))}
 </div>
 </div>

 {/* Public Subnet */}
 <div className="bg-white rounded p-4 border border-dashed border-surface-300 ">
 <div className="text-xs font-medium text-surface-500 mb-3 text-center">Public Subnet (10.0.0.0/24)</div>
 <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
 {[
 { icon: Shield, label: 'Load Balancer' },
 { icon: Zap, label: 'NAT Gateway' },
 ].map((item) => (
 <div key={item.label} className="bg-surface-50 rounded p-3 text-center border border-surface-100">
 <item.icon className="w-5 h-5 text-surface-900 mx-auto mb-1.5" strokeWidth={1.5} />
 <div className="text-xs font-medium text-surface-900">{item.label}</div>
 </div>
 ))}
 </div>
 </div>
 </div>

 {/* Cloud Providers */}
 <div className="flex justify-center gap-8 mt-6 pt-6 border-t border-surface-100">
 {['AWS', 'GCP', 'Azure'].map((provider) => (
 <div key={provider} className="text-surface-400 text-xs font-semibold">
 {provider}
 </div>
 ))}
 </div>
 </div>
 </motion.div>
 </div>
 </div>
 </section>
 );
}
