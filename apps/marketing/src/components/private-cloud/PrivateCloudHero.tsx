'use client';

import { motion } from 'framer-motion';
import { Cloud, Server, Shield, Zap } from 'lucide-react';
import Link from 'next/link';

export function PrivateCloudHero() {
 return (
 <section className="relative min-h-[80vh] flex items-center pt-32 pb-20 bg-surface-50">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
 <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
 {/* Left - Copy */}
 <div>
 <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-primary-50 text-primary-700 border border-primary-100 text-[10px] font-bold uppercase tracking-widest mb-6"
        >
          <Cloud className="w-4 h-4" />
          Private Cloud
        </motion.div>

 <motion.h1
 initial={{ opacity: 0, y: 20 }}
 animate={{ opacity: 1, y: 0 }}
 transition={{ delay: 0.1 }}
 className="text-4xl lg:text-6xl font-bold text-surface-900 mb-6 leading-tight tracking-tight"
 >
 Your VPC.
 <br />
 Your IP.
 <br />
 <span className="text-primary-600">Our Code.</span>
 </motion.h1>

 <motion.p
 initial={{ opacity: 0, y: 20 }}
 animate={{ opacity: 1, y: 0 }}
 transition={{ delay: 0.2 }}
 className="text-xl text-surface-600 mb-8 leading-relaxed"
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
 href="/contact/enterprise"
 className="btn-primary text-lg px-8 py-4"
 >
 Request Demo
 </Link>
 <Link
 href="/docs/private-cloud"
 className="btn-secondary text-lg px-8 py-4 bg-white"
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
 <div className="text-2xl lg:text-3xl font-bold text-surface-900 tabular-nums">{stat.value}</div>
 <div className="text-[10px] font-bold text-surface-500 uppercase tracking-widest">{stat.label}</div>
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
 <div className="premium-card p-8 bg-white">
 {/* VPC Diagram */}
 <div className="text-[10px] font-bold text-surface-400 uppercase tracking-widest mb-4 text-center">Cloud VPC Architecture</div>
 
 <div className="relative bg-surface-50 rounded-xl p-6 border border-surface-200">
 {/* VPC Label */}
 <div className="absolute -top-3 left-4 px-2 bg-white border border-surface-200 rounded text-[10px] font-bold text-primary-600 uppercase tracking-tight">
 vpc-production
 </div>

 {/* Private Subnet */}
 <div className="bg-white rounded-lg p-4 border border-dashed border-surface-300 mb-4 ">
 <div className="text-[10px] font-bold text-surface-400 mb-3 uppercase tracking-tight text-center">Private Subnet (10.0.1.0/24)</div>
 <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
 {[
 { icon: Server, label: 'API Cluster', count: '3x' },
 { icon: Server, label: 'Workers', count: '5x' },
 { icon: Server, label: 'Database', count: '2x' },
 ].map((item) => (
 <div key={item.label} className="bg-surface-50 rounded-lg p-3 text-center border border-surface-100">
 <item.icon className="w-6 h-6 text-primary-600 mx-auto mb-1" />
 <div className="text-[10px] font-bold text-surface-900 uppercase tracking-tighter">{item.label}</div>
 <div className="text-[10px] font-bold text-primary-500">{item.count}</div>
 </div>
 ))}
 </div>
 </div>

 {/* Public Subnet */}
 <div className="bg-white rounded-lg p-4 border border-dashed border-surface-300 ">
 <div className="text-[10px] font-bold text-surface-400 mb-3 uppercase tracking-tight text-center">Public Subnet (10.0.0.0/24)</div>
 <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
 {[
 { icon: Shield, label: 'Load Balancer' },
 { icon: Zap, label: 'NAT Gateway' },
 ].map((item) => (
 <div key={item.label} className="bg-surface-50 rounded-lg p-3 text-center border border-surface-100">
 <item.icon className="w-6 h-6 text-primary-600 mx-auto mb-1" />
 <div className="text-[10px] font-bold text-surface-900 uppercase tracking-tighter">{item.label}</div>
 </div>
 ))}
 </div>
 </div>
 </div>

 {/* Cloud Providers */}
 <div className="flex justify-center gap-8 mt-6 pt-6 border-t border-surface-100">
 {['AWS', 'GCP', 'Azure'].map((provider) => (
 <div key={provider} className="text-surface-400 text-xs font-bold uppercase tracking-widest">
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
