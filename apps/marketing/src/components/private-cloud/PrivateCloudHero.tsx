'use client';

import { motion } from 'framer-motion';
import { Cloud, Server, Shield, Zap } from 'lucide-react';
import Link from 'next/link';

export function PrivateCloudHero() {
  return (
    <section className="relative min-h-[90vh] flex items-center pt-20">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-b from-surface-950 via-surface-900 to-surface-950" />
      <div className="absolute inset-0 opacity-30">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-500/20 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl" />
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
          {/* Left - Copy */}
          <div>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 text-blue-400 text-sm mb-6"
            >
              <Cloud className="w-4 h-4" />
              Private Cloud
            </motion.div>

            <motion.h1
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
              className="text-4xl lg:text-6xl font-bold text-white mb-6 leading-tight"
            >
              Your VPC.
              <br />
              Your IP.
              <br />
              <span className="text-gradient">Our Code.</span>
            </motion.h1>

            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
              className="text-xl text-surface-400 mb-8"
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
                className="inline-flex items-center justify-center gap-2 px-8 py-4 bg-primary-600 text-white font-semibold rounded-xl hover:bg-primary-500 transition-colors"
              >
                Request Demo
              </Link>
              <Link
                href="/docs/private-cloud"
                className="inline-flex items-center justify-center gap-2 px-8 py-4 border border-surface-600 text-white font-semibold rounded-xl hover:border-surface-500 transition-colors"
              >
                View Architecture
              </Link>
            </motion.div>

            {/* Stats */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
              className="grid grid-cols-3 gap-6 mt-12 pt-8 border-t border-surface-800"
            >
              {[
                { value: '< 1ms', label: 'Internal Latency' },
                { value: '100%', label: 'Data Sovereignty' },
                { value: '0', label: 'Shared Resources' },
              ].map((stat) => (
                <div key={stat.label}>
                  <div className="text-2xl lg:text-3xl font-bold text-white">{stat.value}</div>
                  <div className="text-sm text-surface-500">{stat.label}</div>
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
            <div className="glass-card p-8">
              {/* VPC Diagram */}
              <div className="text-sm text-surface-500 mb-4">Your VPC Architecture</div>
              
              <div className="relative bg-surface-900/50 rounded-xl p-6 border border-surface-700">
                {/* VPC Label */}
                <div className="absolute -top-3 left-4 px-2 bg-surface-900 text-xs text-blue-400">
                  vpc-production
                </div>

                {/* Private Subnet */}
                <div className="bg-surface-800/50 rounded-lg p-4 border border-dashed border-surface-600 mb-4">
                  <div className="text-xs text-surface-500 mb-3">Private Subnet (10.0.1.0/24)</div>
                  <div className="grid grid-cols-3 gap-3">
                    {[
                      { icon: Server, label: 'API Cluster', count: '3x' },
                      { icon: Server, label: 'Workers', count: '5x' },
                      { icon: Server, label: 'Database', count: '2x' },
                    ].map((item) => (
                      <div key={item.label} className="bg-surface-900 rounded-lg p-3 text-center">
                        <item.icon className="w-6 h-6 text-blue-400 mx-auto mb-1" />
                        <div className="text-xs text-white">{item.label}</div>
                        <div className="text-xs text-surface-500">{item.count}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Public Subnet */}
                <div className="bg-surface-800/50 rounded-lg p-4 border border-dashed border-surface-600">
                  <div className="text-xs text-surface-500 mb-3">Public Subnet (10.0.0.0/24)</div>
                  <div className="grid grid-cols-2 gap-3">
                    {[
                      { icon: Shield, label: 'Load Balancer' },
                      { icon: Zap, label: 'NAT Gateway' },
                    ].map((item) => (
                      <div key={item.label} className="bg-surface-900 rounded-lg p-3 text-center">
                        <item.icon className="w-6 h-6 text-green-400 mx-auto mb-1" />
                        <div className="text-xs text-white">{item.label}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Cloud Providers */}
              <div className="flex justify-center gap-6 mt-6 pt-6 border-t border-surface-700">
                {['AWS', 'GCP', 'Azure'].map((provider) => (
                  <div key={provider} className="text-surface-500 text-sm">
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
