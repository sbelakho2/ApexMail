'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Globe, Shield, TrendingUp, CheckCircle } from 'lucide-react';

export function DedicatedIPs() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
          {/* Left - Copy */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={inView ? { opacity: 1, x: 0 } : {}}
          >
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/10 text-purple-400 text-sm mb-4">
              <Globe className="w-4 h-4" />
              Dedicated IPs
            </div>
            <h2 className="text-3xl lg:text-4xl font-bold text-white mb-4">
              Your Reputation. Your IPs.
            </h2>
            <p className="text-lg text-surface-400 mb-6">
              With private cloud, you get dedicated IP addresses that no one else shares. 
              Build your sender reputation from scratch, and keep it pristine.
            </p>

            <div className="space-y-4 mb-8">
              {[
                {
                  icon: Shield,
                  title: 'No Noisy Neighbors',
                  description: "Other senders' behavior never affects your deliverability",
                },
                {
                  icon: TrendingUp,
                  title: 'Controlled Warmup',
                  description: 'Warm up IPs at your pace with our automated warmup scheduler',
                },
                {
                  icon: Globe,
                  title: 'Regional IPs',
                  description: 'Get IPs in specific regions for compliance requirements',
                },
              ].map((item) => (
                <div key={item.title} className="flex items-start gap-3">
                  <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center flex-shrink-0">
                    <item.icon className="w-5 h-5 text-purple-400" />
                  </div>
                  <div>
                    <div className="text-white font-medium">{item.title}</div>
                    <div className="text-sm text-surface-400">{item.description}</div>
                  </div>
                </div>
              ))}
            </div>
          </motion.div>

          {/* Right - IP Pool Visual */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={inView ? { opacity: 1, x: 0 } : {}}
            transition={{ delay: 0.2 }}
          >
            <div className="glass-card p-6">
              <div className="flex items-center justify-between mb-6">
                <div className="text-lg font-semibold text-white">IP Pool Dashboard</div>
                <div className="px-2 py-1 bg-green-500/10 text-green-400 text-xs rounded">
                  All Healthy
                </div>
              </div>

              {/* IP List */}
              <div className="space-y-3">
                {[
                  { ip: '198.51.100.10', reputation: 98, volume: '45K/day', status: 'active' },
                  { ip: '198.51.100.11', reputation: 97, volume: '42K/day', status: 'active' },
                  { ip: '198.51.100.12', reputation: 95, volume: '38K/day', status: 'active' },
                  { ip: '198.51.100.13', reputation: 72, volume: '5K/day', status: 'warming' },
                  { ip: '198.51.100.14', reputation: 0, volume: '0/day', status: 'standby' },
                ].map((ipData) => (
                  <div
                    key={ipData.ip}
                    className="flex items-center justify-between p-3 bg-surface-800/50 rounded-lg"
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className={`w-2 h-2 rounded-full ${
                          ipData.status === 'active'
                            ? 'bg-green-400'
                            : ipData.status === 'warming'
                            ? 'bg-yellow-400'
                            : 'bg-surface-500'
                        }`}
                      />
                      <span className="text-white font-mono text-sm">{ipData.ip}</span>
                    </div>
                    <div className="flex items-center gap-6">
                      <div className="text-right">
                        <div className="text-xs text-surface-500">Reputation</div>
                        <div
                          className={`font-semibold ${
                            ipData.reputation >= 90
                              ? 'text-green-400'
                              : ipData.reputation >= 70
                              ? 'text-yellow-400'
                              : 'text-surface-500'
                          }`}
                        >
                          {ipData.reputation}%
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-xs text-surface-500">Volume</div>
                        <div className="text-white text-sm">{ipData.volume}</div>
                      </div>
                      <div
                        className={`px-2 py-1 text-xs rounded capitalize ${
                          ipData.status === 'active'
                            ? 'bg-green-500/10 text-green-400'
                            : ipData.status === 'warming'
                            ? 'bg-yellow-500/10 text-yellow-400'
                            : 'bg-surface-700 text-surface-500'
                        }`}
                      >
                        {ipData.status}
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Features */}
              <div className="mt-6 pt-6 border-t border-surface-700">
                <div className="text-sm text-surface-500 mb-3">Included Features</div>
                <div className="grid grid-cols-2 gap-2">
                  {[
                    'Automatic failover',
                    'Load balancing',
                    'Warmup automation',
                    'Reputation monitoring',
                    'Blacklist alerts',
                    'SPF/DKIM/DMARC setup',
                  ].map((feature) => (
                    <div key={feature} className="flex items-center gap-2 text-sm text-surface-300">
                      <CheckCircle className="w-4 h-4 text-green-400" />
                      {feature}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
