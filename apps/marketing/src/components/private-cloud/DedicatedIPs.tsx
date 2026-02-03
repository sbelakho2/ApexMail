'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Globe, Shield, TrendingUp, CheckCircle } from 'lucide-react';

export function DedicatedIPs() {
 const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

 return (
 <section ref={ref} className="py-20 lg:py-32 relative bg-white">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
 {/* Left - Copy */}
 <motion.div
 initial={{ opacity: 0, x: -20 }}
 animate={inView ? { opacity: 1, x: 0 } : {}}
 >
 <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-primary-50 text-primary-700 border border-primary-100 text-[10px] font-bold uppercase tracking-widest mb-4">
            <Globe className="w-4 h-4" />
            Dedicated IPs
          </div>
 <h2 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-4 tracking-tight">
 Your Reputation. Your IPs.
 </h2>
 <p className="text-lg text-surface-600 mb-8 leading-relaxed font-medium">
 With private cloud, you get dedicated IP addresses that no one else shares. 
 Build your sender reputation from scratch, and keep it pristine.
 </p>

 <div className="space-y-6 mb-8">
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
 <div key={item.title} className="flex items-start gap-4">
 <div className="w-12 h-12 rounded-md bg-primary-50 flex items-center justify-center flex-shrink-0 border border-primary-100">
 <item.icon className="w-6 h-6 text-primary-600" />
 </div>
 <div>
 <div className="text-surface-900 font-bold">{item.title}</div>
 <div className="text-sm text-surface-500 font-medium">{item.description}</div>
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
 <div className="premium-card p-8 bg-surface-50">
 <div className="flex items-center justify-between mb-8">
 <div className="text-[10px] font-bold text-surface-400 uppercase tracking-widest">IP Pool Dashboard</div>
 <div className="px-2.5 py-1 bg-emerald-50 text-emerald-700 border border-emerald-100 text-[10px] font-bold uppercase tracking-tight rounded-md">
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
 className="flex items-center justify-between p-4 bg-white border border-surface-100 rounded-lg "
 >
 <div className="flex items-center gap-3">
 <div
 className={`w-2 h-2 rounded-full ${
 ipData.status === 'active'
 ? 'bg-emerald-500'
 : ipData.status === 'warming'
 ? 'bg-amber-500'
 : 'bg-surface-300'
 }`}
 />
 <span className="text-surface-900 font-mono text-sm font-bold">{ipData.ip}</span>
 </div>
 <div className="flex items-center gap-8">
 <div className="text-right hidden sm:block">
 <div className="text-[9px] font-bold text-surface-400 uppercase tracking-tight">Reputation</div>
 <div
 className={`text-sm font-bold ${
 ipData.reputation >= 90
 ? 'text-emerald-600'
 : ipData.reputation >= 70
 ? 'text-amber-600'
 : 'text-surface-400'
 }`}
 >
 {ipData.reputation}%
 </div>
 </div>
 <div
 className={`px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-tight rounded-md ${
 ipData.status === 'active'
 ? 'bg-emerald-50 text-emerald-700 border border-emerald-100'
 : ipData.status === 'warming'
 ? 'bg-amber-50 text-amber-700 border border-amber-100'
 : 'bg-surface-100 text-surface-500 border border-surface-200'
 }`}
 >
 {ipData.status}
 </div>
 </div>
 </div>
 ))}
 </div>

 {/* Features */}
 <div className="mt-8 pt-8 border-t border-surface-200">
 <div className="text-[10px] font-bold text-surface-400 uppercase tracking-widest mb-4">Included Protection</div>
 <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
 {[
 'Automatic failover',
 'Load balancing',
 'Warmup automation',
 'Reputation monitoring',
 'Blacklist alerts',
 'SPF/DKIM/DMARC setup',
 ].map((feature) => (
 <div key={feature} className="flex items-center gap-2 text-xs font-bold text-surface-700">
 <CheckCircle className="w-4 h-4 text-emerald-600 flex-shrink-0" strokeWidth={3} />
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
