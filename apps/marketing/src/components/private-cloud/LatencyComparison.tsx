'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { useState, useEffect } from 'react';
import { Gauge, Zap, Globe } from 'lucide-react';
import { cn } from '@/lib/utils';

interface LatencyData {
 provider: string;
 scenario: string;
 latency: number;
 color: string;
}

const latencyComparisons: LatencyData[] = [
 { provider: 'ApexMail Private', scenario: 'Same VPC', latency: 0.3, color: 'bg-green-500' },
 { provider: 'ApexMail Private', scenario: 'Same Region', latency: 2.1, color: 'bg-green-500' },
 { provider: 'SendGrid', scenario: 'External API', latency: 45, color: 'bg-red-500' },
 { provider: 'AWS SES', scenario: 'Same Region', latency: 12, color: 'bg-yellow-500' },
 { provider: 'Mailchimp', scenario: 'External API', latency: 120, color: 'bg-red-500' },
];

export function LatencyComparison() {
 const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });
 const [animatedValues, setAnimatedValues] = useState<number[]>(latencyComparisons.map(() => 0));

 useEffect(() => {
 if (inView) {
 const timers = latencyComparisons.map((data, index) => {
 return setTimeout(() => {
 const duration = 1000;
 const startTime = Date.now();
 
 const animate = () => {
 const elapsed = Date.now() - startTime;
 const progress = Math.min(elapsed / duration, 1);
 const eased = 1 - Math.pow(1 - progress, 3);
 
 setAnimatedValues((prev) => {
 const newValues = [...prev];
 newValues[index] = data.latency * eased;
 return newValues;
 });

 if (progress < 1) {
 requestAnimationFrame(animate);
 }
 };

 requestAnimationFrame(animate);
 }, index * 200);
 });

 return () => timers.forEach(clearTimeout);
 }
 }, [inView]);

 const maxLatency = Math.max(...latencyComparisons.map((d) => d.latency));

 return (
 <section ref={ref} className="py-20 lg:py-32 relative bg-white">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 <div className="text-center mb-12">
 <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-yellow-50 text-yellow-700 border border-yellow-100 text-[10px] font-bold uppercase tracking-widest mb-4"
          >
            <Gauge className="w-4 h-4" />
            Latencimeter™
          </motion.div>
 <motion.h2
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.1 }}
 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-4 tracking-tight"
 >
 Speed That Matters
 </motion.h2>
 <motion.p
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.2 }}
 className="text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed font-medium"
 >
 When your application and email infrastructure share the same network, 
 every API call is faster than going to the internet.
 </motion.p>
 </div>

 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.3 }}
 className="premium-card p-8 bg-surface-50"
 >
 {/* Latency Chart */}
 <div className="space-y-8">
 {latencyComparisons.map((data, index) => (
 <div key={`${data.provider}-${data.scenario}`} className="space-y-2">
 <div className="flex justify-between items-center text-sm">
 <div className="flex items-center gap-3">
 <span className="text-surface-900 font-bold">{data.provider}</span>
 <span className="text-[10px] font-bold text-surface-400 uppercase tracking-widest">{data.scenario}</span>
 </div>
 <span className="text-primary-600 font-mono font-bold">
 {animatedValues[index].toFixed(1)}ms
 </span>
 </div>
 <div className="h-4 bg-white border border-surface-100 rounded-full overflow-hidden shadow-inner">
 <motion.div
 initial={{ width: 0 }}
 animate={inView ? { width: `${(data.latency / maxLatency) * 100}%` } : {}}
 transition={{ duration: 1, delay: index * 0.2 }}
 className={cn('h-full rounded-full transition-all', data.color)}
 />
 </div>
 </div>
 ))}
 </div>

 {/* Legend */}
 <div className="flex flex-wrap justify-center gap-8 mt-10 pt-10 border-t border-surface-200">
 <div className="flex items-center gap-2">
 <div className="w-3 h-3 rounded-full bg-green-500" />
 <span className="text-xs font-bold text-surface-500 uppercase tracking-widest">Private Cloud</span>
 </div>
 <div className="flex items-center gap-2">
 <div className="w-3 h-3 rounded-full bg-yellow-500" />
 <span className="text-xs font-bold text-surface-500 uppercase tracking-widest">Same Region</span>
 </div>
 <div className="flex items-center gap-2">
 <div className="w-3 h-3 rounded-full bg-red-500" />
 <span className="text-xs font-bold text-surface-500 uppercase tracking-widest">External API</span>
 </div>
 </div>
 </motion.div>

 {/* Key Points */}
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.4 }}
 className="grid md:grid-cols-3 gap-6 mt-12"
 >
 {[
 {
 icon: Zap,
 title: '40x Faster',
 description: 'Same-VPC calls vs external API calls',
 },
 {
 icon: Globe,
 title: 'Zero Egress',
 description: 'No data leaves your network boundary',
 },
 {
 icon: Gauge,
 title: 'P99 < 5ms',
 description: 'Guaranteed latency for critical paths',
 },
 ].map((item) => (
 <div key={item.title} className="premium-card p-8 text-center bg-white">
 <div className="w-12 h-12 rounded-full bg-yellow-50 flex items-center justify-center mx-auto mb-4 border border-yellow-100">
 <item.icon className="w-6 h-6 text-yellow-600" />
 </div>
 <div className="text-xl font-bold text-surface-900 mb-2">{item.title}</div>
 <div className="text-sm text-surface-500 font-medium leading-relaxed">{item.description}</div>
 </div>
 ))}
 </motion.div>
 </div>
 </section>
 );
}
