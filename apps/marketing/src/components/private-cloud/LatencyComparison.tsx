'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { useState, useEffect } from 'react';
import { Gauge, Zap, Globe } from '@/components/ui/icons';
import { cn } from '@/lib/utils';

interface LatencyData {
  provider: string;
  scenario: string;
  latency: number;
  color: string;
}

const latencyComparisons: LatencyData[] = [
  { provider: 'ApexMail Private', scenario: 'Same VPC', latency: 0.3, color: 'bg-primary-600' },
  { provider: 'ApexMail Private', scenario: 'Same Region', latency: 2.1, color: 'bg-primary-600' },
  { provider: 'SendGrid', scenario: 'External API', latency: 45, color: 'bg-surface-200' },
  { provider: 'AWS SES', scenario: 'Same Region', latency: 12, color: 'bg-surface-300' },
  { provider: 'Mailchimp', scenario: 'External API', latency: 120, color: 'bg-surface-200' },
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
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-100/50 text-surface-900 border border-surface-200 text-xs font-medium mb-4"
          >
            <Gauge className="w-4 h-4 text-surface-500" />
            Performance Benchmarks
          </motion.div>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.1 }}
            className="text-3xl lg:text-4xl font-semibold text-surface-900 mb-4 tracking-tight"
          >
            Reduced Network Latency
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.2 }}
            className="text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed font-medium"
          >
            When your application and email infrastructure share the same network, 
            API communication is nearly instantaneous.
          </motion.p>
        </div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.3 }}
          className="bg-white border border-surface-200 shadow-sm rounded-lg p-8"
        >
          {/* Latency Chart */}
          <div className="space-y-8">
            {latencyComparisons.map((data, index) => (
              <div key={`${data.provider}-${data.scenario}`} className="space-y-2">
                <div className="flex justify-between items-center text-sm">
                  <div className="flex items-center gap-3">
                    <span className="text-surface-900 font-semibold">{data.provider}</span>
                    <span className="text-xs text-surface-500 font-medium">{data.scenario}</span>
                  </div>
                  <span className="text-surface-900 font-mono font-medium">
                    {animatedValues[index].toFixed(1)}ms
                  </span>
                </div>
                <div className="h-3 bg-surface-100 rounded-full overflow-hidden">
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
              <div className="w-3 h-3 rounded-full bg-primary-600" />
              <span className="text-xs font-medium text-surface-600">Private Cloud</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-surface-300" />
              <span className="text-xs font-medium text-surface-600">Same Region</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-surface-200" />
              <span className="text-xs font-medium text-surface-600">External API</span>
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
              description: 'Compared to standard external API calls',
            },
            {
              icon: Globe,
              title: 'Zero Egress',
              description: 'Traffic stays within your VPC network',
            },
            {
              icon: Gauge,
              title: 'P99 < 5ms',
              description: 'Consistent performance for critical paths',
            },
          ].map((item) => (
            <div key={item.title} className="bg-white border border-surface-200 shadow-sm rounded-lg p-8 text-center">
              <div className="w-10 h-10 rounded-full bg-surface-100/50 flex items-center justify-center mx-auto mb-4 border border-surface-200">
                <item.icon className="w-5 h-5 text-surface-900" />
              </div>
              <div className="text-lg font-semibold text-surface-900 mb-2">{item.title}</div>
              <div className="text-sm text-surface-600 font-medium leading-relaxed">{item.description}</div>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
