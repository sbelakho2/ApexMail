'use client';

import { useState, useEffect } from 'react';
import { useInView } from 'react-intersection-observer';
import { Gauge, Zap, Globe } from '@/components/ui/icons';
import { cn } from '@/lib/utils';

interface LatencyData {
  label: string;
  scenario: string;
  description: string;
  relativeWidth: number; // percentage of bar width for illustration
  color: string;
}

// Illustrative deployment scenarios — not real-time measurements.
// Actual latency depends on your VPC topology, region, and network conditions.
const latencyScenarios: LatencyData[] = [
  { label: 'Private Cloud', scenario: 'Same VPC', description: 'Sub-millisecond — app and API share the same network fabric', relativeWidth: 2, color: 'bg-primary-600' },
  { label: 'Private Cloud', scenario: 'Same Region', description: 'Low single-digit milliseconds — minimal cross-AZ hops', relativeWidth: 8, color: 'bg-primary-500' },
  { label: 'Shared Cloud', scenario: 'Cross-region API', description: 'Tens to hundreds of milliseconds — public internet traversal', relativeWidth: 65, color: 'bg-surface-300' },
  { label: 'Third-party SaaS', scenario: 'External HTTPS API', description: 'Variable — DNS, TLS handshake, and internet routing added', relativeWidth: 100, color: 'bg-surface-200' },
];

export function LatencyComparison() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [animated, setAnimated] = useState(false);
  const prefersReducedMotion = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  useEffect(() => {
    if (inView) {
      const t = setTimeout(() => setAnimated(true), prefersReducedMotion ? 0 : 300);
      return () => clearTimeout(t);
    }
  }, [inView, prefersReducedMotion]);

  return (
    <section ref={ref} className="py-20 lg:py-32 relative bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <div className="animate-in inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-100/50 text-surface-900 border border-surface-200 text-xs font-medium mb-4">
            <Gauge className="w-4 h-4 text-surface-500" />
            Performance Benchmarks
          </div>
          <h2 className="animate-in delay-100 text-3xl lg:text-4xl font-semibold text-surface-900 mb-4 tracking-tight">
            Reduced Network Latency
          </motion.h2>
          <p className="animate-in delay-200 text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed font-medium">
            When your application and email infrastructure share the same network, 
            API communication is nearly instantaneous.
          </p>
          <p className="animate-in delay-300 text-xs text-surface-400 max-w-xl mx-auto mt-3">
            Illustrative deployment scenarios. Actual latency depends on your network topology and region.
          </p>
        </div>

        <div className="animate-in delay-300 bg-white border border-surface-200 shadow-sm rounded-lg p-8">
          {/* Latency illustration — relative bar widths only, not numeric measurements */}
          <div className="space-y-8" aria-label="Relative latency comparison by deployment scenario">
            {latencyScenarios.map((data, index) => (
              <div key={`${data.label}-${data.scenario}`} className="space-y-2">
                <div className="flex justify-between items-start gap-4 text-sm">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-surface-900 font-semibold">{data.label}</span>
                      <span className="text-xs text-surface-500 font-medium px-1.5 py-0.5 bg-surface-100 rounded">{data.scenario}</span>
                    </div>
                    <p className="text-xs text-surface-500 mt-0.5">{data.description}</p>
                  </div>
                </div>
                <div className="h-3 bg-surface-100 rounded-full overflow-hidden">
                  <div : {}} className={cn('h-full rounded-full', data.color)} />
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
        </div>

        {/* Key Points */}
        <div className="animate-in delay-400 grid md:grid-cols-3 gap-6 mt-12">
          {[
            {
              icon: Zap,
              title: 'VPC-Collocated',
              description: 'App and API within the same private network — no public internet hops',
            },
            {
              icon: Globe,
              title: 'Zero Egress',
              description: 'Traffic stays within your VPC, reducing cost and exposure',
            },
            {
              icon: Gauge,
              title: 'Predictable P99',
              description: 'No shared-tenant jitter; latency scales with your own infrastructure',
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
        </div>
      </div>
    </section>
  );
}
