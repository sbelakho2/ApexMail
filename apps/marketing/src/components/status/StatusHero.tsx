'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { CheckCircle2, AlertTriangle, XCircle, Activity } from 'lucide-react';

type SystemStatus = 'operational' | 'degraded' | 'outage' | 'maintenance';

const overallStatus: SystemStatus = 'operational';

const statusConfig = {
  operational: {
    icon: CheckCircle2,
    color: 'text-green-500',
    bg: 'bg-green-500/10',
    border: 'border-green-500/20',
    label: 'All Systems Operational',
    description: 'All services are running smoothly.',
  },
  degraded: {
    icon: AlertTriangle,
    color: 'text-yellow-500',
    bg: 'bg-yellow-500/10',
    border: 'border-yellow-500/20',
    label: 'Degraded Performance',
    description: 'Some services are experiencing issues.',
  },
  outage: {
    icon: XCircle,
    color: 'text-red-500',
    bg: 'bg-red-500/10',
    border: 'border-red-500/20',
    label: 'Service Outage',
    description: 'Major service disruption in progress.',
  },
  maintenance: {
    icon: Activity,
    color: 'text-blue-500',
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/20',
    label: 'Scheduled Maintenance',
    description: 'Planned maintenance in progress.',
  },
};

export function StatusHero() {
  const config = statusConfig[overallStatus];
  const Icon = config.icon;
  const [lastUpdated, setLastUpdated] = useState<string>('');

  useEffect(() => {
    setLastUpdated(new Date().toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }));
  }, []);

  return (
    <section className="py-16 md:py-24 bg-white border-b border-surface-100">
      <div className="container mx-auto px-4">
        <motion.div
          className="max-w-2xl mx-auto text-center"
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
        >
          {/* Status Indicator - Minimal & Clear */}
          <motion.div
            className={`inline-flex items-center gap-2.5 px-4 py-2 rounded-full ${config.bg} mb-8`}
            initial={{ scale: 0.95 }}
            animate={{ scale: 1 }}
            transition={{ delay: 0.2, type: 'spring', text: 0.5 }}
          >
            <Icon className={`w-5 h-5 ${config.color}`} strokeWidth={2.5} />
            <span className={`text-sm font-semibold ${config.color}`}>
              {config.label}
            </span>
          </motion.div>

          <h1 className="text-3xl md:text-4xl font-bold text-surface-900 mb-3 tracking-tight">
            ApexMail System Status
          </h1>

          <p className="text-lg text-surface-500 mb-8 leading-relaxed">
            {config.description}
          </p>

          <div className="flex items-center justify-center gap-6 text-sm">
             <div className="text-surface-400">
                Last updated: <span className="font-medium text-surface-600">
                  {lastUpdated}
                </span>
             </div>

            {/* Live indicator - Subtle */}
            <div className="flex items-center gap-2 text-surface-500">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-500"></span>
              </span>
              Auto-updating
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
