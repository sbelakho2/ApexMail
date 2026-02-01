'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Bug, Terminal, Smartphone, Mail, AlertTriangle, CheckCircle } from 'lucide-react';

export function DebugTools() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  const tools = [
    {
      icon: Terminal,
      name: 'CLI Inspector',
      description: 'Debug emails from your terminal with our powerful CLI tool.',
      features: ['Fetch any render', 'Compare snapshots', 'Export screenshots'],
    },
    {
      icon: Mail,
      name: 'Client Emulator',
      description: 'Preview how your email renders across 50+ email clients.',
      features: ['Gmail, Outlook, Apple Mail', 'Mobile & desktop', 'Dark mode variants'],
    },
    {
      icon: Smartphone,
      name: 'Device Lab',
      description: 'Test on real devices in our cloud-based device lab.',
      features: ['iOS & Android', 'Real Gmail app', 'Screen recordings'],
    },
    {
      icon: AlertTriangle,
      name: 'Issue Detector',
      description: 'Automatic detection of common rendering issues.',
      features: ['Clipped content', 'Broken images', 'Font fallbacks'],
    },
  ];

  return (
    <section ref={ref} className="py-20 lg:py-32 relative bg-surface-900/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 text-red-400 text-sm mb-4"
          >
            <Bug className="w-4 h-4" />
            Debug Tools
          </motion.div>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.1 }}
            className="text-3xl lg:text-4xl font-bold text-white mb-4"
          >
            A Complete Debugging Arsenal
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.2 }}
            className="text-lg text-surface-400 max-w-2xl mx-auto"
          >
            Everything you need to find and fix email rendering issues, 
            integrated into your existing workflow.
          </motion.p>
        </div>

        {/* Tools Grid */}
        <div className="grid md:grid-cols-2 gap-6 mb-12">
          {tools.map((tool, index) => (
            <motion.div
              key={tool.name}
              initial={{ opacity: 0, y: 20 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ delay: 0.1 * index }}
              className="glass-card p-6"
            >
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-xl bg-red-500/10 flex items-center justify-center flex-shrink-0">
                  <tool.icon className="w-6 h-6 text-red-400" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-white mb-1">{tool.name}</h3>
                  <p className="text-sm text-surface-400 mb-3">{tool.description}</p>
                  <div className="flex flex-wrap gap-2">
                    {tool.features.map((feature) => (
                      <span
                        key={feature}
                        className="px-2 py-1 bg-surface-800 text-surface-400 text-xs rounded"
                      >
                        {feature}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </motion.div>
          ))}
        </div>

        {/* CLI Demo */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.5 }}
          className="glass-card overflow-hidden"
        >
          <div className="flex items-center gap-2 px-4 py-3 bg-surface-800 border-b border-surface-700">
            <div className="w-3 h-3 rounded-full bg-red-500" />
            <div className="w-3 h-3 rounded-full bg-yellow-500" />
            <div className="w-3 h-3 rounded-full bg-green-500" />
            <span className="ml-2 text-sm text-surface-500">apexmail-cli</span>
          </div>
          <div className="p-6 font-mono text-sm">
            <div className="text-surface-500 mb-2">$ apexmail inspect msg_7f3d8a2b</div>
            <div className="text-green-400 mb-4">✓ Found 4 render snapshots</div>
            
            <div className="space-y-2 text-surface-300">
              <div>
                <span className="text-surface-500">1.</span> Gmail Web{' '}
                <span className="text-surface-500">• 1440x900 •</span>{' '}
                <span className="text-green-400">OK</span>
              </div>
              <div>
                <span className="text-surface-500">2.</span> Outlook 365{' '}
                <span className="text-surface-500">• 1920x1080 •</span>{' '}
                <span className="text-yellow-400">⚠ Font fallback</span>
              </div>
              <div>
                <span className="text-surface-500">3.</span> Apple Mail{' '}
                <span className="text-surface-500">• 1280x800 •</span>{' '}
                <span className="text-green-400">OK</span>
              </div>
              <div>
                <span className="text-surface-500">4.</span> Gmail Android{' '}
                <span className="text-surface-500">• 412x915 •</span>{' '}
                <span className="text-green-400">OK</span>
              </div>
            </div>

            <div className="mt-4 pt-4 border-t border-surface-700">
              <div className="text-surface-500 mb-2">$ apexmail diff snap_001 snap_002</div>
              <div className="text-surface-300">
                <span className="text-red-400">- background-color: #6366f1;</span>
                <br />
                <span className="text-green-400">+ background-color: #4f46e5;</span>
                <br />
                <span className="text-surface-500">// Outlook overrides primary color</span>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
