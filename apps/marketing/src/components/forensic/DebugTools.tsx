'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Bug, Terminal, Smartphone, Mail, AlertTriangle } from 'lucide-react';

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
 <section ref={ref} className="py-20 lg:py-32 relative bg-white">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 <div className="text-center mb-16">
 <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-primary-50 text-primary-700 border border-primary-100 text-[10px] font-bold uppercase tracking-widest mb-4"
          >
            <Bug className="w-4 h-4" />
            Debug Tools
          </motion.div>
 <motion.h2
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.1 }}
 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-4 tracking-tight"
 >
 A Complete Debugging Arsenal
 </motion.h2>
 <motion.p
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.2 }}
 className="text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed font-medium"
 >
 Everything you need to find and fix email rendering issues, 
 integrated into your existing workflow.
 </motion.p>
 </div>

 {/* Tools Grid */}
 <div className="grid md:grid-cols-2 gap-6 mb-16">
 {tools.map((tool, index) => (
 <motion.div
 key={tool.name}
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.1 * index }}
 className="premium-card p-8 bg-surface-50 group hover:border-primary-500/30 transition-all"
 >
 <div className="flex items-start gap-6">
 <div className="w-14 h-14 rounded-md bg-primary-50 flex items-center justify-center flex-shrink-0 border border-primary-100 group-hover:bg-primary-100 transition-colors">
 <tool.icon className="w-7 h-7 text-primary-600" />
 </div>
 <div>
 <h3 className="text-xl font-bold text-surface-900 mb-2">{tool.name}</h3>
 <p className="text-sm text-surface-500 font-medium mb-4 leading-relaxed">{tool.description}</p>
 <div className="flex flex-wrap gap-2">
 {tool.features.map((feature) => (
 <span
 key={feature}
 className="px-2 py-1 bg-white text-surface-600 text-[10px] font-bold uppercase tracking-tight rounded-md border border-surface-200"
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
 className="premium-card overflow-hidden bg-surface-900 "
 >
 <div className="flex items-center gap-2 px-6 py-4 bg-surface-800 border-b border-surface-700">
 <div className="flex gap-1.5">
 <div className="w-3 h-3 rounded-full bg-surface-600" />
 <div className="w-3 h-3 rounded-full bg-surface-600" />
 <div className="w-3 h-3 rounded-full bg-surface-600" />
 </div>
 <span className="ml-4 text-[10px] font-bold text-surface-400 uppercase tracking-widest font-mono">apexmail-cli</span>
 </div>
 <div className="p-8 font-mono text-sm leading-relaxed">
 <div className="text-surface-500 mb-2">$ apexmail inspect msg_7f3d8a2b</div>
 <div className="text-green-400 mb-6 font-bold">✓ Found 4 render snapshots</div>
 
 <div className="space-y-3 text-surface-300">
 <div className="flex items-center gap-4">
 <span className="text-surface-600 w-4">1.</span>
 <span className="w-32 font-bold">Gmail Web</span>
 <span className="text-surface-500 text-xs">1440x900</span>
 <span className="text-green-400 font-bold ml-auto">OK</span>
 </div>
 <div className="flex items-center gap-4">
 <span className="text-surface-600 w-4">2.</span>
 <span className="w-32 font-bold">Outlook 365</span>
 <span className="text-surface-500 text-xs">1920x1080</span>
 <span className="text-yellow-400 font-bold ml-auto">⚠ Font fallback</span>
 </div>
 <div className="flex items-center gap-4">
 <span className="text-surface-600 w-4">3.</span>
 <span className="w-32 font-bold">Apple Mail</span>
 <span className="text-surface-500 text-xs">1280x800</span>
 <span className="text-green-400 font-bold ml-auto">OK</span>
 </div>
 <div className="flex items-center gap-4">
 <span className="text-surface-600 w-4">4.</span>
 <span className="w-32 font-bold">Gmail Android</span>
 <span className="text-surface-500 text-xs">412x915</span>
 <span className="text-green-400 font-bold ml-auto">OK</span>
 </div>
 </div>

 <div className="mt-8 pt-8 border-t border-surface-800">
 <div className="text-surface-500 mb-2">$ apexmail diff snap_001 snap_002</div>
 <div className="text-surface-300 bg-surface-800 p-4 rounded-md border border-surface-700">
 <span className="text-red-400 font-bold">- background-color: #6366f1;</span>
 <br />
 <span className="text-green-400 font-bold">+ background-color: #4f46e5;</span>
 <br />
 <span className="text-surface-500 italic mt-2 block">// Outlook overrides primary color</span>
 </div>
 </div>
 </div>
 </motion.div>
 </div>
 </section>
 );
}
