'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { History, Layers, GitBranch, Eye } from 'lucide-react';

export function RenderHistory() {
 const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

 const historyFeatures = [
 {
 icon: Layers,
 title: 'Version Snapshots',
 description:
 'Every render creates an immutable snapshot. Compare any two versions side-by-side to see exactly what changed.',
 code: `GET /v1/messages/{id}/renders
{
 "renders": [
 {
 "snapshot_id": "snap_7f3d8a2b",
 "client": "gmail_web",
 "timestamp": "2024-02-15T14:32:18Z",
 "viewport": { "width": 1440, "height": 900 },
 "dark_mode": false,
 "html_hash": "sha256:a1b2c3..."
 }
 ]
}`,
 },
 {
 icon: GitBranch,
 title: 'Diff Comparison',
 description:
 'See exactly what changed between renders. Highlights CSS differences, layout shifts, and content variations.',
 code: `GET /v1/messages/{id}/renders/diff
?base=snap_001&compare=snap_002

{
 "changes": [
 {
 "type": "css_override",
 "selector": ".cta-button",
 "property": "background-color",
 "base_value": "#6366f1",
 "compare_value": "#4f46e5"
 }
 ]
}`,
 },
 {
 icon: Eye,
 title: 'Visual Regression',
 description:
 'Automatic screenshot comparison detects visual differences that CSS diffs might miss.',
 code: `POST /v1/messages/{id}/renders/visual-diff
{
 "base_snapshot": "snap_001",
 "compare_snapshot": "snap_002",
 "threshold": 0.01
}

{
 "diff_percentage": 2.3,
 "diff_image_url": "https://...",
 "regions": [
 { "x": 100, "y": 200, "w": 50, "h": 30 }
 ]
}`,
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
            <History className="w-4 h-4" />
            Render History
          </motion.div>
 <motion.h2
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.1 }}
 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-4 tracking-tight"
 >
 90 Days of Perfect Memory
 </motion.h2>
 <motion.p
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.2 }}
 className="text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed font-medium"
 >
 Every email render is captured and stored. Query, compare, and analyze 
 across your entire sending history.
 </motion.p>
 </div>

 <div className="space-y-8">
 {historyFeatures.map((feature, index) => (
 <motion.div
 key={feature.title}
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.1 * index }}
 className="premium-card p-10 bg-surface-50"
 >
 <div className="grid lg:grid-cols-2 gap-12 items-start">
 {/* Info */}
 <div className={index % 2 === 1 ? 'lg:order-2' : ''}>
 <div className="w-14 h-14 rounded-md bg-primary-50 flex items-center justify-center mb-6 border border-primary-100">
 <feature.icon className="w-7 h-7 text-primary-600" />
 </div>
 <h3 className="text-2xl font-bold text-surface-900 mb-4">{feature.title}</h3>
 <p className="text-surface-600 font-medium leading-relaxed">{feature.description}</p>
 </div>

 {/* Code */}
 <div className={index % 2 === 1 ? 'lg:order-1' : ''}>
 <div className="bg-surface-900 rounded-lg p-6 shadow-inner overflow-x-auto">
 <pre className="text-[13px] text-surface-300 font-mono whitespace-pre leading-relaxed">
 {feature.code}
 </pre>
 </div>
 </div>
 </div>
 </motion.div>
 ))}
 </div>
 </div>
 </section>
 );
}
