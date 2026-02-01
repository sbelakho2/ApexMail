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
    <section ref={ref} className="py-20 lg:py-32 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/10 text-purple-400 text-sm mb-4"
          >
            <History className="w-4 h-4" />
            Render History
          </motion.div>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.1 }}
            className="text-3xl lg:text-4xl font-bold text-white mb-4"
          >
            90 Days of Perfect Memory
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.2 }}
            className="text-lg text-surface-400 max-w-2xl mx-auto"
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
              className="glass-card p-8"
            >
              <div className="grid lg:grid-cols-2 gap-8 items-start">
                {/* Info */}
                <div className={index % 2 === 1 ? 'lg:order-2' : ''}>
                  <div className="w-12 h-12 rounded-xl bg-purple-500/10 flex items-center justify-center mb-4">
                    <feature.icon className="w-6 h-6 text-purple-400" />
                  </div>
                  <h3 className="text-xl font-semibold text-white mb-2">{feature.title}</h3>
                  <p className="text-surface-400">{feature.description}</p>
                </div>

                {/* Code */}
                <div className={index % 2 === 1 ? 'lg:order-1' : ''}>
                  <div className="bg-surface-900 rounded-lg p-4 overflow-x-auto">
                    <pre className="text-sm text-surface-300 font-mono whitespace-pre">
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
