'use client';

import { History, Layers, GitBranch, Eye } from '@/components/ui/icons';

export function RenderHistory() {
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
      "base_value": "#3b82f6",
      "compare_value": "#2563eb"
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
    <section className="py-20 lg:py-32 relative bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <div className="animate-in inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-100/50 text-surface-900 border border-surface-200 text-xs font-medium mb-4">
            <History className="w-4 h-4 text-surface-500" />
            Render History
          </div>
          <h2 className="animate-in delay-100 text-3xl lg:text-4xl font-semibold text-surface-900 mb-4 tracking-tight">
            90 Days of Perfect Memory
          </motion.h2>
          <p className="animate-in delay-200 text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed font-medium">
            Every email render is captured and stored. Query, compare, and analyze 
            across your entire sending history.
          </p>
        </div>

        <div className="space-y-8">
          {historyFeatures.map((feature, index) => (
            <div key={feature.title} className="animate-in delay-100 bg-white border border-surface-200 shadow-sm rounded-lg p-10">
              <div className="grid lg:grid-cols-2 gap-12 items-start">
                {/* Info */}
                <div className={index % 2 === 1 ? 'lg:order-2' : ''}>
                  <div className="w-12 h-12 rounded-lg bg-surface-100/50 flex items-center justify-center mb-6 border border-surface-200">
                    <feature.icon className="w-6 h-6 text-surface-900" />
                  </div>
                  <h3 className="text-2xl font-semibold text-surface-900 mb-4">{feature.title}</h3>
                  <p className="text-surface-600 font-medium leading-relaxed">{feature.description}</p>
                </div>

                {/* Code */}
                <div className={index % 2 === 1 ? 'lg:order-1' : ''}>
                  <div className="bg-surface-900 rounded-lg p-6 shadow-inner overflow-x-auto border border-surface-800">
                    <pre className="text-xs text-surface-300 font-mono whitespace-pre leading-relaxed">
                      {feature.code}
                    </pre>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
