import { h } from 'preact';

// Inline SVG icons for Preact (no external icon library dependency)
const HistoryIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
    <path d="M3 3v5h5" /><path d="M12 7v5l4 2" />
  </svg>
);
const LayersIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="m12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.84Z" />
    <path d="m22.54 12.43-1.97-.9L12 15.5 3.43 11.53l-1.97.9a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 .26-1.84Z" />
  </svg>
);
const GitBranchIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <line x1="6" x2="6" y1="3" y2="15" /><circle cx="18" cy="6" r="3" /><circle cx="6" cy="18" r="3" />
    <path d="M18 9a9 9 0 0 1-9 9" />
  </svg>
);
const EyeIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0" />
    <circle cx="12" cy="12" r="3" />
  </svg>
);

const historyFeatures = [
  {
    icon: LayersIcon,
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
    icon: GitBranchIcon,
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
    icon: EyeIcon,
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

export default function RenderHistory() {
  return (
    <section class="py-20 lg:py-32 relative bg-white">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-100/50 text-surface-900 border border-surface-200 text-xs font-medium mb-4">
            <HistoryIcon class="w-4 h-4 text-surface-500" />
            Render History
          </div>
          <h2 class="text-3xl lg:text-4xl font-semibold text-surface-900 mb-4 tracking-tight">
            90 Days of Perfect Memory
          </h2>
          <p class="text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed font-medium">
            Every email render is captured and stored. Query, compare, and analyze
            across your entire sending history.
          </p>
        </div>

        <div class="space-y-8">
          {historyFeatures.map((feature, index) => (
            <div key={feature.title} class="bg-white border border-surface-200 shadow-sm rounded-lg p-10">
              <div class="grid lg:grid-cols-2 gap-12 items-start">
                {/* Info */}
                <div class={index % 2 === 1 ? 'lg:order-2' : ''}>
                  <div class="w-12 h-12 rounded-lg bg-surface-100/50 flex items-center justify-center mb-6 border border-surface-200">
                    <feature.icon class="w-6 h-6 text-surface-900" />
                  </div>
                  <h3 class="text-2xl font-semibold text-surface-900 mb-4">{feature.title}</h3>
                  <p class="text-surface-600 font-medium leading-relaxed">{feature.description}</p>
                </div>

                {/* Code */}
                <div class={index % 2 === 1 ? 'lg:order-1' : ''}>
                  <div class="bg-surface-900 rounded-lg p-6 shadow-inner overflow-x-auto border border-surface-800">
                    <pre class="text-xs text-surface-300 font-mono whitespace-pre leading-relaxed">
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
