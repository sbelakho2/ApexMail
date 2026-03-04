import { h } from 'preact';

// Inline SVG icons for Preact
const BugIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="m8 2 1.88 1.88" /><path d="M14.12 3.88 16 2" /><path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1" />
    <path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6" />
    <path d="M12 20v-9" /><path d="M6.53 9C4.6 8.8 3 7.1 3 5" /><path d="M6 13H2" />
    <path d="M3 21c0-2.1 1.7-3.9 3.8-4" /><path d="M20.97 5c0 2.1-1.6 3.8-3.5 4" />
    <path d="M22 13h-4" /><path d="M17.2 17c2.1.1 3.8 1.9 3.8 4" />
  </svg>
);
const TerminalIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <polyline points="4 17 10 11 4 5" /><line x1="12" x2="20" y1="19" y2="19" />
  </svg>
);
const MailIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <rect width="20" height="16" x="2" y="4" rx="2" /><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
  </svg>
);
const SmartphoneIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <rect width="14" height="20" x="5" y="2" rx="2" ry="2" /><path d="M12 18h.01" />
  </svg>
);
const AlertTriangleIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3" />
    <path d="M12 9v4" /><path d="M12 17h.01" />
  </svg>
);

const tools = [
  {
    icon: TerminalIcon,
    name: 'CLI Inspector',
    description: 'Debug emails from your terminal with our powerful CLI tool.',
    features: ['Fetch any render', 'Compare snapshots', 'Export screenshots'],
  },
  {
    icon: MailIcon,
    name: 'Client Emulator',
    description: 'Preview how your email renders across 50+ email clients.',
    features: ['Gmail, Outlook, Apple Mail', 'Mobile & desktop', 'Dark mode variants'],
  },
  {
    icon: SmartphoneIcon,
    name: 'Device Lab',
    description: 'Test on real devices in our cloud-based device lab.',
    features: ['iOS & Android', 'Real Gmail app', 'Screen recordings'],
  },
  {
    icon: AlertTriangleIcon,
    name: 'Issue Detector',
    description: 'Automatic detection of common rendering issues.',
    features: ['Clipped content', 'Broken images', 'Font fallbacks'],
  },
];

export default function DebugTools() {
  return (
    <section class="py-20 lg:py-32 relative bg-white">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-100/50 text-surface-900 border border-surface-200 text-xs font-medium mb-4">
            <BugIcon class="w-4 h-4 text-surface-500" />
            Debug Tools
          </div>
          <h2 class="text-3xl lg:text-4xl font-semibold text-surface-900 mb-4 tracking-tight">
            A Complete Debugging Arsenal
          </h2>
          <p class="text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed font-medium">
            Everything you need to find and fix email rendering issues,
            integrated into your existing workflow.
          </p>
        </div>

        {/* Tools Grid */}
        <div class="grid md:grid-cols-2 gap-6 mb-16">
          {tools.map((tool) => (
            <div key={tool.name} class="bg-white border border-surface-200 shadow-sm rounded-lg p-8 hover:border-surface-300 transition-all">
              <div class="flex items-start gap-6">
                <div class="w-12 h-12 rounded-lg bg-surface-100/50 flex items-center justify-center flex-shrink-0 border border-surface-200">
                  <tool.icon class="w-6 h-6 text-surface-900" />
                </div>
                <div>
                  <h3 class="text-lg font-semibold text-surface-900 mb-2">{tool.name}</h3>
                  <p class="text-sm text-surface-600 font-medium mb-4 leading-relaxed">{tool.description}</p>
                  <div class="flex flex-wrap gap-2">
                    {tool.features.map((feature) => (
                      <span
                        key={feature}
                        class="px-2.5 py-1 bg-surface-50 text-surface-700 text-xs font-medium rounded-md border border-surface-200"
                      >
                        {feature}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* CLI Demo */}
        <div class="bg-surface-900 rounded-lg overflow-hidden shadow-lg border border-surface-800">
          <div class="flex items-center gap-2 px-6 py-4 bg-surface-800/50 border-b border-surface-700/50">
            <div class="flex gap-1.5">
              <div class="w-3 h-3 rounded-full bg-surface-600" />
              <div class="w-3 h-3 rounded-full bg-surface-600" />
              <div class="w-3 h-3 rounded-full bg-surface-600" />
            </div>
            <span class="ml-4 text-xs font-medium text-surface-400 font-mono">apexmail-cli</span>
          </div>
          <div class="p-8 font-mono text-sm leading-relaxed">
            <div class="text-surface-500 mb-2">$ apexmail inspect msg_7f3d8a2b</div>
            <div class="text-emerald-400 mb-6 font-bold">✓ Found 4 render snapshots</div>

            <div class="space-y-3 text-surface-300">
              <div class="flex items-center gap-4">
                <span class="text-surface-600 w-4">1.</span>
                <span class="w-32 font-semibold">Gmail Web</span>
                <span class="text-surface-500 text-xs">1440x900</span>
                <span class="text-emerald-400 font-semibold ml-auto">OK</span>
              </div>
              <div class="flex items-center gap-4">
                <span class="text-surface-600 w-4">2.</span>
                <span class="w-32 font-semibold">Outlook 365</span>
                <span class="text-surface-500 text-xs">1920x1080</span>
                <span class="text-amber-400 font-semibold ml-auto">⚠ Font fallback</span>
              </div>
              <div class="flex items-center gap-4">
                <span class="text-surface-600 w-4">3.</span>
                <span class="w-32 font-semibold">Apple Mail</span>
                <span class="text-surface-500 text-xs">1280x800</span>
                <span class="text-emerald-400 font-semibold ml-auto">OK</span>
              </div>
              <div class="flex items-center gap-4">
                <span class="text-surface-600 w-4">4.</span>
                <span class="w-32 font-semibold">Gmail Android</span>
                <span class="text-surface-500 text-xs">412x915</span>
                <span class="text-emerald-400 font-semibold ml-auto">OK</span>
              </div>
            </div>

            <div class="mt-8 pt-8 border-t border-surface-800">
              <div class="text-surface-500 mb-2">$ apexmail diff snap_001 snap_002</div>
              <div class="text-surface-300 bg-surface-800 p-4 rounded-md border border-surface-700">
                <span class="text-danger-400">- background-color: #3b82f6</span>{'\n'}
                <span class="text-success-400">+ background-color: #2563eb</span>{'\n'}
                <span class="text-surface-500">  /* .cta-button */</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
