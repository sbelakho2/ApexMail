import { h } from 'preact';
import { useState, useEffect } from 'preact/hooks';

// Inline SVG icons
const PlayIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <polygon points="5 3 19 12 5 21 5 3" />
  </svg>
);
const PauseIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <rect width="4" height="16" x="6" y="4" /><rect width="4" height="16" x="14" y="4" />
  </svg>
);
const SkipBackIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <polygon points="19 20 9 12 19 4 19 20" /><line x1="5" x2="5" y1="19" y2="5" />
  </svg>
);
const SkipForwardIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <polygon points="5 4 15 12 5 20 5 4" /><line x1="19" x2="19" y1="5" y2="19" />
  </svg>
);
const ClockIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" />
  </svg>
);

interface RenderSnapshot {
  id: string;
  timestamp: string;
  client: string;
  viewport: string;
  changes: string[];
}

const renderSnapshots: RenderSnapshot[] = [
  {
    id: 'snap_001',
    timestamp: '2024-02-15T14:32:18Z',
    client: 'Gmail Web',
    viewport: '1440x900',
    changes: ['Initial render', 'Images loaded', 'Fonts applied'],
  },
  {
    id: 'snap_002',
    timestamp: '2024-02-15T14:32:45Z',
    client: 'Outlook 365',
    viewport: '1920x1080',
    changes: ['MSO conditionals applied', 'Table layout fallback', 'Custom fonts replaced'],
  },
  {
    id: 'snap_003',
    timestamp: '2024-02-15T14:33:02Z',
    client: 'Apple Mail',
    viewport: '1280x800',
    changes: ['Dark mode detected', 'Colors inverted', 'Background adjusted'],
  },
  {
    id: 'snap_004',
    timestamp: '2024-02-15T15:01:23Z',
    client: 'Gmail Android',
    viewport: '412x915',
    changes: ['Mobile layout triggered', 'Responsive images', 'Font size adjusted'],
  },
];

export default function TimeTravel() {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);

  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    if (isPlaying) {
      interval = setInterval(() => {
        setCurrentIndex((prev) => (prev + 1) % renderSnapshots.length);
      }, 2000);
    }
    return () => clearInterval(interval);
  }, [isPlaying]);

  const current = renderSnapshots[currentIndex];

  return (
    <section class="py-20 lg:py-32 relative bg-white">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-100/50 text-surface-900 border border-surface-200 text-xs font-medium mb-4">
            <ClockIcon class="w-4 h-4 text-surface-500" />
            Time Travel Demo
          </div>
          <h2 class="text-3xl lg:text-4xl font-semibold text-surface-900 mb-4 tracking-tight">
            Watch Your Email Through Time
          </h2>
          <p class="text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed font-medium">
            Scrub through every render event. See how your email looked in each client, at each point in time.
          </p>
        </div>

        <div class="bg-white border border-surface-200 shadow-sm rounded-lg overflow-hidden">
          {/* Preview Area */}
          <div class="grid lg:grid-cols-3 gap-0">
            {/* Email Preview */}
            <div class="lg:col-span-2 p-8 bg-surface-50/50">
              <div class="flex items-center justify-between mb-6">
                <div class="flex items-center gap-2 px-3 py-1 bg-white border border-surface-200 rounded-full shadow-sm">
                  <span class="text-xs font-medium text-surface-900">{current.client}</span>
                  <span class="text-xs font-medium text-surface-500 font-mono">({current.viewport})</span>
                </div>
                <div class="text-xs font-medium text-surface-500 font-mono">{current.id}</div>
              </div>
              <div key={current.id} class="bg-white border border-surface-200 rounded-lg p-8 min-h-[400px] shadow-sm">
                {/* Mock Email Preview */}
                <div class="max-w-md mx-auto">
                  <div class="text-center mb-8">
                    <div class="w-16 h-16 bg-primary-600 rounded-lg mx-auto mb-4 flex items-center justify-center shadow-md">
                      <span class="text-white text-2xl font-bold">A</span>
                    </div>
                    <h3 class="text-2xl font-semibold text-surface-900 tracking-tight">Welcome to ApexMail!</h3>
                  </div>
                  <p class="text-surface-600 font-medium mb-6 leading-relaxed">
                    Hi John, your account is now active. Here's what you can do next:
                  </p>
                  <ul class="space-y-3 mb-8">
                    {['Send your first email', 'Set up your domain', 'Explore the API'].map((item) => (
                      <li key={item} class="flex items-center gap-3">
                        <div class="w-2 h-2 bg-primary-500 rounded-full" />
                        <span class="text-surface-700 font-medium text-sm">{item}</span>
                      </li>
                    ))}
                  </ul>
                  <button class="w-full btn-primary py-3 rounded-md font-medium text-sm transition-colors">
                    Get Started
                  </button>
                </div>
              </div>
            </div>

            {/* Changes Panel */}
            <div class="p-8 lg:border-l border-surface-200 bg-white">
              <div class="text-xs font-medium text-surface-500 mb-6">Render Changes</div>
              <div class="space-y-4">
                {current.changes.map((change) => (
                  <div key={change} class="flex items-center gap-3">
                    <div class="w-5 h-5 rounded-full bg-primary-50 flex items-center justify-center border border-primary-100 shrink-0">
                      <div class="w-1.5 h-1.5 rounded-full bg-primary-600" />
                    </div>
                    <span class="text-sm text-surface-700 font-medium">{change}</span>
                  </div>
                ))}
              </div>
              <div class="mt-8 pt-8 border-t border-surface-100">
                <div class="text-xs font-medium text-surface-500 mb-2">Timestamp</div>
                <div class="text-surface-900 font-mono font-medium text-xs bg-surface-50 p-2 rounded-md border border-surface-200">
                  {new Date(current.timestamp).toLocaleString()}
                </div>
              </div>
            </div>
          </div>

          {/* Timeline Controls */}
          <div class="p-6 border-t border-surface-200 bg-white">
            <div class="flex items-center gap-8">
              {/* Playback Controls */}
              <div class="flex items-center gap-2">
                <button
                  onClick={() => setCurrentIndex((prev) => Math.max(0, prev - 1))}
                  aria-label="Previous snapshot"
                  class="p-2 text-surface-400 hover:text-primary-600 transition-colors bg-surface-50 rounded-lg hover:bg-surface-100 border border-transparent hover:border-surface-200"
                >
                  <SkipBackIcon class="w-5 h-5" />
                </button>
                <button
                  onClick={() => setIsPlaying(!isPlaying)}
                  aria-label={isPlaying ? 'Pause playback' : 'Start playback'}
                  class="p-3 bg-primary-600 text-white rounded-md border border-primary-600 hover:bg-primary-700 transition-colors"
                >
                  {isPlaying ? <PauseIcon class="w-5 h-5" /> : <PlayIcon class="w-5 h-5" />}
                </button>
                <button
                  onClick={() => setCurrentIndex((prev) => Math.min(renderSnapshots.length - 1, prev + 1))}
                  aria-label="Next snapshot"
                  class="p-2 text-surface-400 hover:text-primary-600 transition-colors bg-surface-50 rounded-lg hover:bg-surface-100 border border-transparent hover:border-surface-200"
                >
                  <SkipForwardIcon class="w-5 h-5" />
                </button>
              </div>

              {/* Timeline Scrubber */}
              <div class="flex-1 relative">
                <div class="h-2 bg-surface-100 rounded-full overflow-hidden">
                  <div
                    class="h-full bg-primary-500 rounded-full transition-all duration-300"
                    style={{ width: `${((currentIndex + 1) / renderSnapshots.length) * 100}%` }}
                  />
                </div>
                <div class="flex justify-between mt-4">
                  {renderSnapshots.map((snapshot, index) => (
                    <button
                      key={snapshot.id}
                      onClick={() => setCurrentIndex(index)}
                      aria-label={`Jump to snapshot for ${snapshot.client}`}
                      class={`text-xs font-medium transition-colors p-1 rounded-md hover:bg-surface-50 ${
                        index === currentIndex ? 'text-primary-700 font-semibold' : 'text-surface-400 hover:text-surface-900'
                      }`}
                    >
                      {snapshot.client}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
