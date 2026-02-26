'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { useState, useEffect } from 'react';
import { Play, Pause, SkipBack, SkipForward, Clock } from '@/components/ui/icons';
import { cn } from '@/lib/utils';

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

export function TimeTravelDemo() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isPlaying) {
      interval = setInterval(() => {
        setCurrentIndex((prev) => (prev + 1) % renderSnapshots.length);
      }, 2000);
    }
    return () => clearInterval(interval);
  }, [isPlaying]);

  const currentSnapshot = renderSnapshots[currentIndex];

  return (
    <section ref={ref} className="py-20 lg:py-32 relative bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-100/50 text-surface-900 border border-surface-200 text-xs font-medium mb-4"
          >
            <Clock className="w-4 h-4 text-surface-500" />
            Time Travel Demo
          </motion.div>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.1 }}
            className="text-3xl lg:text-4xl font-semibold text-surface-900 mb-4 tracking-tight"
          >
            Watch Your Email Through Time
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.2 }}
            className="text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed font-medium"
          >
            Scrub through every render event. See how your email looked in each client, 
            at each point in time.
          </motion.p>
        </div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.3 }}
          className="bg-white border border-surface-200 shadow-sm rounded-lg overflow-hidden"
        >
          {/* Preview Area */}
          <div className="grid lg:grid-cols-3 gap-0">
            {/* Email Preview */}
            <div className="lg:col-span-2 p-8 bg-surface-50/50">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-2 px-3 py-1 bg-white border border-surface-200 rounded-full shadow-sm">
                  <span className="text-xs font-medium text-surface-900">{currentSnapshot.client}</span>
                  <span className="text-xs font-medium text-surface-500 font-mono">({currentSnapshot.viewport})</span>
                </div>
                <div className="text-xs font-medium text-surface-500 font-mono">{currentSnapshot.id}</div>
              </div>
              <motion.div
                key={currentSnapshot.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="bg-white border border-surface-200 rounded-lg p-8 min-h-[400px] shadow-sm"
              >
                {/* Mock Email Preview */}
                <div className="max-w-md mx-auto">
                  <div className="text-center mb-8">
                    <div className="w-16 h-16 bg-primary-600 rounded-lg mx-auto mb-4 flex items-center justify-center shadow-md">
                      <span className="text-white text-2xl font-bold">A</span>
                    </div>
                    <h3 className="text-2xl font-semibold text-surface-900 tracking-tight">Welcome to ApexMail!</h3>
                  </div>
                  <p className="text-surface-600 font-medium mb-6 leading-relaxed">
                    Hi John, your account is now active. Here's what you can do next:
                  </p>
                  <ul className="space-y-3 mb-8">
                    {['Send your first email', 'Set up your domain', 'Explore the API'].map((item) => (
                       <li key={item} className="flex items-center gap-3">
                        <div className="w-2 h-2 bg-primary-500 rounded-full" />
                        <span className="text-surface-700 font-medium text-sm">{item}</span>
                      </li>
                    ))}
                  </ul>
                  <button className="w-full btn-primary py-3 rounded-md font-medium text-sm transition-colors">
                    Get Started
                  </button>
                </div>
              </motion.div>
            </div>

            {/* Changes Panel */}
            <div className="p-8 lg:border-l border-surface-200 bg-white">
              <div className="text-xs font-medium text-surface-500 mb-6">Render Changes</div>
              <div className="space-y-4">
                {currentSnapshot.changes.map((change, i) => (
                  <motion.div
                    key={change}
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.1 }}
                    className="flex items-center gap-3"
                  >
                    <div className="w-5 h-5 rounded-full bg-primary-50 flex items-center justify-center border border-primary-100 shrink-0">
                      <div className="w-1.5 h-1.5 rounded-full bg-primary-600" />
                    </div>
                    <span className="text-sm text-surface-700 font-medium">{change}</span>
                  </motion.div>
                ))}
              </div>

              <div className="mt-8 pt-8 border-t border-surface-100">
                <div className="text-xs font-medium text-surface-500 mb-2">Timestamp</div>
                <div className="text-surface-900 font-mono font-medium text-xs bg-surface-50 p-2 rounded-md border border-surface-200">
                  {new Date(currentSnapshot.timestamp).toLocaleString()}
                </div>
              </div>
            </div>
          </div>

          {/* Timeline Controls */}
          <div className="p-6 border-t border-surface-200 bg-white">
            <div className="flex items-center gap-8">
              {/* Playback Controls */}
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setCurrentIndex((prev) => Math.max(0, prev - 1))}
                  aria-label="Previous snapshot"
                  className="p-2 text-surface-400 hover:text-primary-600 transition-colors bg-surface-50 rounded-lg hover:bg-surface-100 border border-transparent hover:border-surface-200"
                >
                  <SkipBack className="w-5 h-5" />
                </button>
                <button
                  onClick={() => setIsPlaying(!isPlaying)}
                  aria-label={isPlaying ? 'Pause playback' : 'Start playback'}
                  className="p-3 bg-primary-600 text-white rounded-md border border-primary-600 hover:bg-primary-700 transition-colors"
                >
                  {isPlaying ? <Pause className="w-5 h-5" /> : <Play className="w-5 h-5" />}
                </button>
                <button
                  onClick={() => setCurrentIndex((prev) => Math.min(renderSnapshots.length - 1, prev + 1))}
                  aria-label="Next snapshot"
                  className="p-2 text-surface-400 hover:text-primary-600 transition-colors bg-surface-50 rounded-lg hover:bg-surface-100 border border-transparent hover:border-surface-200"
                >
                  <SkipForward className="w-5 h-5" />
                </button>
              </div>

              {/* Timeline Scrubber */}
              <div className="flex-1 relative">
                <div className="h-2 bg-surface-100 rounded-full overflow-hidden">
                  <motion.div
                    className="h-full bg-primary-500 rounded-full"
                    animate={{ width: `${((currentIndex + 1) / renderSnapshots.length) * 100}%` }}
                  />
                </div>
                <div className="flex justify-between mt-4">
                  {renderSnapshots.map((snapshot, index) => (
                    <button
                      key={snapshot.id}
                      onClick={() => setCurrentIndex(index)}
                      aria-label={`Jump to snapshot for ${snapshot.client}`}
                      className={cn(
                        'text-xs font-medium transition-colors p-1 rounded-md hover:bg-surface-50',
                        index === currentIndex ? 'text-primary-700 font-semibold' : 'text-surface-400 hover:text-surface-900'
                      )}
                    >
                      {snapshot.client}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
