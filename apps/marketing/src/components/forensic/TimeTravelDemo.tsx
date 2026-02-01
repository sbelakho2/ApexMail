'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { useState, useEffect } from 'react';
import { Play, Pause, SkipBack, SkipForward, Clock } from 'lucide-react';

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
    <section ref={ref} className="py-20 lg:py-32 relative bg-surface-900/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-orange-500/10 text-orange-400 text-sm mb-4"
          >
            <Clock className="w-4 h-4" />
            Time Travel Demo
          </motion.div>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.1 }}
            className="text-3xl lg:text-4xl font-bold text-white mb-4"
          >
            Watch Your Email Through Time
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.2 }}
            className="text-lg text-surface-400 max-w-2xl mx-auto"
          >
            Scrub through every render event. See how your email looked in each client, 
            at each point in time.
          </motion.p>
        </div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.3 }}
          className="glass-card overflow-hidden"
        >
          {/* Preview Area */}
          <div className="grid lg:grid-cols-3 gap-0">
            {/* Email Preview */}
            <div className="lg:col-span-2 p-6 bg-white">
              <div className="text-center text-gray-500 text-sm mb-2">
                {currentSnapshot.client} • {currentSnapshot.viewport}
              </div>
              <motion.div
                key={currentSnapshot.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="bg-gray-50 rounded-lg p-6 min-h-[400px]"
              >
                {/* Mock Email Preview */}
                <div className="max-w-md mx-auto">
                  <div className="text-center mb-6">
                    <div className="w-16 h-16 bg-primary-600 rounded-xl mx-auto mb-4 flex items-center justify-center">
                      <span className="text-white text-2xl font-bold">A</span>
                    </div>
                    <h3 className="text-xl font-bold text-gray-900">Welcome to ApexMail!</h3>
                  </div>
                  <p className="text-gray-600 mb-4">
                    Hi John, your account is now active. Here's what you can do next:
                  </p>
                  <ul className="space-y-2 mb-6">
                    <li className="flex items-center gap-2">
                      <span className="w-2 h-2 bg-green-500 rounded-full" />
                      <span className="text-gray-700">Send your first email</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <span className="w-2 h-2 bg-green-500 rounded-full" />
                      <span className="text-gray-700">Set up your domain</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <span className="w-2 h-2 bg-green-500 rounded-full" />
                      <span className="text-gray-700">Explore the API</span>
                    </li>
                  </ul>
                  <button className="w-full py-3 bg-primary-600 text-white rounded-lg font-medium">
                    Get Started
                  </button>
                </div>
              </motion.div>
            </div>

            {/* Changes Panel */}
            <div className="p-6 border-l border-surface-700">
              <div className="text-white font-medium mb-4">Render Changes</div>
              <div className="space-y-3">
                {currentSnapshot.changes.map((change, i) => (
                  <motion.div
                    key={change}
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.1 }}
                    className="flex items-center gap-2 text-sm"
                  >
                    <div className="w-2 h-2 rounded-full bg-green-400" />
                    <span className="text-surface-300">{change}</span>
                  </motion.div>
                ))}
              </div>

              <div className="mt-6 pt-6 border-t border-surface-700">
                <div className="text-sm text-surface-500 mb-2">Timestamp</div>
                <div className="text-white font-mono text-sm">
                  {new Date(currentSnapshot.timestamp).toLocaleString()}
                </div>
              </div>

              <div className="mt-4">
                <div className="text-sm text-surface-500 mb-2">Snapshot ID</div>
                <div className="text-surface-400 font-mono text-sm">{currentSnapshot.id}</div>
              </div>
            </div>
          </div>

          {/* Timeline Controls */}
          <div className="p-4 border-t border-surface-700 bg-surface-800/50">
            <div className="flex items-center gap-4">
              {/* Playback Controls */}
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setCurrentIndex((prev) => Math.max(0, prev - 1))}
                  className="p-2 text-surface-400 hover:text-white transition-colors"
                >
                  <SkipBack className="w-5 h-5" />
                </button>
                <button
                  onClick={() => setIsPlaying(!isPlaying)}
                  className="p-2 bg-orange-500 text-white rounded-lg hover:bg-orange-400 transition-colors"
                >
                  {isPlaying ? <Pause className="w-5 h-5" /> : <Play className="w-5 h-5" />}
                </button>
                <button
                  onClick={() => setCurrentIndex((prev) => Math.min(renderSnapshots.length - 1, prev + 1))}
                  className="p-2 text-surface-400 hover:text-white transition-colors"
                >
                  <SkipForward className="w-5 h-5" />
                </button>
              </div>

              {/* Timeline Scrubber */}
              <div className="flex-1 relative">
                <div className="h-2 bg-surface-700 rounded-full">
                  <motion.div
                    className="h-full bg-orange-500 rounded-full"
                    animate={{ width: `${((currentIndex + 1) / renderSnapshots.length) * 100}%` }}
                  />
                </div>
                <div className="flex justify-between mt-2">
                  {renderSnapshots.map((snapshot, index) => (
                    <button
                      key={snapshot.id}
                      onClick={() => setCurrentIndex(index)}
                      className={`text-xs ${
                        index === currentIndex ? 'text-orange-400' : 'text-surface-500 hover:text-white'
                      }`}
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
