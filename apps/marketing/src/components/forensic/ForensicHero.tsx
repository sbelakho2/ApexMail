'use client';

import { motion } from 'framer-motion';
import { Search, Clock, Eye, Bug } from 'lucide-react';
import Link from 'next/link';

export function ForensicHero() {
  return (
    <section className="relative min-h-[80vh] flex items-center pt-32 pb-20 bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
          {/* Left - Copy */}
          <div>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-100/50 text-surface-900 border border-surface-200 text-xs font-medium mb-6"
            >
              <Bug className="w-4 h-4 text-surface-500" />
              Forensic Debugging
            </motion.div>

            <motion.h1
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
              className="text-4xl lg:text-6xl font-semibold text-surface-900 mb-6 leading-tight tracking-tight"
            >
              Time Travel
              <br />
              <span className="text-primary-600">for Email</span>
            </motion.h1>

            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
              className="text-xl text-surface-600 mb-10 leading-relaxed font-medium"
            >
              See exactly what your recipient saw. Every render, every client, every version. 
              Debug rendering issues before they become support tickets.
            </motion.p>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
              className="flex flex-col sm:flex-row gap-4"
            >
              <Link
                href="/signup"
                className="btn-primary text-lg px-8 py-4"
              >
                Try Time Travel
              </Link>
              <Link
                href="/docs/forensic"
                className="btn-secondary text-lg px-8 py-4 bg-white"
              >
                View Documentation
              </Link>
            </motion.div>

            {/* Stats */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
              className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 mt-12 pt-8 border-t border-surface-200"
            >
              {[
                { value: '90 days', label: 'Render History' },
                { value: '50+', label: 'Email Clients' },
                { value: 'Instant', label: 'Playback' },
              ].map((stat) => (
                <div key={stat.label}>
                  <div className="text-2xl lg:text-3xl font-semibold text-surface-900 tabular-nums">{stat.value}</div>
                  <div className="text-xs font-medium text-surface-500">{stat.label}</div>
                </div>
              ))}
            </motion.div>
          </div>

          {/* Right - Visual */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.2 }}
            className="relative"
          >
            <div className="bg-white border border-surface-200 shadow-sm rounded-2xl p-8">
              {/* Timeline Header */}
              <div className="flex items-center justify-between mb-8 pb-4 border-b border-surface-100">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-surface-100/50 flex items-center justify-center border border-surface-200">
                    <Clock className="w-5 h-5 text-surface-900" />
                  </div>
                  <div>
                    <div className="text-surface-900 font-semibold text-sm">Render Timeline</div>
                    <div className="text-xs font-medium text-surface-500 font-mono">msg_7f3d8a2b</div>
                  </div>
                </div>
              </div>

              {/* Timeline */}
              <div className="relative pl-8 space-y-4">
                <div className="absolute left-[11px] top-2 bottom-2 w-0.5 bg-surface-100" />

                {[
                  { time: '14:32:18', client: 'Gmail Web', status: 'rendered', version: 'v1' },
                  { time: '14:32:45', client: 'Outlook 365', status: 'rendered', version: 'v1' },
                  { time: '14:33:02', client: 'Apple Mail', status: 'rendered', version: 'v1' },
                  { time: '15:01:23', client: 'Gmail Android', status: 'rendered', version: 'v1' },
                ].map((event, index) => (
                  <motion.div
                    key={index}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.5 + index * 0.1 }}
                    className="relative"
                  >
                    <div className="absolute -left-[25px] w-3 h-3 rounded-full bg-primary-600 border-2 border-white z-10" />
                    <div className="bg-surface-50 border border-surface-200 rounded-lg p-4 transition-shadow hover:shadow-sm">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-surface-900 font-medium text-sm">{event.client}</span>
                        <span className="text-xs font-medium text-surface-500 font-mono">{event.time}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="flex items-center gap-1">
                          <Eye className="w-4 h-4 text-surface-400" />
                          <span className="text-xs font-medium text-surface-600">
                            {event.status}
                          </span>
                        </div>
                        <div className="text-xs font-medium text-primary-700 bg-primary-50 px-1.5 py-0.5 rounded border border-primary-100">
                          {event.version}
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>

              {/* Search */}
              <div className="mt-8 pt-6 border-t border-surface-100">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-surface-400" />
                  <input
                    type="text"
                    placeholder="Search by message ID..."
                    className="w-full pl-10 pr-4 py-2 bg-surface-50 border border-surface-200 rounded-sm text-sm text-surface-900 font-medium placeholder-surface-400 focus:outline-none focus:ring-2 focus:ring-primary-500/20 focus:border-primary-500 transition-colors"
                  />
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
