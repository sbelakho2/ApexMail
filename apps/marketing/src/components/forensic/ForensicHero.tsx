'use client';

import { motion } from 'framer-motion';
import { Search, Clock, Eye, Bug } from 'lucide-react';
import Link from 'next/link';

export function ForensicHero() {
  return (
    <section className="relative min-h-[90vh] flex items-center pt-20">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-b from-surface-950 via-surface-900 to-surface-950" />
      <div className="absolute inset-0 opacity-30">
        <div className="absolute top-1/3 left-1/3 w-96 h-96 bg-orange-500/20 rounded-full blur-3xl" />
        <div className="absolute bottom-1/3 right-1/3 w-96 h-96 bg-red-500/20 rounded-full blur-3xl" />
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
          {/* Left - Copy */}
          <div>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-orange-500/10 text-orange-400 text-sm mb-6"
            >
              <Bug className="w-4 h-4" />
              Forensic Debugging
            </motion.div>

            <motion.h1
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
              className="text-4xl lg:text-6xl font-bold text-white mb-6 leading-tight"
            >
              Time Travel
              <br />
              <span className="text-gradient">for Email</span>
            </motion.h1>

            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
              className="text-xl text-surface-400 mb-8"
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
                className="inline-flex items-center justify-center gap-2 px-8 py-4 bg-primary-600 text-white font-semibold rounded-xl hover:bg-primary-500 transition-colors"
              >
                Try Time Travel
              </Link>
              <Link
                href="/docs/forensic"
                className="inline-flex items-center justify-center gap-2 px-8 py-4 border border-surface-600 text-white font-semibold rounded-xl hover:border-surface-500 transition-colors"
              >
                View Documentation
              </Link>
            </motion.div>

            {/* Stats */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
              className="grid grid-cols-3 gap-6 mt-12 pt-8 border-t border-surface-800"
            >
              {[
                { value: '90 days', label: 'Render History' },
                { value: '50+', label: 'Email Clients' },
                { value: 'Instant', label: 'Playback' },
              ].map((stat) => (
                <div key={stat.label}>
                  <div className="text-2xl lg:text-3xl font-bold text-white">{stat.value}</div>
                  <div className="text-sm text-surface-500">{stat.label}</div>
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
            <div className="glass-card p-6">
              {/* Timeline Header */}
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Clock className="w-5 h-5 text-orange-400" />
                  <span className="text-white font-medium">Render Timeline</span>
                </div>
                <div className="flex items-center gap-2 text-sm text-surface-400">
                  <span>msg_7f3d8a2b</span>
                </div>
              </div>

              {/* Timeline */}
              <div className="relative pl-8 space-y-4">
                <div className="absolute left-3 top-2 bottom-2 w-0.5 bg-surface-700" />

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
                    <div className="absolute -left-5 w-3 h-3 rounded-full bg-green-500 border-2 border-surface-900" />
                    <div className="bg-surface-800/50 rounded-lg p-3">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-white text-sm font-medium">{event.client}</span>
                        <span className="text-xs text-surface-500">{event.time}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Eye className="w-3 h-3 text-surface-500" />
                        <span className="text-xs text-surface-400">
                          {event.status} • {event.version}
                        </span>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>

              {/* Search */}
              <div className="mt-4 pt-4 border-t border-surface-700">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-surface-500" />
                  <input
                    type="text"
                    placeholder="Search by message ID, recipient, or date..."
                    className="w-full pl-10 pr-4 py-2 bg-surface-800 border border-surface-600 rounded-lg text-sm text-white placeholder-surface-500 focus:outline-none focus:border-orange-500"
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
