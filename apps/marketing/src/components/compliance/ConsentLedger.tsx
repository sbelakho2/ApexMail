'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Database, Link as LinkIcon, Shield, Hash } from 'lucide-react';
import { CodeBlock } from '@/components/ui/CodeBlock';

const ledgerCode = `// Every consent event is cryptographically linked
{
  "id": "consent_8f7k2n4m",
  "email": "user@example.com",
  "type": "marketing",
  "action": "granted",
  "timestamp": "2024-02-15T10:30:00Z",
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0...",
  "source": "signup_form",
  "proof": {
    "hash": "sha256:a1b2c3d4...",
    "previous_hash": "sha256:e5f6g7h8...",
    "signature": "ed25519:i9j0k1l2..."
  }
}`;

export function ConsentLedger() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });

  return (
    <section ref={ref} className="py-20 lg:py-32 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
          {/* Left - Visual */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={inView ? { opacity: 1, x: 0 } : {}}
            className="order-2 lg:order-1"
          >
            <div className="glass-card overflow-hidden">
              {/* Header */}
              <div className="flex items-center gap-2 px-4 py-3 border-b border-surface-700/50 bg-surface-800/50">
                <Database className="w-4 h-4 text-blue-400" />
                <span className="text-sm text-surface-400">Consent Ledger Entry</span>
              </div>
              <CodeBlock code={ledgerCode} language="json" />

              {/* Hash Chain Visualization */}
              <div className="p-4 border-t border-surface-700/50 bg-surface-800/30">
                <div className="flex items-center justify-between gap-4">
                  {[1, 2, 3, 4, 5].map((block, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <div className="w-10 h-10 rounded bg-gradient-to-br from-blue-500/20 to-cyan-500/20 border border-blue-500/30 flex items-center justify-center">
                        <Hash className="w-4 h-4 text-blue-400" />
                      </div>
                      {i < 4 && <LinkIcon className="w-3 h-3 text-surface-600" />}
                    </div>
                  ))}
                </div>
                <p className="text-xs text-surface-500 mt-3 text-center">
                  Immutable hash chain - tampering is mathematically detectable
                </p>
              </div>
            </div>
          </motion.div>

          {/* Right - Copy */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={inView ? { opacity: 1, x: 0 } : {}}
            transition={{ delay: 0.2 }}
            className="order-1 lg:order-2"
          >
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 text-blue-400 text-sm mb-4">
              <Database className="w-4 h-4" />
              Consent Ledger
            </div>
            <h2 className="text-3xl lg:text-4xl font-bold text-white mb-4">
              Immutable Consent Records
            </h2>
            <p className="text-lg text-surface-400 mb-6">
              Every consent event is recorded in a cryptographically-linked chain. 
              Each entry references the hash of the previous one, making any tampering 
              mathematically detectable.
            </p>

            <ul className="space-y-4 mb-8">
              {[
                'SHA-256 hashed entries linked to form immutable chain',
                'Ed25519 digital signatures on every consent event',
                'Full audit trail with IP, timestamp, and user agent',
                'Export-ready for GDPR Article 30 compliance',
                'Real-time verification API for auditors',
              ].map((item) => (
                <li key={item} className="flex items-start gap-3 text-surface-300">
                  <Shield className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                  {item}
                </li>
              ))}
            </ul>

            <div className="p-4 rounded-lg bg-surface-800/50 border border-surface-700">
              <p className="text-sm text-surface-400">
                <strong className="text-white">Auditor-Ready:</strong> Our consent ledger 
                has been reviewed and approved by DPOs at Fortune 500 companies for 
                GDPR Article 7 compliance.
              </p>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
