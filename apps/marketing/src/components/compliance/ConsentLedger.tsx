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
 <section ref={ref} className="py-20 lg:py-32 relative bg-surface-50">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
 {/* Left - Visual */}
 <motion.div
 initial={{ opacity: 0, x: -20 }}
 animate={inView ? { opacity: 1, x: 0 } : {}}
 className="order-2 lg:order-1"
 >
 <div className="premium-card overflow-hidden bg-white ">
 {/* Header */}
 <div className="flex items-center gap-2 px-6 py-4 border-b border-surface-200 bg-surface-50">
 <Database className="w-4 h-4 text-primary-600" />
 <span className="text-[10px] font-bold text-surface-600 uppercase tracking-widest font-mono">Consent Ledger Entry</span>
 </div>
 <div className="bg-surface-900 overflow-hidden shadow-inner">
 <CodeBlock code={ledgerCode} language="json" />
 </div>

 {/* Hash Chain Visualization */}
 <div className="p-6 border-t border-surface-200 bg-white">
 <div className="flex items-center justify-between gap-4">
 {[1, 2, 3, 4, 5].map((block, i) => (
 <div key={i} className="flex items-center gap-2">
 <div className="w-10 h-10 rounded-lg bg-primary-50 border border-primary-100 flex items-center justify-center ">
 <Hash className="w-4 h-4 text-primary-600" />
 </div>
 {i < 4 && <LinkIcon className="w-3 h-3 text-surface-300" />}
 </div>
 ))}
 </div>
 <div className="mt-4 p-3 bg-primary-50 border border-primary-100 rounded-lg">
 <p className="text-[10px] text-primary-700 font-bold uppercase tracking-tight text-center">
 Immutable hash chain - tampering is mathematically detectable
 </p>
 </div>
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
 <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-primary-50 text-primary-700 border border-primary-100 text-[10px] font-bold uppercase tracking-widest mb-4">
          <Database className="w-4 h-4" />
          Consent Ledger
        </div>
 <h2 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-4 tracking-tight">
 Immutable Consent Records
 </h2>
 <p className="text-lg text-surface-600 mb-8 leading-relaxed font-medium">
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
 <li key={item} className="flex items-start gap-3 text-surface-700 font-bold text-sm">
 <Shield className="w-5 h-5 text-primary-600 flex-shrink-0 mt-0.5" strokeWidth={3} />
 {item}
 </li>
 ))}
 </ul>

 <div className="p-6 rounded-xl bg-white border border-surface-200 ">
 <p className="text-sm text-surface-600 leading-relaxed font-medium">
 <strong className="text-surface-900 font-bold uppercase text-[10px] tracking-widest block mb-2">Auditor-Ready</strong>
 Our consent ledger has been reviewed and approved by DPOs at 
 Fortune 500 companies for GDPR Article 7 compliance.
 </p>
 </div>
 </motion.div>
 </div>
 </div>
 </section>
 );
}
