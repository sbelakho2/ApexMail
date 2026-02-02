'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ScrollText, Search, Filter, Download, Clock, User, Shield, Database } from 'lucide-react';
import { useState } from 'react';
import { cn } from '@/lib/utils';

interface AuditEvent {
 id: string;
 timestamp: string;
 actor: string;
 action: string;
 resource: string;
 details: string;
 ipAddress: string;
 outcome: 'success' | 'failure' | 'warning';
}

const mockAuditEvents: AuditEvent[] = [
 {
 id: 'evt_001',
 timestamp: '2024-02-15T14:32:18Z',
 actor: 'admin@acme.com',
 action: 'consent.updated',
 resource: 'user:john.doe@example.com',
 details: 'Marketing consent changed from OPT_IN to OPT_OUT',
 ipAddress: '203.0.113.42',
 outcome: 'success',
 },
 {
 id: 'evt_002',
 timestamp: '2024-02-15T14:30:45Z',
 actor: 'system',
 action: 'dpa.generated',
 resource: 'org:acme-corp',
 details: 'Auto-generated DPA v2.3 for EU processing',
 ipAddress: '10.0.0.1',
 outcome: 'success',
 },
 {
 id: 'evt_003',
 timestamp: '2024-02-15T14:28:12Z',
 actor: 'api_key:sk_live_****',
 action: 'data.export',
 resource: 'user:jane.smith@example.com',
 details: 'GDPR data portability export requested',
 ipAddress: '198.51.100.23',
 outcome: 'success',
 },
 {
 id: 'evt_004',
 timestamp: '2024-02-15T14:25:33Z',
 actor: 'admin@acme.com',
 action: 'rtbf.initiated',
 resource: 'user:deleted_user_12345',
 details: 'Right to be forgotten cascade deletion started',
 ipAddress: '203.0.113.42',
 outcome: 'warning',
 },
 {
 id: 'evt_005',
 timestamp: '2024-02-15T14:22:01Z',
 actor: 'system',
 action: 'backup.encrypted',
 resource: 'backup:daily_2024_02_15',
 details: 'Daily backup encrypted with AES-256-GCM',
 ipAddress: '10.0.0.5',
 outcome: 'success',
 },
];

export function AuditTrail() {
 const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });
 const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);
 const [searchQuery, setSearchQuery] = useState('');

 const filteredEvents = mockAuditEvents.filter(
 (event) =>
 event.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
 event.actor.toLowerCase().includes(searchQuery.toLowerCase()) ||
 event.details.toLowerCase().includes(searchQuery.toLowerCase())
 );

 return (
 <section ref={ref} className="py-20 lg:py-32 relative bg-white">
 <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-start">
 {/* Left - Copy */}
 <motion.div
 initial={{ opacity: 0, x: -20 }}
 animate={inView ? { opacity: 1, x: 0 } : {}}
 className="lg:sticky lg:top-32"
 >
 <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-50 text-primary-700 border border-primary-100 text-[10px] font-bold uppercase tracking-widest mb-4">
 <ScrollText className="w-4 h-4" />
 Audit Trail
 </div>
 <h2 className="text-3xl lg:text-4xl font-bold text-surface-900 mb-4 tracking-tight">
 Every Action. Forever Logged.
 </h2>
 <p className="text-lg text-surface-600 mb-8 leading-relaxed font-medium">
 Tamper-proof audit logs capture every data operation, consent change, and 
 administrative action. Queryable for years, exportable in seconds.
 </p>

 <div className="space-y-6">
 {[
 {
 icon: Shield,
 title: 'Immutable Storage',
 description: 'Write-once logs that cannot be modified or deleted',
 },
 {
 icon: Clock,
 title: '7-Year Retention',
 description: 'Meets GDPR, HIPAA, and SOX retention requirements',
 },
 {
 icon: Search,
 title: 'Full-Text Search',
 description: 'Query across billions of events in milliseconds',
 },
 {
 icon: Database,
 title: 'Cryptographic Integrity',
 description: 'Hash chain verification for forensic audit',
 },
 ].map((feature) => (
 <div key={feature.title} className="flex items-start gap-4">
 <div className="w-12 h-12 rounded-md bg-primary-50 flex items-center justify-center flex-shrink-0 border border-primary-100">
 <feature.icon className="w-6 h-6 text-primary-600" />
 </div>
 <div>
 <div className="text-surface-900 font-bold">{feature.title}</div>
 <div className="text-sm text-surface-500 font-medium">{feature.description}</div>
 </div>
 </div>
 ))}
 </div>
 </motion.div>

 {/* Right - Interactive Audit Log */}
 <motion.div
 initial={{ opacity: 0, x: 20 }}
 animate={inView ? { opacity: 1, x: 0 } : {}}
 transition={{ delay: 0.2 }}
 >
 <div className="premium-card overflow-hidden bg-surface-50 border border-surface-200">
 {/* Search Bar */}
 <div className="p-6 bg-white border-b border-surface-200 flex gap-3">
 <div className="flex-1 relative">
 <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-surface-400" />
 <input
 type="text"
 placeholder="Search audit logs..."
 value={searchQuery}
 onChange={(e) => setSearchQuery(e.target.value)}
 className="w-full pl-10 pr-4 py-2 bg-surface-50 border border-surface-200 rounded-sm text-surface-900 text-sm font-medium placeholder-surface-400 focus:outline-none focus:border-primary-500 transition-colors "
 />
 </div>
 <button className="p-2 bg-white border border-surface-200 rounded-md text-surface-500 hover:text-primary-600 hover:border-primary-200 transition-all ">
 <Filter className="w-4 h-4" />
 </button>
 <button className="p-2 bg-white border border-surface-200 rounded-md text-surface-500 hover:text-primary-600 hover:border-primary-200 transition-all ">
 <Download className="w-4 h-4" />
 </button>
 </div>

 {/* Event List */}
 <div className="divide-y divide-surface-100">
 {filteredEvents.map((event) => (
 <motion.div
 key={event.id}
 onClick={() => setSelectedEvent(selectedEvent?.id === event.id ? null : event)}
 className={cn(
 'p-6 cursor-pointer transition-all',
 selectedEvent?.id === event.id ? 'bg-white shadow-inner' : 'hover:bg-surface-100'
 )}
 >
 <div className="flex items-start justify-between mb-3">
 <div className="flex items-center gap-2">
 <div
 className={`w-2 h-2 rounded-full ${
 event.outcome === 'success'
 ? 'bg-green-500'
 : event.outcome === 'warning'
 ? 'bg-yellow-500'
 : 'bg-red-500'
 }`}
 />
 <span className="text-surface-900 font-bold font-mono text-xs uppercase tracking-tight">{event.action}</span>
 </div>
 <span className="text-[10px] font-bold text-surface-400 uppercase tracking-widest font-mono">
 {new Date(event.timestamp).toLocaleTimeString()}
 </span>
 </div>
 <div className="text-sm text-surface-700 font-medium mb-3 leading-relaxed">{event.details}</div>
 <div className="flex items-center gap-4">
 <div className="flex items-center gap-1.5 px-2 py-1 bg-white border border-surface-200 rounded-md ">
 <User className="w-3 h-3 text-surface-400" />
 <span className="text-[10px] font-bold text-surface-600 font-mono tracking-tight">{event.actor}</span>
 </div>
 <div className="text-[10px] font-bold text-surface-400 font-mono">{event.ipAddress}</div>
 </div>

 {/* Expanded Details */}
 {selectedEvent?.id === event.id && (
 <motion.div
 initial={{ opacity: 0, height: 0 }}
 animate={{ opacity: 1, height: 'auto' }}
 className="mt-6 pt-6 border-t border-surface-100"
 >
 <div className="bg-surface-900 rounded-lg p-4 font-mono text-xs shadow-inner">
 <div className="text-surface-500 mb-3 font-bold uppercase tracking-widest text-[9px] border-b border-surface-800 pb-2">// Full Event Payload</div>
 <pre className="text-surface-300 whitespace-pre-wrap overflow-auto max-h-64">
{JSON.stringify(
 {
 event_id: event.id,
 timestamp: event.timestamp,
 actor: {
 type: event.actor.includes('@') ? 'user' : event.actor.includes('api_key') ? 'api_key' : 'system',
 identifier: event.actor,
 },
 action: event.action,
 resource: event.resource,
 context: {
 ip_address: event.ipAddress,
 user_agent: 'ApexMail-SDK/2.1.0',
 request_id: `req_${Math.random().toString(36).slice(2, 11)}`,
 },
 outcome: event.outcome,
 hash: `sha256:${Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')}`,
 },
 null,
 2
)}
 </pre>
 </div>
 </motion.div>
 )}
 </motion.div>
 ))}
 </div>

 {/* Footer */}
 <div className="p-4 bg-white border-t border-surface-200 text-center">
 <span className="text-[10px] font-bold text-surface-400 uppercase tracking-widest">
 Showing {filteredEvents.length} of 2,847,392 events
 </span>
 </div>
 </div>
 </motion.div>
 </div>
 </div>
 </section>
 );
}
