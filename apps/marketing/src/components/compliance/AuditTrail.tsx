'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { ScrollText, Search, Filter, Download, Clock, User, Shield, Database } from '@/components/ui/icons';
import { useState } from 'react';
import { cn, formatTime, getLocalTimeZone } from '@/lib/utils';

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

// Representative compliance events illustrating the audit trail feature.
// Not real customer data.
const demoAuditEvents: AuditEvent[] = [
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
 const timezone = getLocalTimeZone();

 const filteredEvents = demoAuditEvents.filter(
 (event) =>
 event.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
 event.actor.toLowerCase().includes(searchQuery.toLowerCase()) ||
 event.details.toLowerCase().includes(searchQuery.toLowerCase())
 );

 return (
 <section ref={ref} className="py-24 relative bg-white">
      <div className="max-w-[1200px] mx-auto px-5 sm:px-6 lg:px-8">
 <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-start">
 {/* Left - Copy */}
 <motion.div
 initial={{ opacity: 0, y: 16 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 className="lg:sticky lg:top-32"
 >
 <div className="inline-flex items-center gap-2 px-3 py-1 rounded-sm bg-surface-100/50 border border-surface-200 text-[14px] font-medium text-surface-700 mb-6">
 <ScrollText className="w-4 h-4" />
 Audit Trail
 </div>
 <h2 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-surface-900 mb-6 tracking-tight break-words">
 Every Action. Forever Logged.
 </h2>
 <p className="text-lg text-surface-600 mb-8 leading-relaxed">
 Tamper-proof audit logs capture every data operation, consent change, and 
 administrative action. Queryable for up to 2 years, exportable in seconds.
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
 description: 'Up to 2-year retention (Enterprise plan)',
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
 <div className="w-10 h-10 rounded-sm bg-surface-50 flex items-center justify-center flex-shrink-0 border border-surface-200">
 <feature.icon className="w-5 h-5 text-surface-900" strokeWidth={1.5} />
 </div>
 <div>
 <div className="text-surface-900 font-semibold mb-1">{feature.title}</div>
 <div className="text-sm text-surface-600 leading-relaxed">{feature.description}</div>
 </div>
 </div>
 ))}
 </div>
 </motion.div>

 {/* Right - Interactive Audit Log */}
 <motion.div
 initial={{ opacity: 0, y: 16 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 transition={{ delay: 0.2 }}
 >
 <div className="bg-white rounded-lg border border-surface-200 overflow-hidden shadow-sm">
 {/* Sample data banner */}
 <div className="px-6 py-2 bg-amber-50 border-b border-amber-100 flex items-center justify-between">
   <span className="text-[12px] text-amber-700 font-medium">Sample events — illustrating audit trail capabilities</span>
 </div>
 {/* Search Bar */}
 <div className="p-6 bg-white border-b border-surface-200 flex gap-3">
 <div className="flex-1 relative">
 <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-surface-400" />
 <input
 type="text"
 placeholder="Search audit logs..."
 value={searchQuery}
 onChange={(e) => setSearchQuery(e.target.value)}
 className="w-full pl-10 pr-4 py-2 bg-surface-50 border border-surface-200 rounded-sm text-surface-900 text-sm font-medium placeholder-surface-400 focus:outline-none focus:ring-2 focus:ring-primary-500/20 focus:border-primary-500 transition-colors"
 />
 </div>
 <button className="p-2 bg-white border border-surface-200 rounded-md text-surface-500 hover:text-primary-600 hover:border-primary-200 transition-all ">
 <Filter className="w-4 h-4" />
 </button>
 <button className="p-2 bg-white border border-surface-200 rounded-md text-surface-500 hover:text-primary-600 hover:border-primary-200 transition-all ">
 <Download className="w-4 h-4" />
 </button>
 </div>

 <div className="px-6 py-2 text-xs text-surface-500 border-b border-surface-100">
 Times shown in {timezone}
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
                              ? 'bg-emerald-500'
                              : event.outcome === 'warning'
                              ? 'bg-amber-500'
                              : 'bg-red-500'
                          }`}
                        />
                        <span className="text-surface-900 font-medium font-mono text-[13px]">{event.action}</span>
                      </div>
                      <span className="text-[13px] text-surface-500 font-mono">
                        {formatTime(event.timestamp, { second: '2-digit' })}
                      </span>
                    </div>
                    <div className="text-[14px] text-surface-900 mb-3 leading-relaxed">{event.details}</div>
                    <div className="flex items-center gap-4">
                      <div className="flex items-center gap-1.5 px-2 py-0.5 bg-surface-50 border border-surface-200 rounded-sm text-[13px] ">
                        <User className="w-4 h-4 text-surface-400" />
                        <span className="text-surface-700 font-mono">{event.actor}</span>
                      </div>
                      <div className="text-[13px] text-surface-400 font-mono">{event.ipAddress}</div>
                    </div>

 {/* Expanded Details */}
 {selectedEvent?.id === event.id && (
 <motion.div
 initial={{ opacity: 0, height: 0 }}
 animate={{ opacity: 1, height: 'auto' }}
 className="mt-4 pt-4 border-t border-surface-100"
 >
 <div className="bg-surface-950 rounded-lg p-4 font-mono text-xs shadow-sm">
 <div className="text-surface-500 mb-2 text-xs border-b border-surface-800 pb-2">// Full Event Payload</div>
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
 request_id: `req_${event.id.replace(/[^a-z0-9]/gi, '').slice(0, 9).padEnd(9, '0')}`,
 },
 outcome: event.outcome,
 hash: `sha256:${event.id.replace(/[^a-f0-9]/gi, '').padEnd(64, '0').slice(0, 64)}`,
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
 <div className="p-3 bg-surface-50 border-t border-surface-200 text-center">
                <span className="text-[14px] text-surface-500 font-medium">
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
