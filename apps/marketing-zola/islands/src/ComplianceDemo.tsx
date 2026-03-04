import { h } from 'preact';
import { useState, useEffect, useRef } from 'preact/hooks';

// ── Inline SVG icons ────────────────────────────────────────

const SearchIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <circle cx="11" cy="11" r="8" /><path d="m21 21-4.3-4.3" />
  </svg>
);
const FilterIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
  </svg>
);
const DownloadIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" x2="12" y1="15" y2="3" />
  </svg>
);
const UserIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" />
  </svg>
);
const Trash2Icon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M3 6h18" /><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6" /><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2" /><line x1="10" x2="10" y1="11" y2="17" /><line x1="14" x2="14" y1="11" y2="17" />
  </svg>
);
const DatabaseIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M3 5V19A9 3 0 0 0 21 19V5" /><path d="M3 12A9 3 0 0 0 21 12" />
  </svg>
);
const ServerIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <rect width="20" height="8" x="2" y="2" rx="2" ry="2" /><rect width="20" height="8" x="2" y="14" rx="2" ry="2" />
    <line x1="6" x2="6.01" y1="6" y2="6" /><line x1="6" x2="6.01" y1="18" y2="18" />
  </svg>
);
const CloudIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z" />
  </svg>
);
const CheckCircle2Icon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" />
  </svg>
);
const ScrollTextIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M8 21h12a2 2 0 0 0 2-2v-2H10v2a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v3h4" /><path d="M19 17V5a2 2 0 0 0-2-2H4" /><path d="M15 8h-5" /><path d="M15 12h-5" />
  </svg>
);
const ShieldIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
    <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
  </svg>
);
const ClockIcon = ({ class: cls }: { class?: string }) => (
  <svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" />
  </svg>
);

// ── Types ───────────────────────────────────────────────────

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

type DeletionStage = 'pending' | 'primary' | 'replicas' | 'backups' | 'logs' | 'complete';

// ── Demo Data ───────────────────────────────────────────────

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

const deletionSteps: { id: DeletionStage; label: string; icon: (props: { class?: string }) => h.JSX.Element; systems: string[] }[] = [
  { id: 'primary', label: 'Primary Database', icon: DatabaseIcon, systems: ['PostgreSQL Primary'] },
  { id: 'replicas', label: 'Read Replicas', icon: ServerIcon, systems: ['Replica US-East', 'Replica EU-West', 'Replica APAC'] },
  { id: 'backups', label: 'Backup Systems', icon: CloudIcon, systems: ['S3 Archives', 'Glacier Deep Archive'] },
  { id: 'logs', label: 'Log Aggregators', icon: ServerIcon, systems: ['Elasticsearch', 'CloudWatch', 'Datadog'] },
];

// ── Audit Trail ─────────────────────────────────────────────

function AuditTrail() {
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  const filteredEvents = demoAuditEvents.filter(
    (event) =>
      event.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
      event.actor.toLowerCase().includes(searchQuery.toLowerCase()) ||
      event.details.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const formatTime = (ts: string) => {
    try { return new Date(ts).toLocaleTimeString(); } catch { return ts; }
  };

  return (
    <div class="grid lg:grid-cols-2 gap-12 lg:gap-16 items-start">
      {/* Left - Copy */}
      <div class="lg:sticky lg:top-32">
        <div class="inline-flex items-center gap-2 px-3 py-1 rounded-sm bg-surface-100/50 border border-surface-200 text-[14px] font-medium text-surface-700 mb-6">
          <ScrollTextIcon class="w-4 h-4" />
          Audit Trail
        </div>
        <h2 class="text-2xl sm:text-3xl lg:text-4xl font-bold text-surface-900 mb-6 tracking-tight break-words">
          Every Action. Forever Logged.
        </h2>
        <p class="text-lg text-surface-600 mb-8 leading-relaxed">
          Tamper-proof audit logs capture every data operation, consent change, and
          administrative action. Queryable for up to 2 years, exportable in seconds.
        </p>
        <div class="space-y-6">
          {[
            { icon: ShieldIcon, title: 'Immutable Storage', description: 'Write-once logs that cannot be modified or deleted' },
            { icon: ClockIcon, title: '7-Year Retention', description: 'Up to 2-year retention (Enterprise plan)' },
            { icon: SearchIcon, title: 'Full-Text Search', description: 'Query across billions of events in milliseconds' },
            { icon: DatabaseIcon, title: 'Cryptographic Integrity', description: 'Hash chain verification for forensic audit' },
          ].map((feature) => (
            <div key={feature.title} class="flex items-start gap-4">
              <div class="w-10 h-10 rounded-sm bg-surface-50 flex items-center justify-center flex-shrink-0 border border-surface-200">
                <feature.icon class="w-5 h-5 text-surface-900" />
              </div>
              <div>
                <div class="text-surface-900 font-semibold mb-1">{feature.title}</div>
                <div class="text-sm text-surface-600 leading-relaxed">{feature.description}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Right - Interactive Audit Log */}
      <div>
        <div class="bg-white rounded-lg border border-surface-200 overflow-hidden shadow-sm">
          <div class="px-6 py-2 bg-amber-50 border-b border-amber-100 flex items-center justify-between">
            <span class="text-[12px] text-amber-700 font-medium">Sample events — illustrating audit trail capabilities</span>
          </div>
          <div class="p-6 bg-white border-b border-surface-200 flex gap-3">
            <div class="flex-1 relative">
              <SearchIcon class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-surface-400" />
              <input
                type="text"
                placeholder="Search audit logs..."
                value={searchQuery}
                onInput={(e) => setSearchQuery((e.target as HTMLInputElement).value)}
                class="w-full pl-10 pr-4 py-2 bg-surface-50 border border-surface-200 rounded-sm text-surface-900 text-sm font-medium placeholder-surface-400 focus:outline-none focus:ring-2 focus:ring-primary-500/20 focus:border-primary-500 transition-colors"
              />
            </div>
            <button aria-label="Filter" class="p-2 bg-white border border-surface-200 rounded-md text-surface-500 hover:text-primary-600 hover:border-primary-200 transition-all">
              <FilterIcon class="w-4 h-4" />
            </button>
            <button aria-label="Download" class="p-2 bg-white border border-surface-200 rounded-md text-surface-500 hover:text-primary-600 hover:border-primary-200 transition-all">
              <DownloadIcon class="w-4 h-4" />
            </button>
          </div>

          <div class="divide-y divide-surface-100">
            {filteredEvents.map((event) => (
              <div
                key={event.id}
                onClick={() => setSelectedEvent(selectedEvent?.id === event.id ? null : event)}
                class={`p-6 cursor-pointer transition-all ${selectedEvent?.id === event.id ? 'bg-white shadow-inner' : 'hover:bg-surface-100'}`}
              >
                <div class="flex items-start justify-between mb-3">
                  <div class="flex items-center gap-2">
                    <div class={`w-2 h-2 rounded-full ${event.outcome === 'success' ? 'bg-emerald-500' : event.outcome === 'warning' ? 'bg-amber-500' : 'bg-red-500'}`} />
                    <span class="text-surface-900 font-medium font-mono text-[13px]">{event.action}</span>
                  </div>
                  <span class="text-[13px] text-surface-500 font-mono">{formatTime(event.timestamp)}</span>
                </div>
                <div class="text-[14px] text-surface-900 mb-3 leading-relaxed">{event.details}</div>
                <div class="flex items-center gap-4">
                  <div class="flex items-center gap-1.5 px-2 py-0.5 bg-surface-50 border border-surface-200 rounded-sm text-[13px]">
                    <UserIcon class="w-4 h-4 text-surface-400" />
                    <span class="text-surface-700 font-mono">{event.actor}</span>
                  </div>
                  <div class="text-[13px] text-surface-400 font-mono">{event.ipAddress}</div>
                </div>

                {selectedEvent?.id === event.id && (
                  <div class="mt-4 pt-4 border-t border-surface-100">
                    <div class="bg-surface-950 rounded-lg p-4 font-mono text-xs shadow-sm">
                      <div class="text-surface-500 mb-2 text-xs border-b border-surface-800 pb-2">// Full Event Payload</div>
                      <pre class="text-surface-300 whitespace-pre-wrap overflow-auto max-h-64">
                        {JSON.stringify(
                          {
                            event_id: event.id,
                            timestamp: event.timestamp,
                            actor: { type: event.actor.includes('@') ? 'user' : event.actor.includes('api_key') ? 'api_key' : 'system', identifier: event.actor },
                            action: event.action,
                            resource: event.resource,
                            context: { ip_address: event.ipAddress, user_agent: 'ApexMail-SDK/2.1.0' },
                            outcome: event.outcome,
                            hash: `sha256:${event.id.replace(/[^a-f0-9]/gi, '').padEnd(64, '0').slice(0, 64)}`,
                          },
                          null,
                          2,
                        )}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>

          <div class="p-3 bg-surface-50 border-t border-surface-200 text-center">
            <span class="text-[14px] text-surface-500 font-medium">
              Showing {filteredEvents.length} of 2,847,392 events
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Right to Be Forgotten ───────────────────────────────────

function RightToBeForgotten() {
  const [currentStage, setCurrentStage] = useState<DeletionStage>('pending');
  const [isAnimating, setIsAnimating] = useState(false);
  const sectionRef = useRef<HTMLElement>(null);

  const startDemo = () => {
    if (isAnimating) return;
    setIsAnimating(true);
    setCurrentStage('pending');

    const prefersReduced = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    const stages: DeletionStage[] = ['primary', 'replicas', 'backups', 'logs', 'complete'];

    if (prefersReduced) {
      setCurrentStage('complete');
      setIsAnimating(false);
      return;
    }

    let index = 0;
    const interval = setInterval(() => {
      if (index < stages.length) {
        setCurrentStage(stages[index]);
        index++;
      } else {
        clearInterval(interval);
        setTimeout(() => {
          setIsAnimating(false);
          setCurrentStage('pending');
        }, 3000);
      }
    }, 1500);
  };

  // Auto-start when visible
  useEffect(() => {
    if (!sectionRef.current || typeof IntersectionObserver === 'undefined') return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !isAnimating) {
          setTimeout(startDemo, 1000);
          observer.disconnect();
        }
      },
      { threshold: 0.1 },
    );
    observer.observe(sectionRef.current);
    return () => observer.disconnect();
  }, []);

  const getStageStatus = (stepId: DeletionStage): 'pending' | 'active' | 'complete' => {
    const order: DeletionStage[] = ['pending', 'primary', 'replicas', 'backups', 'logs', 'complete'];
    const currentIndex = order.indexOf(currentStage);
    const stepIndex = order.indexOf(stepId);
    if (currentStage === 'complete' || stepIndex < currentIndex) return 'complete';
    if (stepIndex === currentIndex) return 'active';
    return 'pending';
  };

  return (
    <section ref={sectionRef} class="py-20 lg:py-32 relative bg-white">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-50 text-red-700 border border-red-100 text-xs font-medium mb-6">
            <Trash2Icon class="w-4 h-4" />
            Right to Be Forgotten
          </div>
          <h2 class="text-3xl lg:text-4xl font-bold text-surface-900 mb-6 tracking-tight">
            One Click. Complete Erasure.
          </h2>
          <p class="text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed">
            GDPR Article 17 compliance made simple. Our cascade deletion propagates through
            every system—primary, replicas, backups, and logs—within 72 hours.
          </p>
        </div>

        <div class="bg-white border border-surface-200 rounded-2xl p-8 max-w-4xl mx-auto shadow-sm">
          <div class="flex items-center justify-between mb-10 pb-8 border-b border-surface-200">
            <div>
              <div class="text-xs font-medium text-surface-500 mb-1">Deletion Request</div>
              <div class="text-surface-900 font-mono font-medium text-lg">john.doe@example.com</div>
            </div>
            <button
              onClick={startDemo}
              disabled={isAnimating}
              class={`px-5 py-2.5 rounded-md font-semibold text-sm transition-all shadow-sm ${
                isAnimating ? 'bg-surface-100 text-surface-400 cursor-not-allowed' : 'bg-red-600 text-white hover:bg-red-700'
              }`}
            >
              {isAnimating ? 'Processing...' : 'Execute RTBF'}
            </button>
          </div>

          <div class="space-y-4">
            {deletionSteps.map((step) => {
              const status = getStageStatus(step.id);
              const Icon = step.icon;
              return (
                <div
                  key={step.id}
                  class={`flex items-center gap-4 p-4 rounded-lg border transition-all ${
                    status === 'active'
                      ? 'bg-red-50/50 border-red-200'
                      : status === 'complete'
                        ? 'bg-emerald-50/50 border-emerald-200'
                        : 'bg-white border-surface-200'
                  }`}
                >
                  <div
                    class={`w-10 h-10 rounded-lg flex items-center justify-center border ${
                      status === 'active'
                        ? 'bg-red-100 text-red-600 border-red-200'
                        : status === 'complete'
                          ? 'bg-emerald-100 text-emerald-600 border-emerald-200'
                          : 'bg-surface-50 text-surface-400 border-surface-200'
                    }`}
                  >
                    {status === 'complete' ? (
                      <CheckCircle2Icon class="w-5 h-5" />
                    ) : status === 'active' ? (
                      <Trash2Icon class="w-5 h-5" />
                    ) : (
                      <Icon class="w-5 h-5" />
                    )}
                  </div>
                  <div class="flex-1">
                    <div class="text-surface-900 font-semibold text-sm">{step.label}</div>
                    <div class="flex flex-wrap gap-2 mt-1.5">
                      {step.systems.map((system) => (
                        <span
                          key={system}
                          class={`text-xs px-2 py-0.5 rounded font-medium ${
                            status === 'complete' ? 'bg-emerald-100/50 text-emerald-700' : 'bg-surface-100 text-surface-600'
                          }`}
                        >
                          {system}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div class={`text-xs font-medium ${status === 'active' ? 'text-red-600' : status === 'complete' ? 'text-emerald-600' : 'text-surface-400'}`}>
                    {status === 'active' ? 'Deleting...' : status === 'complete' ? 'Erased' : 'Pending'}
                  </div>
                </div>
              );
            })}
          </div>

          {currentStage === 'complete' && (
            <div class="mt-8 p-6 bg-emerald-50 border border-emerald-200 rounded-lg text-center">
              <CheckCircle2Icon class="w-10 h-10 text-emerald-600 mx-auto mb-3" />
              <div class="text-emerald-800 font-bold text-xs mb-1">Erasure Complete</div>
              <div class="text-sm text-emerald-700 font-medium">
                Certificate of deletion generated and logged to immutable audit trail
              </div>
            </div>
          )}
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-8 max-w-3xl mx-auto mt-16 pt-12 border-t border-surface-100">
          {[
            { value: '< 72h', label: 'Complete Erasure' },
            { value: '100%', label: 'System Coverage' },
            { value: 'Auto', label: 'Compliance Certificate' },
          ].map((stat) => (
            <div key={stat.label} class="text-center">
              <div class="text-2xl lg:text-4xl font-bold text-surface-900 tabular-nums mb-1">{stat.value}</div>
              <div class="text-xs font-bold text-surface-600">{stat.label}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── Main Export ──────────────────────────────────────────────

export default function ComplianceDemo() {
  return (
    <div>
      {/* Audit Trail Section */}
      <section class="py-20 lg:py-32 relative bg-white">
        <div class="max-w-7xl mx-auto px-5 sm:px-6 lg:px-8">
          <AuditTrail />
        </div>
      </section>

      {/* Right to Be Forgotten Section */}
      <RightToBeForgotten />

      {/* Consent Ledger — static with illustrative code block (no JS interaction needed) */}
      <section class="py-20 lg:py-32 relative bg-surface-50">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div class="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
            {/* Left - Code */}
            <div class="order-2 lg:order-1">
              <div class="bg-white rounded-lg border border-surface-200 overflow-hidden shadow-sm">
                <div class="flex items-center justify-between gap-2 px-6 py-4 border-b border-surface-200 bg-surface-50/50">
                  <div class="flex items-center gap-2">
                    <DatabaseIcon class="w-4 h-4 text-surface-500" />
                    <span class="text-xs font-medium text-surface-600 font-mono">Consent Ledger Entry</span>
                  </div>
                  <span class="text-[10px] text-amber-700 font-medium px-2 py-0.5 rounded bg-amber-50 border border-amber-200">Illustrative</span>
                </div>
                <div class="bg-surface-950 overflow-hidden">
                  <pre class="p-6 text-xs text-surface-300 font-mono whitespace-pre-wrap leading-relaxed">{`// Every consent event is cryptographically linked
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
}`}</pre>
                </div>
              </div>
            </div>

            {/* Right - Copy */}
            <div class="order-1 lg:order-2">
              <div class="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-surface-100 border border-surface-200 text-xs font-medium text-surface-900 mb-6">
                <DatabaseIcon class="w-4 h-4" />
                Consent Ledger
              </div>
              <h2 class="text-2xl sm:text-3xl lg:text-4xl font-bold text-surface-900 mb-6 tracking-tight break-words">
                Immutable Consent Records
              </h2>
              <p class="text-lg text-surface-600 mb-8 leading-relaxed">
                Every consent event is recorded in a cryptographically-linked chain.
                Each entry references the hash of the previous one, making any tampering
                mathematically detectable.
              </p>
              <ul class="space-y-4 mb-8">
                {[
                  'SHA-256 hashed entries linked to form immutable chain',
                  'Ed25519 digital signatures on every consent event',
                  'Full audit trail with IP, timestamp, and user agent',
                  'Export-ready for GDPR Article 30 compliance',
                  'Real-time verification API for auditors',
                ].map((item) => (
                  <li key={item} class="flex items-start gap-3 text-surface-700 text-sm leading-relaxed">
                    <ShieldIcon class="w-5 h-5 text-surface-900 flex-shrink-0 mt-0.5" />
                    {item}
                  </li>
                ))}
              </ul>
              <div class="p-6 rounded-lg bg-white border border-surface-200 shadow-sm">
                <p class="text-sm text-surface-600 leading-relaxed">
                  <strong class="text-surface-900 font-semibold block mb-1">Auditor-Ready</strong>
                  Our consent ledger has been reviewed and approved by DPOs at
                  Fortune 500 companies for GDPR Article 7 compliance.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
