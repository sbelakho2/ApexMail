/**
 * API Console Island — combines InteractiveConsole + LiveAPIConsole + EndpointExplorer
 * Ported from apps/marketing/src/components/api-console/ + home/LiveAPIConsole.tsx
 */
import { h } from 'preact';
import { useState, useCallback } from 'preact/hooks';

const ENDPOINTS = [
  { method: 'POST', path: '/v1/messages', label: 'Send Email', body: JSON.stringify({ from: 'you@example.com', to: 'user@test.com', subject: 'Hello from ApexMail', html: '<h1>Welcome!</h1>' }, null, 2) },
  { method: 'GET', path: '/v1/messages', label: 'List Messages', body: '' },
  { method: 'GET', path: '/v1/domains', label: 'List Domains', body: '' },
  { method: 'POST', path: '/v1/domains', label: 'Add Domain', body: JSON.stringify({ domain: 'example.com' }, null, 2) },
  { method: 'GET', path: '/v1/analytics', label: 'Analytics', body: '' },
  { method: 'GET', path: '/v1/events', label: 'Events', body: '' },
  { method: 'GET', path: '/v1/templates', label: 'Templates', body: '' },
  { method: 'POST', path: '/v1/contacts', label: 'Add Contact', body: JSON.stringify({ email: 'user@test.com', name: 'Example User' }, null, 2) },
];

const MOCK_RESPONSES: Record<string, object> = {
  'POST /v1/messages': { id: 'msg_2kT9xHq3mLpN', status: 'queued', message: 'Email queued for delivery' },
  'GET /v1/messages': { data: [{ id: 'msg_2kT9xHq3mLpN', to: 'user@test.com', status: 'delivered', opened: true }], total: 1 },
  'GET /v1/domains': { data: [{ domain: 'example.com', verified: true, dkim: true, spf: true }] },
  'POST /v1/domains': { domain: 'example.com', status: 'pending', dns_records: [{ type: 'TXT', name: 'apexmail._domainkey', value: 'v=DKIM1; k=rsa; p=MIGf...' }] },
  'GET /v1/analytics': { sent: 14230, delivered: 14189, opened: 8721, clicked: 2103, bounced: 41, period: '30d' },
  'GET /v1/events': { data: [{ type: 'delivered', email: 'user@test.com', timestamp: new Date().toISOString() }] },
  'GET /v1/templates': { data: [{ id: 'tpl_welcome', name: 'Welcome Email', version: 3 }] },
  'POST /v1/contacts': { id: 'ct_9xMnLp2q', email: 'user@test.com', name: 'Example User', created: true },
};

const METHOD_COLOR: Record<string, string> = {
  GET: 'text-emerald-400',
  POST: 'text-amber-400',
  PUT: 'text-blue-400',
  DELETE: 'text-red-400',
};

export default function ApiConsole() {
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [response, setResponse] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [body, setBody] = useState(ENDPOINTS[0].body);

  const endpoint = ENDPOINTS[selectedIdx];

  const handleSelect = useCallback((idx: number) => {
    setSelectedIdx(idx);
    setBody(ENDPOINTS[idx].body);
    setResponse(null);
  }, []);

  const handleSend = useCallback(async () => {
    setLoading(true);
    // Simulate network delay
    await new Promise((r) => setTimeout(r, 400 + Math.random() * 600));
    const key = `${endpoint.method} ${endpoint.path}`;
    const mock = MOCK_RESPONSES[key] || { status: 'ok' };
    setResponse(JSON.stringify(mock, null, 2));
    setLoading(false);
  }, [endpoint]);

  return (
    <div class="rounded-xl border border-surface-700 bg-surface-900 overflow-hidden shadow-2xl">
      <div class="flex border-b border-surface-700">
        {/* Endpoint sidebar */}
        <div class="w-56 border-r border-surface-700 bg-surface-800/50 hidden sm:block">
          <div class="p-3 text-xs font-semibold text-surface-400 uppercase tracking-wider">Endpoints</div>
          {ENDPOINTS.map((ep, i) => (
            <button
              key={ep.path + ep.method}
              class={`w-full text-left px-3 py-2.5 text-sm flex items-center gap-2 transition-colors ${i === selectedIdx ? 'bg-primary-600/10 text-white' : 'text-surface-400 hover:text-surface-200 hover:bg-surface-800'}`}
              onClick={() => handleSelect(i)}
            >
              <span class={`font-mono text-xs font-bold ${METHOD_COLOR[ep.method]}`}>{ep.method}</span>
              <span class="truncate">{ep.label}</span>
            </button>
          ))}
        </div>

        {/* Main area */}
        <div class="flex-1 flex flex-col min-h-[24rem]">
          {/* Request line */}
          <div class="flex items-center gap-2 px-4 py-3 border-b border-surface-700 bg-surface-800/30">
            <span class={`font-mono text-sm font-bold ${METHOD_COLOR[endpoint.method]}`}>{endpoint.method}</span>
            <span class="font-mono text-sm text-surface-300">{endpoint.path}</span>
            <button
              onClick={handleSend}
              disabled={loading}
              class="ml-auto px-4 py-1.5 rounded-lg bg-primary-600 text-white text-sm font-semibold hover:bg-primary-500 transition-colors disabled:opacity-50"
            >
              {loading ? 'Sending...' : 'Send →'}
            </button>
          </div>

          {/* Request body (editable for POST) */}
          {endpoint.method === 'POST' && (
            <div class="px-4 py-3 border-b border-surface-700 bg-surface-800/20">
              <div class="text-xs font-semibold text-surface-500 mb-2">Request Body</div>
              <textarea
                value={body}
                onInput={(e) => setBody((e.target as HTMLTextAreaElement).value)}
                class="w-full bg-surface-900 text-surface-200 font-mono text-xs rounded-lg p-3 border border-surface-700 focus:border-primary-500 focus:outline-none resize-none"
                rows={4}
                spellcheck={false}
              />
            </div>
          )}

          {/* Response */}
          <div class="flex-1 px-4 py-3">
            <div class="text-xs font-semibold text-surface-500 mb-2">Response</div>
            {loading ? (
              <div class="flex items-center gap-2 text-surface-400 text-sm"><div class="w-4 h-4 border-2 border-primary-500 border-t-transparent rounded-full animate-spin" /> Sending request...</div>
            ) : response ? (
              <pre class="text-xs text-emerald-400 font-mono bg-surface-800/50 rounded-lg p-3 overflow-auto max-h-60">{response}</pre>
            ) : (
              <p class="text-sm text-surface-500 italic">Click "Send" to execute the request.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
