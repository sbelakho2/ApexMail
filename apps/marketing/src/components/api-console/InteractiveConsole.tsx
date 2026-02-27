'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { useState } from 'react';
import { Send, Clock, CheckCircle, Copy, Play } from '@/components/ui/icons';
import { cn, formatTime, getLocalTimeZone } from '@/lib/utils';
import DOMPurify from 'isomorphic-dompurify';

/**
 * Sanitize HTML to prevent XSS attacks
 * Uses DOMPurify with strict configuration
 */
function sanitizeHtml(html: string): string {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'br', 'strong', 'em', 'u', 'a', 'ul', 'ol', 'li', 'span', 'div', 'table', 'tr', 'td', 'th', 'thead', 'tbody', 'img'],
    ALLOWED_ATTR: ['href', 'src', 'alt', 'class', 'target', 'rel'],
    ALLOW_DATA_ATTR: false,
    ADD_ATTR: ['target'],
    FORBID_TAGS: ['script', 'iframe', 'object', 'embed', 'form', 'input', 'button'],
    FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover'],
  });
}

type TabType = 'request' | 'response' | 'webhook';

interface WebhookEvent {
  id: string;
  type: string;
  timestamp: string;
  data: Record<string, unknown>;
}

export function InteractiveConsole() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [activeTab, setActiveTab] = useState<TabType>('request');
  const [isLoading, setIsLoading] = useState(false);
  const [response, setResponse] = useState<Record<string, unknown> | null>(null);
  const [webhooks, setWebhooks] = useState<WebhookEvent[]>([]);
  const [copied, setCopied] = useState<'idle' | 'ok' | 'err'>('idle');
  const timezone = getLocalTimeZone();

  const [requestBody, setRequestBody] = useState({
    to: 'test@example.com',
    subject: 'Hello from ApexMail!',
    html: '<h1>Welcome!</h1><p>This is a test email.</p>',
  });

  const handleSend = async () => {
    setIsLoading(true);
    setActiveTab('response');

    // Sandbox simulation — no real email is sent from this demo
    await new Promise((resolve) => setTimeout(resolve, 800));

    const mockResponse = {
      id: `msg_${Math.random().toString(36).slice(2, 11)}`,
      status: 'queued',
      to: requestBody.to,
      subject: requestBody.subject,
      created_at: new Date().toISOString(),
      _note: 'Sandbox simulation — no email was delivered',
    };

    setResponse(mockResponse);
    setIsLoading(false);

    // Simulated webhook events (sandbox only)
    setTimeout(() => {
      setWebhooks((prev) => [
        {
          id: `evt_${Math.random().toString(36).slice(2, 11)}`,
          type: 'email.sent',
          timestamp: new Date().toISOString(),
          data: { message_id: mockResponse.id, recipient: requestBody.to, _sandbox: true },
        },
        ...prev,
      ]);
    }, 1500);

    setTimeout(() => {
      setWebhooks((prev) => [
        {
          id: `evt_${Math.random().toString(36).slice(2, 11)}`,
          type: 'email.delivered',
          timestamp: new Date().toISOString(),
          data: { message_id: mockResponse.id, recipient: requestBody.to, mx_host: 'mx.example.com', _sandbox: true },
        },
        ...prev,
      ]);
    }, 3000);
  };

  const copyCode = async () => {
    const code = `curl -X POST https://api.apexmail.ee/v1/messages \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '${JSON.stringify(requestBody, null, 2)}'`;
    try {
      await navigator.clipboard.writeText(code);
      setCopied('ok');
    } catch {
      setCopied('err');
    } finally {
      setTimeout(() => setCopied('idle'), 2500);
    }
  };

  return (
    <section ref={ref} className="py-12 lg:py-20 relative bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section head with cross-link to real product */}
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-bold text-surface-900 sr-only">Interactive API Sandbox</h2>
          <p className="text-xs text-surface-400">
            This is a read-only sandbox. No real emails are sent.{' '}
            <a href="/signup" className="text-primary-600 underline hover:text-primary-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 rounded">
              Sign up to send real emails →
            </a>
          </p>
        </div>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="bg-white border border-surface-200 shadow-sm rounded-lg overflow-hidden"
        >
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 bg-white border-b border-surface-200">
            <div className="flex items-center gap-2">
              <div className="flex gap-1.5 mr-4" aria-hidden="true">
                <div className="w-3 h-3 rounded-full bg-surface-200" />
                <div className="w-3 h-3 rounded-full bg-surface-200" />
                <div className="w-3 h-3 rounded-full bg-surface-200" />
              </div>
              <span className="text-xs font-bold text-surface-600 font-mono">POST /v1/messages</span>
              <span className="ml-2 px-2 py-0.5 text-[10px] font-bold rounded bg-amber-50 text-amber-700 border border-amber-200 uppercase tracking-wide" role="note" aria-label="Sandbox: no real emails sent">
                Sandbox
              </span>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={copyCode}
                aria-label={copied === 'ok' ? 'Copied to clipboard' : copied === 'err' ? 'Copy failed — try manually' : 'Copy cURL command'}
                className={cn(
                  'flex items-center gap-1 px-3 py-1 text-xs font-medium transition-colors',
                  copied === 'err' ? 'text-red-500' : 'text-surface-500 hover:text-primary-600'
                )}
              >
                <Copy className="w-4 h-4" aria-hidden="true" />
                {copied === 'ok' ? 'Copied!' : copied === 'err' ? 'Failed — copy manually' : 'Copy cURL'}
              </button>
              <button
                onClick={handleSend}
                disabled={isLoading}
                aria-label={isLoading ? 'Sending sandbox request…' : 'Run sandbox request'}
                aria-busy={isLoading}
                data-demo-id="sandbox-send"
                className="btn-primary flex items-center gap-2 py-2 px-4 text-xs font-medium"
              >
                {isLoading ? (
                  <Clock className="w-4 h-4 animate-spin" aria-hidden="true" />
                ) : (
                  <Play className="w-4 h-4" aria-hidden="true" />
                )}
                Send Request
              </button>
            </div>
          </div>

          {/* Tabs */}
          <div className="flex bg-white px-6 border-b border-surface-200" role="tablist" aria-label="Console panels">
            {[
              { id: 'request', label: 'Request' },
              { id: 'response', label: 'Response' },
              { id: 'webhook', label: `Webhooks (${webhooks.length})` },
            ].map((tab) => (
              <button
                key={tab.id}
                role="tab"
                aria-selected={activeTab === tab.id}
                aria-controls={`panel-${tab.id}`}
                id={`tab-${tab.id}`}
                onClick={() => setActiveTab(tab.id as TabType)}
                onKeyDown={(e) => {
                  const tabs: TabType[] = ['request', 'response', 'webhook'];
                  const idx = tabs.indexOf(tab.id as TabType);
                  if (e.key === 'ArrowRight') {
                    setActiveTab(tabs[(idx + 1) % tabs.length]);
                    e.preventDefault();
                  } else if (e.key === 'ArrowLeft') {
                    setActiveTab(tabs[(idx + tabs.length - 1) % tabs.length]);
                    e.preventDefault();
                  }
                }}
                className={cn(
                  'px-4 py-3 text-xs font-medium transition-all border-b-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-500',
                  activeTab === tab.id
                    ? 'text-primary-600 border-primary-600'
                    : 'text-surface-400 border-transparent hover:text-surface-900'
                )}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Content */}
          <div className="grid lg:grid-cols-2 gap-0">
            {/* Left Panel - Editor */}
            <div className="p-6 border-r border-surface-200 bg-white">
              {activeTab === 'request' && (
                <div role="tabpanel" id="panel-request" aria-labelledby="tab-request" className="space-y-4">
                  <div>
                    <label className="block text-xs font-medium text-surface-500 mb-2">To</label>
                    <input
                      type="email"
                      value={requestBody.to}
                      onChange={(e) => setRequestBody({ ...requestBody, to: e.target.value })}
                      className="w-full px-4 py-2 bg-surface-50 border border-surface-200 rounded-sm text-surface-900 text-sm font-medium focus:outline-none focus:ring-2 focus:ring-primary-500/20 focus:border-primary-500 transition-colors"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-surface-500 mb-2">Subject</label>
                    <input
                      type="text"
                      value={requestBody.subject}
                      onChange={(e) => setRequestBody({ ...requestBody, subject: e.target.value })}
                      className="w-full px-4 py-2 bg-surface-50 border border-surface-200 rounded-sm text-surface-900 text-sm font-medium focus:outline-none focus:ring-2 focus:ring-primary-500/20 focus:border-primary-500 transition-colors"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-surface-500 mb-2">HTML Body</label>
                    <textarea
                      value={requestBody.html}
                      onChange={(e) => setRequestBody({ ...requestBody, html: e.target.value })}
                      rows={6}
                      className="w-full px-4 py-3 bg-surface-50 border border-surface-200 rounded-sm text-surface-900 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary-500/20 focus:border-primary-500 transition-colors"
                    />
                  </div>
                </div>
              )}

              {activeTab === 'response' && (
                <div role="tabpanel" id="panel-response" aria-labelledby="tab-response">
                  {isLoading ? (
                    <div className="flex flex-col items-center justify-center h-64 text-surface-400">
                      <Clock className="w-8 h-8 animate-spin mb-4 text-primary-200" />
                      <span className="text-xs font-medium">Simulating request (~800ms)…</span>
                    </div>
                  ) : response ? (
                    <div className="space-y-4">
                      <div className="flex items-center gap-2 text-emerald-600">
                        <CheckCircle className="w-5 h-5" strokeWidth={2} aria-hidden="true" />
                        <span className="text-xs font-bold">200 OK</span>
                        <span className="ml-auto text-xs text-amber-600 font-medium px-2 py-0.5 rounded bg-amber-50 border border-amber-200">Sandbox — no email delivered</span>
                      </div>
                      <pre className="text-xs text-surface-300 font-mono bg-surface-900 p-4 rounded-lg overflow-auto shadow-inner border border-surface-800">
                        {JSON.stringify(response, null, 2)}
                      </pre>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center h-64 text-surface-400 text-center">
                      <div className="w-12 h-12 rounded-full bg-surface-50 flex items-center justify-center mb-4">
                        <Play className="w-6 h-6 text-surface-200" aria-hidden="true" />
                      </div>
                      <span className="text-xs font-medium">Click &ldquo;Send Request&rdquo; to see the sandboxed response</span>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'webhook' && (
                <div role="tabpanel" id="panel-webhook" aria-labelledby="tab-webhook">
                  <p className="text-xs text-surface-500 mb-3">Simulated events — times shown in {timezone}</p>
                  {webhooks.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-64 text-surface-400 text-center">
                      <div className="w-12 h-12 rounded-full bg-surface-50 flex items-center justify-center mb-4 animate-pulse">
                        <Send className="w-6 h-6 text-surface-200" />
                      </div>
                      <span className="text-xs font-medium">Simulated webhook events will appear here</span>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {webhooks.map((webhook) => (
                        <motion.div
                          key={webhook.id}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          className="bg-surface-50 border border-surface-100 rounded-lg p-4"
                        >
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-primary-600 font-mono text-xs font-semibold">{webhook.type}</span>
                            <span className="text-xs font-medium text-surface-600 tabular-nums">
                              {formatTime(webhook.timestamp, { second: '2-digit' })}
                            </span>
                          </div>
                          <pre className="text-xs text-surface-500 font-mono bg-white p-2 rounded border border-surface-200 overflow-auto">
                            {JSON.stringify(webhook.data, null, 2)}
                          </pre>
                        </motion.div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Right Panel - Preview */}
            <div className="p-6 bg-surface-50/50 min-h-[400px]">
              <div className="text-xs font-medium text-surface-500 mb-4">Email Live Preview</div>
              <div className="bg-white border border-surface-200 rounded-lg overflow-hidden shadow-sm">
                <div className="bg-surface-50 px-4 py-3 border-b border-surface-200">
                  <div className="text-xs text-surface-500 font-medium">
                    <strong className="text-surface-900 text-xs mr-2">To:</strong> {requestBody.to}
                  </div>
                  <div className="text-xs text-surface-500 font-medium mt-1">
                    <strong className="text-surface-900 text-xs mr-2">Subject:</strong> {requestBody.subject}
                  </div>
                </div>
                {/* XSS Protection: render sanitized HTML in a sandboxed iframe */}
                <iframe
                  className="w-full min-h-[220px] border-0 p-0"
                  sandbox=""
                  srcDoc={sanitizeHtml(requestBody.html)}
                  title="Email preview"
                />
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
