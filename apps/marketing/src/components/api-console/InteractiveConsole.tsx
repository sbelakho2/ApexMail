'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { useState } from 'react';
import { Send, Clock, CheckCircle, Copy, Play } from 'lucide-react';
import { cn } from '@/lib/utils';
import DOMPurify from 'isomorphic-dompurify';

/**
 * Sanitize HTML to prevent XSS attacks
 * Uses DOMPurify with strict configuration
 */
function sanitizeHtml(html: string): string {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'br', 'strong', 'em', 'u', 'a', 'ul', 'ol', 'li', 'span', 'div', 'table', 'tr', 'td', 'th', 'thead', 'tbody', 'img'],
    ALLOWED_ATTR: ['href', 'src', 'alt', 'style', 'class', 'target', 'rel'],
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
  const [copied, setCopied] = useState(false);

  const [requestBody, setRequestBody] = useState({
    to: 'test@example.com',
    subject: 'Hello from ApexMail!',
    html: '<h1>Welcome!</h1><p>This is a test email.</p>',
  });

  const handleSend = async () => {
    setIsLoading(true);
    setActiveTab('response');

    // Simulate API call
    await new Promise((resolve) => setTimeout(resolve, 800));

    const mockResponse = {
      id: `msg_${Math.random().toString(36).slice(2, 11)}`,
      status: 'queued',
      to: requestBody.to,
      subject: requestBody.subject,
      created_at: new Date().toISOString(),
    };

    setResponse(mockResponse);
    setIsLoading(false);

    // Simulate webhooks
    setTimeout(() => {
      setWebhooks((prev) => [
        {
          id: `evt_${Math.random().toString(36).slice(2, 11)}`,
          type: 'email.sent',
          timestamp: new Date().toISOString(),
          data: { message_id: mockResponse.id, recipient: requestBody.to },
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
          data: { message_id: mockResponse.id, recipient: requestBody.to, mx_host: 'mx.example.com' },
        },
        ...prev,
      ]);
    }, 3000);
  };

  const copyCode = () => {
    const code = `curl -X POST https://api.apexmail.ee/v1/send \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '${JSON.stringify(requestBody, null, 2)}'`;
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section ref={ref} className="py-12 lg:py-20 relative bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="bg-white border border-surface-200 shadow-sm rounded-lg overflow-hidden"
        >
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 bg-white border-b border-surface-200">
            <div className="flex items-center gap-2">
              <div className="flex gap-1.5 mr-4">
                <div className="w-3 h-3 rounded-full bg-surface-200" />
                <div className="w-3 h-3 rounded-full bg-surface-200" />
                <div className="w-3 h-3 rounded-full bg-surface-200" />
              </div>
              <span className="text-xs font-bold text-surface-600 font-mono">POST /v1/send</span>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={copyCode}
                className="flex items-center gap-1 px-3 py-1 text-xs font-medium text-surface-500 hover:text-primary-600 transition-colors"
              >
                <Copy className="w-4 h-4" />
                {copied ? 'Copied!' : 'Copy cURL'}
              </button>
              <button
                onClick={handleSend}
                disabled={isLoading}
                className="btn-primary flex items-center gap-2 py-2 px-4 text-xs font-medium"
              >
                {isLoading ? (
                  <Clock className="w-4 h-4 animate-spin" />
                ) : (
                  <Play className="w-4 h-4" />
                )}
                Send Request
              </button>
            </div>
          </div>

          {/* Tabs */}
          <div className="flex bg-white px-6 border-b border-surface-200">
            {[
              { id: 'request', label: 'Request' },
              { id: 'response', label: 'Response' },
              { id: 'webhook', label: `Webhooks (${webhooks.length})` },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as TabType)}
                className={cn(
                  'px-4 py-3 text-xs font-medium transition-all border-b-2',
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
                <div className="space-y-4">
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
                <div>
                  {isLoading ? (
                    <div className="flex flex-col items-center justify-center h-64 text-surface-400">
                      <Clock className="w-8 h-8 animate-spin mb-4 text-primary-200" />
                      <span className="text-xs font-medium">Waiting for response...</span>
                    </div>
                  ) : response ? (
                    <div className="space-y-4">
                      <div className="flex items-center gap-2 text-emerald-600">
                        <CheckCircle className="w-5 h-5" strokeWidth={2} />
                        <span className="text-xs font-bold">200 OK</span>
                      </div>
                      <pre className="text-xs text-surface-300 font-mono bg-surface-900 p-4 rounded-lg overflow-auto shadow-inner border border-surface-800">
                        {JSON.stringify(response, null, 2)}
                      </pre>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center h-64 text-surface-400 text-center">
                      <div className="w-12 h-12 rounded-full bg-surface-50 flex items-center justify-center mb-4">
                        <Play className="w-6 h-6 text-surface-200" />
                      </div>
                      <span className="text-xs font-medium">Click "Send Request" to see the response</span>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'webhook' && (
                <div>
                  {webhooks.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-64 text-surface-400 text-center">
                      <div className="w-12 h-12 rounded-full bg-surface-50 flex items-center justify-center mb-4 animate-pulse">
                        <Send className="w-6 h-6 text-surface-200" />
                      </div>
                      <span className="text-xs font-medium">Webhooks will appear here in real-time</span>
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
                              {new Date(webhook.timestamp).toLocaleTimeString()}
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
                {/* XSS Protection: HTML is sanitized with DOMPurify before rendering */}
                <div
                  className="p-6 text-surface-900"
                  dangerouslySetInnerHTML={{ __html: sanitizeHtml(requestBody.html) }}
                />
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
