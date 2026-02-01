'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { useState } from 'react';
import { Send, Clock, CheckCircle, AlertCircle, Copy, Play } from 'lucide-react';

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
    const code = `curl -X POST https://api.apexmail.io/v1/send \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '${JSON.stringify(requestBody, null, 2)}'`;
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section ref={ref} className="py-12 lg:py-20 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="glass-card overflow-hidden"
        >
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 bg-surface-800 border-b border-surface-700">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-red-500" />
              <div className="w-3 h-3 rounded-full bg-yellow-500" />
              <div className="w-3 h-3 rounded-full bg-green-500" />
              <span className="ml-4 text-sm text-surface-400">POST /v1/send</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={copyCode}
                className="flex items-center gap-1 px-3 py-1 text-sm text-surface-400 hover:text-white transition-colors"
              >
                <Copy className="w-4 h-4" />
                {copied ? 'Copied!' : 'Copy cURL'}
              </button>
              <button
                onClick={handleSend}
                disabled={isLoading}
                className="flex items-center gap-2 px-4 py-1.5 bg-cyan-600 text-white text-sm rounded-lg hover:bg-cyan-500 transition-colors disabled:opacity-50"
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
          <div className="flex border-b border-surface-700">
            {[
              { id: 'request', label: 'Request' },
              { id: 'response', label: 'Response' },
              { id: 'webhook', label: `Webhooks (${webhooks.length})` },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as TabType)}
                className={`px-4 py-2 text-sm font-medium transition-colors ${
                  activeTab === tab.id
                    ? 'text-cyan-400 border-b-2 border-cyan-400'
                    : 'text-surface-400 hover:text-white'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Content */}
          <div className="grid lg:grid-cols-2 gap-0">
            {/* Left Panel - Editor */}
            <div className="p-4 border-r border-surface-700">
              {activeTab === 'request' && (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm text-surface-400 mb-1">To</label>
                    <input
                      type="email"
                      value={requestBody.to}
                      onChange={(e) => setRequestBody({ ...requestBody, to: e.target.value })}
                      className="w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-lg text-white text-sm focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-surface-400 mb-1">Subject</label>
                    <input
                      type="text"
                      value={requestBody.subject}
                      onChange={(e) => setRequestBody({ ...requestBody, subject: e.target.value })}
                      className="w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-lg text-white text-sm focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-surface-400 mb-1">HTML Body</label>
                    <textarea
                      value={requestBody.html}
                      onChange={(e) => setRequestBody({ ...requestBody, html: e.target.value })}
                      rows={6}
                      className="w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-lg text-white text-sm font-mono focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>
              )}

              {activeTab === 'response' && (
                <div>
                  {isLoading ? (
                    <div className="flex items-center justify-center h-48 text-surface-500">
                      <Clock className="w-6 h-6 animate-spin mr-2" />
                      Sending...
                    </div>
                  ) : response ? (
                    <div className="space-y-4">
                      <div className="flex items-center gap-2 text-green-400">
                        <CheckCircle className="w-5 h-5" />
                        <span className="font-medium">200 OK</span>
                      </div>
                      <pre className="text-sm text-surface-300 font-mono bg-surface-900 p-4 rounded-lg overflow-auto">
                        {JSON.stringify(response, null, 2)}
                      </pre>
                    </div>
                  ) : (
                    <div className="flex items-center justify-center h-48 text-surface-500">
                      Click "Send Request" to see the response
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'webhook' && (
                <div>
                  {webhooks.length === 0 ? (
                    <div className="flex items-center justify-center h-48 text-surface-500">
                      Webhooks will appear here in real-time
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {webhooks.map((webhook) => (
                        <motion.div
                          key={webhook.id}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          className="bg-surface-800/50 rounded-lg p-3"
                        >
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-cyan-400 font-mono text-sm">{webhook.type}</span>
                            <span className="text-xs text-surface-500">
                              {new Date(webhook.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                          <pre className="text-xs text-surface-400 font-mono">
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
            <div className="p-4 bg-white min-h-[400px]">
              <div className="text-xs text-gray-500 mb-2">Email Preview</div>
              <div className="border border-gray-200 rounded-lg overflow-hidden">
                <div className="bg-gray-100 px-3 py-2 border-b border-gray-200">
                  <div className="text-sm text-gray-600">
                    <strong>To:</strong> {requestBody.to}
                  </div>
                  <div className="text-sm text-gray-600">
                    <strong>Subject:</strong> {requestBody.subject}
                  </div>
                </div>
                <div
                  className="p-4"
                  dangerouslySetInnerHTML={{ __html: requestBody.html }}
                />
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
