'use client';

import { useEffect, useRef, useState } from 'react';
import { Bot, Loader2, Send, X } from '@/components/ui/icons';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

async function apiCall<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...options?.headers },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ message: res.statusText }));
    throw new Error(err.error?.message || err.message || 'API error');
  }
  return res.json();
}

function findLocalAnswer(text: string): string | null {
  const lower = text.toLowerCase();
  const kb: [string[], string][] = [
    [['domain', 'verify', 'dns', 'spf', 'dkim', 'dmarc'], 'To verify your sending domain, go to Settings → Domains, add your domain, and configure the DNS records shown (SPF, DKIM, DMARC). Verification typically takes a few minutes.'],
    [['rate limit', 'sending limit', 'throttl'], 'Rate limits depend on your plan. Free: 100/day, Starter: 10K/day, Pro: 50K/day, Enterprise: custom. Check Dashboard for usage.'],
    [['bounce', 'bounced'], 'ApexMail auto-processes bounces and adds hard-bounced addresses to suppressions. View in Reports → Bounces.'],
    [['webhook', 'event'], 'Set up webhooks in Settings → API & Webhooks. Add your endpoint URL and select events.'],
    [['api key', 'token', 'auth'], 'Manage API keys in Settings → API & Webhooks. Use Authorization: Bearer <key> header.'],
    [['billing', 'invoice', 'payment', 'plan'], 'Manage billing in the Billing page. View invoices, update payments, change plans.'],
    [['template', 'html', 'design'], 'ApexMail supports HTML, MJML, and text templates. Use {{variableName}} for personalization.'],
    [['unsubscribe', 'opt-out'], 'List-Unsubscribe headers are auto-added. Unsubscribed contacts won\'t receive further emails.'],
    [['campaign', 'bulk', 'mass'], 'Create campaigns: select template → choose list → configure sender → schedule or send.'],
    [['deliverability', 'spam', 'reputation'], 'Improve deliverability: verify domain, warm up IPs, clean lists, keep complaints <0.1%.'],
  ];
  for (const [keywords, answer] of kb) {
    if (keywords.some(kw => lower.includes(kw))) return answer;
  }
  return null;
}

export function SupportChatbotWidget({ onCreateTicket }: { onCreateTicket: () => void }) {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<{ role: 'user' | 'bot'; content: string }[]>([
    { role: 'bot', content: 'Hi! 👋 I\'m the ApexMail support bot. Ask me about domains, deliverability, billing, templates, and more!' },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => { chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  async function sendMessage() {
    if (!input.trim() || loading) return;
    const question = input.trim();
    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: question }]);
    setLoading(true);

    try {
      const res = await apiCall<{ reply: string; escalated: boolean }>('/v1/support/tickets/chatbot-general', {
        method: 'POST',
        body: JSON.stringify({ question }),
      });
      setMessages(prev => [...prev, {
        role: 'bot',
        content: res.escalated ? `${res.reply}\n\nWould you like me to create a support ticket for you?` : res.reply,
      }]);
    } catch {
      const answer = findLocalAnswer(question);
      setMessages(prev => [...prev, {
        role: 'bot',
        content: answer || "I couldn't find an answer to that. Would you like to create a support ticket so our team can help?",
      }]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="fixed bottom-6 right-6 z-50 h-14 w-14 rounded-full bg-primary text-primary-foreground shadow-lg hover:bg-primary/90 transition-all flex items-center justify-center"
        aria-label="Toggle chat"
      >
        {isOpen ? <X className="h-6 w-6" /> : <Bot className="h-6 w-6" />}
      </button>

      {isOpen && (
        <div className="fixed bottom-24 right-6 z-50 w-96 max-w-[calc(100vw-3rem)] bg-card border border-border rounded-2xl shadow-2xl flex flex-col overflow-hidden h-[480px]">
          <div className="bg-primary text-primary-foreground px-4 py-3 flex items-center gap-3">
            <Bot className="h-5 w-5" />
            <div>
              <div className="font-semibold text-sm">ApexMail Support Bot</div>
              <div className="text-xs opacity-80">Ask me anything</div>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-4 space-y-3">
            {messages.map((msg, i) => (
              <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[80%] rounded-2xl px-4 py-2.5 text-sm ${
                  msg.role === 'user'
                    ? 'bg-primary text-primary-foreground rounded-br-md'
                    : 'bg-muted text-foreground rounded-bl-md'
                }`}>
                  <p className="whitespace-pre-wrap">{msg.content}</p>
                </div>
              </div>
            ))}
            {loading && (
              <div className="flex justify-start">
                <div className="bg-muted rounded-2xl rounded-bl-md px-4 py-2.5">
                  <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                </div>
              </div>
            )}
            <div ref={chatEndRef} />
          </div>

          <div className="border-t border-border p-3 space-y-2">
            <div className="flex items-center gap-2">
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && sendMessage()}
                placeholder="Ask a question..."
                className="flex-1 px-3 py-2 text-sm border border-input rounded-lg bg-background focus:outline-none focus:ring-2 focus:ring-primary/20"
              />
              <button
                onClick={sendMessage}
                disabled={!input.trim() || loading}
                className="p-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 transition-colors"
              >
                <Send className="h-4 w-4" />
              </button>
            </div>
            <button
              onClick={() => { setIsOpen(false); onCreateTicket(); }}
              className="w-full text-center text-xs text-muted-foreground hover:text-primary transition-colors"
            >
              Can&apos;t find what you need? <span className="underline">Create a support ticket</span>
            </button>
          </div>
        </div>
      )}
    </>
  );
}
