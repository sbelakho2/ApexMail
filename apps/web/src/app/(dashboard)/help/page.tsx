'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import {
  BookOpen, MessageSquare, Mail, Zap, Shield, Key, Plus,
  Send, Bot, ChevronDown, ChevronRight, ArrowLeft, Clock,
  AlertCircle, CheckCircle2, Loader2, Tag, X
} from 'lucide-react';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

type TicketStatus = 'open' | 'in_progress' | 'waiting_on_customer' | 'resolved' | 'closed';
type TicketPriority = 'low' | 'medium' | 'high' | 'urgent';
type TicketCategory = 'billing' | 'technical' | 'feature_request' | 'bug' | 'general';

interface TicketMessage {
  id: string;
  content: string;
  author: string;
  authorType: 'customer' | 'support' | 'bot';
  createdAt: string;
  attachments: string[];
}

interface Ticket {
  id: string;
  subject: string;
  description: string;
  status: TicketStatus;
  priority: TicketPriority;
  category: TicketCategory;
  createdAt: string;
  updatedAt: string;
  messages: TicketMessage[];
}

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const STATUS_CONFIG: Record<TicketStatus, { label: string; color: string; icon: typeof CheckCircle2 }> = {
  open: { label: 'Open', color: 'text-blue-600 bg-blue-50 dark:bg-blue-500/10', icon: AlertCircle },
  in_progress: { label: 'In Progress', color: 'text-amber-600 bg-amber-50 dark:bg-amber-500/10', icon: Loader2 },
  waiting_on_customer: { label: 'Waiting on You', color: 'text-purple-600 bg-purple-50 dark:bg-purple-500/10', icon: Clock },
  resolved: { label: 'Resolved', color: 'text-green-600 bg-green-50 dark:bg-green-500/10', icon: CheckCircle2 },
  closed: { label: 'Closed', color: 'text-gray-500 bg-gray-100 dark:bg-gray-500/10', icon: CheckCircle2 },
};

const CATEGORY_OPTIONS: { value: TicketCategory; label: string; description: string }[] = [
  { value: 'technical', label: 'Technical Issue', description: 'API errors, integration problems, email delivery' },
  { value: 'billing', label: 'Billing & Account', description: 'Payments, invoices, plan changes, refunds' },
  { value: 'bug', label: 'Bug Report', description: 'Something is broken or not working as expected' },
  { value: 'feature_request', label: 'Feature Request', description: 'Suggest a new feature or improvement' },
  { value: 'general', label: 'General Inquiry', description: 'Other questions or feedback' },
];

const PRIORITY_OPTIONS: { value: TicketPriority; label: string; color: string }[] = [
  { value: 'low', label: 'Low', color: 'text-gray-500' },
  { value: 'medium', label: 'Medium', color: 'text-blue-600' },
  { value: 'high', label: 'High', color: 'text-orange-600' },
  { value: 'urgent', label: 'Urgent', color: 'text-red-600' },
];

const resources = [
  { icon: BookOpen, title: 'Documentation', description: 'Comprehensive guides for API integration and setup.', href: '/docs', color: 'text-primary bg-primary/10' },
  { icon: Key, title: 'API Reference', description: 'Full REST API documentation with request/response examples.', href: '/docs/api', color: 'text-success bg-success/10' },
  { icon: Zap, title: 'Quick Start Guide', description: 'Get up and running with ApexMail in under 5 minutes.', href: '/docs/quickstart', color: 'text-warning bg-warning/10' },
  { icon: Shield, title: 'Security & Compliance', description: 'SPF, DKIM, DMARC setup and compliance best practices.', href: '/docs/security', color: 'text-info bg-info/10' },
];

const faqs = [
  { q: 'How do I verify my sending domain?', a: 'Go to Settings → Domains, add your domain, and configure the DNS records shown (SPF, DKIM, DMARC). Verification typically takes a few minutes.' },
  { q: 'What is the sending rate limit?', a: 'Rate limits depend on your plan. Free tier: 100 emails/day. Pro: 50,000/day. Enterprise: custom limits. Check your plan details in Billing.' },
  { q: 'How do I handle bounces?', a: 'ApexMail automatically processes bounces and adds hard-bounced addresses to your suppression list. View them in the Compliance section.' },
  { q: 'Can I use a custom SMTP server?', a: 'ApexMail includes its own SMTP infrastructure with DKIM signing. You don\'t need a third-party SMTP service.' },
  { q: 'How do I set up webhooks?', a: 'Go to Settings → API & Webhooks. Add a webhook endpoint URL and select the events you want to receive (delivered, opened, clicked, bounced, etc.).' },
];

/* ------------------------------------------------------------------ */
/*  API helpers                                                        */
/* ------------------------------------------------------------------ */

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

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

/* ------------------------------------------------------------------ */
/*  Local chatbot fallback KB                                          */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/*  Chatbot Widget                                                     */
/* ------------------------------------------------------------------ */

function ChatbotWidget({ onCreateTicket }: { onCreateTicket: () => void }) {
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
        <div className="fixed bottom-24 right-6 z-50 w-96 max-w-[calc(100vw-3rem)] bg-card border border-border rounded-2xl shadow-2xl flex flex-col overflow-hidden" style={{ height: '480px' }}>
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
            <div className="flex gap-2">
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

/* ------------------------------------------------------------------ */
/*  Create Ticket Dialog                                               */
/* ------------------------------------------------------------------ */

function CreateTicketDialog({
  isOpen, onClose, onCreated,
}: {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (ticket: Ticket) => void;
}) {
  const [subject, setSubject] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState<TicketCategory | ''>('');
  const [priority, setPriority] = useState<TicketPriority>('medium');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (!subject.trim() || subject.trim().length < 5) { setError('Subject must be at least 5 characters'); return; }
    if (!category) { setError('Please select a category'); return; }
    if (!description.trim() || description.trim().length < 10) { setError('Description must be at least 10 characters'); return; }

    setSubmitting(true);
    try {
      const result = await apiCall<{ ticket: Ticket }>('/v1/support/tickets', {
        method: 'POST',
        body: JSON.stringify({ subject: subject.trim(), description: description.trim(), category, priority }),
      });
      onCreated(result.ticket);
      onClose();
      setSubject(''); setDescription(''); setCategory(''); setPriority('medium');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create ticket');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-card border border-border rounded-2xl shadow-2xl w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold">Create Support Ticket</h2>
            <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1"><X className="h-5 w-5" /></button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-sm font-medium mb-1.5">Subject <span className="text-destructive">*</span></label>
              <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Brief summary of your issue..." maxLength={200}
                className="w-full px-3 py-2.5 border border-input rounded-lg text-sm bg-background focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary" />
              <p className="text-xs text-muted-foreground mt-1">{subject.length}/200 characters (min 5)</p>
            </div>

            <div>
              <label className="block text-sm font-medium mb-1.5">Category <span className="text-destructive">*</span></label>
              <div className="grid gap-2">
                {CATEGORY_OPTIONS.map(opt => (
                  <button key={opt.value} type="button" onClick={() => setCategory(opt.value)}
                    className={`w-full text-left p-3 border rounded-lg transition-all ${category === opt.value ? 'border-primary bg-primary/5 ring-2 ring-primary/20' : 'border-input hover:border-primary/30 bg-background'}`}>
                    <div className="font-medium text-sm">{opt.label}</div>
                    <div className="text-xs text-muted-foreground">{opt.description}</div>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium mb-1.5">Priority</label>
              <div className="flex gap-2">
                {PRIORITY_OPTIONS.map(opt => (
                  <button key={opt.value} type="button" onClick={() => setPriority(opt.value)}
                    className={`flex-1 px-3 py-2 border rounded-lg text-sm font-medium transition-all ${priority === opt.value ? 'border-primary bg-primary/5 ring-2 ring-primary/20' : 'border-input hover:border-primary/30 bg-background'} ${opt.color}`}>
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium mb-1.5">Description <span className="text-destructive">*</span></label>
              <textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Describe your issue in detail..." rows={5} maxLength={5000}
                className="w-full px-3 py-2.5 border border-input rounded-lg text-sm bg-background focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary resize-none" />
              <p className="text-xs text-muted-foreground mt-1">{description.length}/5000 characters (min 10)</p>
            </div>

            {error && (
              <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-lg text-sm text-destructive flex items-center gap-2">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />{error}
              </div>
            )}

            <div className="flex justify-end gap-3 pt-2">
              <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
              <Button type="submit" disabled={submitting}>
                {submitting ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Creating...</> : <><Plus className="h-4 w-4 mr-2" />Create Ticket</>}
              </Button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Ticket Detail View                                                 */
/* ------------------------------------------------------------------ */

function TicketDetailView({ ticket, onBack, onRefresh }: { ticket: Ticket; onBack: () => void; onRefresh: () => void }) {
  const [replyContent, setReplyContent] = useState('');
  const [sending, setSending] = useState(false);
  const [messages, setMessages] = useState(ticket.messages);
  const [ticketStatus, setTicketStatus] = useState<TicketStatus>(ticket.status);
  const [closing, setClosing] = useState(false);
  const [reopening, setReopening] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setMessages(ticket.messages);
    setTicketStatus(ticket.status);
  }, [ticket.id, ticket.messages, ticket.status]);

  useEffect(() => { messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  async function sendReply() {
    if (!replyContent.trim() || sending) return;
    setSending(true);
    try {
      const result = await apiCall<{ message: TicketMessage; botReply?: TicketMessage }>(
        `/v1/support/tickets/${ticket.id}/messages`,
        { method: 'POST', body: JSON.stringify({ content: replyContent.trim() }) }
      );
      const newMsgs = [result.message];
      if (result.botReply) newMsgs.push(result.botReply);
      setMessages(prev => [...prev, ...newMsgs]);
      setReplyContent('');
      onRefresh();
    } catch (err) {
      console.error('Failed to send reply:', err);
    } finally {
      setSending(false);
    }
  }

  async function closeTicket() {
    if (ticketStatus === 'closed' || closing) return;
    if (!window.confirm('Close this ticket? You can create a new ticket if you need more help.')) return;

    setClosing(true);
    try {
      const result = await apiCall<{ ticket: Ticket }>(
        `/v1/support/tickets/${ticket.id}/close`,
        { method: 'POST', body: JSON.stringify({}) }
      );
      setMessages(result.ticket.messages ?? []);
      setTicketStatus(result.ticket.status);
      onRefresh();
    } catch (err) {
      console.error('Failed to close ticket:', err);
    } finally {
      setClosing(false);
    }
  }

  async function reopenTicket() {
    if (ticketStatus !== 'closed' || reopening) return;
    if (!window.confirm('Reopen this ticket?')) return;

    setReopening(true);
    try {
      const result = await apiCall<{ ticket: Ticket }>(
        `/v1/support/tickets/${ticket.id}/reopen`,
        { method: 'POST', body: JSON.stringify({}) }
      );
      setMessages(result.ticket.messages ?? []);
      setTicketStatus(result.ticket.status);
      onRefresh();
    } catch (err) {
      console.error('Failed to reopen ticket:', err);
    } finally {
      setReopening(false);
    }
  }

  const status = STATUS_CONFIG[ticketStatus];
  const StatusIcon = status.icon;

  return (
    <Card className="overflow-hidden">
        <div className="p-4 border-b border-border">
          <div className="flex items-center justify-between gap-3 mb-3">
            <button onClick={onBack} className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground transition-colors">
              <ArrowLeft className="h-4 w-4" />Back to tickets
            </button>
            {ticketStatus === 'closed' ? (
              <Button variant="outline" onClick={reopenTicket} disabled={reopening}>
                {reopening ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
                Reopen Ticket
              </Button>
            ) : (
              <Button variant="outline" onClick={closeTicket} disabled={closing}>
                {closing ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
                Close Ticket
              </Button>
            )}
          </div>
          <h2 className="text-lg font-semibold">{ticket.subject}</h2>
        <div className="flex flex-wrap items-center gap-2 mt-2">
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${status.color}`}>
            <StatusIcon className="h-3 w-3" />{status.label}
          </span>
          <span className="px-2.5 py-1 rounded-full text-xs font-medium bg-muted text-muted-foreground">
            <Tag className="h-3 w-3 inline mr-1" />{CATEGORY_OPTIONS.find(c => c.value === ticket.category)?.label ?? ticket.category}
          </span>
          <span className="text-xs text-muted-foreground">Created {timeAgo(ticket.createdAt)}</span>
        </div>
      </div>

      <div className="p-4 space-y-4 max-h-[500px] overflow-y-auto bg-muted/20">
        {messages.map(msg => (
          <div key={msg.id} className={`flex ${msg.authorType === 'customer' ? 'justify-end' : 'justify-start'}`}>
            <div className={`max-w-[80%] rounded-2xl px-4 py-3 ${
              msg.authorType === 'customer' ? 'bg-primary text-primary-foreground rounded-br-md'
                : msg.authorType === 'bot' ? 'bg-amber-50 dark:bg-amber-500/10 text-foreground border border-amber-200 dark:border-amber-500/20 rounded-bl-md'
                : 'bg-card text-foreground border border-border rounded-bl-md'
            }`}>
              <div className="flex items-center gap-2 mb-1">
                <span className={`text-xs font-medium ${msg.authorType === 'customer' ? 'opacity-80' : 'text-muted-foreground'}`}>
                  {msg.authorType === 'bot' && <Bot className="h-3 w-3 inline mr-1" />}{msg.author}
                </span>
                <span className={`text-xs ${msg.authorType === 'customer' ? 'opacity-60' : 'text-muted-foreground'}`}>{timeAgo(msg.createdAt)}</span>
              </div>
              <p className="text-sm whitespace-pre-wrap">{msg.content}</p>
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      {ticketStatus !== 'closed' && (
        <div className="p-4 border-t border-border">
          <div className="flex gap-2">
            <textarea value={replyContent} onChange={(e) => setReplyContent(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendReply(); } }}
              placeholder="Type your reply... (Enter to send)" rows={2}
              className="flex-1 px-3 py-2 border border-input rounded-lg text-sm bg-background focus:outline-none focus:ring-2 focus:ring-primary/20 resize-none" />
            <Button onClick={sendReply} disabled={!replyContent.trim() || sending} className="self-end">
              {sending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
            </Button>
          </div>
        </div>
      )}
    </Card>
  );
}

/* ------------------------------------------------------------------ */
/*  Main Help Page                                                     */
/* ------------------------------------------------------------------ */

export default function HelpPage() {
  const [activeTab, setActiveTab] = useState<'help' | 'tickets'>('help');
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [loadingTickets, setLoadingTickets] = useState(false);
  const [loadingTicketDetail, setLoadingTicketDetail] = useState(false);
  const [selectedTicket, setSelectedTicket] = useState<Ticket | null>(null);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [expandedFaq, setExpandedFaq] = useState<number | null>(null);

  const loadTickets = useCallback(async () => {
    setLoadingTickets(true);
    try {
      const result = await apiCall<{ tickets: Ticket[]; pagination: { total: number } }>('/v1/support/tickets');
      setTickets(result.tickets.map(ticket => ({ ...ticket, messages: ticket.messages ?? [] })));
    } catch (err) {
      console.error('Failed to load tickets:', err);
    } finally {
      setLoadingTickets(false);
    }
  }, []);

  const openTicket = useCallback(async (ticketId: string) => {
    setLoadingTicketDetail(true);
    setSelectedTicket(null);
    try {
      const result = await apiCall<{ ticket: Ticket }>(`/v1/support/tickets/${ticketId}`);
      setSelectedTicket({ ...result.ticket, messages: result.ticket.messages ?? [] });
    } catch (err) {
      console.error('Failed to load ticket details:', err);
    } finally {
      setLoadingTicketDetail(false);
    }
  }, []);

  useEffect(() => { if (activeTab === 'tickets') loadTickets(); }, [activeTab, loadTickets]);

  function handleTicketCreated(ticket: Ticket) {
    setTickets(prev => [ticket, ...prev]);
    setActiveTab('tickets');
    setSelectedTicket(ticket);
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Help & Support"
        description="Get help, ask our bot, or create a support ticket."
        breadcrumbs={[{ label: 'Help & Support' }]}
      />

      {/* Tab bar */}
      <div className="flex items-center gap-1 bg-muted p-1 rounded-lg w-fit">
        <button onClick={() => { setActiveTab('help'); setSelectedTicket(null); }}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${activeTab === 'help' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}>
          <BookOpen className="h-4 w-4 inline mr-2" />Help Center
        </button>
        <button onClick={() => setActiveTab('tickets')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${activeTab === 'tickets' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}>
          <MessageSquare className="h-4 w-4 inline mr-2" />My Tickets
          {tickets.length > 0 && (
            <span className="ml-2 bg-primary/10 text-primary px-2 py-0.5 rounded-full text-xs">
              {tickets.filter(t => t.status !== 'closed' && t.status !== 'resolved').length}
            </span>
          )}
        </button>
      </div>

      {/* Help Center tab */}
      {activeTab === 'help' && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {resources.map(r => (
              <Card key={r.title} className="hover:border-primary/30 transition-colors cursor-pointer" role="button" tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') window.location.href = r.href; }}>
                <CardContent className="p-6">
                  <div className={`inline-flex rounded-lg p-3 ${r.color} mb-4`}><r.icon className="h-5 w-5" /></div>
                  <h3 className="font-semibold mb-1">{r.title}</h3>
                  <p className="text-sm text-muted-foreground">{r.description}</p>
                </CardContent>
              </Card>
            ))}
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Frequently Asked Questions</CardTitle>
              <CardDescription>Quick answers to common questions</CardDescription>
            </CardHeader>
            <CardContent className="space-y-0">
              {faqs.map((faq, i) => (
                <div key={i}>
                  {i > 0 && <Separator className="my-2" />}
                  <button onClick={() => setExpandedFaq(expandedFaq === i ? null : i)} className="w-full text-left py-3 flex items-start justify-between gap-4 group">
                    <h4 className="font-medium text-sm group-hover:text-primary transition-colors">{faq.q}</h4>
                    {expandedFaq === i ? <ChevronDown className="h-4 w-4 flex-shrink-0 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 flex-shrink-0 text-muted-foreground" />}
                  </button>
                  {expandedFaq === i && <p className="text-sm text-muted-foreground pb-3">{faq.a}</p>}
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardContent className="flex flex-col sm:flex-row items-center justify-between gap-4 p-6">
              <div className="flex items-center gap-4">
                <div className="rounded-lg bg-primary/10 p-3"><MessageSquare className="h-6 w-6 text-primary" /></div>
                <div>
                  <h3 className="font-semibold">Need more help?</h3>
                  <p className="text-sm text-muted-foreground">Create a ticket or chat with our support bot.</p>
                </div>
              </div>
              <div className="flex gap-3">
                <Button variant="outline" onClick={() => setActiveTab('tickets')}><Mail className="mr-2 h-4 w-4" />View Tickets</Button>
                <Button onClick={() => setShowCreateDialog(true)}><Plus className="mr-2 h-4 w-4" />New Ticket</Button>
              </div>
            </CardContent>
          </Card>
        </>
      )}

      {/* My Tickets tab */}
      {activeTab === 'tickets' && (
        loadingTicketDetail ? (
          <div className="flex items-center justify-center h-48"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>
        ) : selectedTicket ? (
          <TicketDetailView ticket={selectedTicket} onBack={() => setSelectedTicket(null)} onRefresh={loadTickets} />
        ) : (
          <>
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">Your Support Tickets</h2>
              <Button onClick={() => setShowCreateDialog(true)}><Plus className="h-4 w-4 mr-2" />New Ticket</Button>
            </div>

            {loadingTickets ? (
              <div className="flex items-center justify-center h-48"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>
            ) : tickets.length === 0 ? (
              <Card>
                <CardContent className="flex flex-col items-center justify-center py-16">
                  <MessageSquare className="h-12 w-12 text-muted-foreground/30 mb-4" />
                  <h3 className="font-semibold text-lg mb-1">No tickets yet</h3>
                  <p className="text-muted-foreground text-sm mb-4">Create a ticket to get help from our support team.</p>
                  <Button onClick={() => setShowCreateDialog(true)}><Plus className="h-4 w-4 mr-2" />Create Your First Ticket</Button>
                </CardContent>
              </Card>
            ) : (
              <div className="space-y-3">
                {tickets.map(ticket => {
                  const cfg = STATUS_CONFIG[ticket.status];
                  const StatusIcon = cfg.icon;
                  return (
                      <button key={ticket.id} onClick={() => openTicket(ticket.id)}
                      className="w-full text-left bg-card border border-border rounded-xl p-4 hover:border-primary/30 transition-all">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <h3 className="font-medium text-foreground truncate">{ticket.subject}</h3>
                          <div className="flex flex-wrap items-center gap-2 mt-2">
                            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${cfg.color}`}>
                              <StatusIcon className="h-3 w-3" />{cfg.label}
                            </span>
                            <span className="text-xs text-muted-foreground bg-muted px-2 py-0.5 rounded-full">
                              {CATEGORY_OPTIONS.find(c => c.value === ticket.category)?.label ?? ticket.category}
                            </span>
                          </div>
                        </div>
                        <div className="text-right flex-shrink-0">
                          <span className="text-xs text-muted-foreground">{timeAgo(ticket.updatedAt)}</span>
                            {ticket.messages?.length > 0 && (
                              <div className="text-xs text-muted-foreground mt-1">{ticket.messages.length} message{ticket.messages.length !== 1 ? 's' : ''}</div>
                            )}
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </>
        )
      )}

      <CreateTicketDialog isOpen={showCreateDialog} onClose={() => setShowCreateDialog(false)} onCreated={handleTicketCreated} />
      <ChatbotWidget onCreateTicket={() => setShowCreateDialog(true)} />
    </div>
  );
}
