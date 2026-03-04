'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import {
  BookOpen, MessageSquare, Mail, Zap, Shield, Key, Plus,
  ChevronDown, ChevronRight, ArrowLeft, Clock,
  AlertCircle, CheckCircle2, Loader2, Tag, Send, X
} from '@/components/ui/icons';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import { formatDate, sanitizeUserInput, getErrorMessage, reportClientError } from '@/lib/utils';
import { getCsrfToken } from '@/hooks/use-api';
import { SupportChatbotWidget } from './support-chatbot-widget';

/* ------------------------------------------------------------------ */
/*  API helper (with CSRF for mutations)                               */
/* ------------------------------------------------------------------ */

async function apiCall<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string> | undefined),
  };

  const method = (options?.method ?? 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') {
    const csrfToken = await getCsrfToken();
    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken;
    }
  }

  const res = await fetch(endpoint, {
    ...options,
    credentials: 'include',
    headers,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ message: res.statusText }));
    throw new Error(err.error?.message || err.message || 'API error');
  }

  return res.json();
}

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

const ASSISTANT_NAME = 'Ava';
const ASSISTANT_LABEL = 'Ava from ApexMail Support';
const ASSISTANT_FACE = '👩‍💼';

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
  { icon: BookOpen, title: 'Documentation', description: 'Comprehensive guides for API integration and setup.', href: 'https://docs.apexmail.ee', color: 'text-primary bg-primary/10' },
  { icon: Key, title: 'API Reference', description: 'Full REST API documentation with request/response examples.', href: 'https://docs.apexmail.ee/api', color: 'text-success bg-success/10' },
  { icon: Zap, title: 'Quick Start Guide', description: 'Get up and running with ApexMail in under 5 minutes.', href: 'https://docs.apexmail.ee/quickstart', color: 'text-warning bg-warning/10' },
  { icon: Shield, title: 'Security & Compliance', description: 'SPF, DKIM, DMARC setup and compliance best practices.', href: 'https://docs.apexmail.ee/security', color: 'text-info bg-info/10' },
];

const faqs = [
  { q: 'How do I verify my sending domain?', a: 'Go to Settings → Domains, add your domain, and configure the DNS records shown (SPF, DKIM, DMARC). Verification typically takes a few minutes.' },
  { q: 'What is the sending rate limit?', a: 'Rate limits depend on your plan. Free tier: 100 emails/day. Pro: 50,000/day. Enterprise: custom limits. Check your plan details in Billing.' },
  { q: 'How do I handle bounces?', a: 'ApexMail automatically processes bounces and adds hard-bounced addresses to your suppression list. View them in the Compliance section.' },
  { q: 'Can I use a custom SMTP server?', a: 'ApexMail includes its own SMTP infrastructure with DKIM signing. You don\'t need a third-party SMTP service.' },
  { q: 'How do I set up webhooks?', a: 'Go to Settings → API & Webhooks. Add a webhook endpoint URL and select the events you want to receive (delivered, opened, clicked, bounced, etc.).' },
];

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return formatDate(dateStr);
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
  const [attachments, setAttachments] = useState<File[]>([]);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [copyStatus, setCopyStatus] = useState('');
  const dialogRef = useRef<HTMLDivElement>(null);
  const lastFocusedElementRef = useRef<HTMLElement | null>(null);
  const draftKey = 'apexmail.help.create-ticket.draft';

  useEffect(() => {
    if (!isOpen) return;
    try {
      const raw = localStorage.getItem(draftKey);
      if (!raw) return;
      const draft = JSON.parse(raw) as { subject?: string; description?: string; category?: TicketCategory; priority?: TicketPriority };
      setSubject(draft.subject ?? '');
      setDescription(draft.description ?? '');
      setCategory(draft.category ?? '');
      setPriority(draft.priority ?? 'medium');
    } catch {
      // noop
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const timer = window.setTimeout(() => {
      try {
        localStorage.setItem(
          draftKey,
          JSON.stringify({ subject, description, category, priority })
        );
      } catch {
        // noop
      }
    }, 300);
    return () => window.clearTimeout(timer);
  }, [subject, description, category, priority, isOpen]);

  useEffect(() => {
    if (!isOpen) return;

    lastFocusedElementRef.current = document.activeElement as HTMLElement | null;
    const timer = window.setTimeout(() => {
      const focusables = dialogRef.current?.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      if (focusables && focusables.length > 0) {
        focusables[0].focus();
      } else {
        dialogRef.current?.focus();
      }
    }, 0);

    return () => {
      window.clearTimeout(timer);
      lastFocusedElementRef.current?.focus();
    };
  }, [isOpen]);

  if (!isOpen) return null;

  function handleDialogKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Escape') {
      onClose();
      return;
    }

    if (e.key !== 'Tab') return;

    const focusables = dialogRef.current?.querySelectorAll<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    if (!focusables || focusables.length === 0) {
      e.preventDefault();
      return;
    }

    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const active = document.activeElement;

    if (e.shiftKey && active === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && active === last) {
      e.preventDefault();
      first.focus();
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (!subject.trim() || subject.trim().length < 5) { setError('Subject must be at least 5 characters'); return; }
    if (!category) { setError('Please select a category'); return; }
    if (!description.trim() || description.trim().length < 10) { setError('Description must be at least 10 characters'); return; }
    if (attachments.length > 5) { setError('You can upload up to 5 attachments.'); return; }

    setSubmitting(true);
    setUploadProgress(10);
    try {
      const progressTimer = window.setInterval(() => {
        setUploadProgress((prev) => Math.min(prev + 15, 95));
      }, 200);

      const result = await apiCall<{ ticket: Ticket }>('/v1/support/tickets', {
        method: 'POST',
        body: JSON.stringify({
          subject: sanitizeUserInput(subject.trim(), 200),
          description: sanitizeUserInput(description.trim(), 5000),
          category,
          priority,
          attachments: attachments.map((file) => file.name),
        }),
      });
      window.clearInterval(progressTimer);
      setUploadProgress(100);
      onCreated(result.ticket);
      onClose();
      setSubject(''); setDescription(''); setCategory(''); setPriority('medium');
      setAttachments([]);
      setUploadProgress(0);
      localStorage.removeItem(draftKey);
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to create ticket'));
      reportClientError(err, 'CreateTicketDialog.handleSubmit');
      setUploadProgress(0);
    } finally {
      setSubmitting(false);
    }
  }

  function handleAttachmentChange(files: FileList | null) {
    if (!files) return;
    const allowed = ['image/png', 'image/jpeg', 'application/pdf', 'text/plain'];
    const maxSize = 5 * 1024 * 1024;
    const accepted: File[] = [];

    for (const file of Array.from(files)) {
      if (!allowed.includes(file.type)) {
        setError(`Unsupported file type: ${file.name}`);
        continue;
      }
      if (file.size > maxSize) {
        setError(`File too large: ${file.name}. Max size is 5MB.`);
        continue;
      }
      accepted.push(file);
    }

    setAttachments((prev) => [...prev, ...accepted].slice(0, 5));
  }

  async function copyDiagnosticBundle() {
    const bundle = {
      subject,
      category,
      priority,
      url: window.location.href,
      userAgent: navigator.userAgent,
      timestamp: new Date().toISOString(),
    };
    try {
      await navigator.clipboard.writeText(JSON.stringify(bundle, null, 2));
      setCopyStatus('Diagnostic bundle copied.');
    } catch {
      setCopyStatus('Failed to copy diagnostic bundle.');
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="create-ticket-title"
      onKeyDown={handleDialogKeyDown}
      tabIndex={-1}
    >
      <div
        ref={dialogRef}
        className="bg-card border border-border rounded-2xl shadow-2xl w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}
        tabIndex={-1}
      >
        <div className="p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 id="create-ticket-title" className="text-xl font-semibold">Create Support Ticket</h2>
            <button onClick={onClose} aria-label="Close create ticket modal" className="text-muted-foreground hover:text-foreground p-1"><X className="h-5 w-5" /></button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-sm font-medium mb-1.5">Subject <span className="text-destructive">*</span></label>
              <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Brief summary of your issue..." maxLength={200}
                className="w-full px-3 py-2.5 border border-input rounded-lg text-sm bg-background focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary" />
              <p className={`text-xs mt-1 ${subject.length > 160 ? 'text-warning' : 'text-muted-foreground'}`}>{subject.length}/200 characters (min 5)</p>
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
              <div className="flex items-center gap-2">
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
              <p className={`text-xs mt-1 ${description.length > 4000 ? 'text-warning' : 'text-muted-foreground'}`}>{description.length}/5000 characters (min 10)</p>
            </div>

            <div>
              <label className="block text-sm font-medium mb-1.5">Attachments</label>
              <input
                type="file"
                multiple
                onChange={(e) => handleAttachmentChange(e.target.files)}
                className="w-full text-sm"
                accept=".png,.jpg,.jpeg,.pdf,.txt"
              />
              {attachments.length > 0 ? (
                <p className="text-xs text-muted-foreground mt-1">{attachments.length} file(s) attached</p>
              ) : null}
              {uploadProgress > 0 ? (
                <p className="text-xs text-muted-foreground mt-1">Upload progress: {uploadProgress}%</p>
              ) : null}
            </div>

            <div className="flex items-center justify-between rounded-lg border border-border p-3">
              <span className="text-sm text-muted-foreground">Need support diagnostics?</span>
              <Button type="button" variant="outline" size="sm" onClick={copyDiagnosticBundle}>Copy Diagnostic Bundle</Button>
            </div>
            {copyStatus ? <p className="text-xs text-muted-foreground">{copyStatus}</p> : null}

            {error && (
              <div role="alert" aria-live="assertive" className="p-3 bg-destructive/10 border border-destructive/20 rounded-lg text-sm text-destructive flex items-center gap-2">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />{error}
              </div>
            )}

            <div className="flex items-center justify-end gap-3 pt-2">
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
  const [replyNotice, setReplyNotice] = useState('');
  const [confirmAction, setConfirmAction] = useState<'close' | 'reopen' | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const latestMessageIdRef = useRef<string | null>(null);

  useEffect(() => {
    setMessages(ticket.messages);
    setTicketStatus(ticket.status);
  }, [ticket.id, ticket.messages, ticket.status]);

  useEffect(() => { messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  useEffect(() => {
    const latest = messages[messages.length - 1];
    if (!latest) return;
    if (latestMessageIdRef.current === latest.id) return;
    latestMessageIdRef.current = latest.id;

    if (latest.authorType === 'support') {
      setReplyNotice('New support reply received.');
    }
  }, [messages]);

  const sanitizedReplyPreview = replyContent
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/on\w+\s*=\s*"[^"]*"/g, '')
    .replace(/javascript:/gi, '');

  const timeline = [
    { key: 'open', label: 'Opened', complete: true },
    { key: 'in_progress', label: 'In Progress', complete: ['in_progress', 'waiting_on_customer', 'resolved', 'closed'].includes(ticketStatus) },
    { key: 'waiting_on_customer', label: 'Waiting', complete: ['waiting_on_customer', 'resolved', 'closed'].includes(ticketStatus) },
    { key: 'resolved', label: 'Resolved', complete: ['resolved', 'closed'].includes(ticketStatus) },
    { key: 'closed', label: 'Closed', complete: ['closed'].includes(ticketStatus) },
  ];

  async function sendReply() {
    if (!replyContent.trim() || sending) return;
    setSending(true);
    try {
      const customerMessageContent = sanitizeUserInput(replyContent.trim(), 5000);
      const result = await apiCall<{ message: TicketMessage; botReply?: TicketMessage }>(
        `/v1/support/tickets/${ticket.id}/messages`,
        {
          method: 'POST',
          body: JSON.stringify({
            content: customerMessageContent,
            requestBotReply: true,
            assistantName: ASSISTANT_LABEL,
            channel: 'support_ticket',
          }),
        }
      );
      const newMsgs = [result.message];
      if (result.botReply) {
        newMsgs.push(result.botReply);
      } else {
        try {
          const fallbackReply = await apiCall<{ reply: string; escalated?: boolean }>(
            '/v1/support/tickets/chatbot-general',
            {
              method: 'POST',
              body: JSON.stringify({
                question: customerMessageContent,
                ticketId: ticket.id,
                assistantName: ASSISTANT_LABEL,
                channel: 'support_ticket_fallback',
                conversationHistory: [...messages, result.message].slice(-10).map((entry) => ({
                  role: entry.authorType === 'customer' ? 'user' : 'bot',
                  content: entry.content,
                })),
              }),
            }
          );

          if (fallbackReply.reply?.trim()) {
            newMsgs.push({
              id: `fallback-assistant-${Date.now()}`,
              content: fallbackReply.reply,
              author: ASSISTANT_LABEL,
              authorType: 'bot',
              createdAt: new Date().toISOString(),
              attachments: [],
            });
            setReplyNotice(`${ASSISTANT_NAME} added an AI follow-up.`);
          }
        } catch {
          // no-op: ticket message still succeeded
        }
      }
      setMessages(prev => [...prev, ...newMsgs]);
      setReplyContent('');
      onRefresh();
    } catch (err) {
      setActionError('Failed to send reply. Please try again.');
    } finally {
      setSending(false);
    }
  }

  async function closeTicket() {
    if (ticketStatus === 'closed' || closing) return;

    setClosing(true);
    setConfirmAction(null);
    setActionError(null);
    try {
      const result = await apiCall<{ ticket: Ticket }>(
        `/v1/support/tickets/${ticket.id}/close`,
        { method: 'POST', body: JSON.stringify({}) }
      );
      setMessages(result.ticket.messages ?? []);
      setTicketStatus(result.ticket.status);
      onRefresh();
    } catch (err) {
      setActionError('Failed to close ticket. Please try again.');
    } finally {
      setClosing(false);
    }
  }

  async function reopenTicket() {
    if (ticketStatus !== 'closed' || reopening) return;

    setReopening(true);
    setConfirmAction(null);
    setActionError(null);
    try {
      const result = await apiCall<{ ticket: Ticket }>(
        `/v1/support/tickets/${ticket.id}/reopen`,
        { method: 'POST', body: JSON.stringify({}) }
      );
      setMessages(result.ticket.messages ?? []);
      setTicketStatus(result.ticket.status);
      onRefresh();
    } catch (err) {
      setActionError('Failed to reopen ticket. Please try again.');
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
            <button aria-label="Back to tickets" onClick={onBack} className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground transition-colors">
              <ArrowLeft className="h-4 w-4" />Back to tickets
            </button>
            {ticketStatus === 'closed' ? (
              <Button variant="outline" onClick={() => setConfirmAction('reopen')} disabled={reopening}>
                {reopening ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
                Reopen Ticket
              </Button>
            ) : (
              <Button variant="outline" onClick={() => setConfirmAction('close')} disabled={closing}>
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

        <div className="mt-4 flex flex-wrap items-center gap-2">
          {timeline.map((step) => (
            <span
              key={step.key}
              className={`px-2 py-1 rounded-full text-xs ${step.complete ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'}`}
            >
              {step.label}
            </span>
          ))}
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
                  {msg.authorType === 'bot' ? (
                    <>
                      <span aria-hidden="true" className="mr-1">{ASSISTANT_FACE}</span>
                      {ASSISTANT_LABEL}
                    </>
                  ) : msg.author}
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
          {replyNotice ? (
            <div className="mb-3 rounded-md border border-primary/20 bg-primary/10 p-2 text-xs text-foreground flex items-center justify-between gap-2">
              <span>{replyNotice}</span>
              <button aria-label="Dismiss reply notice" className="text-primary hover:underline" onClick={() => setReplyNotice('')}>Dismiss</button>
            </div>
          ) : null}

          {actionError ? (
            <div className="mb-3 rounded-md border border-destructive/20 bg-destructive/10 p-2 text-xs text-destructive flex items-center justify-between gap-2">
              <span>{actionError}</span>
              <button aria-label="Dismiss error" className="text-destructive hover:underline" onClick={() => setActionError(null)}>Dismiss</button>
            </div>
          ) : null}

          <div className="flex gap-2">
            <textarea value={replyContent} onChange={(e) => setReplyContent(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendReply(); } }}
              placeholder="Type your reply... (Enter to send)" rows={2}
              className="flex-1 px-3 py-2 border border-input rounded-lg text-sm bg-background focus:outline-none focus:ring-2 focus:ring-primary/20 resize-none" />
            <Button onClick={sendReply} disabled={!replyContent.trim() || sending} className="self-end">
              {sending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
            </Button>
          </div>

          {replyContent ? (
            <div className="mt-3 rounded-md border border-border p-3">
              <p className="text-xs font-medium text-muted-foreground mb-1">Sanitized preview</p>
              <p className="text-sm whitespace-pre-wrap">{sanitizedReplyPreview}</p>
            </div>
          ) : null}
        </div>
      )}

      <Dialog open={confirmAction !== null} onOpenChange={(open) => { if (!open) setConfirmAction(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{confirmAction === 'close' ? 'Close Ticket' : 'Reopen Ticket'}</DialogTitle>
            <DialogDescription>
              {confirmAction === 'close'
                ? 'Are you sure you want to close this ticket? You can create a new ticket if you need more help.'
                : 'Are you sure you want to reopen this ticket?'}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmAction(null)}>Cancel</Button>
            <Button onClick={() => confirmAction === 'close' ? closeTicket() : reopenTicket()}>
              {confirmAction === 'close' ? 'Close Ticket' : 'Reopen Ticket'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
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
        description={`Get help from ${ASSISTANT_NAME}, or create a support ticket.`}
        breadcrumbs={[{ label: 'Help & Support' }]}
      />

      {/* Tab bar */}
      <div className="flex items-center gap-1 bg-muted p-1 rounded-lg w-fit">
        <button aria-label="Open help center" onClick={() => { setActiveTab('help'); setSelectedTicket(null); }}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${activeTab === 'help' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}>
          <BookOpen className="h-4 w-4 inline mr-2" />Help Center
        </button>
        <button aria-label="Open my tickets" onClick={() => setActiveTab('tickets')}
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
              <Card
                key={r.title}
                className="hover:border-primary/30 transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30"
                role="button"
                aria-label={r.title}
                tabIndex={0}
                onClick={() => {
                  window.open(r.href, '_blank', 'noopener,noreferrer');
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    window.open(r.href, '_blank', 'noopener,noreferrer');
                  }
                }}
              >
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
                  <button aria-label={`${expandedFaq === i ? 'Collapse' : 'Expand'} FAQ: ${faq.q}`} onClick={() => setExpandedFaq(expandedFaq === i ? null : i)} className="w-full text-left py-3 flex items-start justify-between gap-4 group">
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
                  <p className="text-sm text-muted-foreground">Create a ticket or chat with {ASSISTANT_NAME}, your support assistant.</p>
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
                      <button aria-label={`Open ticket ${ticket.subject}`} key={ticket.id} onClick={() => openTicket(ticket.id)}
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
      <SupportChatbotWidget onCreateTicket={() => setShowCreateDialog(true)} />
    </div>
  );
}
