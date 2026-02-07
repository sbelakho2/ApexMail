/**
 * Reply Rate Tracking Service
 * 
 * Tracks email reply rates as a key engagement metric.
 * Microsoft "strongly recommends" allowing two-way communication,
 * and reply rates are emerging as an important KPI.
 * 
 * Features:
 * - Reply detection via In-Reply-To/References headers
 * - Reply sentiment analysis
 * - Reply-to configuration (no more no-reply@)
 * - Conversational thread tracking
 * - Auto-response filtering
 * 
 * @see https://www.validity.com/blog/12-expert-predictions-for-the-email-marketing-industry-in-2026
 */

// Types are inline in this module

export interface ReplyEvent {
  originalMessageId: string;
  replyMessageId: string;
  recipientEmail: string;
  replyTimestamp: Date;
  originalSentTimestamp: Date;
  replyContent?: string;
  isAutoReply: boolean;
  sentiment?: ReplySentiment;
  threadDepth: number;
}

export enum ReplySentiment {
  POSITIVE = 'positive',
  NEGATIVE = 'negative',
  NEUTRAL = 'neutral',
  INQUIRY = 'inquiry',
  UNSUBSCRIBE_REQUEST = 'unsubscribe_request',
  OUT_OF_OFFICE = 'out_of_office',
}

export interface ReplyMetrics {
  totalSent: number;
  totalReplies: number;
  humanReplies: number;
  autoReplies: number;
  replyRate: number;
  humanReplyRate: number;
  averageReplyTimeMinutes: number;
  sentimentBreakdown: Record<ReplySentiment, number>;
}

export interface ReplyToConfig {
  type: 'human' | 'alias' | 'support-ticket' | 'custom';
  address: string;
  autoResponderEnabled: boolean;
  autoResponderMessage?: string;
  forwardTo?: string[];
  webhookUrl?: string;
}

// Auto-reply indicators
const AUTO_REPLY_PATTERNS = [
  /^auto:/i,
  /^automatic reply/i,
  /out of office/i,
  /out-of-office/i,
  /vacation reply/i,
  /away from/i,
  /on leave/i,
  /maternity leave/i,
  /paternity leave/i,
  /i am currently out/i,
  /i'm currently out/i,
  /will be out of the office/i,
  /limited access to email/i,
  /this is an automated/i,
  /do not reply to this/i,
  /unattended mailbox/i,
  /no longer with/i,
  /has left the company/i,
];

// Auto-reply headers
const AUTO_REPLY_HEADERS = [
  'auto-submitted',
  'x-auto-response-suppress',
  'x-autoreply',
  'x-autorespond',
  'precedence',
];

export class ReplyTrackingService {
  private replyCache: Map<string, ReplyEvent[]> = new Map();
  /**
   * C-095: Maximum number of message keys in the reply cache before eviction.
   * Without a cap the map grows without bound → eventual OOM.
   */
  private static readonly MAX_REPLY_CACHE_SIZE = 50_000;

  /**
   * Process an incoming reply and extract metadata
   */
  processReply(
    incomingEmail: {
      messageId: string;
      inReplyTo?: string;
      references?: string[];
      from: string;
      subject: string;
      body: string;
      headers: Record<string, string>;
      receivedAt: Date;
    },
    originalMessage?: { sentAt?: Date }
  ): ReplyEvent | null {
    // Must have In-Reply-To or References header
    const originalMessageId = incomingEmail.inReplyTo || 
      (incomingEmail.references && incomingEmail.references[0]);
    
    if (!originalMessageId) {
      return null;
    }

    const isAutoReply = this.detectAutoReply(incomingEmail);
    const sentiment = this.analyzeSentiment(incomingEmail.subject, incomingEmail.body);
    const threadDepth = this.calculateThreadDepth(incomingEmail.references || []);

    const replyEvent: ReplyEvent = {
      originalMessageId,
      replyMessageId: incomingEmail.messageId,
      recipientEmail: incomingEmail.from,
      replyTimestamp: incomingEmail.receivedAt,
      originalSentTimestamp: originalMessage?.sentAt || new Date(),
      replyContent: incomingEmail.body,
      isAutoReply,
      sentiment,
      threadDepth,
    };

    // Cache the reply
    this.cacheReply(replyEvent);

    return replyEvent;
  }

  /**
   * Detect if an email is an auto-reply
   */
  detectAutoReply(email: {
    subject: string;
    body: string;
    headers: Record<string, string>;
  }): boolean {
    // Check headers first (most reliable)
    for (const header of AUTO_REPLY_HEADERS) {
      const value = email.headers[header.toLowerCase()];
      if (value) {
        if (header === 'auto-submitted' && value !== 'no') {
          return true;
        }
        if (header === 'precedence' && ['bulk', 'auto_reply', 'junk'].includes(value.toLowerCase())) {
          return true;
        }
        if (header.startsWith('x-auto')) {
          return true;
        }
      }
    }

    // Check subject line patterns
    const combinedText = `${email.subject} ${email.body}`.toLowerCase();
    for (const pattern of AUTO_REPLY_PATTERNS) {
      if (pattern.test(combinedText)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Analyze reply sentiment
   */
  analyzeSentiment(subject: string, body: string): ReplySentiment {
    const text = `${subject} ${body}`.toLowerCase();

    // Check for out-of-office first
    if (/out of office|vacation|away|leave/.test(text)) {
      return ReplySentiment.OUT_OF_OFFICE;
    }

    // Check for unsubscribe requests
    if (/unsubscribe|stop sending|remove me|opt out|don't email|don't contact/.test(text)) {
      return ReplySentiment.UNSUBSCRIBE_REQUEST;
    }

    // Check for inquiry patterns
    if (/\?|how do|how can|when will|where is|what is|could you|can you|please help/.test(text)) {
      return ReplySentiment.INQUIRY;
    }

    // Simple positive/negative detection
    const positiveWords = /thank|thanks|great|awesome|excellent|love|appreciate|helpful|perfect/;
    const negativeWords = /disappointed|frustrated|angry|terrible|worst|hate|awful|horrible|useless|spam/;

    const hasPositive = positiveWords.test(text);
    const hasNegative = negativeWords.test(text);

    if (hasPositive && !hasNegative) {
      return ReplySentiment.POSITIVE;
    }
    if (hasNegative && !hasPositive) {
      return ReplySentiment.NEGATIVE;
    }

    return ReplySentiment.NEUTRAL;
  }

  /**
   * Calculate thread depth from References header
   */
  calculateThreadDepth(references: string[]): number {
    return references.length;
  }

  /**
   * Cache reply for analytics
   */
  private cacheReply(reply: ReplyEvent): void {
    const existing = this.replyCache.get(reply.originalMessageId) || [];
    existing.push(reply);
    this.replyCache.set(reply.originalMessageId, existing);

    // C-095: Evict oldest entries when cache exceeds cap to prevent OOM
    if (this.replyCache.size > ReplyTrackingService.MAX_REPLY_CACHE_SIZE) {
      const excess = this.replyCache.size - ReplyTrackingService.MAX_REPLY_CACHE_SIZE;
      let removed = 0;
      for (const k of this.replyCache.keys()) {
        if (removed >= excess) break;
        this.replyCache.delete(k);
        removed++;
      }
    }
  }

  /**
   * Get replies for a message
   */
  getRepliesForMessage(messageId: string): ReplyEvent[] {
    return this.replyCache.get(messageId) || [];
  }

  /**
   * Calculate reply metrics for a campaign or time period
   */
  calculateMetrics(
    totalSent: number,
    replies: ReplyEvent[]
  ): ReplyMetrics {
    const humanReplies = replies.filter(r => !r.isAutoReply);
    const autoReplies = replies.filter(r => r.isAutoReply);

    // Calculate average reply time
    const replyTimes = humanReplies.map(r => 
      (r.replyTimestamp.getTime() - r.originalSentTimestamp.getTime()) / (1000 * 60)
    );
    const averageReplyTimeMinutes = replyTimes.length > 0
      ? replyTimes.reduce((a, b) => a + b, 0) / replyTimes.length
      : 0;

    // Calculate sentiment breakdown
    const sentimentBreakdown: Record<ReplySentiment, number> = {
      [ReplySentiment.POSITIVE]: 0,
      [ReplySentiment.NEGATIVE]: 0,
      [ReplySentiment.NEUTRAL]: 0,
      [ReplySentiment.INQUIRY]: 0,
      [ReplySentiment.UNSUBSCRIBE_REQUEST]: 0,
      [ReplySentiment.OUT_OF_OFFICE]: 0,
    };

    for (const reply of replies) {
      if (reply.sentiment) {
        sentimentBreakdown[reply.sentiment]++;
      }
    }

    return {
      totalSent,
      totalReplies: replies.length,
      humanReplies: humanReplies.length,
      autoReplies: autoReplies.length,
      replyRate: totalSent > 0 ? (replies.length / totalSent) * 100 : 0,
      humanReplyRate: totalSent > 0 ? (humanReplies.length / totalSent) * 100 : 0,
      averageReplyTimeMinutes,
      sentimentBreakdown,
    };
  }

  /**
   * Generate recommended reply-to configuration
   * No more no-reply@ addresses!
   */
  generateReplyToConfig(params: {
    brandName: string;
    domain: string;
    supportEmail?: string;
    enableWebhook?: boolean;
    webhookUrl?: string;
  }): ReplyToConfig {
    const { brandName, domain, supportEmail, enableWebhook, webhookUrl } = params;

    // Generate human-friendly reply-to address
    const replyAddress = supportEmail || `hello@${domain}`;

    return {
      type: supportEmail ? 'support-ticket' : 'alias',
      address: replyAddress,
      autoResponderEnabled: true,
      autoResponderMessage: `Thanks for your reply! The ${brandName} team will get back to you within 24 hours.`,
      forwardTo: supportEmail ? [supportEmail] : undefined,
      webhookUrl: enableWebhook ? webhookUrl : undefined,
    };
  }

  /**
   * Generate email headers for proper reply tracking
   */
  generateReplyHeaders(params: {
    messageId: string;
    replyTo: string;
    references?: string[];
    threadId?: string;
  }): Record<string, string> {
    const headers: Record<string, string> = {
      'Message-ID': params.messageId,
      'Reply-To': params.replyTo,
    };

    if (params.references && params.references.length > 0) {
      headers['References'] = params.references.join(' ');
      const lastRef = params.references[params.references.length - 1];
      if (lastRef) headers['In-Reply-To'] = lastRef;
    }

    if (params.threadId) {
      headers['Thread-Topic'] = params.threadId;
      headers['Thread-Index'] = Buffer.from(params.threadId).toString('base64');
    }

    return headers;
  }

  /**
   * Check if reply needs attention (negative sentiment or unsubscribe request)
   */
  needsAttention(reply: ReplyEvent): boolean {
    return (
      reply.sentiment === ReplySentiment.NEGATIVE ||
      reply.sentiment === ReplySentiment.UNSUBSCRIBE_REQUEST ||
      reply.sentiment === ReplySentiment.INQUIRY
    );
  }

  /**
   * Get reply rate benchmarks by industry
   */
  getReplyRateBenchmarks(): Record<string, { good: number; excellent: number }> {
    return {
      transactional: { good: 2, excellent: 5 },
      marketing: { good: 0.5, excellent: 2 },
      sales_outreach: { good: 5, excellent: 15 },
      customer_support: { good: 10, excellent: 25 },
      newsletter: { good: 0.1, excellent: 0.5 },
    };
  }
}

/**
 * Factory function
 */
export function createReplyTrackingService(): ReplyTrackingService {
  return new ReplyTrackingService();
}

export default ReplyTrackingService;
