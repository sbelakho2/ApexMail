/**
 * Bot Click Detection Service
 * 
 * Detects and filters bot/security scanner clicks to provide accurate engagement metrics.
 * Bot clicks have become a major issue distorting email marketing metrics.
 * 
 * Detection methods:
 * - Timing analysis (instant clicks < 1s are likely bots)
 * - Behavioral patterns (multiple links clicked simultaneously)
 * - Known bot user-agents
 * - IP reputation and velocity
 * - Honeypot/invisible link detection
 * 
 * @see https://www.validity.com/blog/are-these-clicks-for-real-the-rise-of-bot-clicks
 */

export interface ClickEvent {
  messageId: string;
  recipientEmail: string;
  linkUrl: string;
  timestamp: Date;
  userAgent: string | null;
  ipAddress: string;
  headers: Record<string, string>;
}

export interface BotDetectionResult {
  isBot: boolean;
  confidence: number; // 0-100
  reasons: string[];
  botType?: BotType;
}

export enum BotType {
  SECURITY_SCANNER = 'security_scanner',
  LINK_PREFETCH = 'link_prefetch',
  EMAIL_GATEWAY = 'email_gateway',
  SPAM_FILTER = 'spam_filter',
  CRAWLER = 'crawler',
  UNKNOWN = 'unknown',
}

// Known bot user-agent patterns — kept for categorisation in categorizeUserAgentBot()
const BOT_USER_AGENT_PATTERNS = [
  // Security/email scanning services
  /barracuda/i,
  /mimecast/i,
  /proofpoint/i,
  /symantec/i,
  /fireeye/i,
  /cisco/i,
  /ironport/i,
  /messagelabs/i,
  /forcepoint/i,
  /websense/i,
  /mcafee/i,
  /sophos/i,
  /trendmicro/i,
  /zscaler/i,
  
  // Link preview/prefetch
  /facebookexternalhit/i,
  /twitterbot/i,
  /linkedinbot/i,
  /slackbot/i,
  /telegrambot/i,
  /whatsapp/i,
  /discord/i,
  
  // Generic bot patterns (word boundaries prevent false positives on brands like "Cubot")
  /\bbot\b/i,
  /\bcrawler\b/i,
  /\bspider\b/i,
  /\bscraper\b/i,
  /headless/i,
  /phantom/i,
  /selenium/i,
  /puppeteer/i,
  /\bwget\b/i,
  /\bcurl\b/i,
  /python-requests/i,
  /axios/i,
  /node-fetch/i,
];

/**
 * Pre-compiled single combined alternation — O(1) per UA string instead of O(n).
 * Compiled once at module load time; JS regex engines build a DFA/NFA once.
 * The individual patterns above are retained for categorisation only.
 */
const BOT_UA_COMBINED: RegExp = new RegExp(
  BOT_USER_AGENT_PATTERNS.map((r) => `(?:${r.source})`).join('|'),
  'i'
);

// Known security gateway IP ranges (sample - should be regularly updated)
const KNOWN_BOT_IP_PATTERNS = [
  // Barracuda Networks
  /^64\.235\./,
  // Mimecast
  /^91\.220\.42\./,
  /^195\.130\.217\./,
  // Proofpoint
  /^67\.231\.1(4[4-9]|5[0-9])\./,
  // Microsoft Defender
  /^40\.94\./,
  /^52\.10[01]\./,
];

export class BotDetectionService {
  private clickVelocityCache: Map<string, ClickEvent[]> = new Map();
  private readonly VELOCITY_WINDOW_MS = 5000; // 5 second window
  private readonly INSTANT_CLICK_THRESHOLD_MS = 1000; // Clicks under 1s are suspicious
  private readonly VELOCITY_THRESHOLD = 3; // 3+ clicks in window is suspicious
  /**
   * C-095: Maximum number of keys in the click velocity cache before eviction.
   * Without a cap, if cleanupVelocityCache is never called (or called too
   * infrequently), the map grows without bound → eventual OOM.
   * 
   * Sized for 1000 tenants × ~500 concurrent opens per tenant = 500K entries.
   * Each entry is ~200 bytes (IP + timestamps array), so 500K ≈ 100MB — well
   * within budget on a 160GB EX44 machine.
   */
  private static readonly MAX_VELOCITY_CACHE_SIZE = 500_000;

  /**
   * Periodic cleanup interval handle (started in constructor, stopped in destroy()).
   * Without this, expired velocity entries only get pruned on-access — pathological
   * cases where a message is never accessed again leak indefinitely.
   */
  private readonly cleanupIntervalId: ReturnType<typeof setInterval>;

  /** Auto-cleanup interval period (10 minutes). */
  private static readonly CLEANUP_INTERVAL_MS = 10 * 60 * 1000;

  constructor() {
    // Auto-cleanup: expire stale velocity-cache entries every 10 minutes.
    // Using unref() so the timer does not prevent process exit.
    this.cleanupIntervalId = setInterval(
      () => this.cleanupVelocityCache(),
      BotDetectionService.CLEANUP_INTERVAL_MS,
    );
    if (typeof this.cleanupIntervalId.unref === 'function') {
      this.cleanupIntervalId.unref();
    }
  }

  /**
   * Stop the background cleanup timer.  Call on service shutdown to avoid
   * keeping the Node.js event loop alive unnecessarily.
   */
  destroy(): void {
    clearInterval(this.cleanupIntervalId);
    this.clickVelocityCache.clear();
  }

  /**
   * Analyze a click event for bot characteristics
   */
  analyzeClick(click: ClickEvent, messageOpenTime?: Date): BotDetectionResult {
    const reasons: string[] = [];
    let botScore = 0;
    let detectedBotType: BotType | undefined;

    // 1. User-agent analysis
    const uaResult = this.analyzeUserAgent(click.userAgent);
    if (uaResult.isBot) {
      botScore += 40;
      reasons.push(`Bot user-agent detected: ${uaResult.pattern}`);
      detectedBotType = uaResult.botType;
    }

    // 2. Timing analysis (instant clicks)
    if (messageOpenTime) {
      const timeSinceOpen = click.timestamp.getTime() - messageOpenTime.getTime();
      if (timeSinceOpen < this.INSTANT_CLICK_THRESHOLD_MS) {
        botScore += 35;
        reasons.push(`Instant click: ${timeSinceOpen}ms after open`);
        if (!detectedBotType) detectedBotType = BotType.SECURITY_SCANNER;
      } else if (timeSinceOpen < 2000) {
        botScore += 15;
        reasons.push(`Very fast click: ${timeSinceOpen}ms after open`);
      }
    }

    // 3. IP reputation analysis
    const ipResult = this.analyzeIP(click.ipAddress);
    if (ipResult.isKnownBot) {
      botScore += 30;
      reasons.push(`Known bot IP range: ${click.ipAddress}`);
      if (!detectedBotType) detectedBotType = BotType.EMAIL_GATEWAY;
    }

    // 4. Click velocity analysis (multiple clicks in short window)
    const velocityResult = this.checkClickVelocity(click);
    if (velocityResult.isHighVelocity) {
      botScore += 25;
      reasons.push(`High click velocity: ${velocityResult.clickCount} clicks in ${this.VELOCITY_WINDOW_MS}ms`);
      if (!detectedBotType) detectedBotType = BotType.SECURITY_SCANNER;
    }

    // 5. Header analysis
    const headerResult = this.analyzeHeaders(click.headers);
    if (headerResult.suspicious) {
      botScore += headerResult.score;
      reasons.push(...headerResult.reasons);
      if (!detectedBotType) detectedBotType = BotType.SECURITY_SCANNER;
    }

    // Normalize score to 0-100
    const confidence = Math.min(100, botScore);
    const isBot = confidence >= 50;

    return {
      isBot,
      confidence,
      reasons,
      botType: isBot ? (detectedBotType || BotType.UNKNOWN) : undefined,
    };
  }

  /**
   * Analyze user-agent string for bot patterns.
   *
   * Uses a single pre-compiled combined regex (BOT_UA_COMBINED) for the hot-path
   * existence check — O(1) instead of O(n) sequential pattern tests.  Only falls
   * back to individual patterns for detailed categorisation after a match.
   */
  private analyzeUserAgent(userAgent: string | null): {
    isBot: boolean;
    pattern?: string;
    botType?: BotType;
  } {
    if (!userAgent) {
      return { isBot: false };
    }

    // Single combined test — compiled once at module load, not per call.
    if (BOT_UA_COMBINED.test(userAgent)) {
      const botType = this.categorizeUserAgentBot(userAgent);
      return { isBot: true, pattern: String(botType), botType };
    }

    // Check for missing or generic user-agents (not caught by pattern list)
    if (userAgent.length < 20 || userAgent === 'Mozilla/5.0') {
      return { isBot: true, pattern: 'generic/minimal', botType: BotType.UNKNOWN };
    }

    return { isBot: false };
  }

  /**
   * Categorize bot type from user-agent
   */
  private categorizeUserAgentBot(userAgent: string): BotType {
    const ua = userAgent.toLowerCase();
    
    if (/barracuda|mimecast|proofpoint|symantec|fireeye|cisco|ironport|mcafee|sophos|zscaler/.test(ua)) {
      return BotType.SECURITY_SCANNER;
    }
    if (/facebookexternalhit|twitterbot|linkedinbot|slackbot|telegrambot|whatsapp|discord/.test(ua)) {
      return BotType.LINK_PREFETCH;
    }
    if (/messagelabs|forcepoint|websense/.test(ua)) {
      return BotType.EMAIL_GATEWAY;
    }
    if (/bot|crawler|spider|scraper/.test(ua)) {
      return BotType.CRAWLER;
    }
    
    return BotType.UNKNOWN;
  }

  /**
   * Analyze IP address for known bot ranges
   */
  private analyzeIP(ipAddress: string): { isKnownBot: boolean } {
    for (const pattern of KNOWN_BOT_IP_PATTERNS) {
      if (pattern.test(ipAddress)) {
        return { isKnownBot: true };
      }
    }
    return { isKnownBot: false };
  }

  /**
   * Check click velocity (multiple clicks in short time window)
   */
  private checkClickVelocity(click: ClickEvent): { 
    isHighVelocity: boolean; 
    clickCount: number 
  } {
    const key = `${click.messageId}:${click.ipAddress}`;
    const now = click.timestamp.getTime();
    
    // Get existing clicks in window
    let recentClicks = this.clickVelocityCache.get(key) ?? [];
    
    // Filter to only clicks within window
    recentClicks = recentClicks.filter(
      (c) => now - c.timestamp.getTime() < this.VELOCITY_WINDOW_MS
    );
    
    // Add current click
    recentClicks.push(click);

    // LRU promotion: delete + re-insert moves entry to tail of Map (most recently used).
    // When we need to evict (below), we remove from the head (least recently used).
    this.clickVelocityCache.delete(key);
    this.clickVelocityCache.set(key, recentClicks);

    // C-095: Evict LRU (head) entries when cache exceeds cap — O(1) per eviction.
    while (this.clickVelocityCache.size > BotDetectionService.MAX_VELOCITY_CACHE_SIZE) {
      const oldest = this.clickVelocityCache.keys().next();
      if (oldest.done || oldest.value === undefined) break;
      this.clickVelocityCache.delete(oldest.value);
    }

    // Check if velocity exceeds threshold
    return {
      isHighVelocity: recentClicks.length >= this.VELOCITY_THRESHOLD,
      clickCount: recentClicks.length,
    };
  }

  /**
   * Analyze HTTP headers for bot indicators
   */
  private analyzeHeaders(headers: Record<string, string>): {
    suspicious: boolean;
    score: number;
    reasons: string[];
  } {
    const reasons: string[] = [];
    let score = 0;

    // Check for missing typical browser headers
    if (!headers['accept-language']) {
      score += 10;
      reasons.push('Missing Accept-Language header');
    }

    if (!headers['accept-encoding']) {
      score += 5;
      reasons.push('Missing Accept-Encoding header');
    }

    // Check for bot-specific headers
    if (headers['x-scanner'] || headers['x-security-scan']) {
      score += 30;
      reasons.push('Security scanner header present');
    }

    // Check for prefetch headers
    if (headers['x-moz'] === 'prefetch' || headers['purpose'] === 'prefetch') {
      score += 25;
      reasons.push('Prefetch header detected');
    }

    return {
      suspicious: score > 0,
      score,
      reasons,
    };
  }

  /**
   * Generate a honeypot link for bot detection
   * This creates an invisible link that only bots would click
   */
  generateHoneypotLink(messageId: string, baseUrl: string): string {
    const honeypotToken = Buffer.from(`honeypot:${messageId}:${Date.now()}`).toString('base64url');
    return `${baseUrl}/track/hp/${honeypotToken}`;
  }

  /**
   * Generate honeypot HTML to embed in emails
   * Uses CSS to make link invisible to humans
   */
  generateHoneypotHtml(honeypotUrl: string): string {
    // Escape URL to prevent XSS via attribute injection
    const safeUrl = honeypotUrl.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return `
      <div style="position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;">
        <a href="${safeUrl}" style="color:transparent;font-size:0;line-height:0;" tabindex="-1" aria-hidden="true">&#8203;</a>
      </div>
    `;
  }

  /**
   * Check if a click is on a honeypot link
   */
  isHoneypotClick(url: string): boolean {
    return url.includes('/track/hp/');
  }

  /**
   * Get engagement metrics adjusted for bot traffic
   */
  getAdjustedMetrics(
    totalClicks: number,
    botClicks: number,
    totalOpens: number,
    botOpens: number
  ): {
    rawClickRate: number;
    adjustedClickRate: number;
    rawOpenRate: number;
    adjustedOpenRate: number;
    botClickPercentage: number;
    botOpenPercentage: number;
  } {
    const humanClicks = totalClicks - botClicks;
    const humanOpens = totalOpens - botOpens;
    
    // Avoid division by zero
    const safeTotal = (n: number) => Math.max(n, 1);

    return {
      rawClickRate: (totalClicks / safeTotal(totalOpens)) * 100,
      adjustedClickRate: (humanClicks / safeTotal(humanOpens)) * 100,
      rawOpenRate: totalOpens, // This would be calculated against total sent
      adjustedOpenRate: humanOpens,
      botClickPercentage: (botClicks / safeTotal(totalClicks)) * 100,
      botOpenPercentage: (botOpens / safeTotal(totalOpens)) * 100,
    };
  }

  /**
   * Clear old entries from velocity cache
   */
  cleanupVelocityCache(): void {
    const now = Date.now();
    for (const [key, clicks] of this.clickVelocityCache.entries()) {
      const recentClicks = clicks.filter(
        c => now - c.timestamp.getTime() < this.VELOCITY_WINDOW_MS * 10
      );
      if (recentClicks.length === 0) {
        this.clickVelocityCache.delete(key);
      } else {
        this.clickVelocityCache.set(key, recentClicks);
      }
    }
  }
}

/**
 * Factory function to create bot detection service
 */
export function createBotDetectionService(): BotDetectionService {
  return new BotDetectionService();
}

export default BotDetectionService;
