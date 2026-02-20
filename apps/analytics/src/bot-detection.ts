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

// Known bot user-agent patterns
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
  
  // Generic bot patterns
  /bot/i,
  /crawler/i,
  /spider/i,
  /scraper/i,
  /headless/i,
  /phantom/i,
  /selenium/i,
  /puppeteer/i,
  /wget/i,
  /curl/i,
  /python-requests/i,
  /axios/i,
  /node-fetch/i,
];

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
   * Analyze user-agent string for bot patterns
   */
  private analyzeUserAgent(userAgent: string | null): { 
    isBot: boolean; 
    pattern?: string; 
    botType?: BotType 
  } {
    if (!userAgent) {
      return { isBot: false };
    }

    for (const pattern of BOT_USER_AGENT_PATTERNS) {
      if (pattern.test(userAgent)) {
        const botType = this.categorizeUserAgentBot(userAgent);
        return { isBot: true, pattern: pattern.source, botType };
      }
    }

    // Check for missing or generic user-agents
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
    let recentClicks = this.clickVelocityCache.get(key) || [];
    
    // Filter to only clicks within window
    recentClicks = recentClicks.filter(
      c => now - c.timestamp.getTime() < this.VELOCITY_WINDOW_MS
    );
    
    // Add current click
    recentClicks.push(click);
    this.clickVelocityCache.set(key, recentClicks);

    // C-095: Evict oldest entries when cache exceeds cap to prevent OOM
    if (this.clickVelocityCache.size > BotDetectionService.MAX_VELOCITY_CACHE_SIZE) {
      const excess = this.clickVelocityCache.size - BotDetectionService.MAX_VELOCITY_CACHE_SIZE;
      let removed = 0;
      for (const k of this.clickVelocityCache.keys()) {
        if (removed >= excess) break;
        this.clickVelocityCache.delete(k);
        removed++;
      }
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
    return `
      <div style="position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;">
        <a href="${honeypotUrl}" style="color:transparent;font-size:0;line-height:0;" tabindex="-1" aria-hidden="true">&#8203;</a>
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
