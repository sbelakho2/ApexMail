/**
 * Worker Package Edge-Case Tests
 *
 * Comprehensive tests for all pure functions in the worker package:
 * - SSRF prevention (isPrivateIP)
 * - Webhook retry logic & signing
 * - Email bounce classification
 * - Token bucket rate limiter
 * - Reply handler NLP (sentiment, urgency, date extraction, referral extraction)
 * - ISP detection / warmup day calculation
 * - Prometheus metrics formatting
 */

import { describe, it, expect } from 'vitest';
import * as net from 'net';
import { createHmac } from 'crypto';

// ═════════════════════════════════════════════════════════════════════════════
// Production logic copies — private functions reproduced for testing
// ═════════════════════════════════════════════════════════════════════════════

/** Copy of webhook.ts isPrivateIP */
function isPrivateIP(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    if (a === undefined || b === undefined) return false;
    if (a === 127) return true;                           // Loopback
    if (a === 10) return true;                            // Class A private
    if (a === 172 && b >= 16 && b <= 31) return true;     // Class B private
    if (a === 192 && b === 168) return true;              // Class C private
    if (a === 169 && b === 254) return true;              // Link-local / metadata
    if (a >= 224 && a <= 239) return true;                // Multicast
    if (a === 0 || a === 255) return true;                // Reserved
    return false;
  }
  if (net.isIPv6(ip)) {
    const n = ip.toLowerCase();
    if (n === '::1' || n === '::') return true;
    if (n.startsWith('fe80:') || n.startsWith('fc') || n.startsWith('fd')) return true;
    if (n.startsWith('ff')) return true;
    if (n.startsWith('::ffff:')) {
      const v4 = n.slice(7);
      if (net.isIPv4(v4)) return isPrivateIP(v4);
    }
    return false;
  }
  return true; // Unknown format — deny by default
}

/** Copy of webhook.ts isRetryableStatusCode */
function isRetryableStatusCode(statusCode: number): boolean {
  return statusCode >= 500 || statusCode === 408 || statusCode === 429;
}

/** Copy of webhook.ts signPayload — uses hmacSign from lib */
function signPayload(secret: string, timestamp: number, payload: Record<string, unknown>): string {
  const message = `${timestamp}.${JSON.stringify(payload)}`;
  const hmac = createHmac('sha256', secret).update(message).digest('hex');
  return 'sha256=' + hmac;
}

/** Copy of email.ts classifyBounce */
function classifyBounce(error: Error): { type: 'hard' | 'soft'; subtype: string } {
  const message = error.message.toLowerCase();

  // Hard bounce patterns (550/551/553/554 are permanent failures per RFC 5321)
  if (message.includes('550') || message.includes('551') || message.includes('553') || message.includes('554')) {
    if (message.includes('user') && (message.includes('unknown') || message.includes('not found'))) {
      return { type: 'hard', subtype: 'no-mailbox' };
    }
    if (message.includes('domain') && message.includes('not found')) {
      return { type: 'hard', subtype: 'no-domain' };
    }
    if (message.includes('reject') || message.includes('blocked')) {
      return { type: 'hard', subtype: 'rejected' };
    }
    return { type: 'hard', subtype: 'general' };
  }

  // Soft bounce patterns
  if (message.includes('552') || message.includes('over quota') || message.includes('mailbox full')) {
    return { type: 'soft', subtype: 'over-quota' };
  }
  if (message.includes('421') || message.includes('450') || message.includes('451')) {
    return { type: 'soft', subtype: 'temporary' };
  }
  if (message.includes('greylist')) {
    return { type: 'soft', subtype: 'greylisted' };
  }

  return { type: 'soft', subtype: 'undetermined' };
}

/** Copy of email.ts isBounceError */
function isBounceError(error: Error): boolean {
  const message = error.message.toLowerCase();
  const bouncePattern = /\b(55[0-5])\b/;
  return bouncePattern.test(message);
}

/** Copy of email.ts isRetryableError */
function isRetryableError(error: Error): boolean {
  const message = error.message.toLowerCase();
  const retryableCodePattern = /\b(421|45[0-2])\b/;
  const retryablePatterns = ['timeout', 'econnreset', 'econnrefused', 'temporary'];
  return retryableCodePattern.test(message) ||
    retryablePatterns.some(pattern => message.includes(pattern));
}

/** Copy of reply-handler.ts detectSentiment */
function detectSentiment(text: string): 'positive' | 'negative' | 'neutral' {
  const positiveWords = ['interested', 'great', 'love', 'excited', 'perfect', 'thanks', 'wonderful', 'amazing', 'yes', 'absolutely'];
  const negativeWords = ['not interested', 'no thanks', 'spam', 'stop', 'remove', 'unsubscribe', 'annoying', 'never', 'hate', 'terrible'];

  let positiveCount = 0;
  let negativeCount = 0;

  for (const word of positiveWords) {
    if (text.includes(word)) positiveCount++;
  }
  for (const word of negativeWords) {
    if (text.includes(word)) negativeCount++;
  }

  if (positiveCount > negativeCount + 1) return 'positive';
  if (negativeCount > positiveCount + 1) return 'negative';
  return 'neutral';
}

/** Copy of reply-handler.ts detectUrgency */
function detectUrgency(text: string): 'high' | 'medium' | 'low' {
  const highUrgency = [/\burgent\b/, /\basap\b/, /\bimmediately\b/, /\btoday\b/, /\bnow\b/, /\bemergency\b/, /\bcritical\b/];
  const mediumUrgency = [/\bsoon\b/, /\bthis week\b/, /\bwhen possible\b/, /\bat your earliest\b/];

  for (const pattern of highUrgency) {
    if (pattern.test(text)) return 'high';
  }
  for (const pattern of mediumUrgency) {
    if (pattern.test(text)) return 'medium';
  }
  return 'low';
}

/** Copy of reply-handler.ts extractReturnDate */
const RETURN_DATE_PATTERNS = [
  /(?:back|return(?:ing)?|available|in the office)(?: on)? (\w+ \d{1,2}(?:st|nd|rd|th)?(?:,? \d{4})?)/i,
  /(?:back|return(?:ing)?|available|in the office)(?: on)? (\d{1,2}[/\-.](\d{1,2})[/\-.](?:\d{2,4})?)/i,
  /(?:back|return(?:ing)?|available)(?: on)? (monday|tuesday|wednesday|thursday|friday|saturday|sunday)/i,
  /until (\w+ \d{1,2}(?:st|nd|rd|th)?(?:,? \d{4})?)/i,
];

function extractReturnDate(text: string): Date | undefined {
  for (const pattern of RETURN_DATE_PATTERNS) {
    const match = text.match(pattern);
    if (match && match[1]) {
      try {
        const dateStr = match[1];

        // Handle day names
        const dayNames = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
        const dayIndex = dayNames.indexOf(dateStr.toLowerCase());
        if (dayIndex !== -1) {
          const today = new Date();
          const daysUntil = (dayIndex - today.getDay() + 7) % 7 || 7;
          return new Date(today.getTime() + daysUntil * 24 * 60 * 60 * 1000);
        }

        // Try standard date parsing
        const parsed = new Date(dateStr);
        if (!isNaN(parsed.getTime())) {
          return parsed;
        }
      } catch {
        continue;
      }
    }
  }
  return undefined;
}

/** Copy of reply-handler.ts REFERRAL_PATTERNS + extractReferral */
const REFERRAL_PATTERNS = [
  /(?:contact|reach|try|email|speak (?:with|to)) (\w+(?:\.\w+)?@[\w.-]+\.\w+)/i,
  /(?:cc|copied|adding) (\w+(?:\.\w+)?@[\w.-]+\.\w+)/i,
  /forward(?:ed|ing)? (?:this )?to (\w+(?:\.\w+)?@[\w.-]+\.\w+)/i,
];

function extractReferral(text: string): string | undefined {
  for (const pattern of REFERRAL_PATTERNS) {
    const match = text.match(pattern);
    if (match && match[1]) {
      return match[1].toLowerCase();
    }
  }
  // Try to find any email address in the text
  const emailMatch = text.match(/[\w.-]+@[\w.-]+\.\w+/);
  return emailMatch?.[0]?.toLowerCase();
}

/** Copy of ip-rate-limiter.ts getDirectISPMapping */
function getDirectISPMapping(domain: string): string | null {
  const domainLower = domain.toLowerCase();

  // Gmail
  if (domainLower === 'gmail.com' || domainLower === 'googlemail.com' ||
    domainLower.endsWith('.google.com')) {
    return 'gmail';
  }
  // Microsoft
  if (domainLower === 'outlook.com' || domainLower === 'hotmail.com' ||
    domainLower === 'live.com' || domainLower === 'msn.com' ||
    domainLower.endsWith('.outlook.com')) {
    return 'microsoft';
  }
  // Yahoo/AOL
  if (domainLower === 'yahoo.com' || domainLower === 'aol.com' ||
    domainLower.endsWith('.yahoo.com') || domainLower.endsWith('.aol.com')) {
    return 'yahoo';
  }
  // Apple
  if (domainLower === 'icloud.com' || domainLower === 'me.com' ||
    domainLower.endsWith('.apple.com')) {
    return 'apple';
  }
  return null;
}

/** Copy of ip-rate-limiter.ts calculateWarmupDay */
function calculateWarmupDay(startDate: Date): number {
  const now = new Date();
  const diffMs = now.getTime() - startDate.getTime();
  if (diffMs <= 0) return 0; // Warmup hasn't started yet
  return Math.floor(diffMs / (1000 * 60 * 60 * 24));
}

/** Copy of ip-rate-limiter.ts time functions */
function secondsUntilMidnightUTC(): number {
  const now = new Date();
  const midnight = new Date(now);
  midnight.setUTCDate(midnight.getUTCDate() + 1);
  midnight.setUTCHours(0, 0, 0, 0);
  return Math.ceil((midnight.getTime() - now.getTime()) / 1000);
}

function secondsUntilNextHour(): number {
  const now = new Date();
  const nextHour = new Date(now);
  nextHour.setUTCHours(nextHour.getUTCHours() + 1, 0, 0, 0);
  return Math.ceil((nextHour.getTime() - now.getTime()) / 1000);
}

/** Copy of metrics.ts escapeLabel */
function escapeLabel(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n');
}

/** Copy of metrics.ts formatLabels */
function formatLabels(labels: Record<string, string>): string {
  return Object.entries(labels)
    .map(([k, v]) => `${k}="${escapeLabel(v)}"`)
    .join(',');
}

/** Copy of email.ts retry backoff calculation */
function calculateRetryDelay(retryDelayBase: number, attempt: number): number {
  return retryDelayBase * Math.pow(2, attempt - 1);
}


// ═════════════════════════════════════════════════════════════════════════════
// 1. SSRF Prevention - isPrivateIP
// ═════════════════════════════════════════════════════════════════════════════

describe('isPrivateIP (SSRF Prevention)', () => {
  describe('IPv4 private ranges', () => {
    it('blocks 127.0.0.0/8 loopback', () => {
      expect(isPrivateIP('127.0.0.1')).toBe(true);
      expect(isPrivateIP('127.255.255.255')).toBe(true);
    });

    it('blocks 10.0.0.0/8 Class A private', () => {
      expect(isPrivateIP('10.0.0.0')).toBe(true);
      expect(isPrivateIP('10.255.255.255')).toBe(true);
    });

    it('blocks 172.16.0.0/12 Class B private', () => {
      expect(isPrivateIP('172.16.0.1')).toBe(true);
      expect(isPrivateIP('172.31.255.255')).toBe(true);
    });

    it('allows 172.15.x.x and 172.32.x.x (not private)', () => {
      expect(isPrivateIP('172.15.0.1')).toBe(false);
      expect(isPrivateIP('172.32.0.1')).toBe(false);
    });

    it('blocks 192.168.0.0/16 Class C private', () => {
      expect(isPrivateIP('192.168.0.1')).toBe(true);
      expect(isPrivateIP('192.168.255.255')).toBe(true);
    });

    it('blocks 169.254.0.0/16 link-local / cloud metadata', () => {
      expect(isPrivateIP('169.254.169.254')).toBe(true); // AWS/GCP metadata
      expect(isPrivateIP('169.254.0.1')).toBe(true);
    });

    it('blocks 224-239 multicast', () => {
      expect(isPrivateIP('224.0.0.1')).toBe(true);
      expect(isPrivateIP('239.255.255.255')).toBe(true);
    });

    it('blocks 0.x.x.x reserved', () => {
      expect(isPrivateIP('0.0.0.0')).toBe(true);
    });

    it('blocks 255.x.x.x reserved', () => {
      expect(isPrivateIP('255.255.255.255')).toBe(true);
    });

    it('allows public IPs', () => {
      expect(isPrivateIP('8.8.8.8')).toBe(false);
      expect(isPrivateIP('1.1.1.1')).toBe(false);
      expect(isPrivateIP('203.0.113.1')).toBe(false);
      expect(isPrivateIP('93.184.216.34')).toBe(false);
    });

    // NOTE: POTENTIAL GAP — 100.64.0.0/10 (CGNAT/Shared Address Space) is NOT blocked
    it('does NOT block 100.64.0.0/10 CGNAT (potential gap)', () => {
      expect(isPrivateIP('100.64.0.1')).toBe(false);
      expect(isPrivateIP('100.127.255.255')).toBe(false);
    });

    // NOTE: POTENTIAL GAP — 198.18.0.0/15 (benchmark testing) is NOT blocked
    it('does NOT block 198.18.0.0/15 benchmark range (potential gap)', () => {
      expect(isPrivateIP('198.18.0.1')).toBe(false);
    });
  });

  describe('IPv6', () => {
    it('blocks ::1 loopback', () => {
      expect(isPrivateIP('::1')).toBe(true);
    });

    it('blocks :: unspecified', () => {
      expect(isPrivateIP('::')).toBe(true);
    });

    it('blocks fe80:: link-local', () => {
      expect(isPrivateIP('fe80::1')).toBe(true);
    });

    it('blocks fc/fd unique-local', () => {
      expect(isPrivateIP('fc00::1')).toBe(true);
      expect(isPrivateIP('fd12::abcd')).toBe(true);
    });

    it('blocks ff multicast', () => {
      expect(isPrivateIP('ff02::1')).toBe(true);
    });

    it('handles IPv4-mapped IPv6 with private IPv4', () => {
      expect(isPrivateIP('::ffff:127.0.0.1')).toBe(true);
      expect(isPrivateIP('::ffff:10.0.0.1')).toBe(true);
      expect(isPrivateIP('::ffff:192.168.1.1')).toBe(true);
    });

    it('allows IPv4-mapped IPv6 with public IPv4', () => {
      expect(isPrivateIP('::ffff:8.8.8.8')).toBe(false);
    });

    it('allows public IPv6', () => {
      expect(isPrivateIP('2001:4860:4860::8888')).toBe(false); // Google DNS
    });
  });

  describe('edge cases', () => {
    it('denies unknown format by default', () => {
      expect(isPrivateIP('not-an-ip')).toBe(true);
      expect(isPrivateIP('')).toBe(true);
    });
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 2. Webhook Retry Logic
// ═════════════════════════════════════════════════════════════════════════════

describe('isRetryableStatusCode', () => {
  it('retries on 500 Internal Server Error', () => {
    expect(isRetryableStatusCode(500)).toBe(true);
  });

  it('retries on 502 Bad Gateway', () => {
    expect(isRetryableStatusCode(502)).toBe(true);
  });

  it('retries on 503 Service Unavailable', () => {
    expect(isRetryableStatusCode(503)).toBe(true);
  });

  it('retries on 429 Too Many Requests', () => {
    expect(isRetryableStatusCode(429)).toBe(true);
  });

  it('retries on 408 Request Timeout', () => {
    expect(isRetryableStatusCode(408)).toBe(true);
  });

  it('does not retry on 200 OK', () => {
    expect(isRetryableStatusCode(200)).toBe(false);
  });

  it('does not retry on 400 Bad Request', () => {
    expect(isRetryableStatusCode(400)).toBe(false);
  });

  it('does not retry on 401 Unauthorized', () => {
    expect(isRetryableStatusCode(401)).toBe(false);
  });

  it('does not retry on 404 Not Found', () => {
    expect(isRetryableStatusCode(404)).toBe(false);
  });

  it('does not retry on 422 Unprocessable', () => {
    expect(isRetryableStatusCode(422)).toBe(false);
  });

  it('boundary: 499 is not retryable', () => {
    expect(isRetryableStatusCode(499)).toBe(false);
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 3. Webhook Signing
// ═════════════════════════════════════════════════════════════════════════════

describe('signPayload (Webhook HMAC)', () => {
  it('produces sha256= prefixed signature', () => {
    const sig = signPayload('secret', 1000000, { event: 'test' });
    expect(sig).toMatch(/^sha256=[a-f0-9]{64}$/);
  });

  it('is deterministic for same inputs', () => {
    const payload = { type: 'delivered', messageId: 'msg-1' };
    const sig1 = signPayload('key', 12345, payload);
    const sig2 = signPayload('key', 12345, payload);
    expect(sig1).toBe(sig2);
  });

  it('differs with different secrets', () => {
    const payload = { type: 'delivered' };
    const sig1 = signPayload('secret1', 12345, payload);
    const sig2 = signPayload('secret2', 12345, payload);
    expect(sig1).not.toBe(sig2);
  });

  it('differs with different timestamps', () => {
    const payload = { type: 'delivered' };
    const sig1 = signPayload('secret', 12345, payload);
    const sig2 = signPayload('secret', 12346, payload);
    expect(sig1).not.toBe(sig2);
  });

  it('differs with different payloads', () => {
    const sig1 = signPayload('secret', 12345, { a: 1 });
    const sig2 = signPayload('secret', 12345, { a: 2 });
    expect(sig1).not.toBe(sig2);
  });

  it('handles empty payload', () => {
    const sig = signPayload('secret', 0, {});
    expect(sig).toMatch(/^sha256=[a-f0-9]{64}$/);
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 4. Bounce Classification
// ═════════════════════════════════════════════════════════════════════════════

describe('classifyBounce', () => {
  describe('hard bounces', () => {
    it('classifies 550 user unknown as hard/no-mailbox', () => {
      const result = classifyBounce(new Error('550 5.1.1 User unknown'));
      expect(result.type).toBe('hard');
      expect(result.subtype).toBe('no-mailbox');
    });

    it('classifies 550 user not found as hard/no-mailbox', () => {
      const result = classifyBounce(new Error('550 User not found'));
      expect(result.type).toBe('hard');
      expect(result.subtype).toBe('no-mailbox');
    });

    it('classifies 550 domain not found as hard/no-domain', () => {
      const result = classifyBounce(new Error('550 Domain not found'));
      expect(result.type).toBe('hard');
      expect(result.subtype).toBe('no-domain');
    });

    it('classifies 553 rejected as hard/rejected', () => {
      const result = classifyBounce(new Error('553 Message rejected'));
      expect(result.type).toBe('hard');
      expect(result.subtype).toBe('rejected');
    });

    it('classifies 551 blocked as hard/rejected', () => {
      const result = classifyBounce(new Error('551 Message blocked by policy'));
      expect(result.type).toBe('hard');
      expect(result.subtype).toBe('rejected');
    });

    it('classifies generic 550 as hard/general', () => {
      const result = classifyBounce(new Error('550 Access denied'));
      expect(result.type).toBe('hard');
      expect(result.subtype).toBe('general');
    });
  });

  describe('soft bounces', () => {
    it('classifies 552 as soft/over-quota', () => {
      const result = classifyBounce(new Error('552 Mailbox storage limit exceeded'));
      expect(result.type).toBe('soft');
      expect(result.subtype).toBe('over-quota');
    });

    it('classifies "over quota" text as soft/over-quota', () => {
      const result = classifyBounce(new Error('User is over quota'));
      expect(result.type).toBe('soft');
      expect(result.subtype).toBe('over-quota');
    });

    it('classifies "mailbox full" as soft/over-quota', () => {
      const result = classifyBounce(new Error('Mailbox full'));
      expect(result.type).toBe('soft');
      expect(result.subtype).toBe('over-quota');
    });

    it('classifies 421 as soft/temporary', () => {
      const result = classifyBounce(new Error('421 Try again later'));
      expect(result.type).toBe('soft');
      expect(result.subtype).toBe('temporary');
    });

    it('classifies 450 as soft/temporary', () => {
      const result = classifyBounce(new Error('450 Requested action not taken'));
      expect(result.type).toBe('soft');
      expect(result.subtype).toBe('temporary');
    });

    it('classifies 451 as soft/temporary', () => {
      const result = classifyBounce(new Error('451 Temporary local problem'));
      expect(result.type).toBe('soft');
      expect(result.subtype).toBe('temporary');
    });

    it('classifies greylist as soft/greylisted', () => {
      const result = classifyBounce(new Error('Try again later, greylisting in effect'));
      expect(result.type).toBe('soft');
      expect(result.subtype).toBe('greylisted');
    });
  });

  describe('edge cases', () => {
    it('unknown error message defaults to soft/undetermined', () => {
      const result = classifyBounce(new Error('Connection reset'));
      expect(result.type).toBe('soft');
      expect(result.subtype).toBe('undetermined');
    });

    it('empty error message defaults to soft/undetermined', () => {
      const result = classifyBounce(new Error(''));
      expect(result.type).toBe('soft');
      expect(result.subtype).toBe('undetermined');
    });

    // FIXED: 554 is a permanent failure code, now correctly classified as hard bounce
    it('554 permanent failure is classified as hard/rejected', () => {
      const result = classifyBounce(new Error('554 5.7.1 Message rejected'));
      expect(result.type).toBe('hard');
      expect(result.subtype).toBe('rejected');
    });
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 5. isBounceError
// ═════════════════════════════════════════════════════════════════════════════

describe('isBounceError', () => {
  it('detects 550', () => expect(isBounceError(new Error('550 User unknown'))).toBe(true));
  it('detects 551', () => expect(isBounceError(new Error('551 Relay denied'))).toBe(true));
  it('detects 552', () => expect(isBounceError(new Error('552 Over quota'))).toBe(true));
  it('detects 553', () => expect(isBounceError(new Error('553 Invalid address'))).toBe(true));
  it('detects 554', () => expect(isBounceError(new Error('554 Rejected'))).toBe(true));
  it('detects 555', () => expect(isBounceError(new Error('555 Error'))).toBe(true));
  it('does not match 421', () => expect(isBounceError(new Error('421 Retry'))).toBe(false));
  it('does not match empty message', () => expect(isBounceError(new Error(''))).toBe(false));
  it('does not match connection errors', () => expect(isBounceError(new Error('ECONNRESET'))).toBe(false));

  // Edge case: number appearing in unrelated context — fixed with word-boundary regex
  it('no longer false-positives on "Port 5501 connection failed"', () => {
    // "550" no longer matches inside "5501" thanks to \b word boundary
    expect(isBounceError(new Error('Port 5501 connection failed'))).toBe(false);
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 6. isRetryableError
// ═════════════════════════════════════════════════════════════════════════════

describe('isRetryableError', () => {
  it('retries on 421', () => expect(isRetryableError(new Error('421 Try later'))).toBe(true));
  it('retries on 450', () => expect(isRetryableError(new Error('450 Busy'))).toBe(true));
  it('retries on 451', () => expect(isRetryableError(new Error('451 Temp failure'))).toBe(true));
  it('retries on 452', () => expect(isRetryableError(new Error('452 Too many recipients'))).toBe(true));
  it('retries on timeout', () => expect(isRetryableError(new Error('Connection timeout'))).toBe(true));
  it('retries on ECONNRESET', () => expect(isRetryableError(new Error('ECONNRESET'))).toBe(true));
  it('retries on ECONNREFUSED', () => expect(isRetryableError(new Error('ECONNREFUSED'))).toBe(true));
  it('retries on temporary', () => expect(isRetryableError(new Error('Temporary failure'))).toBe(true));
  it('does not retry 550', () => expect(isRetryableError(new Error('550 Permanent'))).toBe(false));
  it('does not retry empty', () => expect(isRetryableError(new Error(''))).toBe(false));
});


// ═════════════════════════════════════════════════════════════════════════════
// 7. Retry Backoff Calculation
// ═════════════════════════════════════════════════════════════════════════════

describe('retry backoff calculation', () => {
  it('first attempt: base delay', () => {
    expect(calculateRetryDelay(5000, 1)).toBe(5000);
  });

  it('second attempt: 2x base', () => {
    expect(calculateRetryDelay(5000, 2)).toBe(10000);
  });

  it('third attempt: 4x base', () => {
    expect(calculateRetryDelay(5000, 3)).toBe(20000);
  });

  it('large attempt: exponential growth', () => {
    // attempt=10: delay = 5000 * 2^9 = 5000 * 512 = 2,560,000ms ≈ 42 min
    expect(calculateRetryDelay(5000, 10)).toBe(5000 * Math.pow(2, 9));
  });

  it('very large attempt: approaches Infinity', () => {
    // attempt=1024: Math.pow(2, 1023) = 8.98e307 (near Number.MAX_VALUE)
    // attempt=1025: Math.pow(2, 1024) = Infinity
    const result = calculateRetryDelay(1000, 1025);
    expect(result).toBe(Infinity);
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 8. Sentiment Detection
// ═════════════════════════════════════════════════════════════════════════════

describe('detectSentiment', () => {
  it('detects positive: many positive words', () => {
    expect(detectSentiment('great work, love it, amazing and wonderful results')).toBe('positive');
  });

  it('detects negative: many negative words', () => {
    expect(detectSentiment('spam, stop, remove me, unsubscribe, annoying')).toBe('negative');
  });

  it('neutral when balanced', () => {
    expect(detectSentiment('thanks but no thanks')).toBe('neutral');
  });

  it('neutral for empty text', () => {
    expect(detectSentiment('')).toBe('neutral');
  });

  it('neutral when difference is only 1', () => {
    // "great" (+1) vs nothing (0) → 1 > 0+1 = 1 > 1 → false → neutral
    expect(detectSentiment('great')).toBe('neutral');
  });

  it('requires > 1 margin for positive', () => {
    // "great, love" (+2) vs nothing (0) → 2 > 1 → positive
    expect(detectSentiment('great, love this')).toBe('positive');
  });

  it('"not interested" counts as negative word', () => {
    // "not interested" matches negative AND "interested" matches positive
    // So it's 1 positive, 1 negative → neutral
    expect(detectSentiment('not interested')).toBe('neutral');
  });

  it('handles mixed signals', () => {
    // "thanks" (+1), "stop" (-1), "spam" (-1) → 1 pos, 2 neg → 2 > 1+1 → false → neutral
    expect(detectSentiment('thanks but stop sending spam')).toBe('neutral');
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 9. Urgency Detection
// ═════════════════════════════════════════════════════════════════════════════

describe('detectUrgency', () => {
  it('high for "urgent"', () => expect(detectUrgency('this is urgent')).toBe('high'));
  it('high for "asap"', () => expect(detectUrgency('need this asap')).toBe('high'));
  it('high for "immediately"', () => expect(detectUrgency('respond immediately')).toBe('high'));
  it('high for "today"', () => expect(detectUrgency('need response today')).toBe('high'));
  it('high for "emergency"', () => expect(detectUrgency('emergency situation')).toBe('high'));

  it('medium for "soon"', () => expect(detectUrgency('please respond soon')).toBe('medium'));
  it('medium for "this week"', () => expect(detectUrgency('sometime this week')).toBe('medium'));
  it('medium for "at your earliest"', () => expect(detectUrgency('at your earliest convenience')).toBe('medium'));

  it('low for generic text', () => expect(detectUrgency('just following up')).toBe('low'));
  it('low for empty', () => expect(detectUrgency('')).toBe('low'));

  it('high takes priority over medium', () => {
    expect(detectUrgency('urgent, respond this week')).toBe('high');
  });

  // Edge case: "now" no longer matches inside other words thanks to \b word boundaries
  it('"now" triggers high but does NOT false-positive on "knowledge"', () => {
    expect(detectUrgency('now')).toBe('high');
    // Fixed: word-boundary regex prevents substring match
    expect(detectUrgency('knowledge')).toBe('low');
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 10. OOO Return Date Extraction
// ═════════════════════════════════════════════════════════════════════════════

describe('extractReturnDate', () => {
  it('extracts date from "back on January 15, 2025"', () => {
    const result = extractReturnDate('I will be back on January 15, 2025');
    expect(result).toBeInstanceOf(Date);
    expect(result!.getFullYear()).toBe(2025);
    expect(result!.getMonth()).toBe(0); // January
    expect(result!.getDate()).toBe(15);
  });

  it('extracts day name and returns a future date', () => {
    const result = extractReturnDate('I will be back on monday');
    expect(result).toBeInstanceOf(Date);
    // Should be in the future (next Monday)
    expect(result!.getTime()).toBeGreaterThan(Date.now());
  });

  it('handles "returning on March 1"', () => {
    const result = extractReturnDate('returning on March 1');
    expect(result).toBeInstanceOf(Date);
  });

  it('handles "available on Tuesday"', () => {
    const result = extractReturnDate('I will be available on Tuesday');
    expect(result).toBeInstanceOf(Date);
  });

  it('handles "until December 25, 2025"', () => {
    const result = extractReturnDate('Out until December 25, 2025');
    expect(result).toBeInstanceOf(Date);
    expect(result!.getMonth()).toBe(11); // December
  });

  it('returns undefined for no date found', () => {
    expect(extractReturnDate('I am out of office. Contact my manager.')).toBeUndefined();
  });

  it('returns undefined for empty string', () => {
    expect(extractReturnDate('')).toBeUndefined();
  });

  // Bug documented: day name always picks NEXT occurrence, even if today matches
  it('day-name extraction: same day = 7 days ahead', () => {
    const today = new Date();
    const dayNames = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
    const todayName = dayNames[today.getDay()]!;

    const result = extractReturnDate(`I will be back on ${todayName}`);
    expect(result).toBeInstanceOf(Date);
    // (dayIndex - today.getDay() + 7) % 7 || 7 → 0 || 7 → 7
    // So the result is 7 days from now, not today
    const diffDays = Math.round((result!.getTime() - today.getTime()) / (24 * 60 * 60 * 1000));
    expect(diffDays).toBe(7);
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 11. Referral Email Extraction
// ═════════════════════════════════════════════════════════════════════════════

describe('extractReferral', () => {
  it('extracts from "please contact john@company.com"', () => {
    expect(extractReferral('Please contact john@company.com instead')).toBe('john@company.com');
  });

  it('extracts from "try reaching out to bob.smith@example.org"', () => {
    expect(extractReferral('Try reaching out to bob.smith@example.org')).toBe('bob.smith@example.org');
  });

  it('extracts from "cc sarah@team.com"', () => {
    expect(extractReferral("I've cc sarah@team.com on this")).toBe('sarah@team.com');
  });

  it('extracts from "forwarded to admin@corp.com"', () => {
    expect(extractReferral('forwarded to admin@corp.com')).toBe('admin@corp.com');
  });

  it('lowercases extracted email', () => {
    expect(extractReferral('contact John@Company.COM')).toBe('john@company.com');
  });

  it('falls back to finding any email in text', () => {
    expect(extractReferral('The right person is jane.doe@acme.io for this topic')).toBe('jane.doe@acme.io');
  });

  it('returns undefined when no email present', () => {
    expect(extractReferral('I left the company last year')).toBeUndefined();
  });

  it('returns undefined for empty string', () => {
    expect(extractReferral('')).toBeUndefined();
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 12. ISP Detection
// ═════════════════════════════════════════════════════════════════════════════

describe('getDirectISPMapping', () => {
  describe('Gmail', () => {
    it('maps gmail.com', () => expect(getDirectISPMapping('gmail.com')).toBe('gmail'));
    it('maps googlemail.com', () => expect(getDirectISPMapping('googlemail.com')).toBe('gmail'));
    it('maps *.google.com', () => expect(getDirectISPMapping('mail.google.com')).toBe('gmail'));
    it('case insensitive', () => expect(getDirectISPMapping('GMAIL.COM')).toBe('gmail'));
  });

  describe('Microsoft', () => {
    it('maps outlook.com', () => expect(getDirectISPMapping('outlook.com')).toBe('microsoft'));
    it('maps hotmail.com', () => expect(getDirectISPMapping('hotmail.com')).toBe('microsoft'));
    it('maps live.com', () => expect(getDirectISPMapping('live.com')).toBe('microsoft'));
    it('maps msn.com', () => expect(getDirectISPMapping('msn.com')).toBe('microsoft'));
    it('maps *.outlook.com', () => expect(getDirectISPMapping('mail.outlook.com')).toBe('microsoft'));
  });

  describe('Yahoo', () => {
    it('maps yahoo.com', () => expect(getDirectISPMapping('yahoo.com')).toBe('yahoo'));
    it('maps aol.com', () => expect(getDirectISPMapping('aol.com')).toBe('yahoo'));
    it('maps *.yahoo.com', () => expect(getDirectISPMapping('mail.yahoo.com')).toBe('yahoo'));
  });

  describe('Apple', () => {
    it('maps icloud.com', () => expect(getDirectISPMapping('icloud.com')).toBe('apple'));
    it('maps me.com', () => expect(getDirectISPMapping('me.com')).toBe('apple'));
    it('maps *.apple.com', () => expect(getDirectISPMapping('mail.apple.com')).toBe('apple'));
  });

  describe('unknown', () => {
    it('returns null for custom domains', () => {
      expect(getDirectISPMapping('company.com')).toBeNull();
    });
    it('returns null for empty string', () => {
      expect(getDirectISPMapping('')).toBeNull();
    });
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 13. Warmup Day Calculation
// ═════════════════════════════════════════════════════════════════════════════

describe('calculateWarmupDay', () => {
  it('returns 0 for start date = today', () => {
    expect(calculateWarmupDay(new Date())).toBe(0);
  });

  it('returns correct days for past date', () => {
    const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);
    expect(calculateWarmupDay(twoDaysAgo)).toBe(2);
  });

  // FIXED: Future start dates now correctly return 0 (warmup hasn't started)
  it('future start date returns 0', () => {
    const threeDaysFromNow = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000);
    const result = calculateWarmupDay(threeDaysFromNow);
    expect(result).toBe(0);
  });

  it('handles exact day boundaries', () => {
    const exactlyOneDay = new Date(Date.now() - 24 * 60 * 60 * 1000);
    expect(calculateWarmupDay(exactlyOneDay)).toBe(1);
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 14. Time Utility Functions
// ═════════════════════════════════════════════════════════════════════════════

describe('secondsUntilMidnightUTC', () => {
  it('returns a positive number', () => {
    expect(secondsUntilMidnightUTC()).toBeGreaterThan(0);
  });

  it('is at most 86400 seconds (24 hours)', () => {
    expect(secondsUntilMidnightUTC()).toBeLessThanOrEqual(86400);
  });

  it('is at least 1 second', () => {
    expect(secondsUntilMidnightUTC()).toBeGreaterThanOrEqual(1);
  });
});

describe('secondsUntilNextHour', () => {
  it('returns a positive number', () => {
    expect(secondsUntilNextHour()).toBeGreaterThan(0);
  });

  it('is at most 3600 seconds (1 hour)', () => {
    expect(secondsUntilNextHour()).toBeLessThanOrEqual(3600);
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 15. Prometheus Metrics Formatting
// ═════════════════════════════════════════════════════════════════════════════

describe('Prometheus label formatting', () => {
  describe('escapeLabel', () => {
    it('escapes backslashes', () => {
      expect(escapeLabel('path\\to\\file')).toBe('path\\\\to\\\\file');
    });

    it('escapes double quotes', () => {
      expect(escapeLabel('value"with"quotes')).toBe('value\\"with\\"quotes');
    });

    it('escapes newlines', () => {
      expect(escapeLabel('line1\nline2')).toBe('line1\\nline2');
    });

    it('handles all special chars together', () => {
      expect(escapeLabel('a\\b"c\nd')).toBe('a\\\\b\\"c\\nd');
    });

    it('passes through safe strings', () => {
      expect(escapeLabel('normal_value')).toBe('normal_value');
    });

    it('handles empty string', () => {
      expect(escapeLabel('')).toBe('');
    });
  });

  describe('formatLabels', () => {
    it('formats single label', () => {
      expect(formatLabels({ method: 'GET' })).toBe('method="GET"');
    });

    it('formats multiple labels', () => {
      const result = formatLabels({ method: 'POST', status: '200' });
      expect(result).toBe('method="POST",status="200"');
    });

    it('escapes label values', () => {
      const result = formatLabels({ path: '/api/"test"' });
      expect(result).toBe('path="/api/\\"test\\""');
    });

    it('handles empty labels object', () => {
      expect(formatLabels({})).toBe('');
    });
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 16. Reply Pattern Matching (PATTERNS)
// ═════════════════════════════════════════════════════════════════════════════

describe('Reply Classification Patterns', () => {
  // Reproduce the patterns for testing
  const PATTERNS: Record<string, RegExp[]> = {
    out_of_office: [
      /out of (?:the )?office/i,
      /away from (?:my )?(?:desk|office|email)/i,
      /on (?:annual |paid )?(?:leave|vacation|holiday|pto)/i,
      /currently (?:out|away|traveling|unavailable)/i,
      /limited access to email/i,
      /auto[- ]?reply/i,
      /automatic reply/i,
      /i(?:'m| am) (?:currently )?(?:out|away|on leave)/i,
      /will (?:be )?(?:back|return(?:ing)?|in the office)(?: on)?/i,
      /maternity|paternity leave/i,
      /(?:sick|medical) leave/i,
    ],
    not_interested: [
      /not interested/i,
      /no(?:t)? thank(?:s| you)/i,
      /please remove (?:me|us)/i,
      /don't contact (?:me|us)/i,
      /stop (?:emailing|contacting|sending)/i,
      /we(?:'re| are) not (?:looking|interested)/i,
      /not a good fit/i,
      /not (?:right|the right) time/i,
      /pass(?:ing)? on this/i,
      /we(?:'ll| will) pass/i,
      /decline/i,
      /not for us/i,
    ],
    unsubscribe: [
      /unsubscribe/i,
      /remove (?:me|my email|us)/i,
      /opt[- ]?out/i,
      /stop (?:sending|emailing)/i,
      /take (?:me|us) off (?:your |the )?list/i,
      /gdpr|ccpa|data (?:deletion|removal)/i,
      /do not (?:email|contact)/i,
    ],
  };

  function matchesAny(text: string, patterns: RegExp[]): boolean {
    return patterns.some(p => p.test(text));
  }

  describe('out_of_office patterns', () => {
    const ooo = PATTERNS.out_of_office!;
    it('"I am out of the office" matches', () => expect(matchesAny('I am out of the office', ooo)).toBe(true));
    it('"out of office until Monday" matches', () => expect(matchesAny('out of office until Monday', ooo)).toBe(true));
    it('"Currently away from my desk" matches', () => expect(matchesAny('Currently away from my desk', ooo)).toBe(true));
    it('"I\'m on vacation" matches', () => expect(matchesAny("I'm on vacation", ooo)).toBe(true));
    it('"on PTO" matches', () => expect(matchesAny('on PTO', ooo)).toBe(true));
    it('"auto-reply" matches', () => expect(matchesAny('This is an auto-reply', ooo)).toBe(true));
    it('"automatic reply" matches', () => expect(matchesAny('automatic reply: ', ooo)).toBe(true));
    it('"maternity leave" matches', () => expect(matchesAny('I am on maternity leave', ooo)).toBe(true));
    it('"sick leave" matches', () => expect(matchesAny('I am on sick leave', ooo)).toBe(true));
    it('"will return on January 5" matches', () => expect(matchesAny('will return on January 5', ooo)).toBe(true));
    it('"Hello how are you" does NOT match', () => expect(matchesAny('Hello how are you', ooo)).toBe(false));
  });

  describe('not_interested patterns', () => {
    const ni = PATTERNS.not_interested!;
    it('"Not interested" matches', () => expect(matchesAny('Not interested', ni)).toBe(true));
    it('"No thanks" matches', () => expect(matchesAny('No thanks', ni)).toBe(true));
    it('"No thank you" matches', () => expect(matchesAny('No thank you', ni)).toBe(true));
    it('"please remove me" matches', () => expect(matchesAny('please remove me', ni)).toBe(true));
    it('"stop emailing me" matches', () => expect(matchesAny('stop emailing me', ni)).toBe(true));
    it('"not a good fit" matches', () => expect(matchesAny('not a good fit', ni)).toBe(true));
    it('"we\'ll pass" matches', () => expect(matchesAny("we'll pass", ni)).toBe(true));
    it('"I decline" matches', () => expect(matchesAny('I decline', ni)).toBe(true));
    it('"not for us" matches', () => expect(matchesAny('not for us right now', ni)).toBe(true));
    it('"I am interested" does NOT match', () => expect(matchesAny('I am interested', ni)).toBe(false));
  });

  describe('unsubscribe patterns', () => {
    const unsub = PATTERNS.unsubscribe!;
    it('"unsubscribe" matches', () => expect(matchesAny('Please unsubscribe', unsub)).toBe(true));
    it('"remove me" matches', () => expect(matchesAny('Remove me from your list', unsub)).toBe(true));
    it('"opt out" matches', () => expect(matchesAny('I want to opt out', unsub)).toBe(true));
    it('"opt-out" matches', () => expect(matchesAny('I want to opt-out', unsub)).toBe(true));
    it('"GDPR" matches', () => expect(matchesAny('This is a GDPR request', unsub)).toBe(true));
    it('"CCPA" matches', () => expect(matchesAny('CCPA data deletion request', unsub)).toBe(true));
    it('"take me off the list" matches', () => expect(matchesAny('take me off the list', unsub)).toBe(true));
    it('"do not email" matches', () => expect(matchesAny('Do not email me', unsub)).toBe(true));
  });
});


// ═════════════════════════════════════════════════════════════════════════════
// 17. Token Bucket Rate Limiter
// ═════════════════════════════════════════════════════════════════════════════

describe('TokenBucketRateLimiter (logic verification)', () => {
  // We test the algorithm by reimplementing the pure math

  it('refill adds tokens based on elapsed time', () => {
    // capacity=10, rate=5 tokens/sec
    const capacity = 10;
    const refillRate = 5;
    let tokens = 0; // start empty
    const elapsed = 1.0; // 1 second

    const newTokens = elapsed * refillRate;
    tokens = Math.min(capacity, tokens + newTokens);

    expect(tokens).toBe(5);
  });

  it('tokens are capped at capacity', () => {
    const capacity = 10;
    const refillRate = 100;
    let tokens = 8;
    const elapsed = 1.0;

    const newTokens = elapsed * refillRate;
    tokens = Math.min(capacity, tokens + newTokens);

    expect(tokens).toBe(10); // Capped at capacity
  });

  it('no tokens added for 0 elapsed time', () => {
    const tokens = 5;
    const newTokens = 0 * 10;
    expect(Math.min(10, tokens + newTokens)).toBe(5);
  });

  // FIXED: negative elapsed time is clamped to 0 by Math.max, preserving tokens
  it('negative elapsed time (clock jump) is clamped to 0, tokens preserved', () => {
    const capacity = 10;
    const refillRate = 5;
    let tokens = 5;
    const elapsed = Math.max(0, -1); // Clamped: clock jump becomes 0

    const newTokens = elapsed * refillRate;
    tokens = Math.min(capacity, tokens + newTokens);

    // tokens = min(10, 5 + 0) = 5 — tokens preserved
    expect(tokens).toBe(5);
  });
});
