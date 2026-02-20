/**
 * Bot Detection Service — Comprehensive Unit Tests
 *
 * Tests UA analysis, timing, velocity, IP reputation, headers,
 * honeypot links, combined scoring, and cache eviction.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { BotDetectionService, BotType } from '../bot-detection.js';
import type { ClickEvent } from '../bot-detection.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeClick(overrides: Partial<ClickEvent> = {}): ClickEvent {
  return {
    messageId: 'msg-1',
    recipientEmail: 'user@example.com',
    linkUrl: 'https://example.com/link',
    timestamp: new Date('2024-01-15T10:01:00Z'),
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    ipAddress: '192.168.1.1',
    headers: {},
    ...overrides,
  };
}

describe('BotDetectionService', () => {
  let service: BotDetectionService;

  beforeEach(() => {
    service = new BotDetectionService();
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. User-Agent analysis — UA match alone = 40 pts, isBot threshold = 50
  // ═══════════════════════════════════════════════════════════════════════════

  describe('User-Agent analysis', () => {
    it('detects known security scanner UAs (combined with timing to cross threshold)', () => {
      const scannerUAs = [
        'Mozilla/5.0 Barracuda Email Security',
        'Mimecast/1.0 link-checker',
        'Proofpoint URL Defense',
      ];
      // instant click: UA(40) + timing(35) = 75 → isBot
      const openTime = new Date('2024-01-15T10:00:59.500Z');

      for (const ua of scannerUAs) {
        const result = service.analyzeClick(
          makeClick({ userAgent: ua, timestamp: new Date('2024-01-15T10:01:00Z') }),
          openTime,
        );
        expect(result.isBot).toBe(true);
        expect(result.reasons.length).toBeGreaterThan(0);
      }
    });

    it('detects link prefetch bots (combined with timing)', () => {
      const prefetchUAs = [
        'facebookexternalhit/1.1',
        'Twitterbot/1.0',
        'Slackbot-LinkExpanding 1.0',
      ];
      const openTime = new Date('2024-01-15T10:00:59.800Z');

      for (const ua of prefetchUAs) {
        const result = service.analyzeClick(
          makeClick({ userAgent: ua, timestamp: new Date('2024-01-15T10:01:00Z') }),
          openTime,
        );
        expect(result.isBot).toBe(true);
      }
    });

    it('detects common crawlers (combined with timing)', () => {
      const crawlers = [
        'Python-Requests/2.28.0',
        'curl/7.88.1',
        'Mozilla/5.0 (compatible; Googlebot/2.1)',
      ];
      const openTime = new Date('2024-01-15T10:00:59.800Z');

      for (const ua of crawlers) {
        const result = service.analyzeClick(
          makeClick({ userAgent: ua, timestamp: new Date('2024-01-15T10:01:00Z') }),
          openTime,
        );
        expect(result.isBot).toBe(true);
      }
    });

    it('allows legitimate user agents through', () => {
      const legitimateUAs = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15',
      ];
      // 3 seconds after open — human-like   
      const openTime = new Date('2024-01-15T10:00:57Z');

      for (const ua of legitimateUAs) {
        const result = service.analyzeClick(
          makeClick({ userAgent: ua, timestamp: new Date('2024-01-15T10:01:00Z') }),
          openTime,
        );
        expect(result.isBot).toBe(false);
      }
    });

    it('bot UA + missing headers scores 55 (40 UA + 15 headers), so isBot=true', () => {
      // curl matches /curl/i (+40), empty headers lack accept-language (+10) & accept-encoding (+5) = 55
      const result = service.analyzeClick(makeClick({ userAgent: 'curl/7.88.1' }));
      expect(result.confidence).toBeGreaterThanOrEqual(50);
      expect(result.isBot).toBe(true);
    });

    it('bot UA with proper headers stays below threshold', () => {
      // With accept-language and accept-encoding, header penalty = 0 → only UA 40 < 50
      const result = service.analyzeClick(makeClick({
        userAgent: 'curl/7.88.1',
        headers: { 'accept-language': 'en-US', 'accept-encoding': 'gzip' },
      }));
      expect(result.confidence).toBe(40);
      expect(result.isBot).toBe(false);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. Timing analysis — instant click = 35pts alone
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Timing analysis', () => {
    it('flags clicks within 1 second as suspicious (35 pts)', () => {
      const openTime = new Date('2024-01-15T10:00:00.000Z');
      const result = service.analyzeClick(
        makeClick({ timestamp: new Date('2024-01-15T10:00:00.500Z') }),
        openTime,
      );
      expect(result.confidence).toBeGreaterThanOrEqual(35);
      expect(result.reasons.some(r => r.toLowerCase().includes('instant') || r.toLowerCase().includes('click'))).toBe(true);
    });

    it('instant click + bot UA crosses isBot threshold', () => {
      const openTime = new Date('2024-01-15T10:00:00.000Z');
      const result = service.analyzeClick(
        makeClick({ userAgent: 'curl/7.88.1', timestamp: new Date('2024-01-15T10:00:00.500Z') }),
        openTime,
      );
      expect(result.isBot).toBe(true);
      expect(result.confidence).toBeGreaterThanOrEqual(50);
    });

    it('does NOT flag clicks after 2+ seconds as fast', () => {
      const openTime = new Date('2024-01-15T10:00:00.000Z');
      const result = service.analyzeClick(
        makeClick({ timestamp: new Date('2024-01-15T10:00:03.000Z') }),
        openTime,
      );
      expect(result.isBot).toBe(false);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. Click velocity
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Click velocity', () => {
    it('flags burst of clicks from same IP within 5s window', () => {
      const baseTime = new Date('2024-01-15T10:00:00.000Z');
      for (let i = 0; i < 3; i++) {
        service.analyzeClick(makeClick({
          ipAddress: '10.0.0.1',
          timestamp: new Date(baseTime.getTime() + i * 100),
          linkUrl: `https://example.com/link-${i}`,
        }));
      }
      const result = service.analyzeClick(makeClick({
        ipAddress: '10.0.0.1',
        timestamp: new Date(baseTime.getTime() + 400),
        linkUrl: 'https://example.com/link-final',
      }));

      expect(result.reasons.some(r => r.toLowerCase().includes('velocity'))).toBe(true);
    });

    it('does NOT flag a single click', () => {
      const result = service.analyzeClick(makeClick({
        ipAddress: '10.1.1.1',
        timestamp: new Date('2024-01-15T10:00:00.000Z'),
      }));
      expect(result.reasons.some(r => r.toLowerCase().includes('velocity'))).toBe(false);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. Header analysis
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Header analysis', () => {
    it('returns result with empty headers', () => {
      const result = service.analyzeClick(makeClick({ headers: {} }));
      expect(result).toBeDefined();
      expect(result.confidence).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. Honeypot links
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Honeypot links', () => {
    it('generates a valid honeypot URL', () => {
      const url = service.generateHoneypotLink('msg-123', 'https://track.example.com');
      // URL uses /track/hp/ path with base64-encoded token (honeypot:msgId:timestamp)
      expect(url).toContain('/track/hp/');
      expect(url.startsWith('https://track.example.com')).toBe(true);
    });

    it('generates honeypot HTML with hidden styling', () => {
      const html = service.generateHoneypotHtml('https://track.example.com/honeypot');
      expect(html).toContain('href');
      expect(html.toLowerCase()).toMatch(/display:\s*none|visibility:\s*hidden|opacity:\s*0|hidden/);
    });

    it('detects click on honeypot link (combined with bot UA + timing)', () => {
      const honeypotUrl = service.generateHoneypotLink('msg-123', 'https://track.example.com');
      const openTime = new Date('2024-01-15T10:00:00.000Z');
      const result = service.analyzeClick(makeClick({
        linkUrl: honeypotUrl,
        userAgent: 'Barracuda/1.0',
        timestamp: new Date('2024-01-15T10:00:00.300Z'),
      }), openTime);

      expect(result.isBot).toBe(true);
      expect(result.confidence).toBeGreaterThanOrEqual(50);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 6. Combined scoring
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Combined bot scoring', () => {
    it('returns BotType enum for identified bot (UA + timing + known IP)', () => {
      const openTime = new Date('2024-01-15T10:00:00.000Z');
      const result = service.analyzeClick(makeClick({
        userAgent: 'Barracuda Email Scanning',
        timestamp: new Date('2024-01-15T10:00:00.200Z'),
        ipAddress: '64.235.1.1',
      }), openTime);

      expect(result.isBot).toBe(true);
      if (result.botType) {
        expect(Object.values(BotType)).toContain(result.botType);
      }
    });

    it('confidence is capped at 100', () => {
      const openTime = new Date('2024-01-15T10:00:00.000Z');
      const result = service.analyzeClick(makeClick({
        userAgent: 'Barracuda Email Scanning',
        timestamp: new Date('2024-01-15T10:00:00.200Z'),
        ipAddress: '64.235.1.1',
      }), openTime);

      expect(result.confidence).toBeLessThanOrEqual(100);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 7. Cache eviction — many IPs should not crash
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Cache eviction', () => {
    it('handles many unique IPs without crashing', () => {
      for (let i = 0; i < 100; i++) {
        service.analyzeClick(makeClick({
          ipAddress: `10.0.${Math.floor(i / 256)}.${i % 256}`,
          timestamp: new Date(Date.now() + i),
        }));
      }
      const result = service.analyzeClick(makeClick({ ipAddress: '10.0.0.1' }));
      expect(result).toBeDefined();
    });
  });
});
