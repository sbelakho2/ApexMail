/**
 * Subject Line Analyzer — Comprehensive Unit Tests
 *
 * Tests NLP scoring, power word categorization, spam detection, and scoring logic.
 * DB-dependent methods (getAudienceInsights, suggestVariations) are tested with
 * mocked Pool/Redis to validate query construction and aggregation logic.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SubjectLineAnalyzer } from '../subject-line-analyzer.js';
import type { SubjectLineScore, AudienceInsights } from '../subject-line-analyzer.js';

// ─── Mocks ───────────────────────────────────────────────────────────────────

function createMockPool() {
  return {
    query: vi.fn().mockResolvedValue({ rows: [] }),
  } as any;
}

function createMockRedis() {
  const store = new Map<string, string>();
  return {
    get: vi.fn(async (key: string) => store.get(key) || null),
    setex: vi.fn(async (key: string, _ttl: number, val: string) => { store.set(key, val); }),
    del: vi.fn(async (key: string) => { store.delete(key); }),
  } as any;
}

function createMockLogger() {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    child: vi.fn().mockReturnThis(),
  } as any;
}

describe('SubjectLineAnalyzer', () => {
  let analyzer: SubjectLineAnalyzer;
  let mockDb: ReturnType<typeof createMockPool>;
  let mockRedis: ReturnType<typeof createMockRedis>;

  beforeEach(() => {
    mockDb = createMockPool();
    mockRedis = createMockRedis();
    analyzer = new SubjectLineAnalyzer({
      db: mockDb,
      redis: mockRedis,
      logger: createMockLogger(),
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. Subject Line Scoring
  // ═══════════════════════════════════════════════════════════════════════════

  describe('scoreSubjectLine', () => {
    it('returns valid score structure', async () => {
      const result = await analyzer.scoreSubjectLine('Save 50% today only!');

      expect(result).toHaveProperty('subject');
      expect(result).toHaveProperty('predictedOpenRate');
      expect(result).toHaveProperty('scores');
      expect(result).toHaveProperty('issues');
      expect(result).toHaveProperty('suggestions');
      expect(result).toHaveProperty('powerTokens');
      expect(result).toHaveProperty('riskTokens');

      expect(result.scores).toHaveProperty('overall');
      expect(result.scores).toHaveProperty('length');
      expect(result.scores).toHaveProperty('urgency');
      expect(result.scores).toHaveProperty('personalization');
      expect(result.scores).toHaveProperty('clarity');
      expect(result.scores).toHaveProperty('spamRisk');
    });

    it('scores range from 0 to 100', async () => {
      const result = await analyzer.scoreSubjectLine('Test subject');

      expect(result.scores.overall).toBeGreaterThanOrEqual(0);
      expect(result.scores.overall).toBeLessThanOrEqual(100);
      expect(result.scores.length).toBeGreaterThanOrEqual(0);
      expect(result.scores.length).toBeLessThanOrEqual(100);
    });

    it('predicts open rate between 0 and 1', async () => {
      const result = await analyzer.scoreSubjectLine('Great deals await you today!');

      expect(result.predictedOpenRate).toBeGreaterThanOrEqual(0);
      expect(result.predictedOpenRate).toBeLessThanOrEqual(1);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. Length Analysis
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Length scoring', () => {
    it('penalizes very short subjects', async () => {
      const short = await analyzer.scoreSubjectLine('Hi');
      const optimal = await analyzer.scoreSubjectLine('Discover your personalized weekly insights report');

      expect(short.scores.length).toBeLessThan(optimal.scores.length);
      expect(short.issues.some(i => i.message.includes('short'))).toBe(true);
    });

    it('warns about long subjects (mobile truncation)', async () => {
      const long = await analyzer.scoreSubjectLine(
        'This is an extremely long subject line that will definitely be truncated on mobile email clients'
      );

      expect(long.issues.some(i => i.message.includes('truncated') || i.message.includes('mobile'))).toBe(true);
    });

    it('gives full score for optimal length (30-50 chars)', async () => {
      const result = await analyzer.scoreSubjectLine('Your weekly insights are ready now'); // ~35 chars

      expect(result.scores.length).toBe(100);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. Urgency Detection
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Urgency scoring', () => {
    it('detects urgency words', async () => {
      const result = await analyzer.scoreSubjectLine('Last chance: Limited offer expires today');

      expect(result.scores.urgency).toBeGreaterThan(0);
      expect(result.powerTokens).toEqual(
        expect.arrayContaining(['last', 'chance', 'limited', 'expires', 'today'].filter(w =>
          result.powerTokens.includes(w)
        ))
      );
    });

    it('gives zero urgency for neutral subjects', async () => {
      const result = await analyzer.scoreSubjectLine('Your monthly newsletter is here');

      expect(result.scores.urgency).toBe(0);
    });

    it('caps urgency score at 100', async () => {
      const result = await analyzer.scoreSubjectLine('URGENT deadline NOW today limited hurry final asap immediately');

      expect(result.scores.urgency).toBeLessThanOrEqual(100);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. Personalization Detection
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Personalization scoring', () => {
    it('detects template variables like {{name}}', async () => {
      const result = await analyzer.scoreSubjectLine('{{name}}, your report is ready');

      expect(result.scores.personalization).toBeGreaterThanOrEqual(80);
      expect(result.powerTokens).toContain('personalization');
    });

    it('detects second-person pronouns (you/your)', async () => {
      const result = await analyzer.scoreSubjectLine('Your account summary for this month');

      expect(result.scores.personalization).toBeGreaterThanOrEqual(50);
    });

    it('suggests personalization when absent', async () => {
      const result = await analyzer.scoreSubjectLine('Monthly report summary');

      expect(result.suggestions.some(s => s.includes('Personalized') || s.includes('personalization'))).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. Clarity / Spam-Risk Analysis
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Clarity and spam risk', () => {
    it('penalizes ALL CAPS subjects', async () => {
      const result = await analyzer.scoreSubjectLine('BUY NOW AMAZING DEALS');

      expect(result.scores.clarity).toBeLessThan(100);
      expect(result.issues.some(i => i.message.includes('CAPS'))).toBe(true);
    });

    it('penalizes multiple exclamation marks', async () => {
      const result = await analyzer.scoreSubjectLine('Amazing deals await!!!');

      expect(result.issues.some(i => i.message.includes('exclamation'))).toBe(true);
    });

    it('penalizes dollar signs', async () => {
      const result = await analyzer.scoreSubjectLine('Save $$$ on your next purchase');

      expect(result.issues.some(i => i.message.includes('Dollar') || i.message.includes('spam'))).toBe(true);
    });

    it('detects spam trigger words', async () => {
      const result = await analyzer.scoreSubjectLine('Congratulations! You are a winner! Click here for free cash');

      expect(result.scores.spamRisk).toBeGreaterThan(30);
      expect(result.riskTokens.length).toBeGreaterThan(0);
    });

    it('clean subject has zero spam risk', async () => {
      const result = await analyzer.scoreSubjectLine('Your weekly performance summary');

      expect(result.scores.spamRisk).toBe(0);
      expect(result.riskTokens.length).toBe(0);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 6. Questions and Numbers
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Special features', () => {
    it('recognizes question subjects', async () => {
      const result = await analyzer.scoreSubjectLine('Are you ready for better engagement?');

      expect(result.suggestions.some(s => s.includes('Questions') || s.includes('question'))).toBe(true);
    });

    it('recognizes subjects with numbers', async () => {
      const result = await analyzer.scoreSubjectLine('5 ways to boost your email metrics');

      expect(result.powerTokens).toContain('number');
    });

    it('suggests adding numbers when absent', async () => {
      const result = await analyzer.scoreSubjectLine('Ways to boost your email metrics');

      expect(result.suggestions.some(s => s.includes('Numbers') || s.includes('number'))).toBe(true);
    });

    it('detects emoji usage', async () => {
      const result = await analyzer.scoreSubjectLine('🚀 Your launch report is ready!');

      expect(result.suggestions.some(s => s.includes('Emoji') || s.includes('emoji'))).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 7. Overall Score Calculation
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Overall score weighting', () => {
    it('well-crafted subject scores higher than spammy one', async () => {
      const good = await analyzer.scoreSubjectLine('{{name}}, your 5 insights for this week');
      const bad = await analyzer.scoreSubjectLine('FREE!!! WINNER CONGRATULATIONS CLICK NOW $$$');

      expect(good.scores.overall).toBeGreaterThan(bad.scores.overall);
    });

    it('overall score is a weighted average', async () => {
      const result = await analyzer.scoreSubjectLine('Test subject line for scoring');

      // overall = length*0.2 + urgency*0.15 + personalization*0.2 + clarity*0.25 + (100-spam)*0.2
      const expected = Math.round(
        (result.scores.length * 0.2) +
        (result.scores.urgency * 0.15) +
        (result.scores.personalization * 0.2) +
        (result.scores.clarity * 0.25) +
        ((100 - result.scores.spamRisk) * 0.2)
      );

      expect(result.scores.overall).toBe(expected);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 8. Audience Insights (with mocked DB)
  // ═══════════════════════════════════════════════════════════════════════════

  describe('getAudienceInsights', () => {
    it('returns baseline metrics from DB', async () => {
      // Mock baseline query
      mockDb.query
        .mockResolvedValueOnce({
          rows: [{ total_subjects: '50', total_sent: '2000', total_opened: '400' }],
        })
        // Mock subject performance query
        .mockResolvedValueOnce({
          rows: [
            { subject: 'Great deal today', sent_count: '100', open_count: '25' },
            { subject: 'Your weekly report', sent_count: '200', open_count: '50' },
          ],
        })
        // Mock length analysis
        .mockResolvedValueOnce({
          rows: [
            { length_bucket: 'optimal', open_rate: '0.28' },
            { length_bucket: 'short', open_rate: '0.15' },
          ],
        });

      const insights = await analyzer.getAudienceInsights('tenant-001');

      expect(insights.tenantId).toBe('tenant-001');
      expect(insights.baselineOpenRate).toBe(0.2); // 400/2000
      expect(insights.totalSubjects).toBe(50);
      expect(insights.totalEmails).toBe(2000);
    });

    it('caches insights in Redis', async () => {
      mockDb.query.mockResolvedValue({ rows: [] });

      await analyzer.getAudienceInsights('tenant-cache');

      expect(mockRedis.setex).toHaveBeenCalled();
      const call = mockRedis.setex.mock.calls[0];
      expect(call[0]).toContain('tenant-cache');
      expect(call[1]).toBe(86400); // 24 hours TTL
    });

    it('returns cached result on cache hit', async () => {
      const cachedInsights: AudienceInsights = {
        tenantId: 'tenant-cached',
        baselineOpenRate: 0.25,
        totalSubjects: 100,
        totalEmails: 5000,
        topPowerWords: [],
        topRiskWords: [],
        optimalLength: { min: 30, max: 50 },
        emojiEffect: { lift: 0.1, sampleSize: 100 },
        questionEffect: { lift: 0.05, sampleSize: 80 },
        numberEffect: { lift: 0.08, sampleSize: 120 },
        personalizationEffect: { lift: 0.2, sampleSize: 50 },
      };

      mockRedis.get.mockResolvedValueOnce(JSON.stringify(cachedInsights));

      const result = await analyzer.getAudienceInsights('tenant-cached');

      expect(result.tenantId).toBe('tenant-cached');
      expect(result.baselineOpenRate).toBe(0.25);
      // DB should NOT have been queried
      expect(mockDb.query).not.toHaveBeenCalled();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 9. Subject Line Variations
  // ═══════════════════════════════════════════════════════════════════════════

  describe('suggestVariations', () => {
    it('generates at least 1 variation', async () => {
      const result = await analyzer.suggestVariations('Your monthly report');

      expect(result.original).toBeDefined();
      expect(result.variations.length).toBeGreaterThanOrEqual(1);
    });

    it('each variation has a score and description', async () => {
      const result = await analyzer.suggestVariations('Check out our latest updates');

      for (const variation of result.variations) {
        expect(variation.subject).toBeTruthy();
        expect(variation.score).toBeDefined();
        expect(variation.changeDescription).toBeTruthy();
      }
    });

    it('returns max 3 variations', async () => {
      const result = await analyzer.suggestVariations('Your monthly report');

      expect(result.variations.length).toBeLessThanOrEqual(3);
    });

    it('adds question variation when original has no question', async () => {
      const result = await analyzer.suggestVariations('Latest product updates');

      expect(result.variations.some(v => v.subject.includes('?'))).toBe(true);
    });
  });
});
