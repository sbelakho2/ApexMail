/**
 * Inbox Placement Testing Service
 * 
 * Tests actual inbox vs spam folder placement using seed lists across major ISPs.
 * This is critical for understanding real deliverability, not just "delivered" status.
 * 
 * Features:
 * - Seed list management across major providers (Gmail, Outlook, Yahoo, etc.)
 * - Automated test email sending
 * - Placement detection (inbox/spam/missing)
 * - Historical tracking and trend analysis
 * - ISP-specific recommendations
 * 
 * Industry benchmarks:
 * - Transactional emails: 95-99% inbox placement
 * - Marketing emails: 85-95% inbox placement
 * - Below 80%: Requires immediate attention
 * 
 * @see Mailtrap, Mailgun, and other industry best practices
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';
import { generateId } from '@apexmail/lib';

export interface SeedAccount {
  id: string;
  email: string;
  provider: EmailProvider;
  imapHost: string;
  imapPort: number;
  imapUser: string;
  // imapPassword stored securely, not in interface
  status: 'active' | 'inactive' | 'error';
  lastChecked: Date | null;
  createdAt: Date;
}

export type EmailProvider = 
  | 'gmail'
  | 'outlook'
  | 'yahoo'
  | 'aol'
  | 'icloud'
  | 'protonmail'
  | 'zoho'
  | 'gmx'
  | 'other';

export interface PlacementTest {
  id: string;
  tenantId: string;
  campaignId?: string;
  testName: string;
  subject: string;
  fromAddress: string;
  status: 'pending' | 'sending' | 'checking' | 'completed' | 'failed';
  results: PlacementTestResult[];
  summary: PlacementSummary;
  createdAt: Date;
  completedAt: Date | null;
}

export interface PlacementTestResult {
  seedAccountId: string;
  provider: EmailProvider;
  placement: 'inbox' | 'spam' | 'promotions' | 'social' | 'missing';
  deliveredAt: Date | null;
  checkedAt: Date;
  spamScore?: number;
  headers?: Record<string, string>;
}

export interface PlacementSummary {
  totalSent: number;
  totalReceived: number;
  inboxCount: number;
  spamCount: number;
  promotionsCount: number;
  missingCount: number;
  inboxRate: number;  // Percentage
  deliveryRate: number;
  byProvider: Record<EmailProvider, {
    sent: number;
    inbox: number;
    spam: number;
    other: number;
    missing: number;
    inboxRate: number;
  }>;
}

export interface InboxPlacementConfig {
  db: Pool;
  redis: Redis;
  logger: Logger;
  sendEmail: (to: string, subject: string, body: string, headers: Record<string, string>) => Promise<void>;
  checkMailbox: (account: SeedAccount, testId: string) => Promise<PlacementTestResult>;
}

export class InboxPlacementService {
  private readonly db: Pool;
  private readonly redis: Redis;
  private readonly logger: Logger;
  private readonly sendEmail: InboxPlacementConfig['sendEmail'];
  private readonly checkMailbox: InboxPlacementConfig['checkMailbox'];

  constructor(config: InboxPlacementConfig) {
    this.db = config.db;
    this.redis = config.redis;
    this.logger = config.logger;
    this.sendEmail = config.sendEmail;
    this.checkMailbox = config.checkMailbox;
  }

  /**
   * Create and run a new inbox placement test
   */
  async runPlacementTest(
    tenantId: string,
    options: {
      testName: string;
      subject: string;
      htmlBody: string;
      textBody?: string;
      fromAddress: string;
      fromName?: string;
      campaignId?: string;
      seedAccountIds?: string[];  // If not provided, use all active accounts
    }
  ): Promise<PlacementTest> {
    const testId = generateId('ipt');
    
    // Get seed accounts
    const seedAccounts = options.seedAccountIds
      ? await this.getSeedAccountsByIds(options.seedAccountIds)
      : await this.getAllActiveSeedAccounts();

    if (seedAccounts.length === 0) {
      throw new Error('No seed accounts available for testing');
    }

    // Create test record
    const test: PlacementTest = {
      id: testId,
      tenantId,
      campaignId: options.campaignId,
      testName: options.testName,
      subject: options.subject,
      fromAddress: options.fromAddress,
      status: 'sending',
      results: [],
      summary: this.createEmptySummary(),
      createdAt: new Date(),
      completedAt: null,
    };

    await this.saveTest(test);
    this.logger.info('Starting inbox placement test', { testId, seedCount: seedAccounts.length });

    // Send to all seed accounts
    const uniqueTestSubject = `${options.subject} [APT-${testId}]`;
    
    for (const account of seedAccounts) {
      try {
        await this.sendEmail(
          account.email,
          uniqueTestSubject,
          options.htmlBody,
          {
            'X-ApexMail-Test-Id': testId,
            'X-ApexMail-Seed-Id': account.id,
          }
        );
        
        this.logger.debug('Test email sent to seed', { testId, email: account.email, provider: account.provider });
      } catch (error) {
        this.logger.error('Failed to send test email', { 
          testId, 
          email: account.email, 
          error: error instanceof Error ? error.message : 'Unknown error' 
        });
      }
    }

    // Update status
    test.status = 'checking';
    await this.saveTest(test);

    // Schedule mailbox checks (after delay for delivery)
    await this.scheduleMailboxChecks(testId, seedAccounts);

    return test;
  }

  /**
   * Check placement results after emails have been delivered
   */
  async checkTestResults(testId: string): Promise<PlacementTest> {
    const test = await this.getTest(testId);
    if (!test) {
      throw new Error('Test not found');
    }

    const seedAccounts = await this.getAllActiveSeedAccounts();
    const results: PlacementTestResult[] = [];

    for (const account of seedAccounts) {
      try {
        const result = await this.checkMailbox(account, testId);
        results.push(result);
        this.logger.debug('Checked mailbox', { 
          testId, 
          provider: account.provider, 
          placement: result.placement 
        });
      } catch (error) {
        this.logger.error('Failed to check mailbox', { 
          testId, 
          email: account.email, 
          error: error instanceof Error ? error.message : 'Unknown error' 
        });
        results.push({
          seedAccountId: account.id,
          provider: account.provider,
          placement: 'missing',
          deliveredAt: null,
          checkedAt: new Date(),
        });
      }
    }

    // Update test with results
    test.results = results;
    test.summary = this.calculateSummary(results, seedAccounts);
    test.status = 'completed';
    test.completedAt = new Date();

    await this.saveTest(test);
    
    // Generate recommendations
    const recommendations = this.generateRecommendations(test.summary);
    this.logger.info('Inbox placement test completed', { 
      testId, 
      inboxRate: test.summary.inboxRate,
      recommendations: recommendations.length,
    });

    return test;
  }

  /**
   * Get placement trends over time
   */
  async getPlacementTrends(
    tenantId: string,
    options: {
      startDate: Date;
      endDate: Date;
      granularity: 'day' | 'week' | 'month';
    }
  ): Promise<{
    periods: Array<{
      period: string;
      inboxRate: number;
      spamRate: number;
      testCount: number;
    }>;
    overallTrend: 'improving' | 'declining' | 'stable';
    recommendation: string;
  }> {
    const result = await this.db.query<{
      period: string;
      avg_inbox_rate: string;
      avg_spam_rate: string;
      test_count: string;
    }>(`
      SELECT 
        DATE_TRUNC($3, completed_at) as period,
        AVG((summary->>'inboxRate')::float) as avg_inbox_rate,
        AVG(CASE WHEN summary->>'totalSent' != '0' 
            THEN ((summary->>'spamCount')::float / (summary->>'totalSent')::float) * 100 
            ELSE 0 END) as avg_spam_rate,
        COUNT(*) as test_count
      FROM inbox_placement_tests
      WHERE tenant_id = $1
        AND completed_at BETWEEN $2 AND $4
        AND status = 'completed'
      GROUP BY DATE_TRUNC($3, completed_at)
      ORDER BY period
    `, [tenantId, options.startDate, options.granularity, options.endDate]);

    const periods = result.rows.map(row => ({
      period: row.period,
      inboxRate: parseFloat(row.avg_inbox_rate),
      spamRate: parseFloat(row.avg_spam_rate),
      testCount: parseInt(row.test_count, 10),
    }));

    // Calculate trend
    let overallTrend: 'improving' | 'declining' | 'stable' = 'stable';
    if (periods.length >= 2) {
      const firstPeriod = periods[0]!;
      const lastPeriod = periods[periods.length - 1]!;
      const diff = lastPeriod.inboxRate - firstPeriod.inboxRate;
      
      if (diff > 5) overallTrend = 'improving';
      else if (diff < -5) overallTrend = 'declining';
    }

    // Generate recommendation
    let recommendation = '';
    const avgInboxRate = periods.reduce((sum, p) => sum + p.inboxRate, 0) / Math.max(periods.length, 1);
    
    if (avgInboxRate < 80) {
      recommendation = 'Critical: Inbox placement is below industry standards. Review authentication, engagement, and content.';
    } else if (avgInboxRate < 90) {
      recommendation = 'Warning: Inbox placement needs improvement. Focus on list hygiene and engagement.';
    } else if (overallTrend === 'declining') {
      recommendation = 'Alert: Inbox placement is declining. Investigate recent changes and monitor closely.';
    } else {
      recommendation = 'Good: Inbox placement is healthy. Continue monitoring and optimizing.';
    }

    return { periods, overallTrend, recommendation };
  }

  /**
   * Get provider-specific placement analysis
   */
  async getProviderAnalysis(
    tenantId: string,
    days: number = 30
  ): Promise<Record<EmailProvider, {
    avgInboxRate: number;
    avgSpamRate: number;
    testCount: number;
    trend: 'up' | 'down' | 'stable';
    tips: string[];
  }>> {
    const providers: EmailProvider[] = ['gmail', 'outlook', 'yahoo', 'aol', 'icloud', 'other'];
    const analysis: Record<string, {
      avgInboxRate: number;
      avgSpamRate: number;
      testCount: number;
      trend: 'up' | 'down' | 'stable';
      tips: string[];
    }> = {};

    for (const provider of providers) {
      // Get historical data
      const result = await this.db.query<{
        inbox_rate: string;
        spam_rate: string;
        test_count: string;
        week_num: string;
      }>(`
        SELECT 
          AVG(CASE WHEN (r->>'placement') = 'inbox' THEN 1.0 ELSE 0.0 END) * 100 as inbox_rate,
          AVG(CASE WHEN (r->>'placement') = 'spam' THEN 1.0 ELSE 0.0 END) * 100 as spam_rate,
          COUNT(*) as test_count,
          EXTRACT(WEEK FROM t.completed_at) as week_num
        FROM inbox_placement_tests t,
             jsonb_array_elements(t.results) as r
        WHERE t.tenant_id = $1
          AND t.completed_at > NOW() - INTERVAL '${days} days'
          AND (r->>'provider') = $2
          AND t.status = 'completed'
        GROUP BY week_num
        ORDER BY week_num DESC
        LIMIT 4
      `, [tenantId, provider]);

      if (result.rows.length === 0) {
        analysis[provider] = {
          avgInboxRate: 0,
          avgSpamRate: 0,
          testCount: 0,
          trend: 'stable',
          tips: ['No test data available. Run placement tests to get insights.'],
        };
        continue;
      }

      const avgInboxRate = result.rows.reduce((sum, r) => sum + parseFloat(r.inbox_rate), 0) / result.rows.length;
      const avgSpamRate = result.rows.reduce((sum, r) => sum + parseFloat(r.spam_rate), 0) / result.rows.length;
      const testCount = result.rows.reduce((sum, r) => sum + parseInt(r.test_count, 10), 0);

      // Calculate trend
      let trend: 'up' | 'down' | 'stable' = 'stable';
      if (result.rows.length >= 2) {
        const recent = parseFloat(result.rows[0]!.inbox_rate);
        const older = parseFloat(result.rows[result.rows.length - 1]!.inbox_rate);
        if (recent > older + 5) trend = 'up';
        else if (recent < older - 5) trend = 'down';
      }

      analysis[provider] = {
        avgInboxRate,
        avgSpamRate,
        testCount,
        trend,
        tips: this.getProviderTips(provider, avgInboxRate, avgSpamRate),
      };
    }

    return analysis as Record<EmailProvider, typeof analysis[string]>;
  }

  // Private helper methods

  private async getSeedAccountsByIds(ids: string[]): Promise<SeedAccount[]> {
    const result = await this.db.query<SeedAccount>(`
      SELECT * FROM seed_accounts WHERE id = ANY($1) AND status = 'active'
    `, [ids]);
    return result.rows;
  }

  private async getAllActiveSeedAccounts(): Promise<SeedAccount[]> {
    const result = await this.db.query<SeedAccount>(`
      SELECT * FROM seed_accounts WHERE status = 'active' ORDER BY provider
    `);
    return result.rows;
  }

  private async saveTest(test: PlacementTest): Promise<void> {
    await this.db.query(`
      INSERT INTO inbox_placement_tests (id, tenant_id, campaign_id, test_name, subject, from_address, status, results, summary, created_at, completed_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      ON CONFLICT (id) DO UPDATE SET
        status = EXCLUDED.status,
        results = EXCLUDED.results,
        summary = EXCLUDED.summary,
        completed_at = EXCLUDED.completed_at
    `, [
      test.id,
      test.tenantId,
      test.campaignId,
      test.testName,
      test.subject,
      test.fromAddress,
      test.status,
      JSON.stringify(test.results),
      JSON.stringify(test.summary),
      test.createdAt,
      test.completedAt,
    ]);
  }

  private async getTest(testId: string): Promise<PlacementTest | null> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      campaign_id: string | null;
      test_name: string;
      subject: string;
      from_address: string;
      status: string;
      results: string;
      summary: string;
      created_at: Date;
      completed_at: Date | null;
    }>(`
      SELECT * FROM inbox_placement_tests WHERE id = $1
    `, [testId]);

    if (result.rows.length === 0) return null;

    const row = result.rows[0]!;
    return {
      id: row.id,
      tenantId: row.tenant_id,
      campaignId: row.campaign_id ?? undefined,
      testName: row.test_name,
      subject: row.subject,
      fromAddress: row.from_address,
      status: row.status as PlacementTest['status'],
      results: JSON.parse(row.results),
      summary: JSON.parse(row.summary),
      createdAt: row.created_at,
      completedAt: row.completed_at,
    };
  }

  private async scheduleMailboxChecks(testId: string, accounts: SeedAccount[]): Promise<void> {
    // In production, this would use a job queue (BullMQ, etc.)
    // Schedule checks 5 minutes after sending, then again at 15 and 30 minutes
    const delays = [5 * 60 * 1000, 15 * 60 * 1000, 30 * 60 * 1000];
    
    for (const delay of delays) {
      const checkTime = Date.now() + delay;
      await this.redis.zadd('inbox_placement_checks', checkTime, JSON.stringify({
        testId,
        accountIds: accounts.map(a => a.id),
      }));
    }
  }

  private createEmptySummary(): PlacementSummary {
    return {
      totalSent: 0,
      totalReceived: 0,
      inboxCount: 0,
      spamCount: 0,
      promotionsCount: 0,
      missingCount: 0,
      inboxRate: 0,
      deliveryRate: 0,
      byProvider: {} as PlacementSummary['byProvider'],
    };
  }

  private calculateSummary(results: PlacementTestResult[], accounts: SeedAccount[]): PlacementSummary {
    const summary = this.createEmptySummary();
    summary.totalSent = accounts.length;

    // Initialize provider stats
    for (const account of accounts) {
      if (!summary.byProvider[account.provider]) {
        summary.byProvider[account.provider] = {
          sent: 0,
          inbox: 0,
          spam: 0,
          other: 0,
          missing: 0,
          inboxRate: 0,
        };
      }
      summary.byProvider[account.provider]!.sent++;
    }

    // Count results
    for (const result of results) {
      const providerStats = summary.byProvider[result.provider]!;
      
      switch (result.placement) {
        case 'inbox':
          summary.inboxCount++;
          summary.totalReceived++;
          providerStats.inbox++;
          break;
        case 'spam':
          summary.spamCount++;
          summary.totalReceived++;
          providerStats.spam++;
          break;
        case 'promotions':
        case 'social':
          summary.promotionsCount++;
          summary.totalReceived++;
          providerStats.other++;
          break;
        case 'missing':
          summary.missingCount++;
          providerStats.missing++;
          break;
      }
    }

    // Calculate rates
    summary.inboxRate = summary.totalSent > 0 
      ? (summary.inboxCount / summary.totalSent) * 100 
      : 0;
    summary.deliveryRate = summary.totalSent > 0 
      ? (summary.totalReceived / summary.totalSent) * 100 
      : 0;

    // Calculate provider rates
    for (const provider of Object.keys(summary.byProvider) as EmailProvider[]) {
      const stats = summary.byProvider[provider]!;
      stats.inboxRate = stats.sent > 0 ? (stats.inbox / stats.sent) * 100 : 0;
    }

    return summary;
  }

  private generateRecommendations(summary: PlacementSummary): string[] {
    const recommendations: string[] = [];

    // Overall inbox rate
    if (summary.inboxRate < 70) {
      recommendations.push('CRITICAL: Inbox placement is severely degraded. Immediate action required.');
    } else if (summary.inboxRate < 85) {
      recommendations.push('WARNING: Inbox placement is below industry standards. Review authentication and content.');
    }

    // Provider-specific
    for (const [provider, stats] of Object.entries(summary.byProvider)) {
      if (stats.sent > 0 && stats.inboxRate < 70) {
        recommendations.push(`${provider.toUpperCase()}: Low inbox placement (${stats.inboxRate.toFixed(1)}%). Review ${provider}-specific guidelines.`);
      }
    }

    // Spam rate
    const spamRate = summary.totalSent > 0 ? (summary.spamCount / summary.totalSent) * 100 : 0;
    if (spamRate > 15) {
      recommendations.push('High spam rate detected. Check content for spam triggers and verify authentication.');
    }

    // Missing rate
    const missingRate = summary.totalSent > 0 ? (summary.missingCount / summary.totalSent) * 100 : 0;
    if (missingRate > 10) {
      recommendations.push('Many emails not received. Check for blocklisting or delivery issues.');
    }

    return recommendations;
  }

  private getProviderTips(provider: EmailProvider, inboxRate: number, spamRate: number): string[] {
    const tips: string[] = [];

    if (inboxRate < 80) {
      // Provider-specific tips
      switch (provider) {
        case 'gmail':
          tips.push('Gmail: Use Google Postmaster Tools to monitor reputation');
          tips.push('Gmail: Segment inactive subscribers to improve engagement');
          tips.push('Gmail: Ensure proper List-Unsubscribe-Post header (RFC 8058)');
          break;
        case 'outlook':
          tips.push('Outlook: Register for Microsoft SNDS (Smart Network Data Services)');
          tips.push('Outlook: Apply for Junk Mail Reporting Program (JMRP)');
          tips.push('Outlook: Use Outlook.com Sender Support form if blocklisted');
          break;
        case 'yahoo':
          tips.push('Yahoo: Ensure proper FBL registration');
          tips.push('Yahoo: Watch for rate limiting on new IPs');
          tips.push('Yahoo: Use complaint feedback loop actively');
          break;
        default:
          tips.push('Check authentication (SPF, DKIM, DMARC)');
          tips.push('Monitor bounce rates and engagement');
      }
    }

    if (spamRate > 10) {
      tips.push('Review content for spam trigger words');
      tips.push('Check image-to-text ratio (should be balanced)');
      tips.push('Verify all links are legitimate');
    }

    if (tips.length === 0) {
      tips.push('Placement looks good! Continue monitoring.');
    }

    return tips;
  }
}

// Database migration for inbox placement testing
export const INBOX_PLACEMENT_MIGRATION = `
-- Seed accounts for inbox placement testing
CREATE TABLE IF NOT EXISTS seed_accounts (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  provider TEXT NOT NULL,
  imap_host TEXT NOT NULL,
  imap_port INTEGER NOT NULL DEFAULT 993,
  imap_user TEXT NOT NULL,
  imap_password_encrypted TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  last_checked TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_seed_accounts_provider ON seed_accounts(provider);
CREATE INDEX IF NOT EXISTS idx_seed_accounts_status ON seed_accounts(status);

-- Inbox placement test records
CREATE TABLE IF NOT EXISTS inbox_placement_tests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  campaign_id TEXT REFERENCES campaigns(id),
  test_name TEXT NOT NULL,
  subject TEXT NOT NULL,
  from_address TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  results JSONB NOT NULL DEFAULT '[]',
  summary JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_inbox_placement_tests_tenant ON inbox_placement_tests(tenant_id);
CREATE INDEX IF NOT EXISTS idx_inbox_placement_tests_status ON inbox_placement_tests(status);
CREATE INDEX IF NOT EXISTS idx_inbox_placement_tests_completed ON inbox_placement_tests(completed_at);
`;
