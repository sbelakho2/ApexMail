/**
 * QBR (Quarterly Business Review) Service
 * 
 * Automated QBR generation and scheduling for enterprise accounts
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
import { v4 as uuidv4 } from 'uuid';
import { config, EnterprisePlan } from '../config.js';

// Result type for error handling
type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export enum QBRStatus {
  SCHEDULED = 'scheduled',
  DATA_GATHERING = 'data_gathering',
  READY = 'ready',
  DELIVERED = 'delivered',
  ARCHIVED = 'archived',
}

export interface QBR {
  id: string;
  accountId: string;
  quarter: string; // e.g., "2024-Q1"
  status: QBRStatus;
  scheduledDate?: Date;
  preparedBy?: string;
  deliveredBy?: string;
  deliveredAt?: Date;
  attendees: QBRAttendee[];
  executiveSummary?: string;
  metrics: QBRMetrics;
  insights: QBRInsight[];
  recommendations: QBRRecommendation[];
  goals: QBRGoal[];
  attachments: QBRAttachment[];
  feedback?: QBRFeedback;
  createdAt: Date;
  updatedAt: Date;
}

export interface QBRAttendee {
  name: string;
  email: string;
  role: string;
  company: string;
  isInternal: boolean;
}

export interface QBRMetrics {
  emailVolume: VolumeMetrics;
  deliverability: DeliverabilityMetrics;
  engagement: EngagementMetrics;
  support: SupportMetrics;
  usage: UsageMetrics;
  costs: CostMetrics;
  trends: TrendData[];
}

export interface VolumeMetrics {
  totalSent: number;
  previousQuarter: number;
  changePercent: number;
  monthlyBreakdown: { month: string; count: number }[];
  peakDay: { date: string; count: number };
  averageDaily: number;
}

export interface DeliverabilityMetrics {
  deliveryRate: number;
  bounceRate: number;
  spamRate: number;
  inboxRate: number;
  previousQuarter: {
    deliveryRate: number;
    bounceRate: number;
    spamRate: number;
  };
  byDomain: { domain: string; deliveryRate: number; volume: number }[];
  ipReputation: { ip: string; reputation: number }[];
}

export interface EngagementMetrics {
  openRate: number;
  clickRate: number;
  unsubscribeRate: number;
  previousQuarter: {
    openRate: number;
    clickRate: number;
    unsubscribeRate: number;
  };
  byCategory: { category: string; openRate: number; clickRate: number }[];
  bestPerforming: { subject: string; openRate: number; clickRate: number }[];
}

export interface SupportMetrics {
  totalTickets: number;
  averageResolutionTime: number;
  satisfactionScore: number;
  ticketsByCategory: Record<string, number>;
  escalationRate: number;
  slaCompliance: number;
}

export interface UsageMetrics {
  apiCalls: number;
  activeUsers: number;
  featuresUsed: string[];
  underutilizedFeatures: string[];
  storageUsed: number;
  storageLimit: number;
}

export interface CostMetrics {
  currentSpend: number;
  projectedSpend: number;
  costPerEmail: number;
  savings?: number;
  upgradeSuggestion?: string;
}

export interface TrendData {
  metric: string;
  values: { date: string; value: number }[];
  trend: 'up' | 'down' | 'stable';
  percentChange: number;
}

export interface QBRInsight {
  id: string;
  type: 'positive' | 'negative' | 'neutral' | 'opportunity';
  title: string;
  description: string;
  metric?: string;
  value?: number;
  benchmark?: number;
  priority: 'high' | 'medium' | 'low';
}

export interface QBRRecommendation {
  id: string;
  title: string;
  description: string;
  expectedImpact: string;
  effort: 'low' | 'medium' | 'high';
  category: string;
  priority: number;
  resources?: string[];
}

export interface QBRGoal {
  id: string;
  title: string;
  description: string;
  targetMetric: string;
  currentValue: number;
  targetValue: number;
  deadline: Date;
  status: 'pending' | 'in_progress' | 'achieved' | 'missed';
  progress: number;
}

export interface QBRAttachment {
  id: string;
  type: 'pdf' | 'csv' | 'excel' | 'presentation';
  name: string;
  url: string;
  size: number;
}

export interface QBRFeedback {
  rating: number;
  useful: boolean;
  comments?: string;
  actionsTaken: string[];
  submittedAt: Date;
}

export interface QBRTemplate {
  id: string;
  name: string;
  sections: QBRSection[];
  isDefault: boolean;
}

export interface QBRSection {
  id: string;
  title: string;
  type: 'metrics' | 'insights' | 'recommendations' | 'goals' | 'custom';
  order: number;
  visible: boolean;
  customContent?: string;
}

/**
 * QBR Automation Service
 */
export class QBRService {
  private pool: Pool;
  private redis: Redis;

  constructor(pool: Pool, redis: Redis) {
    this.pool = pool;
    this.redis = redis;
  }

  /**
   * Schedule QBR
   */
  async scheduleQBR(
    accountId: string,
    quarter: string,
    scheduledDate: Date,
    attendees: QBRAttendee[]
  ): Promise<Result<QBR>> {
    try {
      const id = uuidv4();

      await this.pool.query(`
        INSERT INTO ent_qbrs (
          id, account_id, quarter, status, scheduled_date, attendees,
          metrics, insights, recommendations, goals, attachments,
          created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, '{}', '[]', '[]', '[]', '[]', NOW(), NOW())
      `, [
        id,
        accountId,
        quarter,
        QBRStatus.SCHEDULED,
        scheduledDate,
        JSON.stringify(attendees),
      ]);

      // Schedule data gathering job
      const gatherDate = new Date(scheduledDate.getTime() - 7 * 24 * 60 * 60 * 1000); // 7 days before
      await this.redis.zadd('qbr:data_gathering', gatherDate.getTime(), id);

      return this.getQBR(id);
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get QBR by ID
   */
  async getQBR(id: string): Promise<Result<QBR>> {
    try {
      const result = await this.pool.query(`
        SELECT * FROM ent_qbrs WHERE id = $1
      `, [id]);

      if (result.rows.length === 0) {
        return { ok: false, error: new Error('QBR not found') };
      }

      return { ok: true, value: this.rowToQBR(result.rows[0]) };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * List QBRs for account
   */
  async listQBRs(
    accountId: string,
    status?: QBRStatus
  ): Promise<Result<QBR[]>> {
    try {
      let query = `SELECT * FROM ent_qbrs WHERE account_id = $1`;
      const params: any[] = [accountId];

      if (status) {
        query += ` AND status = $2`;
        params.push(status);
      }

      query += ` ORDER BY quarter DESC`;

      const result = await this.pool.query(query, params);

      return {
        ok: true,
        value: result.rows.map(row => this.rowToQBR(row)),
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Generate QBR data
   */
  async generateQBRData(id: string): Promise<Result<QBR>> {
    try {
      const qbrResult = await this.getQBR(id);
      if (!qbrResult.ok) return { ok: false, error: qbrResult.error };

      const qbr = qbrResult.value;

      // Update status
      await this.pool.query(`
        UPDATE ent_qbrs SET status = $2, updated_at = NOW() WHERE id = $1
      `, [id, QBRStatus.DATA_GATHERING]);

      // Get quarter date range
      const { startDate, endDate } = this.getQuarterDates(qbr.quarter);

      // Gather metrics
      const metrics = await this.gatherMetrics(qbr.accountId, startDate, endDate);

      // Generate insights
      const insights = this.generateInsights(metrics);

      // Generate recommendations
      const recommendations = this.generateRecommendations(metrics, insights);

      // Generate goals
      const goals = this.generateGoals(metrics, qbr.quarter);

      // Generate executive summary
      const executiveSummary = this.generateExecutiveSummary(metrics, insights);

      // Update QBR
      await this.pool.query(`
        UPDATE ent_qbrs SET
          status = $2,
          metrics = $3,
          insights = $4,
          recommendations = $5,
          goals = $6,
          executive_summary = $7,
          updated_at = NOW()
        WHERE id = $1
      `, [
        id,
        QBRStatus.READY,
        JSON.stringify(metrics),
        JSON.stringify(insights),
        JSON.stringify(recommendations),
        JSON.stringify(goals),
        executiveSummary,
      ]);

      return this.getQBR(id);
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Generate QBR report PDF
   */
  async generateReport(id: string): Promise<Result<QBRAttachment>> {
    try {
      const qbrResult = await this.getQBR(id);
      if (!qbrResult.ok) return { ok: false, error: qbrResult.error };

      const qbr = qbrResult.value;

      // In production, use PDFKit to generate PDF
      const attachmentId = uuidv4();
      const filename = `QBR_${qbr.quarter}_${qbr.accountId}.pdf`;
      const url = `https://reports.apexmail.com/qbr/${attachmentId}.pdf`;

      const attachment: QBRAttachment = {
        id: attachmentId,
        type: 'pdf',
        name: filename,
        url,
        size: 0, // Would be actual size after generation
      };

      // Update QBR with attachment
      const attachments = [...qbr.attachments, attachment];
      await this.pool.query(`
        UPDATE ent_qbrs SET attachments = $2, updated_at = NOW() WHERE id = $1
      `, [id, JSON.stringify(attachments)]);

      return { ok: true, value: attachment };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Mark QBR as delivered
   */
  async markDelivered(
    id: string,
    deliveredBy: string
  ): Promise<Result<QBR>> {
    try {
      await this.pool.query(`
        UPDATE ent_qbrs SET
          status = $2,
          delivered_by = $3,
          delivered_at = NOW(),
          updated_at = NOW()
        WHERE id = $1
      `, [id, QBRStatus.DELIVERED, deliveredBy]);

      return this.getQBR(id);
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Submit QBR feedback
   */
  async submitFeedback(
    id: string,
    feedback: Omit<QBRFeedback, 'submittedAt'>
  ): Promise<Result<void>> {
    try {
      const fullFeedback: QBRFeedback = {
        ...feedback,
        submittedAt: new Date(),
      };

      await this.pool.query(`
        UPDATE ent_qbrs SET
          feedback = $2,
          updated_at = NOW()
        WHERE id = $1
      `, [id, JSON.stringify(fullFeedback)]);

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Update goal progress
   */
  async updateGoalProgress(
    qbrId: string,
    goalId: string,
    progress: number,
    status?: 'pending' | 'in_progress' | 'achieved' | 'missed'
  ): Promise<Result<void>> {
    try {
      const qbrResult = await this.getQBR(qbrId);
      if (!qbrResult.ok) return { ok: false, error: qbrResult.error };

      const qbr = qbrResult.value;
      const goals = qbr.goals.map(g => {
        if (g.id === goalId) {
          return {
            ...g,
            progress: Math.min(100, Math.max(0, progress)),
            status: status || (progress >= 100 ? 'achieved' : g.status),
          };
        }
        return g;
      });

      await this.pool.query(`
        UPDATE ent_qbrs SET goals = $2, updated_at = NOW() WHERE id = $1
      `, [qbrId, JSON.stringify(goals)]);

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get QBR benchmarks
   */
  async getBenchmarks(industry?: string): Promise<Result<{
    deliveryRate: { average: number; p75: number; p90: number };
    openRate: { average: number; p75: number; p90: number };
    clickRate: { average: number; p75: number; p90: number };
    bounceRate: { average: number; p25: number; p10: number };
    unsubscribeRate: { average: number; p25: number; p10: number };
  }>> {
    try {
      // In production, calculate from anonymized aggregate data
      // These are industry benchmarks
      const benchmarks = {
        deliveryRate: { average: 0.95, p75: 0.97, p90: 0.99 },
        openRate: { average: 0.21, p75: 0.28, p90: 0.35 },
        clickRate: { average: 0.025, p75: 0.04, p90: 0.06 },
        bounceRate: { average: 0.02, p25: 0.01, p10: 0.005 },
        unsubscribeRate: { average: 0.002, p25: 0.001, p10: 0.0005 },
      };

      return { ok: true, value: benchmarks };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Schedule recurring QBRs
   */
  async scheduleRecurringQBRs(accountId: string): Promise<Result<void>> {
    try {
      const currentQuarter = this.getCurrentQuarter();
      const nextQuarters = this.getNextQuarters(4);

      for (const quarter of nextQuarters) {
        // Check if already scheduled
        const existing = await this.pool.query(`
          SELECT id FROM ent_qbrs WHERE account_id = $1 AND quarter = $2
        `, [accountId, quarter.name]);

        if (existing.rows.length === 0) {
          await this.scheduleQBR(accountId, quarter.name, quarter.endDate, []);
        }
      }

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  // Private helper methods

  private async gatherMetrics(
    accountId: string,
    startDate: Date,
    endDate: Date
  ): Promise<QBRMetrics> {
    // Gather email volume metrics
    const volumeResult = await this.pool.query(`
      SELECT
        COUNT(*) as total,
        DATE_TRUNC('month', created_at) as month,
        DATE_TRUNC('day', created_at) as day
      FROM emails
      WHERE account_id = $1 AND created_at BETWEEN $2 AND $3
      GROUP BY month, day
    `, [accountId, startDate, endDate]);

    // Get previous quarter for comparison
    const prevStartDate = new Date(startDate.getTime() - 90 * 24 * 60 * 60 * 1000);
    const prevEndDate = new Date(startDate.getTime() - 1);

    const prevVolumeResult = await this.pool.query(`
      SELECT COUNT(*) as total FROM emails
      WHERE account_id = $1 AND created_at BETWEEN $2 AND $3
    `, [accountId, prevStartDate, prevEndDate]);

    const totalSent = volumeResult.rows.reduce((sum, r) => sum + parseInt(r.total, 10), 0);
    const previousQuarter = parseInt(prevVolumeResult.rows[0]?.total || '0', 10);

    // Gather deliverability metrics
    const deliverabilityResult = await this.pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE status = 'delivered') as delivered,
        COUNT(*) FILTER (WHERE status = 'bounced') as bounced,
        COUNT(*) FILTER (WHERE status = 'spam') as spam,
        COUNT(*) as total
      FROM email_events
      WHERE account_id = $1 AND created_at BETWEEN $2 AND $3
    `, [accountId, startDate, endDate]);

    const dStats = deliverabilityResult.rows[0];
    const dTotal = parseInt(dStats.total, 10) || 1;

    // Gather engagement metrics
    const engagementResult = await this.pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE event_type = 'opened') as opened,
        COUNT(*) FILTER (WHERE event_type = 'clicked') as clicked,
        COUNT(*) FILTER (WHERE event_type = 'unsubscribed') as unsubscribed,
        COUNT(DISTINCT message_id) as unique_messages
      FROM email_events
      WHERE account_id = $1 AND created_at BETWEEN $2 AND $3
    `, [accountId, startDate, endDate]);

    const eStats = engagementResult.rows[0];
    const uniqueMessages = parseInt(eStats.unique_messages, 10) || 1;

    return {
      emailVolume: {
        totalSent,
        previousQuarter,
        changePercent: previousQuarter > 0 ? ((totalSent - previousQuarter) / previousQuarter) * 100 : 0,
        monthlyBreakdown: [],
        peakDay: { date: '', count: 0 },
        averageDaily: Math.round(totalSent / 90),
      },
      deliverability: {
        deliveryRate: parseInt(dStats.delivered, 10) / dTotal,
        bounceRate: parseInt(dStats.bounced, 10) / dTotal,
        spamRate: parseInt(dStats.spam, 10) / dTotal,
        inboxRate: 0.85, // Would calculate from placement tests
        previousQuarter: {
          deliveryRate: 0,
          bounceRate: 0,
          spamRate: 0,
        },
        byDomain: [],
        ipReputation: [],
      },
      engagement: {
        openRate: parseInt(eStats.opened, 10) / uniqueMessages,
        clickRate: parseInt(eStats.clicked, 10) / uniqueMessages,
        unsubscribeRate: parseInt(eStats.unsubscribed, 10) / uniqueMessages,
        previousQuarter: {
          openRate: 0,
          clickRate: 0,
          unsubscribeRate: 0,
        },
        byCategory: [],
        bestPerforming: [],
      },
      support: {
        totalTickets: 0,
        averageResolutionTime: 0,
        satisfactionScore: 0,
        ticketsByCategory: {},
        escalationRate: 0,
        slaCompliance: 0,
      },
      usage: {
        apiCalls: 0,
        activeUsers: 0,
        featuresUsed: [],
        underutilizedFeatures: [],
        storageUsed: 0,
        storageLimit: 0,
      },
      costs: {
        currentSpend: 0,
        projectedSpend: 0,
        costPerEmail: 0,
      },
      trends: [],
    };
  }

  private generateInsights(metrics: QBRMetrics): QBRInsight[] {
    const insights: QBRInsight[] = [];

    // Volume insights
    if (metrics.emailVolume.changePercent > 20) {
      insights.push({
        id: uuidv4(),
        type: 'positive',
        title: 'Strong Volume Growth',
        description: `Email volume increased ${metrics.emailVolume.changePercent.toFixed(1)}% compared to last quarter`,
        metric: 'volume',
        value: metrics.emailVolume.changePercent,
        priority: 'medium',
      });
    } else if (metrics.emailVolume.changePercent < -20) {
      insights.push({
        id: uuidv4(),
        type: 'negative',
        title: 'Volume Decline',
        description: `Email volume decreased ${Math.abs(metrics.emailVolume.changePercent).toFixed(1)}% compared to last quarter`,
        metric: 'volume',
        value: metrics.emailVolume.changePercent,
        priority: 'high',
      });
    }

    // Deliverability insights
    if (metrics.deliverability.deliveryRate >= 0.97) {
      insights.push({
        id: uuidv4(),
        type: 'positive',
        title: 'Excellent Deliverability',
        description: `Your delivery rate of ${(metrics.deliverability.deliveryRate * 100).toFixed(1)}% exceeds industry benchmarks`,
        metric: 'deliveryRate',
        value: metrics.deliverability.deliveryRate,
        benchmark: 0.95,
        priority: 'low',
      });
    } else if (metrics.deliverability.deliveryRate < 0.90) {
      insights.push({
        id: uuidv4(),
        type: 'negative',
        title: 'Deliverability Concern',
        description: `Your delivery rate of ${(metrics.deliverability.deliveryRate * 100).toFixed(1)}% is below optimal`,
        metric: 'deliveryRate',
        value: metrics.deliverability.deliveryRate,
        benchmark: 0.95,
        priority: 'high',
      });
    }

    // Engagement insights
    if (metrics.engagement.openRate >= 0.25) {
      insights.push({
        id: uuidv4(),
        type: 'positive',
        title: 'Above Average Engagement',
        description: `Open rate of ${(metrics.engagement.openRate * 100).toFixed(1)}% is above industry average`,
        metric: 'openRate',
        value: metrics.engagement.openRate,
        benchmark: 0.21,
        priority: 'medium',
      });
    }

    return insights;
  }

  private generateRecommendations(metrics: QBRMetrics, insights: QBRInsight[]): QBRRecommendation[] {
    const recommendations: QBRRecommendation[] = [];

    // Based on deliverability
    if (metrics.deliverability.bounceRate > 0.03) {
      recommendations.push({
        id: uuidv4(),
        title: 'Implement List Hygiene',
        description: 'Your bounce rate is elevated. Regular list cleaning can improve deliverability.',
        expectedImpact: '10-15% reduction in bounces',
        effort: 'medium',
        category: 'deliverability',
        priority: 1,
        resources: ['https://docs.apexmail.com/list-hygiene'],
      });
    }

    // Based on engagement
    if (metrics.engagement.openRate < 0.18) {
      recommendations.push({
        id: uuidv4(),
        title: 'Optimize Subject Lines',
        description: 'A/B test subject lines to improve open rates.',
        expectedImpact: '5-20% improvement in open rates',
        effort: 'low',
        category: 'engagement',
        priority: 2,
      });
    }

    // General recommendations
    recommendations.push({
      id: uuidv4(),
      title: 'Enable Engagement Tracking',
      description: 'Full engagement tracking provides valuable insights into recipient behavior.',
      expectedImpact: 'Better campaign optimization',
      effort: 'low',
      category: 'analytics',
      priority: 3,
    });

    return recommendations;
  }

  private generateGoals(metrics: QBRMetrics, quarter: string): QBRGoal[] {
    const nextQuarter = this.getNextQuarter(quarter);
    const deadline = this.getQuarterEndDate(nextQuarter);

    return [
      {
        id: uuidv4(),
        title: 'Improve Delivery Rate',
        description: 'Achieve 98% delivery rate',
        targetMetric: 'deliveryRate',
        currentValue: metrics.deliverability.deliveryRate * 100,
        targetValue: 98,
        deadline,
        status: 'pending',
        progress: 0,
      },
      {
        id: uuidv4(),
        title: 'Increase Open Rate',
        description: 'Improve open rate by 10%',
        targetMetric: 'openRate',
        currentValue: metrics.engagement.openRate * 100,
        targetValue: metrics.engagement.openRate * 100 * 1.1,
        deadline,
        status: 'pending',
        progress: 0,
      },
      {
        id: uuidv4(),
        title: 'Reduce Bounce Rate',
        description: 'Keep bounce rate below 2%',
        targetMetric: 'bounceRate',
        currentValue: metrics.deliverability.bounceRate * 100,
        targetValue: 2,
        deadline,
        status: 'pending',
        progress: 0,
      },
    ];
  }

  private generateExecutiveSummary(metrics: QBRMetrics, insights: QBRInsight[]): string {
    const positiveInsights = insights.filter(i => i.type === 'positive').length;
    const negativeInsights = insights.filter(i => i.type === 'negative').length;

    let summary = `This quarter, you sent ${metrics.emailVolume.totalSent.toLocaleString()} emails, `;
    
    if (metrics.emailVolume.changePercent > 0) {
      summary += `a ${metrics.emailVolume.changePercent.toFixed(1)}% increase from last quarter. `;
    } else if (metrics.emailVolume.changePercent < 0) {
      summary += `a ${Math.abs(metrics.emailVolume.changePercent).toFixed(1)}% decrease from last quarter. `;
    } else {
      summary += `consistent with last quarter. `;
    }

    summary += `\n\nYour delivery rate of ${(metrics.deliverability.deliveryRate * 100).toFixed(1)}% `;
    summary += metrics.deliverability.deliveryRate >= 0.95 ? 'meets' : 'is below';
    summary += ` industry standards. `;

    summary += `Engagement metrics show an open rate of ${(metrics.engagement.openRate * 100).toFixed(1)}% `;
    summary += `and click rate of ${(metrics.engagement.clickRate * 100).toFixed(2)}%.\n\n`;

    if (positiveInsights > negativeInsights) {
      summary += 'Overall, your email program is performing well this quarter.';
    } else if (negativeInsights > positiveInsights) {
      summary += 'There are areas requiring attention to improve your email program performance.';
    } else {
      summary += 'Your email program shows mixed results with opportunities for improvement.';
    }

    return summary;
  }

  private getQuarterDates(quarter: string): { startDate: Date; endDate: Date } {
    const [year, q] = quarter.split('-Q');
    const quarterNum = parseInt(q, 10);
    const startMonth = (quarterNum - 1) * 3;
    
    const startDate = new Date(parseInt(year, 10), startMonth, 1);
    const endDate = new Date(parseInt(year, 10), startMonth + 3, 0, 23, 59, 59);
    
    return { startDate, endDate };
  }

  private getCurrentQuarter(): string {
    const now = new Date();
    const q = Math.ceil((now.getMonth() + 1) / 3);
    return `${now.getFullYear()}-Q${q}`;
  }

  private getNextQuarter(quarter: string): string {
    const [year, q] = quarter.split('-Q');
    const quarterNum = parseInt(q, 10);
    
    if (quarterNum === 4) {
      return `${parseInt(year, 10) + 1}-Q1`;
    }
    return `${year}-Q${quarterNum + 1}`;
  }

  private getQuarterEndDate(quarter: string): Date {
    const { endDate } = this.getQuarterDates(quarter);
    return endDate;
  }

  private getNextQuarters(count: number): { name: string; endDate: Date }[] {
    const quarters: { name: string; endDate: Date }[] = [];
    let current = this.getCurrentQuarter();
    
    for (let i = 0; i < count; i++) {
      current = this.getNextQuarter(current);
      quarters.push({
        name: current,
        endDate: this.getQuarterEndDate(current),
      });
    }
    
    return quarters;
  }

  private rowToQBR(row: any): QBR {
    return {
      id: row.id,
      accountId: row.account_id,
      quarter: row.quarter,
      status: row.status as QBRStatus,
      scheduledDate: row.scheduled_date,
      preparedBy: row.prepared_by,
      deliveredBy: row.delivered_by,
      deliveredAt: row.delivered_at,
      attendees: row.attendees,
      executiveSummary: row.executive_summary,
      metrics: row.metrics,
      insights: row.insights,
      recommendations: row.recommendations,
      goals: row.goals,
      attachments: row.attachments,
      feedback: row.feedback,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
