/**
 * Template Approval Service
 * 
 * Workflow for template review and approval
 */

import { Pool } from 'pg';
import type { Redis } from 'ioredis';
import { v4 as uuidv4 } from 'uuid';
import { config, TemplateApprovalStatus } from '../config.js';

// Result type for error handling
type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export interface TemplateSubmission {
  id: string;
  accountId: string;
  submittedBy: string;
  templateType: 'email' | 'sms' | 'push';
  name: string;
  subject?: string;
  content: string;
  previewUrl?: string;
  status: TemplateApprovalStatus;
  reviewedBy?: string;
  reviewedAt?: Date;
  reviewNotes?: string;
  rejectionReason?: string;
  version: number;
  previousVersionId?: string;
  metadata: TemplateMetadata;
  createdAt: Date;
  updatedAt: Date;
}

export interface TemplateMetadata {
  industry?: string;
  useCase?: string;
  targetAudience?: string;
  sendVolume?: string;
  containsLinks: boolean;
  containsImages: boolean;
  containsPersonalization: boolean;
  spamScore?: number;
}

export interface ApprovalRule {
  id: string;
  name: string;
  description: string;
  conditions: ApprovalCondition[];
  action: 'auto_approve' | 'auto_reject' | 'require_review' | 'flag';
  priority: number;
  isActive: boolean;
  createdAt: Date;
}

export interface ApprovalCondition {
  field: string;
  operator: 'contains' | 'not_contains' | 'equals' | 'not_equals' | 'regex' | 'greater_than' | 'less_than';
  value: string | number;
}

export interface ApprovalComment {
  id: string;
  submissionId: string;
  authorId: string;
  authorName: string;
  content: string;
  isInternal: boolean;
  createdAt: Date;
}

export interface ApprovalStats {
  pending: number;
  approved: number;
  rejected: number;
  flagged: number;
  averageReviewTime: number;
  approvalRate: number;
}

/**
 * Template Approval Workflow Service
 */
export class TemplateApprovalService {
  private pool: Pool;
  private redis: Redis;
  private spamKeywords: string[];

  constructor(pool: Pool, redis: Redis) {
    this.pool = pool;
    this.redis = redis;
    this.spamKeywords = [
      'viagra', 'cialis', 'lottery', 'winner', 'prize',
      'crypto', 'bitcoin', 'investment opportunity',
      'act now', 'limited time', 'congratulations',
      'click here', 'urgent', 'verify your account',
    ];
  }

  /**
   * Submit template for approval
   */
  async submitTemplate(
    accountId: string,
    submittedBy: string,
    data: {
      templateType: 'email' | 'sms' | 'push';
      name: string;
      subject?: string;
      content: string;
      metadata?: Partial<TemplateMetadata>;
    }
  ): Promise<Result<TemplateSubmission>> {
    try {
      const id = uuidv4();

      // Analyze content
      const metadata = this.analyzeContent(data.content, data.metadata);

      // Check auto-approval rules
      const autoResult = await this.checkAutoApprovalRules(accountId, data.content, metadata);

      let status = TemplateApprovalStatus.PENDING;
      if (autoResult.action === 'auto_approve') {
        status = TemplateApprovalStatus.APPROVED;
      } else if (autoResult.action === 'auto_reject') {
        status = TemplateApprovalStatus.REJECTED;
      }

      // Get latest version number
      const versionResult = await this.pool.query(`
        SELECT MAX(version) as max_version FROM ent_template_submissions
        WHERE account_id = $1 AND name = $2
      `, [accountId, data.name]);
      const version = (versionResult.rows[0]?.max_version ?? 0) + 1;

      await this.pool.query(`
        INSERT INTO ent_template_submissions (
          id, account_id, submitted_by, template_type, name, subject,
          content, status, version, metadata, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
      `, [
        id,
        accountId,
        submittedBy,
        data.templateType,
        data.name,
        data.subject,
        data.content,
        status,
        version,
        JSON.stringify(metadata),
      ]);

      // If auto-rejected, add the reason
      if (status === TemplateApprovalStatus.REJECTED && autoResult.reason) {
        await this.pool.query(`
          UPDATE ent_template_submissions SET
            rejection_reason = $2,
            review_notes = $3
          WHERE id = $1
        `, [id, autoResult.reason, `Auto-rejected by rule: ${autoResult.ruleName}`]);
      }

      // Publish event
      await this.redis.publish('template:submission', JSON.stringify({
        id,
        accountId,
        status,
        timestamp: new Date().toISOString(),
      }));

      return this.getSubmission(id);
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get submission by ID
   */
  async getSubmission(id: string): Promise<Result<TemplateSubmission>> {
    try {
      const result = await this.pool.query(`
        SELECT * FROM ent_template_submissions WHERE id = $1
      `, [id]);

      if (result.rows.length === 0) {
        return { ok: false, error: new Error('Submission not found') };
      }

      return { ok: true, value: this.rowToSubmission(result.rows[0]) };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * List submissions with filters
   */
  async listSubmissions(
    filters: {
      accountId?: string;
      status?: TemplateApprovalStatus;
      templateType?: string;
      startDate?: Date;
      endDate?: Date;
    },
    pagination: { page: number; limit: number } = { page: 1, limit: 20 }
  ): Promise<Result<{ submissions: TemplateSubmission[]; total: number }>> {
    try {
      const conditions: string[] = [];
      // Use union type for SQL parameter values
      const params: (string | Date | number)[] = [];
      let paramIndex = 1;

      if (filters.accountId) {
        conditions.push(`account_id = $${paramIndex++}`);
        params.push(filters.accountId);
      }
      if (filters.status) {
        conditions.push(`status = $${paramIndex++}`);
        params.push(filters.status);
      }
      if (filters.templateType) {
        conditions.push(`template_type = $${paramIndex++}`);
        params.push(filters.templateType);
      }
      if (filters.startDate) {
        conditions.push(`created_at >= $${paramIndex++}`);
        params.push(filters.startDate);
      }
      if (filters.endDate) {
        conditions.push(`created_at <= $${paramIndex++}`);
        params.push(filters.endDate);
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

      // Get total count
      const countResult = await this.pool.query(`
        SELECT COUNT(*) as total FROM ent_template_submissions ${whereClause}
      `, params);

      // Get submissions
      const offset = (pagination.page - 1) * pagination.limit;
      params.push(pagination.limit, offset);

      const result = await this.pool.query(`
        SELECT * FROM ent_template_submissions 
        ${whereClause}
        ORDER BY created_at DESC
        LIMIT $${paramIndex++} OFFSET $${paramIndex}
      `, params);

      return {
        ok: true,
        value: {
          submissions: result.rows.map(row => this.rowToSubmission(row)),
          total: parseInt(countResult.rows[0].total, 10),
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Approve template
   */
  async approveTemplate(
    id: string,
    reviewerId: string,
    notes?: string
  ): Promise<Result<TemplateSubmission>> {
    try {
      await this.pool.query(`
        UPDATE ent_template_submissions SET
          status = $2,
          reviewed_by = $3,
          reviewed_at = NOW(),
          review_notes = $4,
          updated_at = NOW()
        WHERE id = $1
      `, [id, TemplateApprovalStatus.APPROVED, reviewerId, notes]);

      // Publish event
      await this.redis.publish('template:approved', JSON.stringify({
        id,
        reviewerId,
        timestamp: new Date().toISOString(),
      }));

      return this.getSubmission(id);
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Reject template
   */
  async rejectTemplate(
    id: string,
    reviewerId: string,
    reason: string,
    notes?: string
  ): Promise<Result<TemplateSubmission>> {
    try {
      await this.pool.query(`
        UPDATE ent_template_submissions SET
          status = $2,
          reviewed_by = $3,
          reviewed_at = NOW(),
          rejection_reason = $4,
          review_notes = $5,
          updated_at = NOW()
        WHERE id = $1
      `, [id, TemplateApprovalStatus.REJECTED, reviewerId, reason, notes]);

      // Publish event
      await this.redis.publish('template:rejected', JSON.stringify({
        id,
        reviewerId,
        reason,
        timestamp: new Date().toISOString(),
      }));

      return this.getSubmission(id);
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Request changes on template
   */
  async requestChanges(
    id: string,
    reviewerId: string,
    comments: string
  ): Promise<Result<TemplateSubmission>> {
    try {
      await this.pool.query(`
        UPDATE ent_template_submissions SET
          status = $2,
          reviewed_by = $3,
          review_notes = $4,
          updated_at = NOW()
        WHERE id = $1
      `, [id, TemplateApprovalStatus.CHANGES_REQUESTED, reviewerId, comments]);

      // Add comment
      await this.addComment(id, reviewerId, 'Reviewer', comments, true);

      return this.getSubmission(id);
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Add comment to submission
   */
  async addComment(
    submissionId: string,
    authorId: string,
    authorName: string,
    content: string,
    isInternal: boolean = false
  ): Promise<Result<ApprovalComment>> {
    try {
      const id = uuidv4();

      await this.pool.query(`
        INSERT INTO ent_template_comments (
          id, submission_id, author_id, author_name, content, is_internal, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
      `, [id, submissionId, authorId, authorName, content, isInternal]);

      return {
        ok: true,
        value: {
          id,
          submissionId,
          authorId,
          authorName,
          content,
          isInternal,
          createdAt: new Date(),
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get comments for submission
   */
  async getComments(
    submissionId: string,
    includeInternal: boolean = false
  ): Promise<Result<ApprovalComment[]>> {
    try {
      let query = `
        SELECT * FROM ent_template_comments
        WHERE submission_id = $1
      `;

      if (!includeInternal) {
        query += ` AND is_internal = false`;
      }

      query += ` ORDER BY created_at ASC`;

      const result = await this.pool.query(query, [submissionId]);

      return {
        ok: true,
        value: result.rows.map(row => ({
          id: row.id,
          submissionId: row.submission_id,
          authorId: row.author_id,
          authorName: row.author_name,
          content: row.content,
          isInternal: row.is_internal,
          createdAt: row.created_at,
        })),
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Create approval rule
   */
  async createRule(
    data: Omit<ApprovalRule, 'id' | 'createdAt'>
  ): Promise<Result<ApprovalRule>> {
    try {
      const id = uuidv4();

      await this.pool.query(`
        INSERT INTO ent_approval_rules (
          id, name, description, conditions, action, priority, is_active, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
      `, [
        id,
        data.name,
        data.description,
        JSON.stringify(data.conditions),
        data.action,
        data.priority,
        data.isActive,
      ]);

      // Invalidate rule cache
      await this.redis.del('approval:rules');

      return this.getRule(id);
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get rule by ID
   */
  async getRule(id: string): Promise<Result<ApprovalRule>> {
    try {
      const result = await this.pool.query(`
        SELECT * FROM ent_approval_rules WHERE id = $1
      `, [id]);

      if (result.rows.length === 0) {
        return { ok: false, error: new Error('Rule not found') };
      }

      return { ok: true, value: this.rowToRule(result.rows[0]) };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * List all rules
   */
  async listRules(): Promise<Result<ApprovalRule[]>> {
    try {
      // Check cache
      const cached = await this.redis.get('approval:rules');
      if (cached) {
        return { ok: true, value: JSON.parse(cached) };
      }

      const result = await this.pool.query(`
        SELECT * FROM ent_approval_rules
        ORDER BY priority ASC, created_at ASC
      `);

      const rules = result.rows.map(row => this.rowToRule(row));

      // Cache for 5 minutes
      await this.redis.setex('approval:rules', 300, JSON.stringify(rules));

      return { ok: true, value: rules };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get approval statistics
   */
  async getStats(
    accountId?: string,
    startDate?: Date,
    endDate?: Date
  ): Promise<Result<ApprovalStats>> {
    try {
      const conditions: string[] = [];
      // Use union type for SQL parameter values
      const params: (string | Date)[] = [];
      let paramIndex = 1;

      if (accountId) {
        conditions.push(`account_id = $${paramIndex++}`);
        params.push(accountId);
      }
      if (startDate) {
        conditions.push(`created_at >= $${paramIndex++}`);
        params.push(startDate);
      }
      if (endDate) {
        conditions.push(`created_at <= $${paramIndex++}`);
        params.push(endDate);
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

      const result = await this.pool.query(`
        SELECT
          COUNT(*) FILTER (WHERE status = 'pending') as pending,
          COUNT(*) FILTER (WHERE status = 'approved') as approved,
          COUNT(*) FILTER (WHERE status = 'rejected') as rejected,
          COUNT(*) FILTER (WHERE status = 'flagged') as flagged,
          AVG(EXTRACT(EPOCH FROM (reviewed_at - created_at))) FILTER (WHERE reviewed_at IS NOT NULL) as avg_review_time,
          COUNT(*) FILTER (WHERE status = 'approved')::float / NULLIF(COUNT(*) FILTER (WHERE status IN ('approved', 'rejected')), 0) as approval_rate
        FROM ent_template_submissions
        ${whereClause}
      `, params);

      const row = result.rows[0];
      return {
        ok: true,
        value: {
          pending: parseInt(row.pending, 10),
          approved: parseInt(row.approved, 10),
          rejected: parseInt(row.rejected, 10),
          flagged: parseInt(row.flagged, 10),
          averageReviewTime: Math.round(parseFloat(row.avg_review_time) || 0),
          approvalRate: parseFloat(row.approval_rate) || 0,
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Analyze content for metadata
   */
  private analyzeContent(content: string, existing?: Partial<TemplateMetadata>): TemplateMetadata {
    const containsLinks = /<a\s+(?:[^>]*?\s+)?href=/i.test(content) || /https?:\/\//i.test(content);
    const containsImages = /<img/i.test(content);
    const containsPersonalization = /{{.+?}}/i.test(content) || /%\w+%/i.test(content);

    // Calculate spam score (0-100)
    const spamScore = this.calculateSpamScore(content);

    return {
      industry: existing?.industry,
      useCase: existing?.useCase,
      targetAudience: existing?.targetAudience,
      sendVolume: existing?.sendVolume,
      containsLinks,
      containsImages,
      containsPersonalization,
      spamScore,
    };
  }

  /**
   * Calculate spam score
   */
  private calculateSpamScore(content: string): number {
    let score = 0;
    const lowerContent = content.toLowerCase();

    // Check for spam keywords
    for (const keyword of this.spamKeywords) {
      if (lowerContent.includes(keyword)) {
        score += 10;
      }
    }

    // Check for excessive capitalization
    const upperCaseRatio = (content.match(/[A-Z]/g) || []).length / content.length;
    if (upperCaseRatio > 0.3) {
      score += 15;
    }

    // Check for excessive exclamation marks
    const exclamationCount = (content.match(/!/g) || []).length;
    if (exclamationCount > 3) {
      score += exclamationCount * 2;
    }

    // Check for suspicious patterns
    if (/\$\d+/i.test(content)) score += 10; // Money amounts
    if (/free\s+money/i.test(content)) score += 20;
    if (/click\s+here\s+now/i.test(content)) score += 15;
    if (/unsubscribe/i.test(content) === false) score += 5; // Missing unsubscribe

    return Math.min(100, score);
  }

  /**
   * Check auto-approval rules
   */
  private async checkAutoApprovalRules(
    accountId: string,
    content: string,
    metadata: TemplateMetadata
  ): Promise<{ action: 'auto_approve' | 'auto_reject' | 'require_review' | 'flag' | null; reason?: string; ruleName?: string }> {
    // Account ID reserved for future account-specific rules
    void accountId;
    
    const rulesResult = await this.listRules();
    if (!rulesResult.ok) {
      return { action: null };
    }

    const activeRules = rulesResult.value.filter(r => r.isActive);

    for (const rule of activeRules) {
      const matches = this.evaluateConditions(rule.conditions, content, metadata);
      if (matches) {
        return {
          action: rule.action,
          reason: rule.description,
          ruleName: rule.name,
        };
      }
    }

    // Default: auto-reject if spam score too high
    if (metadata.spamScore && metadata.spamScore >= config.templateApproval.maxSpamScore) {
      return {
        action: 'auto_reject',
        reason: `Spam score (${metadata.spamScore}) exceeds threshold (${config.templateApproval.maxSpamScore})`,
        ruleName: 'Built-in Spam Filter',
      };
    }

    return { action: null };
  }

  /**
   * Evaluate rule conditions
   */
  private evaluateConditions(
    conditions: ApprovalCondition[],
    content: string,
    metadata: TemplateMetadata
  ): boolean {
    for (const condition of conditions) {
      let fieldValue: any;

      if (condition.field === 'content') {
        fieldValue = content.toLowerCase();
      } else if (condition.field === 'spamScore') {
        fieldValue = metadata.spamScore;
      } else if (condition.field === 'containsLinks') {
        fieldValue = metadata.containsLinks;
      } else if (condition.field === 'containsImages') {
        fieldValue = metadata.containsImages;
      } else {
        continue;
      }

      let matches = false;

      switch (condition.operator) {
        case 'contains':
          matches = String(fieldValue).includes(String(condition.value).toLowerCase());
          break;
        case 'not_contains':
          matches = !String(fieldValue).includes(String(condition.value).toLowerCase());
          break;
        case 'equals':
          matches = fieldValue === condition.value;
          break;
        case 'not_equals':
          matches = fieldValue !== condition.value;
          break;
        case 'regex':
          matches = new RegExp(String(condition.value), 'i').test(String(fieldValue));
          break;
        case 'greater_than':
          matches = Number(fieldValue) > Number(condition.value);
          break;
        case 'less_than':
          matches = Number(fieldValue) < Number(condition.value);
          break;
      }

      if (!matches) {
        return false; // All conditions must match
      }
    }

    return conditions.length > 0;
  }

  private rowToSubmission(row: any): TemplateSubmission {
    return {
      id: row.id,
      accountId: row.account_id,
      submittedBy: row.submitted_by,
      templateType: row.template_type,
      name: row.name,
      subject: row.subject,
      content: row.content,
      previewUrl: row.preview_url,
      status: row.status as TemplateApprovalStatus,
      reviewedBy: row.reviewed_by,
      reviewedAt: row.reviewed_at,
      reviewNotes: row.review_notes,
      rejectionReason: row.rejection_reason,
      version: row.version,
      previousVersionId: row.previous_version_id,
      metadata: row.metadata,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private rowToRule(row: any): ApprovalRule {
    return {
      id: row.id,
      name: row.name,
      description: row.description,
      conditions: row.conditions,
      action: row.action,
      priority: row.priority,
      isActive: row.is_active,
      createdAt: row.created_at,
    };
  }
}
