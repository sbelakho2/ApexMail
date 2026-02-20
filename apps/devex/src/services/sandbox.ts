/**
 * Sandbox Mode Service
 * 
 * Provides isolated test environments for:
 * - Email testing without delivery
 * - API testing with simulated responses
 * - Webhook testing
 * - Rate limit testing
 */

import { generateUUID } from '@apexmail/lib/crypto';
import { createLogger } from '@apexmail/lib';
import type { Pool } from 'pg';

const logger = createLogger({ name: 'devex-sandbox' });

export interface SandboxEnvironment {
  id: string;
  tenantId: string;
  name: string;
  mode: SandboxMode;
  settings: SandboxSettings;
  rateLimits: SandboxRateLimits;
  createdAt: Date;
  updatedAt: Date;
  expiresAt: Date | null;
}

export enum SandboxMode {
  CAPTURE = 'capture',      // Capture emails without sending
  SIMULATE = 'simulate',    // Simulate responses
  FORWARD = 'forward',      // Forward to test inbox
  REPLAY = 'replay',        // Replay recorded events
}

export interface SandboxSettings {
  captureEmails: boolean;
  simulateDelivery: boolean;
  simulateBounces: boolean;
  bounceRate: number;          // 0-1
  simulateComplaints: boolean;
  complaintRate: number;       // 0-1
  simulateDelays: boolean;
  delayMinMs: number;
  delayMaxMs: number;
  forwardTo: string | null;
  allowedRecipientPatterns: string[];
  blockedRecipientPatterns: string[];
  webhookUrl: string | null;
  maxEmailsPerDay: number;
  retainEmailsDays: number;
}

export interface SandboxRateLimits {
  maxRequestsPerMinute: number;
  maxEmailsPerMinute: number;
  maxBurstRequests: number;
}

export interface CapturedEmail {
  id: string;
  sandboxId: string;
  from: string;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  textContent: string | null;
  htmlContent: string | null;
  headers: Record<string, string>;
  attachments: CapturedAttachment[];
  metadata: Record<string, unknown>;
  simulatedEvents: SimulatedEvent[];
  capturedAt: Date;
}

export interface CapturedAttachment {
  filename: string;
  contentType: string;
  size: number;
  content: string;  // base64
}

export interface SimulatedEvent {
  type: string;
  timestamp: Date;
  data: Record<string, unknown>;
}

export interface SandboxStats {
  emailsCaptured: number;
  emailsForwarded: number;
  simulatedDeliveries: number;
  simulatedBounces: number;
  simulatedComplaints: number;
  webhooksTriggered: number;
  apiCalls: number;
}

type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

const DEFAULT_SETTINGS: SandboxSettings = {
  captureEmails: true,
  simulateDelivery: true,
  simulateBounces: false,
  bounceRate: 0.05,
  simulateComplaints: false,
  complaintRate: 0.001,
  simulateDelays: false,
  delayMinMs: 100,
  delayMaxMs: 2000,
  forwardTo: null,
  allowedRecipientPatterns: ['*'],
  blockedRecipientPatterns: [],
  webhookUrl: null,
  maxEmailsPerDay: 1000,
  retainEmailsDays: 7,
};

const DEFAULT_RATE_LIMITS: SandboxRateLimits = {
  maxRequestsPerMinute: 100,
  maxEmailsPerMinute: 50,
  maxBurstRequests: 20,
};

export class SandboxService {
  private db: Pool;
  private environments: Map<string, SandboxEnvironment>;
  private capturedEmails: Map<string, CapturedEmail[]>;
  // FIX-500-342: Cap in-memory captured emails to prevent unbounded growth
  private static readonly MAX_CAPTURES_PER_SANDBOX = 10_000;
  private static readonly MAX_SANDBOX_ENVIRONMENTS = 1_000;

  constructor(db: Pool) {
    this.db = db;
    this.environments = new Map();
    this.capturedEmails = new Map();
  }

  /**
   * FIX-500-410: Evict oldest environments when Map exceeds cap
   */
  private evictEnvironmentsIfNeeded(): void {
    while (this.environments.size > SandboxService.MAX_SANDBOX_ENVIRONMENTS) {
      const firstKey = this.environments.keys().next().value;
      if (firstKey !== undefined) {
        this.environments.delete(firstKey);
        this.capturedEmails.delete(firstKey);
      } else {
        break;
      }
    }
  }

  /**
   * Create a new sandbox environment
   */
  async createEnvironment(
    tenantId: string,
    name: string,
    mode: SandboxMode = SandboxMode.CAPTURE,
    settings?: Partial<SandboxSettings>,
    rateLimits?: Partial<SandboxRateLimits>,
    expiresInHours?: number
  ): Promise<Result<SandboxEnvironment>> {
    try {
      // FIX-500-342: Cap total sandbox environments to prevent unbounded growth
      if (this.environments.size >= SandboxService.MAX_SANDBOX_ENVIRONMENTS) {
        return { ok: false, error: new Error(`Maximum sandbox environments (${SandboxService.MAX_SANDBOX_ENVIRONMENTS}) reached`) };
      }

      const id = `sbx_${generateUUID().replace(/-/g, '')}`;
      
      const environment: SandboxEnvironment = {
        id,
        tenantId,
        name,
        mode,
        settings: { ...DEFAULT_SETTINGS, ...settings },
        rateLimits: { ...DEFAULT_RATE_LIMITS, ...rateLimits },
        createdAt: new Date(),
        updatedAt: new Date(),
        expiresAt: expiresInHours ? new Date(Date.now() + expiresInHours * 60 * 60 * 1000) : null,
      };

      // Store in database
      await this.db.query(`
        INSERT INTO sandbox_environments (
          id, tenant_id, name, mode, settings, rate_limits, created_at, updated_at, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      `, [
        environment.id,
        environment.tenantId,
        environment.name,
        environment.mode,
        JSON.stringify(environment.settings),
        JSON.stringify(environment.rateLimits),
        environment.createdAt,
        environment.updatedAt,
        environment.expiresAt,
      ]);

      this.environments.set(id, environment);
      this.capturedEmails.set(id, []);
      this.evictEnvironmentsIfNeeded(); // FIX-500-410

      // FIX-500-150: Initialize stats in DB instead of in-memory Map
      await this.db.query(
        `INSERT INTO sandbox_stats (sandbox_id) VALUES ($1) ON CONFLICT (sandbox_id) DO NOTHING`,
        [id]
      );

      return { ok: true, value: environment };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get sandbox environment
   */
  async getEnvironment(id: string): Promise<Result<SandboxEnvironment | null>> {
    try {
      // Check cache first
      if (this.environments.has(id)) {
        return { ok: true, value: this.environments.get(id)! };
      }

      // Load from database
      const result = await this.db.query(`
        SELECT * FROM sandbox_environments WHERE id = $1 AND (expires_at IS NULL OR expires_at > NOW())
      `, [id]);

      if (result.rows.length === 0) {
        return { ok: true, value: null };
      }

      const row = result.rows[0];
      const environment: SandboxEnvironment = {
        id: row.id,
        tenantId: row.tenant_id,
        name: row.name,
        mode: row.mode,
        settings: row.settings,
        rateLimits: row.rate_limits,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        expiresAt: row.expires_at,
      };

      this.environments.set(id, environment);
      this.evictEnvironmentsIfNeeded(); // FIX-500-410
      return { ok: true, value: environment };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * List sandbox environments for a tenant
   */
  async listEnvironments(tenantId: string): Promise<Result<SandboxEnvironment[]>> {
    try {
      const result = await this.db.query(`
        SELECT * FROM sandbox_environments 
        WHERE tenant_id = $1 AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY created_at DESC
      `, [tenantId]);

      const environments = result.rows.map(row => ({
        id: row.id,
        tenantId: row.tenant_id,
        name: row.name,
        mode: row.mode,
        settings: row.settings,
        rateLimits: row.rate_limits,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        expiresAt: row.expires_at,
      }));

      return { ok: true, value: environments };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Update sandbox settings
   */
  async updateSettings(
    id: string,
    settings: Partial<SandboxSettings>
  ): Promise<Result<SandboxEnvironment>> {
    try {
      const envResult = await this.getEnvironment(id);
      if (!envResult.ok) return envResult;
      if (!envResult.value) {
        return { ok: false, error: new Error('Sandbox environment not found') };
      }

      const environment = envResult.value;
      environment.settings = { ...environment.settings, ...settings };
      environment.updatedAt = new Date();

      await this.db.query(`
        UPDATE sandbox_environments 
        SET settings = $2, updated_at = $3
        WHERE id = $1
      `, [id, JSON.stringify(environment.settings), environment.updatedAt]);

      this.environments.set(id, environment);
      return { ok: true, value: environment };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Delete sandbox environment
   */
  async deleteEnvironment(id: string): Promise<Result<void>> {
    try {
      await this.db.query(`DELETE FROM sandbox_environments WHERE id = $1`, [id]);
      await this.db.query(`DELETE FROM sandbox_captured_emails WHERE sandbox_id = $1`, [id]);
      await this.db.query(`DELETE FROM sandbox_stats WHERE sandbox_id = $1`, [id]);

      this.environments.delete(id);
      this.capturedEmails.delete(id);

      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Capture an email in sandbox mode
   */
  async captureEmail(
    sandboxId: string,
    email: {
      from: string;
      to: string[];
      cc?: string[];
      bcc?: string[];
      subject: string;
      textContent?: string;
      htmlContent?: string;
      headers?: Record<string, string>;
      attachments?: CapturedAttachment[];
      metadata?: Record<string, unknown>;
    }
  ): Promise<Result<CapturedEmail>> {
    try {
      const envResult = await this.getEnvironment(sandboxId);
      if (!envResult.ok) return { ok: false, error: envResult.error };
      if (!envResult.value) {
        return { ok: false, error: new Error('Sandbox environment not found') };
      }

      const environment = envResult.value;
      const settings = environment.settings;

      // Check recipient patterns
      for (const recipient of email.to) {
        if (!this.matchesPattern(recipient, settings.allowedRecipientPatterns)) {
          return { ok: false, error: new Error(`Recipient ${recipient} not allowed in sandbox`) };
        }
        if (this.matchesPattern(recipient, settings.blockedRecipientPatterns)) {
          return { ok: false, error: new Error(`Recipient ${recipient} is blocked in sandbox`) };
        }
      }

      // Create captured email
      const id = `cap_${generateUUID().replace(/-/g, '')}`;
      const captured: CapturedEmail = {
        id,
        sandboxId,
        from: email.from,
        to: email.to,
        cc: email.cc ?? [],
        bcc: email.bcc ?? [],
        subject: email.subject,
        textContent: email.textContent ?? null,
        htmlContent: email.htmlContent ?? null,
        headers: email.headers ?? {},
        attachments: email.attachments ?? [],
        metadata: email.metadata ?? {},
        simulatedEvents: [],
        capturedAt: new Date(),
      };

      // Simulate events based on mode
      if (settings.simulateDelivery) {
        captured.simulatedEvents.push(...this.simulateDeliveryEvents(environment, captured));
      }

      // Store captured email
      await this.db.query(`
        INSERT INTO sandbox_captured_emails (
          id, sandbox_id, from_address, to_addresses, cc_addresses, bcc_addresses,
          subject, text_content, html_content, headers, attachments, metadata,
          simulated_events, captured_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
      `, [
        captured.id,
        captured.sandboxId,
        captured.from,
        captured.to,
        captured.cc,
        captured.bcc,
        captured.subject,
        captured.textContent,
        captured.htmlContent,
        JSON.stringify(captured.headers),
        JSON.stringify(captured.attachments),
        JSON.stringify(captured.metadata),
        JSON.stringify(captured.simulatedEvents),
        captured.capturedAt,
      ]);

      // Update in-memory cache
      const emails = this.capturedEmails.get(sandboxId) ?? [];
      emails.push(captured);
      // FIX-500-411: Use splice instead of while+shift for O(1) trimming
      if (emails.length > SandboxService.MAX_CAPTURES_PER_SANDBOX) {
        const excess = emails.length - SandboxService.MAX_CAPTURES_PER_SANDBOX;
        emails.splice(0, excess);
      }
      this.capturedEmails.set(sandboxId, emails);

      // FIX-500-411: Also cap total number of sandbox keys in capturedEmails
      if (this.capturedEmails.size > SandboxService.MAX_SANDBOX_ENVIRONMENTS) {
        const firstKey = this.capturedEmails.keys().next().value;
        if (firstKey !== undefined && firstKey !== sandboxId) {
          this.capturedEmails.delete(firstKey);
        }
      }

      // FIX-500-150/412: Atomically update stats in DB via ON CONFLICT DO UPDATE
      await this.db.query(
        `INSERT INTO sandbox_stats (sandbox_id, emails_captured, emails_forwarded, updated_at)
         VALUES ($1, 1, $2, NOW())
         ON CONFLICT (sandbox_id) DO UPDATE
         SET emails_captured = sandbox_stats.emails_captured + 1,
             emails_forwarded = sandbox_stats.emails_forwarded + $2,
             updated_at = NOW()`,
        [sandboxId, settings.forwardTo ? 1 : 0]
      );

      // Forward if configured
      if (settings.forwardTo) {
        await this.forwardEmail(captured, settings.forwardTo);
      }

      // Trigger webhook if configured
      if (settings.webhookUrl) {
        await this.triggerWebhook(settings.webhookUrl, 'email.captured', captured);
        await this.db.query(
          `INSERT INTO sandbox_stats (sandbox_id, webhooks_triggered, updated_at)
           VALUES ($1, 1, NOW())
           ON CONFLICT (sandbox_id) DO UPDATE
           SET webhooks_triggered = sandbox_stats.webhooks_triggered + 1,
               updated_at = NOW()`,
          [sandboxId]
        );
      }

      return { ok: true, value: captured };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get captured emails
   */
  async getCapturedEmails(
    sandboxId: string,
    options?: {
      limit?: number;
      offset?: number;
      from?: string;
      to?: string;
      subject?: string;
      startDate?: Date;
      endDate?: Date;
    }
  ): Promise<Result<{ emails: CapturedEmail[]; total: number }>> {
    try {
      let query = `
        SELECT * FROM sandbox_captured_emails 
        WHERE sandbox_id = $1
      `;
      const params: unknown[] = [sandboxId];
      let paramIndex = 2;

      if (options?.from) {
        query += ` AND from_address ILIKE $${paramIndex}`;
        params.push(`%${options.from}%`);
        paramIndex++;
      }

      if (options?.to) {
        query += ` AND $${paramIndex} = ANY(to_addresses)`;
        params.push(options.to);
        paramIndex++;
      }

      if (options?.subject) {
        query += ` AND subject ILIKE $${paramIndex}`;
        params.push(`%${options.subject}%`);
        paramIndex++;
      }

      if (options?.startDate) {
        query += ` AND captured_at >= $${paramIndex}`;
        params.push(options.startDate);
        paramIndex++;
      }

      if (options?.endDate) {
        query += ` AND captured_at <= $${paramIndex}`;
        params.push(options.endDate);
        paramIndex++;
      }

      // Get total count
      const countResult = await this.db.query(
        `SELECT COUNT(*) as total FROM (${query}) subq`,
        params
      );
      const total = parseInt(countResult.rows[0]?.total ?? '0', 10);

      // Add ordering and pagination
      query += ` ORDER BY captured_at DESC`;

      if (options?.limit) {
        query += ` LIMIT $${paramIndex}`;
        params.push(options.limit);
        paramIndex++;
      }

      if (options?.offset) {
        query += ` OFFSET $${paramIndex}`;
        params.push(options.offset);
      }

      const result = await this.db.query(query, params);

      const emails = result.rows.map(row => ({
        id: row.id,
        sandboxId: row.sandbox_id,
        from: row.from_address,
        to: row.to_addresses,
        cc: row.cc_addresses,
        bcc: row.bcc_addresses,
        subject: row.subject,
        textContent: row.text_content,
        htmlContent: row.html_content,
        headers: row.headers,
        attachments: row.attachments,
        metadata: row.metadata,
        simulatedEvents: row.simulated_events,
        capturedAt: row.captured_at,
      }));

      return { ok: true, value: { emails, total } };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get a specific captured email
   */
  async getCapturedEmail(emailId: string): Promise<Result<CapturedEmail | null>> {
    try {
      const result = await this.db.query(`
        SELECT * FROM sandbox_captured_emails WHERE id = $1
      `, [emailId]);

      if (result.rows.length === 0) {
        return { ok: true, value: null };
      }

      const row = result.rows[0];
      return {
        ok: true,
        value: {
          id: row.id,
          sandboxId: row.sandbox_id,
          from: row.from_address,
          to: row.to_addresses,
          cc: row.cc_addresses,
          bcc: row.bcc_addresses,
          subject: row.subject,
          textContent: row.text_content,
          htmlContent: row.html_content,
          headers: row.headers,
          attachments: row.attachments,
          metadata: row.metadata,
          simulatedEvents: row.simulated_events,
          capturedAt: row.captured_at,
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Delete a captured email
   */
  async deleteCapturedEmail(emailId: string): Promise<Result<void>> {
    try {
      await this.db.query(`DELETE FROM sandbox_captured_emails WHERE id = $1`, [emailId]);
      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Clear all captured emails
   */
  async clearCapturedEmails(sandboxId: string): Promise<Result<void>> {
    try {
      await this.db.query(`DELETE FROM sandbox_captured_emails WHERE sandbox_id = $1`, [sandboxId]);
      this.capturedEmails.set(sandboxId, []);
      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get sandbox statistics — FIX-500-150: fully DB-backed via sandbox_stats table
   */
  async getStats(sandboxId: string): Promise<Result<SandboxStats>> {
    try {
      const result = await this.db.query(`
        SELECT emails_captured, emails_forwarded, simulated_deliveries,
               simulated_bounces, simulated_complaints, webhooks_triggered, api_calls
        FROM sandbox_stats
        WHERE sandbox_id = $1
      `, [sandboxId]);

      if (result.rows.length === 0) {
        return { ok: true, value: this.createEmptyStats() };
      }

      const row = result.rows[0];
      const stats: SandboxStats = {
        emailsCaptured: parseInt(row.emails_captured) || 0,
        emailsForwarded: parseInt(row.emails_forwarded) || 0,
        simulatedDeliveries: parseInt(row.simulated_deliveries) || 0,
        simulatedBounces: parseInt(row.simulated_bounces) || 0,
        simulatedComplaints: parseInt(row.simulated_complaints) || 0,
        webhooksTriggered: parseInt(row.webhooks_triggered) || 0,
        apiCalls: parseInt(row.api_calls) || 0,
      };

      return { ok: true, value: stats };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Simulate API response
   */
  async simulateApiResponse(
    sandboxId: string,
    endpoint: string,
    method: string,
    body?: unknown
  ): Promise<Result<{ status: number; body: unknown; delay: number }>> {
    try {
      const envResult = await this.getEnvironment(sandboxId);
      if (!envResult.ok) return { ok: false, error: envResult.error };
      if (!envResult.value) {
        return { ok: false, error: new Error('Sandbox environment not found') };
      }

      const settings = envResult.value.settings;

      // Calculate delay
      let delay = 0;
      if (settings.simulateDelays) {
        delay = Math.floor(
          Math.random() * (settings.delayMaxMs - settings.delayMinMs) + settings.delayMinMs
        );
      }

      // Simulate based on endpoint
      const response = this.getSimulatedResponse(endpoint, method, body, settings);

      // FIX-500-150: Update stats in DB instead of in-memory Map
      await this.db.query(
        `INSERT INTO sandbox_stats (sandbox_id, api_calls, updated_at)
         VALUES ($1, 1, NOW())
         ON CONFLICT (sandbox_id) DO UPDATE
         SET api_calls = sandbox_stats.api_calls + 1,
             updated_at = NOW()`,
        [sandboxId]
      );

      return { ok: true, value: { ...response, delay } };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Create a test inbox
   */
  async createTestInbox(sandboxId: string): Promise<Result<{ email: string; inboxId: string }>> {
    try {
      const inboxId = `inbox_${generateUUID().replace(/-/g, '')}`;
      const email = `test-${inboxId.slice(0, 8)}@sandbox.apexmail.ee`;

      await this.db.query(`
        INSERT INTO sandbox_test_inboxes (id, sandbox_id, email, created_at)
        VALUES ($1, $2, $3, NOW())
      `, [inboxId, sandboxId, email]);

      return { ok: true, value: { email, inboxId } };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get test inbox emails
   */
  async getTestInboxEmails(inboxId: string): Promise<Result<CapturedEmail[]>> {
    try {
      const inboxResult = await this.db.query(`
        SELECT email FROM sandbox_test_inboxes WHERE id = $1
      `, [inboxId]);

      if (inboxResult.rows.length === 0) {
        return { ok: false, error: new Error('Test inbox not found') };
      }

      const email = inboxResult.rows[0].email;

      const result = await this.db.query(`
        SELECT * FROM sandbox_captured_emails 
        WHERE $1 = ANY(to_addresses)
        ORDER BY captured_at DESC
      `, [email]);

      const emails = result.rows.map(row => ({
        id: row.id,
        sandboxId: row.sandbox_id,
        from: row.from_address,
        to: row.to_addresses,
        cc: row.cc_addresses,
        bcc: row.bcc_addresses,
        subject: row.subject,
        textContent: row.text_content,
        htmlContent: row.html_content,
        headers: row.headers,
        attachments: row.attachments,
        metadata: row.metadata,
        simulatedEvents: row.simulated_events,
        capturedAt: row.captured_at,
      }));

      return { ok: true, value: emails };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Generate sandbox API key
   */
  async generateSandboxApiKey(
    tenantId: string,
    sandboxId: string
  ): Promise<Result<{ apiKey: string; prefix: string }>> {
    try {
      const keyId = generateUUID().replace(/-/g, '').slice(0, 16);
      const secret = generateUUID().replace(/-/g, '') + generateUUID().replace(/-/g, '');
      const apiKey = `am_test_${keyId}${secret}`;
      const prefix = apiKey.slice(0, 16);

      await this.db.query(`
        INSERT INTO sandbox_api_keys (id, tenant_id, sandbox_id, key_prefix, key_hash, created_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
      `, [
        `key_${keyId}`,
        tenantId,
        sandboxId,
        prefix,
        await this.hashApiKey(apiKey),
      ]);

      return { ok: true, value: { apiKey, prefix } };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Validate sandbox API key
   */
  async validateSandboxApiKey(apiKey: string): Promise<Result<{ sandboxId: string; tenantId: string } | null>> {
    try {
      if (!apiKey.startsWith('am_test_')) {
        return { ok: true, value: null };
      }

      const prefix = apiKey.slice(0, 16);
      const hash = await this.hashApiKey(apiKey);

      const result = await this.db.query(`
        SELECT sandbox_id, tenant_id FROM sandbox_api_keys 
        WHERE key_prefix = $1 AND key_hash = $2
      `, [prefix, hash]);

      if (result.rows.length === 0) {
        return { ok: true, value: null };
      }

      return {
        ok: true,
        value: {
          sandboxId: result.rows[0].sandbox_id,
          tenantId: result.rows[0].tenant_id,
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  // Private helper methods

  /**
   * Check if an email matches any of the given patterns
   * SECURITY: Patterns are converted to safe regex to prevent ReDoS attacks
   * Patterns support only '*' as a wildcard for "any characters"
   * Examples: "*@example.com", "test-*@*.example.com"
   */
  private matchesPattern(email: string, patterns: string[]): boolean {
    for (const pattern of patterns) {
      if (pattern === '*') return true;
      
      // SECURITY: Use a safe pattern matching approach instead of arbitrary regex
      // This prevents ReDoS attacks from malicious patterns like "(a+)+b"
      if (this.safePatternMatch(email.toLowerCase(), pattern.toLowerCase())) {
        return true;
      }
    }
    return false;
  }

  /**
   * Safe pattern matching using string operations instead of regex
   * Supports only '*' as wildcard - no regex metacharacters allowed
   * This prevents ReDoS vulnerabilities from user-provided patterns
   */
  private safePatternMatch(email: string, pattern: string): boolean {
    // Split pattern by wildcard
    const parts = pattern.split('*');
    
    // If no wildcards, exact match
    if (parts.length === 1) {
      return email === pattern;
    }

    let position = 0;
    
    // Check first part (must match at start if not empty)
    const firstPart = parts[0];
    if (firstPart && firstPart.length > 0) {
      if (!email.startsWith(firstPart)) {
        return false;
      }
      position = firstPart.length;
    }

    // Check middle parts (must exist somewhere after previous match)
    for (let i = 1; i < parts.length - 1; i++) {
      const part = parts[i];
      if (!part || part.length === 0) continue;
      
      const idx = email.indexOf(part, position);
      if (idx === -1) {
        return false;
      }
      position = idx + part.length;
    }

    // Check last part (must match at end if not empty)
    const lastPart = parts[parts.length - 1];
    if (lastPart && lastPart.length > 0) {
      if (!email.endsWith(lastPart)) {
        return false;
      }
      // Also verify we haven't gone past where it ends
      const lastPartStart = email.length - lastPart.length;
      if (lastPartStart < position) {
        return false;
      }
    }

    return true;
  }

  private simulateDeliveryEvents(
    environment: SandboxEnvironment,
    email: CapturedEmail
  ): SimulatedEvent[] {
    const events: SimulatedEvent[] = [];
    const settings = environment.settings;
    const now = new Date();

    // Processing event
    events.push({
      type: 'email.processing',
      timestamp: now,
      data: { emailId: email.id },
    });

    // For each recipient
    for (const recipient of email.to) {
      const baseDelay = settings.simulateDelays
        ? Math.random() * (settings.delayMaxMs - settings.delayMinMs) + settings.delayMinMs
        : 100;

      // Sent event
      events.push({
        type: 'email.sent',
        timestamp: new Date(now.getTime() + baseDelay),
        data: { emailId: email.id, recipient },
      });

      // Simulate bounce
      if (settings.simulateBounces && Math.random() < settings.bounceRate) {
        events.push({
          type: 'email.bounced',
          timestamp: new Date(now.getTime() + baseDelay + 1000),
          data: {
            emailId: email.id,
            recipient,
            bounceType: Math.random() > 0.5 ? 'hard' : 'soft',
            bounceCode: '550',
            bounceMessage: 'Simulated bounce',
          },
        });
        continue;
      }

      // Simulate complaint
      if (settings.simulateComplaints && Math.random() < settings.complaintRate) {
        events.push({
          type: 'email.complained',
          timestamp: new Date(now.getTime() + baseDelay + 60000),
          data: { emailId: email.id, recipient },
        });
      }

      // Delivered event
      events.push({
        type: 'email.delivered',
        timestamp: new Date(now.getTime() + baseDelay + 500),
        data: { emailId: email.id, recipient },
      });

      // Simulate open (50% chance)
      if (Math.random() > 0.5) {
        events.push({
          type: 'email.opened',
          timestamp: new Date(now.getTime() + baseDelay + Math.random() * 3600000),
          data: { emailId: email.id, recipient },
        });

        // Simulate click (30% of opens)
        if (Math.random() > 0.7) {
          events.push({
            type: 'email.clicked',
            timestamp: new Date(now.getTime() + baseDelay + Math.random() * 7200000),
            data: { emailId: email.id, recipient, url: 'https://example.com' },
          });
        }
      }
    }

    return events;
  }

  private getSimulatedResponse(
    endpoint: string,
    method: string,
    body: unknown,
    _settings: SandboxSettings
  ): { status: number; body: unknown } {
    // Email send endpoint
    if (endpoint.includes('/emails') && method === 'POST') {
      return {
        status: 200,
        body: {
          id: `msg_${generateUUID().replace(/-/g, '')}`,
          status: 'queued',
          message: 'Email queued for delivery (sandbox mode)',
        },
      };
    }

    // Email status endpoint
    if (endpoint.match(/\/emails\/msg_[a-z0-9]+$/) && method === 'GET') {
      return {
        status: 200,
        body: {
          id: endpoint.split('/').pop(),
          status: 'delivered',
          events: [
            { type: 'queued', timestamp: new Date().toISOString() },
            { type: 'sent', timestamp: new Date().toISOString() },
            { type: 'delivered', timestamp: new Date().toISOString() },
          ],
        },
      };
    }

    // Domain verification
    if (endpoint.includes('/domains') && method === 'POST') {
      return {
        status: 200,
        body: {
          id: `dom_${generateUUID().replace(/-/g, '')}`,
          domain: (body as Record<string, unknown>)?.domain ?? 'example.com',
          status: 'pending_verification',
          dnsRecords: [
            {
              type: 'TXT',
              name: '_apexmail',
              value: `apexmail-verify=${generateUUID()}`,
            },
            {
              type: 'TXT',
              name: '_dmarc',
              value: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@apexmail.ee',
            },
          ],
        },
      };
    }

    // Default response
    return {
      status: 200,
      body: { message: 'Simulated response', sandbox: true },
    };
  }

  private async forwardEmail(email: CapturedEmail, forwardTo: string): Promise<void> {
    const forwardedCopy: CapturedEmail = {
      ...email,
      id: generateUUID(),
      to: [forwardTo],
      cc: [],
      bcc: [],
      metadata: {
        ...email.metadata,
        forwarded: true,
        forwardedFromEmailId: email.id,
        forwardedTo: forwardTo,
      },
      capturedAt: new Date(),
    };

    await this.db.query(
      `INSERT INTO sandbox_captured_emails (
          id, sandbox_id, from_address, to_addresses, cc_addresses, bcc_addresses,
          subject, text_content, html_content, headers, attachments, metadata,
          simulated_events, captured_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
      [
        forwardedCopy.id,
        forwardedCopy.sandboxId,
        forwardedCopy.from,
        forwardedCopy.to,
        forwardedCopy.cc,
        forwardedCopy.bcc,
        forwardedCopy.subject,
        forwardedCopy.textContent,
        forwardedCopy.htmlContent,
        JSON.stringify(forwardedCopy.headers),
        JSON.stringify(forwardedCopy.attachments),
        JSON.stringify(forwardedCopy.metadata),
        JSON.stringify(forwardedCopy.simulatedEvents),
        forwardedCopy.capturedAt,
      ]
    );

    const cached = this.capturedEmails.get(email.sandboxId) ?? [];
    cached.push(forwardedCopy);
    if (cached.length > SandboxService.MAX_CAPTURES_PER_SANDBOX) {
      cached.splice(0, cached.length - SandboxService.MAX_CAPTURES_PER_SANDBOX);
    }
    this.capturedEmails.set(email.sandboxId, cached);

    logger.info(`[Sandbox] Forwarded captured email ${email.id} to ${forwardTo} as ${forwardedCopy.id}`);
  }

  private async triggerWebhook(url: string, event: string, payload: unknown): Promise<void> {
    try {
      await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-ApexMail-Event': event,
          'X-ApexMail-Sandbox': 'true',
        },
        body: JSON.stringify({ event, data: payload, timestamp: new Date().toISOString() }),
      });
    } catch (error) {
      logger.error(`[Sandbox] Webhook trigger failed:`, { error: error instanceof Error ? error.message : String(error) });
    }
  }

  private async hashApiKey(apiKey: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(apiKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  private createEmptyStats(): SandboxStats {
    return {
      emailsCaptured: 0,
      emailsForwarded: 0,
      simulatedDeliveries: 0,
      simulatedBounces: 0,
      simulatedComplaints: 0,
      webhooksTriggered: 0,
      apiCalls: 0,
    };
  }

  /**
   * Clean up expired sandboxes
   */
  async cleanupExpired(): Promise<Result<{ deleted: number }>> {
    try {
      // Delete captured emails for expired sandboxes
      await this.db.query(`
        DELETE FROM sandbox_captured_emails 
        WHERE sandbox_id IN (
          SELECT id FROM sandbox_environments WHERE expires_at < NOW()
        )
      `);

      // Delete stats for expired sandboxes
      await this.db.query(`
        DELETE FROM sandbox_stats
        WHERE sandbox_id IN (
          SELECT id FROM sandbox_environments WHERE expires_at < NOW()
        )
      `);

      // Delete expired sandboxes
      const result = await this.db.query(`
        DELETE FROM sandbox_environments WHERE expires_at < NOW()
        RETURNING id
      `);

      // Clean up in-memory cache
      for (const row of result.rows) {
        this.environments.delete(row.id);
        this.capturedEmails.delete(row.id);
      }

      return { ok: true, value: { deleted: result.rowCount ?? 0 } };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get retention policy for sandbox
   */
  getRetentionPolicy(): { maxEmailsPerSandbox: number; maxAttachmentSizeMb: number; retentionDays: number } {
    return {
      maxEmailsPerSandbox: 10000,
      maxAttachmentSizeMb: 10,
      retentionDays: 30,
    };
  }
}
