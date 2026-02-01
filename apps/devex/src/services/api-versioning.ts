/**
 * API Versioning Service
 * 
 * Implements semantic API versioning with:
 * - Date-based versioning (YYYY-MM format)
 * - Header-based version selection
 * - Automatic deprecation warnings
 * - Response transformation per version
 * - Changelog generation
 */

import type { Pool } from 'pg';
import type { Context, Next } from 'hono';
import { config } from '../config.js';

export interface ApiVersion {
  version: string;
  releaseDate: Date;
  status: 'current' | 'supported' | 'deprecated' | 'sunset';
  sunsetDate?: Date;
  changelog: ChangelogEntry[];
}

export interface ChangelogEntry {
  type: 'added' | 'changed' | 'deprecated' | 'removed' | 'fixed' | 'security';
  description: string;
  endpoint?: string;
  breaking: boolean;
}

export interface VersionContext {
  requestedVersion: string;
  resolvedVersion: string;
  isDeprecated: boolean;
  sunsetDate?: Date;
}

type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export class ApiVersioningService {
  private db: Pool;
  private versions: Map<string, ApiVersion>;
  private transformers: Map<string, VersionTransformer>;

  constructor(db: Pool) {
    this.db = db;
    this.versions = new Map();
    this.transformers = new Map();
    this.initializeVersions();
    this.initializeTransformers();
  }

  private initializeVersions(): void {
    const versions: ApiVersion[] = [
      {
        version: '2024-01',
        releaseDate: new Date('2024-01-15'),
        status: 'current',
        changelog: [
          { type: 'added', description: 'Batch email sending endpoint', endpoint: 'POST /v1/emails/batch', breaking: false },
          { type: 'added', description: 'Email templates with Handlebars support', breaking: false },
          { type: 'added', description: 'Real-time delivery webhooks', breaking: false },
          { type: 'changed', description: 'Rate limits increased to 1000 req/min for paid plans', breaking: false },
          { type: 'fixed', description: 'Timezone handling in scheduled sends', breaking: false },
        ],
      },
      {
        version: '2023-10',
        releaseDate: new Date('2023-10-01'),
        status: 'supported',
        sunsetDate: new Date('2025-01-01'),
        changelog: [
          { type: 'added', description: 'Webhook signatures with HMAC-SHA256', breaking: false },
          { type: 'added', description: 'Custom tracking domains', breaking: false },
          { type: 'changed', description: 'Error response format standardized', breaking: true },
          { type: 'deprecated', description: 'Legacy /send endpoint', endpoint: 'POST /v1/send', breaking: false },
        ],
      },
      {
        version: '2023-06',
        releaseDate: new Date('2023-06-15'),
        status: 'supported',
        sunsetDate: new Date('2024-09-01'),
        changelog: [
          { type: 'added', description: 'Suppression list management', breaking: false },
          { type: 'added', description: 'Email validation endpoint', breaking: false },
          { type: 'changed', description: 'Pagination uses cursor-based pagination', breaking: true },
        ],
      },
      {
        version: '2023-01',
        releaseDate: new Date('2023-01-10'),
        status: 'deprecated',
        sunsetDate: new Date('2024-06-01'),
        changelog: [
          { type: 'added', description: 'Initial API release', breaking: false },
          { type: 'added', description: 'Email sending', breaking: false },
          { type: 'added', description: 'Basic analytics', breaking: false },
        ],
      },
      {
        version: '2022-10',
        releaseDate: new Date('2022-10-01'),
        status: 'sunset',
        sunsetDate: new Date('2023-12-01'),
        changelog: [
          { type: 'added', description: 'Beta API release', breaking: false },
        ],
      },
    ];

    for (const v of versions) {
      this.versions.set(v.version, v);
    }
  }

  private initializeTransformers(): void {
    // Transformer for 2023-10 → 2024-01 (current)
    this.transformers.set('2023-10', {
      transformRequest: (body: Record<string, unknown>) => {
        // Transform legacy 'recipients' to 'to'
        if (body.recipients && !body.to) {
          body.to = body.recipients;
          delete body.recipients;
        }
        return body;
      },
      transformResponse: (body: Record<string, unknown>) => {
        // Transform new format back to old
        if (body.delivery_status) {
          body.status = body.delivery_status;
        }
        return body;
      },
    });

    // Transformer for 2023-06 → 2024-01
    this.transformers.set('2023-06', {
      transformRequest: (body: Record<string, unknown>) => {
        // Handle old pagination params
        if (body.page !== undefined && body.per_page !== undefined) {
          body.limit = body.per_page;
          delete body.page;
          delete body.per_page;
        }
        return body;
      },
      transformResponse: (body: Record<string, unknown>) => {
        // Transform cursor pagination back to offset
        if (body.next_cursor) {
          body.has_more = true;
        }
        return body;
      },
    });

    // Transformer for 2023-01 → 2024-01
    this.transformers.set('2023-01', {
      transformRequest: (body: Record<string, unknown>) => {
        // Handle legacy error format expectation
        return body;
      },
      transformResponse: (body: Record<string, unknown>) => {
        // Transform to legacy error format
        if (body.error && typeof body.error === 'object') {
          const err = body.error as Record<string, unknown>;
          body.error_code = err.code;
          body.error_message = err.message;
        }
        return body;
      },
    });
  }

  /**
   * Resolve API version from request
   */
  resolveVersion(requestedVersion?: string): VersionContext {
    const version = requestedVersion ?? config.currentApiVersion;

    // Check if requested version is valid
    const versionInfo = this.versions.get(version);

    if (!versionInfo) {
      // Default to current version if invalid
      return {
        requestedVersion: version,
        resolvedVersion: config.currentApiVersion,
        isDeprecated: false,
      };
    }

    // Check if deprecated
    const isDeprecated = versionInfo.status === 'deprecated' || versionInfo.status === 'sunset';

    return {
      requestedVersion: version,
      resolvedVersion: version,
      isDeprecated,
      sunsetDate: versionInfo.sunsetDate,
    };
  }

  /**
   * Get Hono middleware for version handling
   */
  middleware() {
    return async (c: Context, next: Next): Promise<Response | void> => {
      // Get version from header, query, or default
      const requestedVersion = 
        c.req.header('X-API-Version') ?? 
        c.req.header('ApexMail-Version') ?? 
        c.req.query('api_version') ?? 
        undefined;

      const versionContext = this.resolveVersion(requestedVersion);

      // Check if version is sunset
      const versionInfo = this.versions.get(versionContext.resolvedVersion);
      if (versionInfo?.status === 'sunset') {
        return c.json({
          error: {
            code: 'version_sunset',
            message: `API version ${versionContext.resolvedVersion} has been sunset. Please upgrade to ${config.currentApiVersion}`,
            docs: `${config.docsBaseUrl}/api/versioning`,
          },
        }, 410);
      }

      // Store version context
      c.set('apiVersion', versionContext);

      // Add deprecation headers
      if (versionContext.isDeprecated) {
        c.header('Deprecation', 'true');
        c.header('Sunset', versionContext.sunsetDate?.toISOString() ?? '');
        c.header('Link', `<${config.docsBaseUrl}/api/migration>; rel="deprecation"`);
      }

      // Always return the resolved version
      c.header('X-API-Version', versionContext.resolvedVersion);

      await next();
    };
  }

  /**
   * Transform request body for older API versions
   */
  transformRequest(version: string, body: Record<string, unknown>): Record<string, unknown> {
    const transformer = this.transformers.get(version);
    if (transformer?.transformRequest) {
      return transformer.transformRequest(body);
    }
    return body;
  }

  /**
   * Transform response body for older API versions
   */
  transformResponse(version: string, body: Record<string, unknown>): Record<string, unknown> {
    const transformer = this.transformers.get(version);
    if (transformer?.transformResponse) {
      return transformer.transformResponse(body);
    }
    return body;
  }

  /**
   * Get all API versions
   */
  async getAllVersions(): Promise<Result<ApiVersion[]>> {
    try {
      return { ok: true, value: Array.from(this.versions.values()) };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get version details
   */
  async getVersion(version: string): Promise<Result<ApiVersion | null>> {
    try {
      return { ok: true, value: this.versions.get(version) ?? null };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get full changelog
   */
  async getChangelog(fromVersion?: string): Promise<Result<ChangelogEntry[]>> {
    try {
      const allVersions = Array.from(this.versions.values())
        .sort((a, b) => b.releaseDate.getTime() - a.releaseDate.getTime());

      let changelog: ChangelogEntry[] = [];
      let startCollecting = !fromVersion;

      for (const v of allVersions) {
        if (v.version === fromVersion) {
          startCollecting = true;
          continue;
        }
        if (startCollecting) {
          changelog = changelog.concat(v.changelog.map(entry => ({
            ...entry,
            version: v.version,
            date: v.releaseDate,
          })));
        }
      }

      return { ok: true, value: changelog };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Check if version upgrade is needed
   */
  async checkUpgradeNeeded(tenantId: string): Promise<Result<UpgradeRecommendation | null>> {
    try {
      // Get tenant's current API version usage
      const result = await this.db.query(
        `SELECT api_version, COUNT(*) as request_count
         FROM api_request_logs
         WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '30 days'
         GROUP BY api_version
         ORDER BY request_count DESC
         LIMIT 1`,
        [tenantId]
      );

      if (result.rows.length === 0) {
        return { ok: true, value: null };
      }

      const usedVersion = result.rows[0].api_version;
      const versionInfo = this.versions.get(usedVersion);

      if (!versionInfo) {
        return { ok: true, value: null };
      }

      if (versionInfo.status === 'current') {
        return { ok: true, value: null };
      }

      const recommendation: UpgradeRecommendation = {
        currentVersion: usedVersion,
        recommendedVersion: config.currentApiVersion,
        urgency: versionInfo.status === 'deprecated' ? 'high' : 'medium',
        sunsetDate: versionInfo.sunsetDate,
        breakingChanges: this.getBreakingChanges(usedVersion, config.currentApiVersion),
        migrationGuideUrl: `${config.docsBaseUrl}/api/migration/${usedVersion}-to-${config.currentApiVersion}`,
      };

      return { ok: true, value: recommendation };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get breaking changes between versions
   */
  private getBreakingChanges(fromVersion: string, toVersion: string): string[] {
    const changes: string[] = [];
    const allVersions = Array.from(this.versions.values())
      .sort((a, b) => a.releaseDate.getTime() - b.releaseDate.getTime());

    let collecting = false;

    for (const v of allVersions) {
      if (v.version === fromVersion) {
        collecting = true;
        continue;
      }
      if (v.version === toVersion) {
        collecting = false;
      }
      if (collecting) {
        for (const entry of v.changelog) {
          if (entry.breaking) {
            changes.push(`[${v.version}] ${entry.description}`);
          }
        }
      }
    }

    return changes;
  }

  /**
   * Record API version usage
   */
  async recordVersionUsage(
    tenantId: string,
    version: string,
    endpoint: string,
    method: string
  ): Promise<Result<void>> {
    try {
      await this.db.query(
        `INSERT INTO api_request_logs (tenant_id, api_version, endpoint, method, created_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [tenantId, version, endpoint, method]
      );

      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }
}

interface VersionTransformer {
  transformRequest?: (body: Record<string, unknown>) => Record<string, unknown>;
  transformResponse?: (body: Record<string, unknown>) => Record<string, unknown>;
}

interface UpgradeRecommendation {
  currentVersion: string;
  recommendedVersion: string;
  urgency: 'low' | 'medium' | 'high' | 'critical';
  sunsetDate?: Date;
  breakingChanges: string[];
  migrationGuideUrl: string;
}
