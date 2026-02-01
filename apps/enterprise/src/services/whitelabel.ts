/**
 * White-Label Service
 * 
 * Custom branding and domain management for enterprise customers
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import { config } from '../config.js';

// Result type for error handling
type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export enum DomainVerificationStatus {
  PENDING = 'pending',
  VERIFIED = 'verified',
  FAILED = 'failed',
}

export enum DomainType {
  TRACKING = 'tracking',
  DASHBOARD = 'dashboard',
  EMAIL = 'email',
}

export interface WhiteLabelConfig {
  id: string;
  accountId: string;
  companyName: string;
  logoUrl?: string;
  faviconUrl?: string;
  primaryColor: string;
  secondaryColor: string;
  accentColor: string;
  emailFromName: string;
  supportEmail: string;
  supportUrl?: string;
  privacyPolicyUrl?: string;
  termsUrl?: string;
  footerHtml?: string;
  customCss?: string;
  domains: WhiteLabelDomain[];
  features: WhiteLabelFeatures;
  createdAt: Date;
  updatedAt: Date;
}

export interface WhiteLabelDomain {
  id: string;
  configId: string;
  domain: string;
  type: DomainType;
  verificationStatus: DomainVerificationStatus;
  verificationToken: string;
  verificationMethod: 'dns_txt' | 'dns_cname' | 'meta_tag';
  sslCertificateId?: string;
  verifiedAt?: Date;
  createdAt: Date;
}

export interface WhiteLabelFeatures {
  removeBranding: boolean;
  customEmailTemplates: boolean;
  customDashboard: boolean;
  customLoginPage: boolean;
  customUnsubscribePage: boolean;
  customErrorPages: boolean;
  customTrackingDomain: boolean;
}

export interface EmailTemplate {
  id: string;
  accountId: string;
  name: string;
  type: 'transactional' | 'marketing' | 'system';
  subject: string;
  htmlContent: string;
  textContent: string;
  variables: string[];
  isDefault: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface SSLCertificate {
  id: string;
  domainId: string;
  certificateArn?: string;
  status: 'pending' | 'issued' | 'failed' | 'expired';
  expiresAt?: Date;
  issuedAt?: Date;
  createdAt: Date;
}

/**
 * White-Label Service for enterprise branding
 */
export class WhiteLabelService {
  private pool: Pool;
  private redis: Redis;

  constructor(pool: Pool, redis: Redis) {
    this.pool = pool;
    this.redis = redis;
  }

  /**
   * Create or update white-label configuration
   */
  async upsertConfig(
    accountId: string,
    data: Partial<Omit<WhiteLabelConfig, 'id' | 'accountId' | 'domains' | 'createdAt' | 'updatedAt'>>
  ): Promise<Result<WhiteLabelConfig>> {
    try {
      const existing = await this.pool.query(`
        SELECT id FROM ent_whitelabel_configs WHERE account_id = $1
      `, [accountId]);

      let configId: string;

      if (existing.rows.length > 0) {
        configId = existing.rows[0].id;
        
        // Update existing
        await this.pool.query(`
          UPDATE ent_whitelabel_configs SET
            company_name = COALESCE($2, company_name),
            logo_url = COALESCE($3, logo_url),
            favicon_url = COALESCE($4, favicon_url),
            primary_color = COALESCE($5, primary_color),
            secondary_color = COALESCE($6, secondary_color),
            accent_color = COALESCE($7, accent_color),
            email_from_name = COALESCE($8, email_from_name),
            support_email = COALESCE($9, support_email),
            support_url = COALESCE($10, support_url),
            privacy_policy_url = COALESCE($11, privacy_policy_url),
            terms_url = COALESCE($12, terms_url),
            footer_html = COALESCE($13, footer_html),
            custom_css = COALESCE($14, custom_css),
            features = COALESCE($15, features),
            updated_at = NOW()
          WHERE id = $1
        `, [
          configId,
          data.companyName,
          data.logoUrl,
          data.faviconUrl,
          data.primaryColor,
          data.secondaryColor,
          data.accentColor,
          data.emailFromName,
          data.supportEmail,
          data.supportUrl,
          data.privacyPolicyUrl,
          data.termsUrl,
          data.footerHtml,
          data.customCss,
          data.features ? JSON.stringify(data.features) : null,
        ]);
      } else {
        configId = uuidv4();
        
        const defaultFeatures: WhiteLabelFeatures = {
          removeBranding: false,
          customEmailTemplates: true,
          customDashboard: false,
          customLoginPage: false,
          customUnsubscribePage: false,
          customErrorPages: false,
          customTrackingDomain: true,
          ...data.features,
        };

        await this.pool.query(`
          INSERT INTO ent_whitelabel_configs (
            id, account_id, company_name, logo_url, favicon_url,
            primary_color, secondary_color, accent_color,
            email_from_name, support_email, support_url,
            privacy_policy_url, terms_url, footer_html, custom_css,
            features, created_at, updated_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW(), NOW())
        `, [
          configId,
          accountId,
          data.companyName || 'Company',
          data.logoUrl,
          data.faviconUrl,
          data.primaryColor || '#0066cc',
          data.secondaryColor || '#f5f5f5',
          data.accentColor || '#ff6600',
          data.emailFromName || 'Team',
          data.supportEmail || 'support@example.com',
          data.supportUrl,
          data.privacyPolicyUrl,
          data.termsUrl,
          data.footerHtml,
          data.customCss,
          JSON.stringify(defaultFeatures),
        ]);
      }

      // Clear cache
      await this.redis.del(`whitelabel:config:${accountId}`);

      return this.getConfig(accountId);
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get white-label configuration
   */
  async getConfig(accountId: string): Promise<Result<WhiteLabelConfig>> {
    try {
      // Check cache
      const cached = await this.redis.get(`whitelabel:config:${accountId}`);
      if (cached) {
        return { ok: true, value: JSON.parse(cached) };
      }

      const result = await this.pool.query(`
        SELECT * FROM ent_whitelabel_configs WHERE account_id = $1
      `, [accountId]);

      if (result.rows.length === 0) {
        return { ok: false, error: new Error('White-label configuration not found') };
      }

      const row = result.rows[0];

      // Get domains
      const domainsResult = await this.pool.query(`
        SELECT * FROM ent_whitelabel_domains WHERE config_id = $1
      `, [row.id]);

      const config: WhiteLabelConfig = {
        id: row.id,
        accountId: row.account_id,
        companyName: row.company_name,
        logoUrl: row.logo_url,
        faviconUrl: row.favicon_url,
        primaryColor: row.primary_color,
        secondaryColor: row.secondary_color,
        accentColor: row.accent_color,
        emailFromName: row.email_from_name,
        supportEmail: row.support_email,
        supportUrl: row.support_url,
        privacyPolicyUrl: row.privacy_policy_url,
        termsUrl: row.terms_url,
        footerHtml: row.footer_html,
        customCss: row.custom_css,
        domains: domainsResult.rows.map(d => this.rowToDomain(d)),
        features: row.features,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      };

      // Cache for 5 minutes
      await this.redis.setex(`whitelabel:config:${accountId}`, 300, JSON.stringify(config));

      return { ok: true, value: config };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Add custom domain
   */
  async addDomain(
    configId: string,
    domain: string,
    type: DomainType,
    verificationMethod: 'dns_txt' | 'dns_cname' | 'meta_tag' = 'dns_txt'
  ): Promise<Result<WhiteLabelDomain>> {
    try {
      // Validate domain format
      const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
      if (!domainRegex.test(domain)) {
        return { ok: false, error: new Error('Invalid domain format') };
      }

      // Check if domain already exists
      const existing = await this.pool.query(`
        SELECT id FROM ent_whitelabel_domains WHERE domain = $1
      `, [domain.toLowerCase()]);

      if (existing.rows.length > 0) {
        return { ok: false, error: new Error('Domain already registered') };
      }

      const id = uuidv4();
      const verificationToken = crypto.randomBytes(32).toString('hex');

      await this.pool.query(`
        INSERT INTO ent_whitelabel_domains (
          id, config_id, domain, type, verification_status,
          verification_token, verification_method, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
      `, [
        id,
        configId,
        domain.toLowerCase(),
        type,
        DomainVerificationStatus.PENDING,
        verificationToken,
        verificationMethod,
      ]);

      const result = await this.pool.query(`
        SELECT * FROM ent_whitelabel_domains WHERE id = $1
      `, [id]);

      // Invalidate config cache
      await this.invalidateCacheByConfigId(configId);

      return { ok: true, value: this.rowToDomain(result.rows[0]) };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Verify domain
   */
  async verifyDomain(domainId: string): Promise<Result<{ verified: boolean; error?: string }>> {
    try {
      const result = await this.pool.query(`
        SELECT * FROM ent_whitelabel_domains WHERE id = $1
      `, [domainId]);

      if (result.rows.length === 0) {
        return { ok: false, error: new Error('Domain not found') };
      }

      const domainRecord = this.rowToDomain(result.rows[0]);
      let verified = false;
      let verificationError: string | undefined;

      if (domainRecord.verificationMethod === 'dns_txt') {
        // Check for TXT record
        const dns = require('dns').promises;
        try {
          const records = await dns.resolveTxt(domainRecord.domain);
          const flatRecords = records.flat();
          verified = flatRecords.some((r: string) => 
            r.includes(`apex-verification=${domainRecord.verificationToken}`)
          );
          if (!verified) {
            verificationError = 'TXT record not found or token mismatch';
          }
        } catch (e) {
          verificationError = 'Failed to resolve DNS TXT record';
        }
      } else if (domainRecord.verificationMethod === 'dns_cname') {
        // Check for CNAME record
        const dns = require('dns').promises;
        try {
          const records = await dns.resolveCname(domainRecord.domain);
          verified = records.some((r: string) => r.includes('apex-verify.'));
          if (!verified) {
            verificationError = 'CNAME record not found';
          }
        } catch (e) {
          verificationError = 'Failed to resolve DNS CNAME record';
        }
      }

      // Update verification status
      if (verified) {
        await this.pool.query(`
          UPDATE ent_whitelabel_domains SET
            verification_status = $2,
            verified_at = NOW()
          WHERE id = $1
        `, [domainId, DomainVerificationStatus.VERIFIED]);

        // Trigger SSL certificate provisioning
        await this.provisionSSLCertificate(domainId);
      } else {
        await this.pool.query(`
          UPDATE ent_whitelabel_domains SET
            verification_status = $2
          WHERE id = $1
        `, [domainId, DomainVerificationStatus.FAILED]);
      }

      // Invalidate cache
      await this.invalidateCacheByDomainId(domainId);

      return {
        ok: true,
        value: { verified, error: verificationError },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Remove domain
   */
  async removeDomain(domainId: string): Promise<Result<void>> {
    try {
      // Get config ID for cache invalidation
      const result = await this.pool.query(`
        SELECT config_id FROM ent_whitelabel_domains WHERE id = $1
      `, [domainId]);

      if (result.rows.length === 0) {
        return { ok: false, error: new Error('Domain not found') };
      }

      const configId = result.rows[0].config_id;

      await this.pool.query(`
        DELETE FROM ent_whitelabel_domains WHERE id = $1
      `, [domainId]);

      await this.invalidateCacheByConfigId(configId);

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get domain verification instructions
   */
  getVerificationInstructions(domain: WhiteLabelDomain): Record<string, string> {
    const instructions: Record<string, string> = {};

    if (domain.verificationMethod === 'dns_txt') {
      instructions.recordType = 'TXT';
      instructions.host = domain.domain;
      instructions.value = `apex-verification=${domain.verificationToken}`;
      instructions.instructions = `Add a TXT record to your DNS with the value above`;
    } else if (domain.verificationMethod === 'dns_cname') {
      instructions.recordType = 'CNAME';
      instructions.host = `_apex.${domain.domain}`;
      instructions.value = `apex-verify.apexmail.com`;
      instructions.instructions = `Add a CNAME record pointing _apex.${domain.domain} to apex-verify.apexmail.com`;
    } else if (domain.verificationMethod === 'meta_tag') {
      instructions.metaTag = `<meta name="apex-verification" content="${domain.verificationToken}">`;
      instructions.instructions = `Add the meta tag to the <head> section of your website's homepage`;
    }

    return instructions;
  }

  /**
   * Create or update email template
   */
  async upsertEmailTemplate(
    accountId: string,
    data: Omit<EmailTemplate, 'id' | 'accountId' | 'createdAt' | 'updatedAt'> & { id?: string }
  ): Promise<Result<EmailTemplate>> {
    try {
      const templateId = data.id || uuidv4();
      const variables = this.extractTemplateVariables(data.htmlContent);

      await this.pool.query(`
        INSERT INTO ent_email_templates (
          id, account_id, name, type, subject, html_content, text_content,
          variables, is_default, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
        ON CONFLICT (id) DO UPDATE SET
          name = EXCLUDED.name,
          type = EXCLUDED.type,
          subject = EXCLUDED.subject,
          html_content = EXCLUDED.html_content,
          text_content = EXCLUDED.text_content,
          variables = EXCLUDED.variables,
          is_default = EXCLUDED.is_default,
          updated_at = NOW()
      `, [
        templateId,
        accountId,
        data.name,
        data.type,
        data.subject,
        data.htmlContent,
        data.textContent,
        variables,
        data.isDefault || false,
      ]);

      return this.getEmailTemplate(templateId);
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get email template
   */
  async getEmailTemplate(id: string): Promise<Result<EmailTemplate>> {
    try {
      const result = await this.pool.query(`
        SELECT * FROM ent_email_templates WHERE id = $1
      `, [id]);

      if (result.rows.length === 0) {
        return { ok: false, error: new Error('Template not found') };
      }

      return { ok: true, value: this.rowToTemplate(result.rows[0]) };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * List email templates
   */
  async listEmailTemplates(accountId: string, type?: string): Promise<Result<EmailTemplate[]>> {
    try {
      let query = `SELECT * FROM ent_email_templates WHERE account_id = $1`;
      const params: any[] = [accountId];

      if (type) {
        query += ` AND type = $2`;
        params.push(type);
      }

      query += ` ORDER BY created_at DESC`;

      const result = await this.pool.query(query, params);

      return {
        ok: true,
        value: result.rows.map(row => this.rowToTemplate(row)),
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Render email template with variables
   */
  renderTemplate(template: EmailTemplate, variables: Record<string, string>): { subject: string; html: string; text: string } {
    let subject = template.subject;
    let html = template.htmlContent;
    let text = template.textContent;

    for (const [key, value] of Object.entries(variables)) {
      const regex = new RegExp(`{{\\s*${key}\\s*}}`, 'g');
      subject = subject.replace(regex, value);
      html = html.replace(regex, value);
      text = text.replace(regex, value);
    }

    return { subject, html, text };
  }

  /**
   * Generate dashboard CSS with custom colors
   */
  generateCustomCSS(config: WhiteLabelConfig): string {
    return `
:root {
  --apex-primary: ${config.primaryColor};
  --apex-secondary: ${config.secondaryColor};
  --apex-accent: ${config.accentColor};
}

.apex-header {
  background-color: var(--apex-primary);
}

.apex-sidebar {
  background-color: var(--apex-secondary);
}

.apex-button-primary {
  background-color: var(--apex-primary);
  color: white;
}

.apex-button-primary:hover {
  background-color: color-mix(in srgb, var(--apex-primary) 85%, black);
}

.apex-link {
  color: var(--apex-accent);
}

${config.customCss || ''}
`.trim();
  }

  /**
   * Get config by domain
   */
  async getConfigByDomain(domain: string): Promise<Result<WhiteLabelConfig | null>> {
    try {
      const cached = await this.redis.get(`whitelabel:domain:${domain}`);
      if (cached) {
        if (cached === 'null') return { ok: true, value: null };
        return { ok: true, value: JSON.parse(cached) };
      }

      const result = await this.pool.query(`
        SELECT c.* FROM ent_whitelabel_configs c
        JOIN ent_whitelabel_domains d ON c.id = d.config_id
        WHERE d.domain = $1 AND d.verification_status = 'verified'
      `, [domain.toLowerCase()]);

      if (result.rows.length === 0) {
        await this.redis.setex(`whitelabel:domain:${domain}`, 300, 'null');
        return { ok: true, value: null };
      }

      const accountId = result.rows[0].account_id;
      const configResult = await this.getConfig(accountId);

      if (configResult.ok) {
        await this.redis.setex(`whitelabel:domain:${domain}`, 300, JSON.stringify(configResult.value));
      }

      return configResult;
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Provision SSL certificate for domain
   */
  private async provisionSSLCertificate(domainId: string): Promise<Result<SSLCertificate>> {
    try {
      const domainResult = await this.pool.query(`
        SELECT * FROM ent_whitelabel_domains WHERE id = $1
      `, [domainId]);

      if (domainResult.rows.length === 0) {
        return { ok: false, error: new Error('Domain not found') };
      }

      const domain = domainResult.rows[0].domain;
      const certId = uuidv4();

      // In production, this would call AWS ACM or Let's Encrypt
      // For now, we create a pending certificate record

      await this.pool.query(`
        INSERT INTO ent_ssl_certificates (
          id, domain_id, status, created_at
        ) VALUES ($1, $2, 'pending', NOW())
      `, [certId, domainId]);

      // Update domain with certificate ID
      await this.pool.query(`
        UPDATE ent_whitelabel_domains SET ssl_certificate_id = $1 WHERE id = $2
      `, [certId, domainId]);

      return {
        ok: true,
        value: {
          id: certId,
          domainId,
          status: 'pending',
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

  private extractTemplateVariables(content: string): string[] {
    const regex = /{{\s*(\w+)\s*}}/g;
    const variables: Set<string> = new Set();
    let match;
    while ((match = regex.exec(content)) !== null) {
      variables.add(match[1]);
    }
    return Array.from(variables);
  }

  private async invalidateCacheByConfigId(configId: string): Promise<void> {
    const result = await this.pool.query(`
      SELECT account_id FROM ent_whitelabel_configs WHERE id = $1
    `, [configId]);
    if (result.rows.length > 0) {
      await this.redis.del(`whitelabel:config:${result.rows[0].account_id}`);
    }
  }

  private async invalidateCacheByDomainId(domainId: string): Promise<void> {
    const result = await this.pool.query(`
      SELECT c.account_id FROM ent_whitelabel_configs c
      JOIN ent_whitelabel_domains d ON c.id = d.config_id
      WHERE d.id = $1
    `, [domainId]);
    if (result.rows.length > 0) {
      await this.redis.del(`whitelabel:config:${result.rows[0].account_id}`);
    }
  }

  private rowToDomain(row: any): WhiteLabelDomain {
    return {
      id: row.id,
      configId: row.config_id,
      domain: row.domain,
      type: row.type as DomainType,
      verificationStatus: row.verification_status as DomainVerificationStatus,
      verificationToken: row.verification_token,
      verificationMethod: row.verification_method,
      sslCertificateId: row.ssl_certificate_id,
      verifiedAt: row.verified_at,
      createdAt: row.created_at,
    };
  }

  private rowToTemplate(row: any): EmailTemplate {
    return {
      id: row.id,
      accountId: row.account_id,
      name: row.name,
      type: row.type,
      subject: row.subject,
      htmlContent: row.html_content,
      textContent: row.text_content,
      variables: row.variables,
      isDefault: row.is_default,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
