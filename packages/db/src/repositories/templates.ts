/**
 * Templates Repository - Versioned templates with rollback support
 */

import { Result, parseJsonOrDefault } from '@apexmail/lib';
import { generateUuid } from '@apexmail/lib/id';
import type { DatabasePool } from '../pool.js';

export interface TemplateVersion {
  version: number;
  htmlContent: string | null;
  textContent: string | null;
  subject: string;
  variables: string[];
  createdAt: Date;
  createdBy: string | null;
  changelog: string | null;
}

export interface Template {
  id: string;
  tenantId: string;
  name: string;
  slug: string;
  description: string | null;
  category: string | null;
  currentVersion: number;
  htmlContent: string | null;
  textContent: string | null;
  subject: string;
  preheader: string | null;
  variables: string[];
  defaultData: Record<string, unknown>;
  engine: 'handlebars' | 'mjml' | 'liquid' | 'ejs';
  isActive: boolean;
  isDefault: boolean;
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
  publishedAt: Date | null;
}

export interface CreateTemplateInput {
  tenantId: string;
  name: string;
  slug?: string;
  description?: string;
  category?: string;
  htmlContent?: string;
  textContent?: string;
  subject: string;
  preheader?: string;
  variables?: string[];
  defaultData?: Record<string, unknown>;
  engine?: Template['engine'];
  metadata?: Record<string, unknown>;
  createdBy?: string;
}

export interface UpdateTemplateInput {
  name?: string;
  slug?: string;
  description?: string;
  category?: string;
  htmlContent?: string;
  textContent?: string;
  subject?: string;
  preheader?: string;
  variables?: string[];
  defaultData?: Record<string, unknown>;
  engine?: Template['engine'];
  isActive?: boolean;
  isDefault?: boolean;
  metadata?: Record<string, unknown>;
  updatedBy?: string;
  changelog?: string;
}

export class TemplatesRepository {
  constructor(private readonly db: DatabasePool) {}

  private generateSlug(name: string): string {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
  }

  /**
   * E-155: Validate template syntax before saving.
   * Catches malformed template expressions (e.g. unclosed Handlebars tags)
   * so broken templates cannot be persisted.
   */
  private validateTemplateSyntax(content: string, engine: Template['engine']): string | null {
    if (!content) return null;

    switch (engine) {
      case 'handlebars':
      case 'mjml': {
        // Check for balanced {{ and }} — unmatched openers/closers indicate broken syntax
        const opens = (content.match(/\{\{/g) || []).length;
        const closes = (content.match(/\}\}/g) || []).length;
        if (opens !== closes) {
          return `Unbalanced Handlebars tags: ${opens} opening vs ${closes} closing`;
        }
        // Check that block helpers (#if, #each, #unless, #with) have matching closing tags
        const blockOpeners = content.match(/\{\{#(\w+)/g) || [];
        const blockClosers = content.match(/\{\{\/(\w+)/g) || [];
        if (blockOpeners.length !== blockClosers.length) {
          return `Unbalanced Handlebars block helpers: ${blockOpeners.length} opening vs ${blockClosers.length} closing`;
        }
        // Verify each block opener has a matching closer
        const openerNames = blockOpeners.map(o => o.replace('{{#', ''));
        const closerNames = blockClosers.map(c => c.replace('{{/', ''));
        for (const name of openerNames) {
          const idx = closerNames.indexOf(name);
          if (idx === -1) {
            return `Missing closing tag for {{#${name}}}`;
          }
          closerNames.splice(idx, 1);
        }
        break;
      }
      case 'liquid': {
        // Check for balanced {% and %}
        const lqOpens = (content.match(/\{%/g) || []).length;
        const lqCloses = (content.match(/%\}/g) || []).length;
        if (lqOpens !== lqCloses) {
          return `Unbalanced Liquid tags: ${lqOpens} opening vs ${lqCloses} closing`;
        }
        // Check for balanced {{ and }}
        const lqVarOpens = (content.match(/\{\{/g) || []).length;
        const lqVarCloses = (content.match(/\}\}/g) || []).length;
        if (lqVarOpens !== lqVarCloses) {
          return `Unbalanced Liquid variable tags: ${lqVarOpens} opening vs ${lqVarCloses} closing`;
        }
        break;
      }
      case 'ejs': {
        // Check for balanced <% and %>
        const ejsOpens = (content.match(/<%/g) || []).length;
        const ejsCloses = (content.match(/%>/g) || []).length;
        if (ejsOpens !== ejsCloses) {
          return `Unbalanced EJS tags: ${ejsOpens} opening vs ${ejsCloses} closing`;
        }
        break;
      }
    }

    return null; // Valid
  }

  private extractVariables(content: string, engine: Template['engine']): string[] {
    const variables = new Set<string>();
    let match;

    switch (engine) {
      case 'handlebars': {
        // Match {{variable}} and {{#each variable}} etc.
        const handlebarsRegex = /\{\{(?:#[a-z]+\s+)?([a-zA-Z_][a-zA-Z0-9_.]*)/g;
        while ((match = handlebarsRegex.exec(content)) !== null) {
          const varPart = match[1]?.split('.')[0];
          if (varPart) variables.add(varPart);
        }
        break;
      }
      case 'mjml': {
        // MJML uses Handlebars by default
        const mjmlRegex = /\{\{(?:#[a-z]+\s+)?([a-zA-Z_][a-zA-Z0-9_.]*)/g;
        while ((match = mjmlRegex.exec(content)) !== null) {
          const varPart = match[1]?.split('.')[0];
          if (varPart) variables.add(varPart);
        }
        break;
      }
      case 'liquid': {
        // Match {{ variable }} and {% for item in variable %}
        const liquidRegex = /\{\{\s*([a-zA-Z_][a-zA-Z0-9_.]*)|{%\s*(?:for|if|unless)\s+\w+\s+in\s+([a-zA-Z_][a-zA-Z0-9_.]*)/g;
        while ((match = liquidRegex.exec(content)) !== null) {
          const varName = match[1] || match[2];
          if (varName) {
            const varPart = varName.split('.')[0];
            if (varPart) variables.add(varPart);
          }
        }
        break;
      }
      case 'ejs': {
        // Match <%= variable %> and <% variable %>
        const ejsRegex = /<%[=-]?\s*([a-zA-Z_][a-zA-Z0-9_.]*)/g;
        while ((match = ejsRegex.exec(content)) !== null) {
          const varPart = match[1]?.split('.')[0];
          if (varPart) variables.add(varPart);
        }
        break;
      }
    }

    return Array.from(variables).sort();
  }

  async create(input: CreateTemplateInput): Promise<Result<Template, Error>> {
    const id = generateUuid();
    const slug = input.slug || this.generateSlug(input.name);
    const engine = input.engine ?? 'handlebars';
    const now = new Date();

    // E-155: Validate template syntax before saving
    const htmlError = input.htmlContent ? this.validateTemplateSyntax(input.htmlContent, engine) : null;
    const textError = input.textContent ? this.validateTemplateSyntax(input.textContent, engine) : null;
    const subjectError = this.validateTemplateSyntax(input.subject, engine);
    const syntaxError = htmlError || textError || subjectError;
    if (syntaxError) {
      return Result.err(new Error(`Template syntax error: ${syntaxError}`));
    }

    // Auto-extract variables from content
    const contentToScan = (input.htmlContent || '') + (input.textContent || '') + input.subject;
    const extractedVariables = this.extractVariables(contentToScan, engine);
    const variables = input.variables ?? extractedVariables;

    // B-047: Wrap template insert + version record in a transaction so a crash
    // between the two operations cannot leave a template without an initial version.
    const client = await this.db.getPool().connect();
    try {
      await client.query('BEGIN');

      // F-187: ON CONFLICT prevents duplicate template names within a tenant.
      // If a template with the same (tenant_id, name) already exists the INSERT
      // returns no rows and we report the conflict below.
      const result = await client.query(
        `INSERT INTO templates (
          id, tenant_id, name, slug, description, category, current_version,
          html_content, text_content, subject, preheader, variables,
          default_data, engine, is_active, is_default, metadata,
          created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
        ON CONFLICT (tenant_id, name) DO NOTHING
        RETURNING *`,
        [
          id,
          input.tenantId,
          input.name,
          slug,
          input.description ?? null,
          input.category ?? null,
          1,
          input.htmlContent ?? null,
          input.textContent ?? null,
          input.subject,
          input.preheader ?? null,
          variables,
          JSON.stringify(input.defaultData ?? {}),
          engine,
          true,
          false,
          JSON.stringify(input.metadata ?? {}),
          now,
          now,
        ]
      );

      const row = result.rows[0];
      if (!row) {
        await client.query('ROLLBACK');
        // F-187: No row returned means ON CONFLICT (tenant_id, name) fired
        return Result.err(new Error(`Template name "${input.name}" already exists for this tenant`));
      }

      // Create initial version record (inside same transaction)
      await client.query(
        `INSERT INTO template_versions (
          id, template_id, version, html_content, text_content,
          subject, variables, created_at, created_by, changelog
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          generateUuid(),
          id,
          1,
          input.htmlContent ?? null,
          input.textContent ?? null,
          input.subject,
          variables,
          now,
          input.createdBy ?? null,
          'Initial version',
        ]
      );

      await client.query('COMMIT');
      return Result.ok(this.mapRow(row));
    } catch (error) {
      await client.query('ROLLBACK');
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    } finally {
      client.release();
    }
  }

  async findById(id: string, tenantId?: string): Promise<Result<Template | null, Error>> {
    // SECURITY: When tenantId provided, filter in query for tenant isolation
    const query = tenantId
      ? 'SELECT * FROM templates WHERE id = $1 AND tenant_id = $2'
      : 'SELECT * FROM templates WHERE id = $1';
    const params = tenantId ? [id, tenantId] : [id];
    
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      name: string;
      slug: string;
      description: string | null;
      category: string | null;
      current_version: number;
      html_content: string | null;
      text_content: string | null;
      subject: string;
      preheader: string | null;
      variables: string[];
      default_data: string;
      engine: Template['engine'];
      is_active: boolean;
      is_default: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
      published_at: Date | null;
    }>(
      query,
      params
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async findBySlug(slug: string, tenantId: string): Promise<Result<Template | null, Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      name: string;
      slug: string;
      description: string | null;
      category: string | null;
      current_version: number;
      html_content: string | null;
      text_content: string | null;
      subject: string;
      preheader: string | null;
      variables: string[];
      default_data: string;
      engine: Template['engine'];
      is_active: boolean;
      is_default: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
      published_at: Date | null;
    }>(
      'SELECT * FROM templates WHERE slug = $1 AND tenant_id = $2',
      [slug, tenantId]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async update(
    id: string,
    input: UpdateTemplateInput,
    createNewVersion = true
  ): Promise<Result<Template, Error>> {
    // Get current template to determine version
    const current = await this.findById(id);
    if (!current.ok) return current;
    if (!current.value) return Result.err(new Error('Template not found'));

    // E-155: Validate template syntax before saving updates
    const engine = input.engine ?? current.value.engine;
    if (input.htmlContent !== undefined) {
      const htmlErr = this.validateTemplateSyntax(input.htmlContent, engine);
      if (htmlErr) return Result.err(new Error(`Template syntax error: ${htmlErr}`));
    }
    if (input.textContent !== undefined) {
      const textErr = this.validateTemplateSyntax(input.textContent, engine);
      if (textErr) return Result.err(new Error(`Template syntax error: ${textErr}`));
    }
    if (input.subject !== undefined) {
      const subjectErr = this.validateTemplateSyntax(input.subject, engine);
      if (subjectErr) return Result.err(new Error(`Template syntax error: ${subjectErr}`));
    }

    const updates: string[] = [];
    const values: unknown[] = [];
    let paramIndex = 1;

    const newVersion = createNewVersion && (input.htmlContent !== undefined || input.textContent !== undefined || input.subject !== undefined)
      ? current.value.currentVersion + 1
      : current.value.currentVersion;

    if (input.name !== undefined) {
      updates.push(`name = $${paramIndex++}`);
      values.push(input.name);
    }
    if (input.slug !== undefined) {
      updates.push(`slug = $${paramIndex++}`);
      values.push(input.slug);
    }
    if (input.description !== undefined) {
      updates.push(`description = $${paramIndex++}`);
      values.push(input.description);
    }
    if (input.category !== undefined) {
      updates.push(`category = $${paramIndex++}`);
      values.push(input.category);
    }
    if (input.htmlContent !== undefined) {
      updates.push(`html_content = $${paramIndex++}`);
      values.push(input.htmlContent);
    }
    if (input.textContent !== undefined) {
      updates.push(`text_content = $${paramIndex++}`);
      values.push(input.textContent);
    }
    if (input.subject !== undefined) {
      updates.push(`subject = $${paramIndex++}`);
      values.push(input.subject);
    }
    if (input.preheader !== undefined) {
      updates.push(`preheader = $${paramIndex++}`);
      values.push(input.preheader);
    }
    if (input.engine !== undefined) {
      updates.push(`engine = $${paramIndex++}`);
      values.push(input.engine);
    }
    if (input.isActive !== undefined) {
      updates.push(`is_active = $${paramIndex++}`);
      values.push(input.isActive);
    }
    if (input.isDefault !== undefined) {
      updates.push(`is_default = $${paramIndex++}`);
      values.push(input.isDefault);
    }
    if (input.defaultData !== undefined) {
      updates.push(`default_data = $${paramIndex++}::jsonb`);
      values.push(JSON.stringify(input.defaultData));
    }
    if (input.metadata !== undefined) {
      updates.push(`metadata = metadata || $${paramIndex++}::jsonb`);
      values.push(JSON.stringify(input.metadata));
    }

    // Update variables if content changed
    const htmlContent = input.htmlContent ?? current.value.htmlContent ?? '';
    const textContent = input.textContent ?? current.value.textContent ?? '';
    const subject = input.subject ?? current.value.subject;
    
    if (input.variables !== undefined) {
      updates.push(`variables = $${paramIndex++}`);
      values.push(input.variables);
    } else if (input.htmlContent !== undefined || input.textContent !== undefined || input.subject !== undefined) {
      const extractedVariables = this.extractVariables(htmlContent + textContent + subject, engine);
      updates.push(`variables = $${paramIndex++}`);
      values.push(extractedVariables);
    }

    // Update version if content changed
    if (newVersion !== current.value.currentVersion) {
      updates.push(`current_version = $${paramIndex++}`);
      values.push(newVersion);
    }

    updates.push(`updated_at = $${paramIndex++}`);
    values.push(new Date());

    values.push(id);

    // B-032: Wrap template update + version record in a transaction
    // Previously these were two separate operations; a crash between them
    // would leave the template at a new version with no version record.
    const client = await this.db.getPool().connect();
    try {
      await client.query('BEGIN');

      const result = await client.query(
        `UPDATE templates SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
        values
      );

      const row = result.rows[0];
      if (!row) {
        await client.query('ROLLBACK');
        return Result.err(new Error('Template not found'));
      }

      // Create version record if version changed (inside same transaction)
      if (newVersion !== current.value.currentVersion) {
        await client.query(
          `INSERT INTO template_versions (id, template_id, version, html_content, text_content, subject, variables, created_by, changelog, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())`,
          [
            generateUuid(),
            id,
            newVersion,
            input.htmlContent ?? current.value.htmlContent,
            input.textContent ?? current.value.textContent,
            input.subject ?? current.value.subject,
            row.variables,
            input.updatedBy ?? null,
            input.changelog ?? null,
          ]
        );
      }

      await client.query('COMMIT');
      return Result.ok(this.mapRow(row));
    } catch (err) {
      await client.query('ROLLBACK');
      return Result.err(err instanceof Error ? err : new Error(String(err)));
    } finally {
      client.release();
    }
  }

  async publish(id: string, tenantId?: string): Promise<Result<Template, Error>> {
    const sql = tenantId
      ? `UPDATE templates SET published_at = NOW(), updated_at = NOW() WHERE id = $1 AND tenant_id = $2 RETURNING *`
      : `UPDATE templates SET published_at = NOW(), updated_at = NOW() WHERE id = $1 RETURNING *`;
    const params = tenantId ? [id, tenantId] : [id];
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      name: string;
      slug: string;
      description: string | null;
      category: string | null;
      current_version: number;
      html_content: string | null;
      text_content: string | null;
      subject: string;
      preheader: string | null;
      variables: string[];
      default_data: string;
      engine: Template['engine'];
      is_active: boolean;
      is_default: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
      published_at: Date | null;
    }>(
      sql,
      params
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('Template not found'));
    }

    return Result.ok(this.mapRow(row));
  }

  /**
   * F-228: Template version immutability guard.
   * Once a version record is created it MUST NOT be modified. This method
   * explicitly rejects any attempt to update an existing version row,
   * enforcing append-only semantics for the version history.
   */
  async updateVersion(
    _templateId: string,
    _version: number,
    _input: Partial<TemplateVersion>,
  ): Promise<Result<never, Error>> {
    return Result.err(
      new Error(
        'F-228: Template versions are immutable. Create a new version by updating the template instead.'
      )
    );
  }

  async getVersion(templateId: string, version: number): Promise<Result<TemplateVersion | null, Error>> {
    const result = await this.db.query<{
      version: number;
      html_content: string | null;
      text_content: string | null;
      subject: string;
      variables: string[];
      created_at: Date;
      created_by: string | null;
      changelog: string | null;
    }>(
      `SELECT version, html_content, text_content, subject, variables, created_at, created_by, changelog
       FROM template_versions
       WHERE template_id = $1 AND version = $2`,
      [templateId, version]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) return Result.ok(null);

    return Result.ok({
      version: row.version,
      htmlContent: row.html_content,
      textContent: row.text_content,
      subject: row.subject,
      variables: row.variables,
      createdAt: row.created_at,
      createdBy: row.created_by,
      changelog: row.changelog,
    });
  }

  /**
   * C-079: Paginated version listing.
   * Default limit = 20, max = 100. Prevents unbounded result sets for
   * templates with many versions.
   */
  async listVersions(
    templateId: string,
    // FIX-500-053: Add tenantId to scope queries to the owning tenant
    tenantId?: string,
    options: { limit?: number; offset?: number } = {}
  ): Promise<Result<{ versions: TemplateVersion[]; total: number }, Error>> {
    const limit = Math.max(1, Math.min(options.limit ?? 20, 100));
    const offset = Math.max(0, options.offset ?? 0);

    // FIX-500-053: Join with templates table to enforce tenant_id scoping
    const countSql = tenantId
      ? `SELECT COUNT(*) as count FROM template_versions tv JOIN templates t ON tv.template_id = t.id WHERE tv.template_id = $1 AND t.tenant_id = $2`
      : `SELECT COUNT(*) as count FROM template_versions WHERE template_id = $1`;
    const countParams = tenantId ? [templateId, tenantId] : [templateId];
    const countResult = await this.db.query<{ count: string }>(countSql, countParams);

    if (!countResult.ok) return countResult;

    const total = parseInt(countResult.value.rows[0]?.count ?? '0', 10);

    const result = await this.db.query<{
      version: number;
      html_content: string | null;
      text_content: string | null;
      subject: string;
      variables: string[];
      created_at: Date;
      created_by: string | null;
      changelog: string | null;
    }>(
      `SELECT version, html_content, text_content, subject, variables, created_at, created_by, changelog
       FROM template_versions tv
       ${tenantId ? 'JOIN templates t ON tv.template_id = t.id' : ''}
       WHERE tv.template_id = $1
       ${tenantId ? 'AND t.tenant_id = $2' : ''}
       ORDER BY version DESC
       LIMIT $${tenantId ? 3 : 2} OFFSET $${tenantId ? 4 : 3}`,
      tenantId ? [templateId, tenantId, limit, offset] : [templateId, limit, offset]
    );

    if (!result.ok) return result;

    return Result.ok({
      versions: result.value.rows.map((row) => ({
        version: row.version,
        htmlContent: row.html_content,
        textContent: row.text_content,
        subject: row.subject,
        variables: row.variables,
        createdAt: row.created_at,
        createdBy: row.created_by,
        changelog: row.changelog,
      })),
      total,
    });
  }

  async rollback(templateId: string, version: number, tenantId?: string): Promise<Result<Template, Error>> {
    // A-009: Verify template belongs to tenant before rollback
    if (tenantId) {
      const template = await this.findById(templateId, tenantId);
      if (!template.ok) return template;
      if (!template.value) {
        return Result.err(new Error('Template not found'));
      }
    }

    const versionData = await this.getVersion(templateId, version);
    if (!versionData.ok) return versionData;
    if (!versionData.value) {
      return Result.err(new Error(`Version ${version} not found`));
    }

    return this.update(templateId, {
      htmlContent: versionData.value.htmlContent ?? undefined,
      textContent: versionData.value.textContent ?? undefined,
      subject: versionData.value.subject,
      variables: versionData.value.variables,
      changelog: `Rolled back to version ${version}`,
    });
  }

  /**
   * A-008 + B-031: Delete template with tenant_id isolation and transaction safety.
   * Deletes versions and template atomically within a transaction.
   */
  async delete(id: string, tenantId?: string): Promise<Result<void, Error>> {
    let client;
    try {
      client = await this.db.getClient();
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }

    try {
      await client.query('BEGIN');

      await client.query('DELETE FROM template_versions WHERE template_id = $1', [id]);

      const sql = tenantId
        ? 'DELETE FROM templates WHERE id = $1 AND tenant_id = $2'
        : 'DELETE FROM templates WHERE id = $1';
      const params = tenantId ? [id, tenantId] : [id];
      await client.query(sql, params);

      await client.query('COMMIT');
      return Result.ok(undefined);
    } catch (error) {
      await client.query('ROLLBACK');
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    } finally {
      client.release();
    }
  }

  async listByTenant(
    tenantId: string,
    options: {
      category?: string;
      isActive?: boolean;
      search?: string;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<Result<{ templates: Template[]; total: number }, Error>> {
    const conditions = ['tenant_id = $1'];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (options.category) {
      conditions.push(`category = $${paramIndex++}`);
      values.push(options.category);
    }
    if (options.isActive !== undefined) {
      conditions.push(`is_active = $${paramIndex++}`);
      values.push(options.isActive);
    }
    if (options.search) {
      // A-021: Escape ILIKE wildcards in user input to prevent injection
      const escaped = options.search.replace(/[%_\\]/g, '\\$&');
      // C-083: ILIKE without a trigram index can be slow on large tables.
      // For production, consider adding a pg_trgm GIN index:
      //   CREATE INDEX idx_templates_name_trgm ON templates USING gin (name gin_trgm_ops);
      //   CREATE INDEX idx_templates_description_trgm ON templates USING gin (description gin_trgm_ops);
      // Requires: CREATE EXTENSION IF NOT EXISTS pg_trgm;
      conditions.push(`(name ILIKE $${paramIndex} OR slug ILIKE $${paramIndex} OR description ILIKE $${paramIndex})`);
      values.push(`%${escaped}%`);
      paramIndex++;
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    const countResult = await this.db.query<{ count: string }>(
      `SELECT COUNT(*) as count FROM templates ${whereClause}`,
      values
    );

    if (!countResult.ok) return countResult;

    const limit = options.limit ?? 50;
    const offset = options.offset ?? 0;
    values.push(limit, offset);

    /**
     * C-136: Template list query optimization.
     * Exclude large columns (html_content, text_content) from list queries.
     * These columns can be very large (full HTML email templates) and are
     * not needed for list views — they are fetched on-demand via findById.
     */
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      name: string;
      slug: string;
      description: string | null;
      category: string | null;
      current_version: number;
      subject: string;
      preheader: string | null;
      variables: string[];
      default_data: string;
      engine: Template['engine'];
      is_active: boolean;
      is_default: boolean;
      metadata: string;
      created_at: Date;
      updated_at: Date;
      published_at: Date | null;
    }>(
      `SELECT id, tenant_id, name, slug, description, category, current_version,
              subject, preheader, variables, default_data, engine,
              is_active, is_default, metadata, created_at, updated_at, published_at
       FROM templates ${whereClause}
       ORDER BY updated_at DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
      values
    );

    if (!result.ok) return result;

    return Result.ok({
      templates: result.value.rows.map((row) => this.mapRow({ ...row, html_content: null, text_content: null })),
      total: parseInt(countResult.value.rows[0]?.count ?? '0', 10),
    });
  }

  async duplicate(id: string, newName: string): Promise<Result<Template, Error>> {
    const original = await this.findById(id);
    if (!original.ok) return original;
    if (!original.value) return Result.err(new Error('Template not found'));

    return this.create({
      tenantId: original.value.tenantId,
      name: newName,
      description: original.value.description ?? undefined,
      category: original.value.category ?? undefined,
      htmlContent: original.value.htmlContent ?? undefined,
      textContent: original.value.textContent ?? undefined,
      subject: original.value.subject,
      preheader: original.value.preheader ?? undefined,
      variables: original.value.variables,
      defaultData: original.value.defaultData,
      engine: original.value.engine,
      metadata: { duplicatedFrom: id },
    });
  }

  private mapRow(row: {
    id: string;
    tenant_id: string;
    name: string;
    slug: string;
    description: string | null;
    category: string | null;
    current_version: number;
    html_content: string | null;
    text_content: string | null;
    subject: string;
    preheader: string | null;
    variables: string[];
    default_data: string;
    engine: Template['engine'];
    is_active: boolean;
    is_default: boolean;
    metadata: string;
    created_at: Date;
    updated_at: Date;
    published_at: Date | null;
  }): Template {
    return {
      id: row.id,
      tenantId: row.tenant_id,
      name: row.name,
      slug: row.slug,
      description: row.description,
      category: row.category,
      currentVersion: row.current_version,
      htmlContent: row.html_content,
      textContent: row.text_content,
      subject: row.subject,
      preheader: row.preheader,
      variables: row.variables,
      defaultData: typeof row.default_data === 'string'
        ? parseJsonOrDefault<Record<string, unknown>>(row.default_data, {})
        : row.default_data as unknown as Record<string, unknown>,
      engine: row.engine,
      isActive: row.is_active,
      isDefault: row.is_default,
      metadata: typeof row.metadata === 'string'
        ? parseJsonOrDefault<Record<string, unknown>>(row.metadata, {})
        : row.metadata as unknown as Record<string, unknown>,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      publishedAt: row.published_at,
    };
  }
}
