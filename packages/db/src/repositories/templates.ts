/**
 * Templates Repository - Versioned templates with rollback support
 */

import { Result } from '@apexmail/lib';
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

  private extractVariables(content: string, engine: Template['engine']): string[] {
    const variables = new Set<string>();

    switch (engine) {
      case 'handlebars':
        // Match {{variable}} and {{#each variable}} etc.
        const handlebarsRegex = /\{\{(?:#[a-z]+\s+)?([a-zA-Z_][a-zA-Z0-9_.]*)/g;
        let match;
        while ((match = handlebarsRegex.exec(content)) !== null) {
          variables.add(match[1].split('.')[0]);
        }
        break;
      case 'mjml':
        // MJML uses Handlebars by default
        const mjmlRegex = /\{\{(?:#[a-z]+\s+)?([a-zA-Z_][a-zA-Z0-9_.]*)/g;
        while ((match = mjmlRegex.exec(content)) !== null) {
          variables.add(match[1].split('.')[0]);
        }
        break;
      case 'liquid':
        // Match {{ variable }} and {% for item in variable %}
        const liquidRegex = /\{\{\s*([a-zA-Z_][a-zA-Z0-9_.]*)|{%\s*(?:for|if|unless)\s+\w+\s+in\s+([a-zA-Z_][a-zA-Z0-9_.]*)/g;
        while ((match = liquidRegex.exec(content)) !== null) {
          const varName = match[1] || match[2];
          if (varName) {
            variables.add(varName.split('.')[0]);
          }
        }
        break;
      case 'ejs':
        // Match <%= variable %> and <% variable %>
        const ejsRegex = /<%[=-]?\s*([a-zA-Z_][a-zA-Z0-9_.]*)/g;
        while ((match = ejsRegex.exec(content)) !== null) {
          variables.add(match[1].split('.')[0]);
        }
        break;
    }

    return Array.from(variables).sort();
  }

  async create(input: CreateTemplateInput): Promise<Result<Template, Error>> {
    const id = generateUuid();
    const slug = input.slug || this.generateSlug(input.name);
    const engine = input.engine ?? 'handlebars';
    const now = new Date();

    // Auto-extract variables from content
    const contentToScan = (input.htmlContent || '') + (input.textContent || '') + input.subject;
    const extractedVariables = this.extractVariables(contentToScan, engine);
    const variables = input.variables ?? extractedVariables;

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
      `INSERT INTO templates (
        id, tenant_id, name, slug, description, category, current_version,
        html_content, text_content, subject, preheader, variables,
        default_data, engine, is_active, is_default, metadata,
        created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
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

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('Failed to create template'));
    }

    // Create initial version record
    await this.createVersionRecord(id, {
      version: 1,
      htmlContent: input.htmlContent ?? null,
      textContent: input.textContent ?? null,
      subject: input.subject,
      variables,
      createdBy: input.createdBy ?? null,
      changelog: 'Initial version',
    });

    return Result.ok(this.mapRow(row));
  }

  private async createVersionRecord(
    templateId: string,
    version: {
      version: number;
      htmlContent: string | null;
      textContent: string | null;
      subject: string;
      variables: string[];
      createdBy: string | null;
      changelog: string | null;
    }
  ): Promise<Result<void, Error>> {
    const result = await this.db.query(
      `INSERT INTO template_versions (
        id, template_id, version, html_content, text_content,
        subject, variables, created_at, created_by, changelog
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        generateUuid(),
        templateId,
        version.version,
        version.htmlContent,
        version.textContent,
        version.subject,
        version.variables,
        new Date(),
        version.createdBy,
        version.changelog,
      ]
    );

    return result.ok ? Result.ok(undefined) : result;
  }

  async findById(id: string): Promise<Result<Template | null, Error>> {
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
      'SELECT * FROM templates WHERE id = $1',
      [id]
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
    const engine = input.engine ?? current.value.engine;
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
      `UPDATE templates SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
      values
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('Template not found'));
    }

    // Create version record if version changed
    if (newVersion !== current.value.currentVersion) {
      await this.createVersionRecord(id, {
        version: newVersion,
        htmlContent: input.htmlContent ?? current.value.htmlContent,
        textContent: input.textContent ?? current.value.textContent,
        subject: input.subject ?? current.value.subject,
        variables: row.variables,
        createdBy: input.updatedBy ?? null,
        changelog: input.changelog ?? null,
      });
    }

    return Result.ok(this.mapRow(row));
  }

  async publish(id: string): Promise<Result<Template, Error>> {
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
      `UPDATE templates SET published_at = NOW(), updated_at = NOW() WHERE id = $1 RETURNING *`,
      [id]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('Template not found'));
    }

    return Result.ok(this.mapRow(row));
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

  async listVersions(templateId: string): Promise<Result<TemplateVersion[], Error>> {
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
       WHERE template_id = $1
       ORDER BY version DESC`,
      [templateId]
    );

    if (!result.ok) return result;

    return Result.ok(
      result.value.rows.map((row) => ({
        version: row.version,
        htmlContent: row.html_content,
        textContent: row.text_content,
        subject: row.subject,
        variables: row.variables,
        createdAt: row.created_at,
        createdBy: row.created_by,
        changelog: row.changelog,
      }))
    );
  }

  async rollback(templateId: string, version: number): Promise<Result<Template, Error>> {
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

  async delete(id: string): Promise<Result<void, Error>> {
    // Delete versions first
    await this.db.query('DELETE FROM template_versions WHERE template_id = $1', [id]);
    
    const result = await this.db.query('DELETE FROM templates WHERE id = $1', [id]);
    return result.ok ? Result.ok(undefined) : result;
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
      conditions.push(`(name ILIKE $${paramIndex} OR slug ILIKE $${paramIndex} OR description ILIKE $${paramIndex})`);
      values.push(`%${options.search}%`);
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
      `SELECT * FROM templates ${whereClause}
       ORDER BY updated_at DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
      values
    );

    if (!result.ok) return result;

    return Result.ok({
      templates: result.value.rows.map((row) => this.mapRow(row)),
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
        ? JSON.parse(row.default_data) as Record<string, unknown>
        : row.default_data as unknown as Record<string, unknown>,
      engine: row.engine,
      isActive: row.is_active,
      isDefault: row.is_default,
      metadata: typeof row.metadata === 'string'
        ? JSON.parse(row.metadata) as Record<string, unknown>
        : row.metadata as unknown as Record<string, unknown>,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      publishedAt: row.published_at,
    };
  }
}
