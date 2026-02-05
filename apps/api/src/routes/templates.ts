/**
 * Templates Routes - Email template management
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv, AppContext } from '../app.js';
import { TemplatesRepository, AuditLogsRepository } from '@apexmail/db';
import { ApiError } from '../middleware/error-handler.js';
import { requireScopes } from '../middleware/auth.js';

const createTemplateSchema = z.object({
  name: z.string().min(1).max(100),
  slug: z.string().min(1).max(100).regex(/^[a-z0-9-]+$/).optional(),
  description: z.string().max(500).optional(),
  category: z.string().max(50).optional(),
  subject: z.string().min(1).max(998),
  html: z.string().max(10_000_000).optional(),
  text: z.string().max(1_000_000).optional(),
  preheader: z.string().max(200).optional(),
  engine: z.enum(['handlebars', 'mjml', 'liquid', 'ejs']).default('handlebars'),
  defaultData: z.record(z.unknown()).optional(),
  metadata: z.record(z.unknown()).optional(),
});

const updateTemplateSchema = createTemplateSchema.partial().extend({
  changelog: z.string().max(500).optional(),
});

const renderTemplateSchema = z.object({
  data: z.record(z.unknown()),
});

export function templatesRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const templatesRepo = new TemplatesRepository(ctx.db);
  const auditRepo = new AuditLogsRepository(ctx.db);

  // Create template
  router.post('/', requireScopes('templates:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const logger = c.get('logger');

    const body = await c.req.json();
    const input = createTemplateSchema.parse(body);

    // RACE-001 FIX: Removed pre-check for duplicate slug - rely on database 
    // unique constraint to prevent race conditions (TOCTOU vulnerability).
    // The constraint UNIQUE(tenant_id, slug, version) ensures atomicity.

    const result = await templatesRepo.create({
      tenantId,
      name: input.name,
      slug: input.slug,
      description: input.description,
      category: input.category,
      subject: input.subject,
      htmlContent: input.html,
      textContent: input.text,
      preheader: input.preheader,
      engine: input.engine,
      defaultData: input.defaultData,
      metadata: input.metadata,
      createdBy: userId ?? undefined,
    });

    if (!result.ok) {
      // Check for unique constraint violation (duplicate slug)
      const errorMessage = result.error.message || '';
      if (errorMessage.includes('unique') || errorMessage.includes('duplicate') || 
          errorMessage.includes('23505') || errorMessage.includes('UNIQUE constraint')) {
        throw ApiError.conflict(`Template with slug '${input.slug || input.name}' already exists`, 'SLUG_EXISTS');
      }
      logger.error('Failed to create template', { error: result.error });
      throw ApiError.internal('Failed to create template');
    }

    const template = result.value;

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'template.created',
      resourceType: 'template',
      resourceId: template.id,
      metadata: { name: input.name, slug: template.slug },
    });

    logger.info('Template created', { templateId: template.id, name: input.name });

    return c.json({
      template: {
        id: template.id,
        name: template.name,
        slug: template.slug,
        description: template.description,
        category: template.category,
        subject: template.subject,
        engine: template.engine,
        variables: template.variables,
        currentVersion: template.currentVersion,
        createdAt: template.createdAt,
      },
    }, 201);
  });

  // Get template by ID
  router.get('/:id', requireScopes('templates:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const templateId = c.req.param('id');

    // SECURITY: Filter by tenant_id in query to prevent fetch-before-check vulnerability
    const result = await templatesRepo.findById(templateId, tenantId);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to fetch template');
    }

    if (!result.value) {
      throw ApiError.notFound('Template');
    }

    const template = result.value;

    return c.json({
      template: {
        id: template.id,
        name: template.name,
        slug: template.slug,
        description: template.description,
        category: template.category,
        subject: template.subject,
        html: template.htmlContent,
        text: template.textContent,
        preheader: template.preheader,
        engine: template.engine,
        variables: template.variables,
        defaultData: template.defaultData,
        currentVersion: template.currentVersion,
        isActive: template.isActive,
        publishedAt: template.publishedAt,
        createdAt: template.createdAt,
        updatedAt: template.updatedAt,
      },
    });
  });

  // Get template by slug
  router.get('/slug/:slug', requireScopes('templates:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const slug = c.req.param('slug');

    const result = await templatesRepo.findBySlug(slug, tenantId);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to fetch template');
    }

    if (!result.value) {
      throw ApiError.notFound('Template');
    }

    const template = result.value;

    return c.json({
      template: {
        id: template.id,
        name: template.name,
        slug: template.slug,
        description: template.description,
        category: template.category,
        subject: template.subject,
        html: template.htmlContent,
        text: template.textContent,
        preheader: template.preheader,
        engine: template.engine,
        variables: template.variables,
        defaultData: template.defaultData,
        currentVersion: template.currentVersion,
        isActive: template.isActive,
        publishedAt: template.publishedAt,
        createdAt: template.createdAt,
        updatedAt: template.updatedAt,
      },
    });
  });

  // List templates
  router.get('/', requireScopes('templates:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const category = c.req.query('category');
    const isActive = c.req.query('active');
    const search = c.req.query('search');
    const limit = parseInt(c.req.query('limit') ?? '50', 10);
    const offset = parseInt(c.req.query('offset') ?? '0', 10);

    const result = await templatesRepo.listByTenant(tenantId, {
      category,
      isActive: isActive !== undefined ? isActive === 'true' : undefined,
      search,
      limit: Math.min(limit, 100),
      offset,
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch templates');
    }

    return c.json({
      templates: result.value.templates.map((t) => ({
        id: t.id,
        name: t.name,
        slug: t.slug,
        description: t.description,
        category: t.category,
        subject: t.subject,
        engine: t.engine,
        variables: t.variables,
        currentVersion: t.currentVersion,
        isActive: t.isActive,
        publishedAt: t.publishedAt,
        createdAt: t.createdAt,
        updatedAt: t.updatedAt,
      })),
      pagination: {
        total: result.value.total,
        limit,
        offset,
        hasMore: offset + result.value.templates.length < result.value.total,
      },
    });
  });

  // Update template
  router.patch('/:id', requireScopes('templates:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const templateId = c.req.param('id');
    const logger = c.get('logger');

    // Verify ownership
    const existing = await templatesRepo.findById(templateId);
    if (!existing.ok || !existing.value || existing.value.tenantId !== tenantId) {
      throw ApiError.notFound('Template');
    }

    const body = await c.req.json();
    const input = updateTemplateSchema.parse(body);

    // Check for duplicate slug if changing
    if (input.slug && input.slug !== existing.value.slug) {
      const slugExists = await templatesRepo.findBySlug(input.slug, tenantId);
      if (slugExists.ok && slugExists.value) {
        throw ApiError.conflict(`Template with slug '${input.slug}' already exists`, 'SLUG_EXISTS');
      }
    }

    const result = await templatesRepo.update(templateId, {
      name: input.name,
      slug: input.slug,
      description: input.description,
      category: input.category,
      subject: input.subject,
      htmlContent: input.html,
      textContent: input.text,
      preheader: input.preheader,
      engine: input.engine,
      defaultData: input.defaultData,
      metadata: input.metadata,
      changelog: input.changelog,
      updatedBy: userId ?? undefined,
    });

    if (!result.ok) {
      throw ApiError.internal('Failed to update template');
    }

    const template = result.value;

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'template.updated',
      resourceType: 'template',
      resourceId: template.id,
      changes: {
        fields: Object.keys(input).filter(k => input[k as keyof typeof input] !== undefined),
      },
      metadata: { changelog: input.changelog },
    });

    logger.info('Template updated', { templateId: template.id, version: template.currentVersion });

    return c.json({
      template: {
        id: template.id,
        name: template.name,
        slug: template.slug,
        currentVersion: template.currentVersion,
        updatedAt: template.updatedAt,
      },
    });
  });

  // Publish template
  router.post('/:id/publish', requireScopes('templates:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const templateId = c.req.param('id');
    const logger = c.get('logger');

    // Verify ownership
    const existing = await templatesRepo.findById(templateId);
    if (!existing.ok || !existing.value || existing.value.tenantId !== tenantId) {
      throw ApiError.notFound('Template');
    }

    const result = await templatesRepo.publish(templateId);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to publish template');
    }

    const template = result.value;

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'template.published',
      resourceType: 'template',
      resourceId: template.id,
      metadata: { version: template.currentVersion },
    });

    logger.info('Template published', { templateId: template.id });

    return c.json({
      template: {
        id: template.id,
        publishedAt: template.publishedAt,
        currentVersion: template.currentVersion,
      },
    });
  });

  // Get template versions
  router.get('/:id/versions', requireScopes('templates:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const templateId = c.req.param('id');

    // Verify ownership
    const existing = await templatesRepo.findById(templateId);
    if (!existing.ok || !existing.value || existing.value.tenantId !== tenantId) {
      throw ApiError.notFound('Template');
    }

    const result = await templatesRepo.listVersions(templateId);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to fetch versions');
    }

    return c.json({
      versions: result.value.map((v) => ({
        version: v.version,
        subject: v.subject,
        variables: v.variables,
        changelog: v.changelog,
        createdAt: v.createdAt,
        createdBy: v.createdBy,
      })),
    });
  });

  // Get specific version
  router.get('/:id/versions/:version', requireScopes('templates:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const templateId = c.req.param('id');
    const version = parseInt(c.req.param('version'), 10);

    if (isNaN(version) || version < 1) {
      throw ApiError.badRequest('Invalid version number');
    }

    // Verify ownership
    const existing = await templatesRepo.findById(templateId);
    if (!existing.ok || !existing.value || existing.value.tenantId !== tenantId) {
      throw ApiError.notFound('Template');
    }

    const result = await templatesRepo.getVersion(templateId, version);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to fetch version');
    }

    if (!result.value) {
      throw ApiError.notFound('Version');
    }

    const v = result.value;

    return c.json({
      version: {
        version: v.version,
        subject: v.subject,
        html: v.htmlContent,
        text: v.textContent,
        variables: v.variables,
        changelog: v.changelog,
        createdAt: v.createdAt,
        createdBy: v.createdBy,
      },
    });
  });

  // Rollback to version
  router.post('/:id/rollback/:version', requireScopes('templates:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const templateId = c.req.param('id');
    const version = parseInt(c.req.param('version'), 10);
    const logger = c.get('logger');

    if (isNaN(version) || version < 1) {
      throw ApiError.badRequest('Invalid version number');
    }

    // Verify ownership
    const existing = await templatesRepo.findById(templateId);
    if (!existing.ok || !existing.value || existing.value.tenantId !== tenantId) {
      throw ApiError.notFound('Template');
    }

    const result = await templatesRepo.rollback(templateId, version);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to rollback template');
    }

    const template = result.value;

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'template.updated',
      resourceType: 'template',
      resourceId: template.id,
      metadata: { rolledBackTo: version, newVersion: template.currentVersion },
    });

    logger.info('Template rolled back', { templateId: template.id, toVersion: version });

    return c.json({
      template: {
        id: template.id,
        currentVersion: template.currentVersion,
        message: `Rolled back to version ${version}`,
      },
    });
  });

  // Render template (preview)
  router.post('/:id/render', requireScopes('templates:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const templateId = c.req.param('id');

    // Verify ownership
    const existing = await templatesRepo.findById(templateId);
    if (!existing.ok || !existing.value || existing.value.tenantId !== tenantId) {
      throw ApiError.notFound('Template');
    }

    const template = existing.value;
    const body = await c.req.json();
    const { data } = renderTemplateSchema.parse(body);

    // Merge with default data
    const mergedData = { ...template.defaultData, ...data };

    try {
      const rendered = await renderTemplate(template, mergedData);
      return c.json({
        rendered: {
          subject: rendered.subject,
          html: rendered.html,
          text: rendered.text,
        },
      });
    } catch (error) {
      throw ApiError.badRequest(
        `Template rendering failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'RENDER_FAILED'
      );
    }
  });

  // Duplicate template
  router.post('/:id/duplicate', requireScopes('templates:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const templateId = c.req.param('id');
    const logger = c.get('logger');

    // Verify ownership
    const existing = await templatesRepo.findById(templateId);
    if (!existing.ok || !existing.value || existing.value.tenantId !== tenantId) {
      throw ApiError.notFound('Template');
    }

    const body = await c.req.json();
    const newName = body.name ?? `${existing.value.name} (Copy)`;

    const result = await templatesRepo.duplicate(templateId, newName);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to duplicate template');
    }

    const template = result.value;

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'template.created',
      resourceType: 'template',
      resourceId: template.id,
      metadata: { duplicatedFrom: templateId, name: newName },
    });

    logger.info('Template duplicated', { originalId: templateId, newId: template.id });

    return c.json({
      template: {
        id: template.id,
        name: template.name,
        slug: template.slug,
        createdAt: template.createdAt,
      },
    }, 201);
  });

  // Delete template
  router.delete('/:id', requireScopes('templates:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const templateId = c.req.param('id');
    const logger = c.get('logger');

    // Verify ownership
    const existing = await templatesRepo.findById(templateId);
    if (!existing.ok || !existing.value || existing.value.tenantId !== tenantId) {
      throw ApiError.notFound('Template');
    }

    const result = await templatesRepo.delete(templateId);
    
    if (!result.ok) {
      throw ApiError.internal('Failed to delete template');
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: userId ?? undefined,
      action: 'template.deleted',
      resourceType: 'template',
      resourceId: templateId,
      metadata: { name: existing.value.name },
    });

    logger.info('Template deleted', { templateId });

    return c.json({ success: true });
  });

  return router;
}

interface TemplateData {
  engine: 'handlebars' | 'mjml' | 'liquid' | 'ejs';
  subject: string;
  htmlContent: string | null;
  textContent: string | null;
}

interface RenderedTemplate {
  subject: string;
  html: string | null;
  text: string | null;
}

async function renderTemplate(
  template: TemplateData,
  data: Record<string, unknown>
): Promise<RenderedTemplate> {
  // Simple variable replacement for now
  // In production, you'd use the actual template engine
  
  const replaceVariables = (content: string): string => {
    return content.replace(/\{\{([^}]+)\}\}/g, (match, key) => {
      const trimmedKey = key.trim();
      const value = getNestedValue(data, trimmedKey);
      return value !== undefined ? String(value) : match;
    });
  };

  const subject = replaceVariables(template.subject);
  const html = template.htmlContent ? replaceVariables(template.htmlContent) : null;
  const text = template.textContent ? replaceVariables(template.textContent) : null;

  return { subject, html, text };
}

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const keys = path.split('.');
  let value: unknown = obj;
  
  for (const key of keys) {
    if (value === null || value === undefined) return undefined;
    if (typeof value !== 'object') return undefined;
    value = (value as Record<string, unknown>)[key];
  }
  
  return value;
}
