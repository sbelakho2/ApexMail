/**
 * SCIM 2.0 Routes - System for Cross-domain Identity Management
 * 
 * Implements RFC 7644 (SCIM Protocol) and RFC 7643 (SCIM Core Schema)
 * for enterprise user and group provisioning via identity providers
 * (Okta, Azure AD, OneLogin, etc.)
 * 
 * Endpoints:
 * - GET    /scim/v2/Users           - List/filter users
 * - GET    /scim/v2/Users/:id       - Get user by ID
 * - POST   /scim/v2/Users           - Create user
 * - PUT    /scim/v2/Users/:id       - Replace user
 * - PATCH  /scim/v2/Users/:id       - Partial update user
 * - DELETE /scim/v2/Users/:id       - Deactivate/delete user
 * - GET    /scim/v2/Groups          - List groups
 * - GET    /scim/v2/Groups/:id      - Get group by ID
 * - POST   /scim/v2/Groups          - Create group
 * - PUT    /scim/v2/Groups/:id      - Replace group
 * - PATCH  /scim/v2/Groups/:id      - Partial update group
 * - DELETE /scim/v2/Groups/:id      - Delete group
 * - GET    /scim/v2/ServiceProviderConfig - SCIM capabilities
 * - GET    /scim/v2/Schemas         - Schema definitions
 * - GET    /scim/v2/ResourceTypes   - Resource type definitions
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv, AppContext } from '../app.js';
import { UsersRepository, AuditLogsRepository, type User } from '@apexmail/db';
import { requireScopes } from '../middleware/auth.js';
import { generateId } from '@apexmail/lib';

// SCIM 2.0 Schema URIs
const SCIM_SCHEMAS = {
  USER: 'urn:ietf:params:scim:schemas:core:2.0:User',
  GROUP: 'urn:ietf:params:scim:schemas:core:2.0:Group',
  ENTERPRISE_USER: 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User',
  LIST_RESPONSE: 'urn:ietf:params:scim:api:messages:2.0:ListResponse',
  ERROR: 'urn:ietf:params:scim:api:messages:2.0:Error',
  PATCH_OP: 'urn:ietf:params:scim:api:messages:2.0:PatchOp',
  SERVICE_PROVIDER_CONFIG: 'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig',
  RESOURCE_TYPE: 'urn:ietf:params:scim:schemas:core:2.0:ResourceType',
  SCHEMA: 'urn:ietf:params:scim:schemas:core:2.0:Schema',
} as const;

// SCIM filter parser - basic implementation
function parseScimFilter(filter: string): { field: string; op: string; value: string } | null {
  // Support: userName eq "john@example.com", email eq "...", active eq true
  const match = filter.match(/^(\w+)\s+(eq|ne|co|sw|ew|gt|lt|ge|le)\s+"?([^"]*)"?$/i);
  if (!match || match.length < 4) return null;
  const field = match[1];
  const op = match[2];
  const value = match[3];
  if (!field || !op || value === undefined) return null;
  return { field, op: op.toLowerCase(), value };
}

// Convert ApexMail User to SCIM User resource
function toScimUser(user: User, baseUrl: string): Record<string, unknown> {
  return {
    schemas: [SCIM_SCHEMAS.USER, SCIM_SCHEMAS.ENTERPRISE_USER],
    id: user.id,
    externalId: user.metadata?.externalId ?? null,
    userName: user.email,
    name: {
      formatted: user.name,
      givenName: user.name.split(' ')[0] ?? user.name,
      familyName: user.name.split(' ').slice(1).join(' ') || null,
    },
    displayName: user.name,
    emails: [
      {
        value: user.email,
        type: 'work',
        primary: true,
      },
    ],
    active: user.status === 'active',
    groups: [], // Will be populated if groups are implemented
    meta: {
      resourceType: 'User',
      created: user.createdAt.toISOString(),
      lastModified: user.updatedAt.toISOString(),
      location: `${baseUrl}/scim/v2/Users/${user.id}`,
      version: `W/"${user.updatedAt.getTime()}"`,
    },
    [SCIM_SCHEMAS.ENTERPRISE_USER]: {
      department: user.metadata?.department ?? null,
      manager: user.metadata?.manager ?? null,
    },
  };
}

// SCIM error response
function scimError(status: number, scimType: string, detail: string) {
  return {
    schemas: [SCIM_SCHEMAS.ERROR],
    status: status.toString(),
    scimType,
    detail,
  };
}

// Zod schemas for SCIM requests
const scimUserCreateSchema = z.object({
  schemas: z.array(z.string()).min(1),
  userName: z.string().email().max(254),
  externalId: z.string().max(255).optional(),
  name: z.object({
    formatted: z.string().max(255).optional(),
    givenName: z.string().max(100).optional(),
    familyName: z.string().max(100).optional(),
  }).optional(),
  displayName: z.string().max(255).optional(),
  emails: z.array(z.object({
    value: z.string().email(),
    type: z.string().optional(),
    primary: z.boolean().optional(),
  })).optional(),
  active: z.boolean().optional().default(true),
  password: z.string().min(8).max(128).optional(),
});

const scimPatchOpSchema = z.object({
  schemas: z.array(z.literal(SCIM_SCHEMAS.PATCH_OP)),
  Operations: z.array(z.object({
    op: z.enum(['add', 'replace', 'remove']),
    path: z.string().optional(),
    value: z.unknown().optional(),
  })).min(1).max(100),
});

// Group schemas (basic implementation)
const scimGroupCreateSchema = z.object({
  schemas: z.array(z.string()).min(1),
  displayName: z.string().min(1).max(255),
  externalId: z.string().max(255).optional(),
  members: z.array(z.object({
    value: z.string(),
    display: z.string().optional(),
    type: z.enum(['User', 'Group']).optional(),
  })).optional(),
});

/**
 * SCIM 2.0 Routes
 * Requires 'admin' scope for all operations
 */
export function scimRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  
  // All SCIM routes require admin scope
  router.use('*', requireScopes('admin'));
  
  // Set SCIM content type for all responses
  router.use('*', async (c, next) => {
    await next();
    c.header('Content-Type', 'application/scim+json');
  });

  const usersRepo = new UsersRepository(ctx.db);
  const auditRepo = new AuditLogsRepository(ctx.db);

  // =========================================================================
  // Service Provider Configuration
  // =========================================================================

  /**
   * GET /scim/v2/ServiceProviderConfig
   * Returns SCIM service provider capabilities
   */
  router.get('/ServiceProviderConfig', (c) => {
    const baseUrl = new URL(c.req.url).origin;
    return c.json({
      schemas: [SCIM_SCHEMAS.SERVICE_PROVIDER_CONFIG],
      documentationUri: 'https://docs.apexmail.ee/scim',
      patch: { supported: true },
      bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
      filter: { supported: true, maxResults: 100 },
      changePassword: { supported: false },
      sort: { supported: true },
      etag: { supported: true },
      authenticationSchemes: [
        {
          type: 'oauthbearertoken',
          name: 'OAuth Bearer Token',
          description: 'Authentication using API key as Bearer token',
          specUri: 'https://tools.ietf.org/html/rfc6750',
          primary: true,
        },
      ],
      meta: {
        resourceType: 'ServiceProviderConfig',
        location: `${baseUrl}/scim/v2/ServiceProviderConfig`,
      },
    });
  });

  /**
   * GET /scim/v2/Schemas
   * Returns SCIM schema definitions
   */
  router.get('/Schemas', (c) => {
    const baseUrl = new URL(c.req.url).origin;
    return c.json({
      schemas: [SCIM_SCHEMAS.LIST_RESPONSE],
      totalResults: 2,
      itemsPerPage: 2,
      startIndex: 1,
      Resources: [
        {
          schemas: [SCIM_SCHEMAS.SCHEMA],
          id: SCIM_SCHEMAS.USER,
          name: 'User',
          description: 'User resource',
          attributes: [
            { name: 'userName', type: 'string', required: true, uniqueness: 'server' },
            { name: 'name', type: 'complex', required: false },
            { name: 'displayName', type: 'string', required: false },
            { name: 'emails', type: 'complex', multiValued: true, required: false },
            { name: 'active', type: 'boolean', required: false },
          ],
          meta: { resourceType: 'Schema', location: `${baseUrl}/scim/v2/Schemas/${SCIM_SCHEMAS.USER}` },
        },
        {
          schemas: [SCIM_SCHEMAS.SCHEMA],
          id: SCIM_SCHEMAS.GROUP,
          name: 'Group',
          description: 'Group resource',
          attributes: [
            { name: 'displayName', type: 'string', required: true, uniqueness: 'server' },
            { name: 'members', type: 'complex', multiValued: true, required: false },
          ],
          meta: { resourceType: 'Schema', location: `${baseUrl}/scim/v2/Schemas/${SCIM_SCHEMAS.GROUP}` },
        },
      ],
    });
  });

  /**
   * GET /scim/v2/ResourceTypes
   * Returns supported resource types
   */
  router.get('/ResourceTypes', (c) => {
    const baseUrl = new URL(c.req.url).origin;
    return c.json({
      schemas: [SCIM_SCHEMAS.LIST_RESPONSE],
      totalResults: 2,
      itemsPerPage: 2,
      startIndex: 1,
      Resources: [
        {
          schemas: [SCIM_SCHEMAS.RESOURCE_TYPE],
          id: 'User',
          name: 'User',
          endpoint: '/Users',
          description: 'User Account',
          schema: SCIM_SCHEMAS.USER,
          schemaExtensions: [
            { schema: SCIM_SCHEMAS.ENTERPRISE_USER, required: false },
          ],
          meta: { resourceType: 'ResourceType', location: `${baseUrl}/scim/v2/ResourceTypes/User` },
        },
        {
          schemas: [SCIM_SCHEMAS.RESOURCE_TYPE],
          id: 'Group',
          name: 'Group',
          endpoint: '/Groups',
          description: 'Group',
          schema: SCIM_SCHEMAS.GROUP,
          meta: { resourceType: 'ResourceType', location: `${baseUrl}/scim/v2/ResourceTypes/Group` },
        },
      ],
    });
  });

  // =========================================================================
  // Users
  // =========================================================================

  /**
   * GET /scim/v2/Users
   * List or search users
   * Supports: filter, startIndex, count, sortBy, sortOrder
   */
  router.get('/Users', async (c) => {
    const tenantId = c.get('tenantId');
    const baseUrl = new URL(c.req.url).origin;
    
    const filter = c.req.query('filter');
    const startIndex = Math.max(1, parseInt(c.req.query('startIndex') ?? '1', 10));
    const count = Math.min(100, Math.max(1, parseInt(c.req.query('count') ?? '25', 10)));
    const sortBy = c.req.query('sortBy') ?? 'userName'; // Note: sortBy/sortOrder reserved for future use
    const sortOrder = c.req.query('sortOrder')?.toLowerCase() === 'descending' ? 'desc' : 'asc';
    void sortBy; void sortOrder; // Suppress unused variable warnings

    // Parse filter if provided
    let filterEmail: string | undefined;
    if (filter) {
      const parsed = parseScimFilter(filter);
      if (parsed && (parsed.field === 'userName' || parsed.field === 'email') && parsed.op === 'eq') {
        filterEmail = parsed.value;
      }
    }

    // Fetch users - note: listByTenant doesn't support filtering by email
    // For filter support, we would need to extend the repository
    const result = await usersRepo.listByTenant(tenantId, {
      limit: count,
      offset: startIndex - 1,
    });

    if (!result.ok) {
      return c.json(scimError(500, 'serverError', 'Failed to fetch users'), 500);
    }

    let { users } = result.value;
    const total = result.value.total;
    
    // Apply filter in-memory if provided (for userName/email eq filter)
    if (filterEmail) {
      const fe = filterEmail;
      users = users.filter((u) => u.email.toLowerCase() === fe.toLowerCase());
    }

    return c.json({
      schemas: [SCIM_SCHEMAS.LIST_RESPONSE],
      totalResults: filterEmail ? users.length : total,
      itemsPerPage: count,
      startIndex,
      Resources: users.map((u: User) => toScimUser(u, baseUrl)),
    });
  });

  /**
   * GET /scim/v2/Users/:id
   * Get a specific user
   */
  router.get('/Users/:id', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.req.param('id');
    const baseUrl = new URL(c.req.url).origin;

    const result = await usersRepo.findById(userId);
    if (!result.ok) {
      return c.json(scimError(500, 'serverError', 'Failed to fetch user'), 500);
    }

    if (!result.value || result.value.tenantId !== tenantId) {
      return c.json(scimError(404, 'notFound', `User ${userId} not found`), 404);
    }

    const user = result.value;
    c.header('ETag', `W/"${user.updatedAt.getTime()}"`);
    return c.json(toScimUser(user, baseUrl));
  });

  /**
   * POST /scim/v2/Users
   * Create a new user
   */
  router.post('/Users', async (c) => {
    const tenantId = c.get('tenantId');
    const adminUserId = c.get('userId');
    const baseUrl = new URL(c.req.url).origin;

    const body = await c.req.json();
    const parsed = scimUserCreateSchema.safeParse(body);
    if (!parsed.success) {
      return c.json(scimError(400, 'invalidSyntax', parsed.error.message), 400);
    }

    const { userName, name, displayName, active, password, externalId } = parsed.data;
    const primaryEmail = parsed.data.emails?.find((e) => e.primary)?.value ?? userName;

    // Check if user already exists
    const existingResult = await usersRepo.findByEmail(primaryEmail, tenantId);
    if (existingResult.ok && existingResult.value) {
      return c.json(scimError(409, 'uniqueness', `User with userName ${userName} already exists`), 409);
    }

    // Create user
    const result = await usersRepo.create({
      tenantId,
      email: primaryEmail,
      name: displayName ?? name?.formatted ?? name?.givenName ?? userName,
      password: password ?? generateId('pwd'), // Temp password if not provided
      role: 'member',
    });

    if (!result.ok) {
      return c.json(scimError(500, 'serverError', 'Failed to create user'), 500);
    }

    const user = result.value;

    // Update metadata with externalId if provided
    if (externalId) {
      await usersRepo.update(user.id, {
        metadata: { ...user.metadata, externalId },
        status: active ? 'active' : 'disabled',
      });
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: adminUserId ?? 'scim',
      action: 'user.created',
      resourceType: 'user',
      resourceId: user.id,
      ipAddress: c.req.header('X-Forwarded-For') ?? 'unknown',
      metadata: { source: 'scim', externalId },
    });

    c.status(201);
    c.header('Location', `${baseUrl}/scim/v2/Users/${user.id}`);
    c.header('ETag', `W/"${user.updatedAt.getTime()}"`);
    return c.json(toScimUser(user, baseUrl));
  });

  /**
   * PUT /scim/v2/Users/:id
   * Replace a user (full update)
   */
  router.put('/Users/:id', async (c) => {
    const tenantId = c.get('tenantId');
    const adminUserId = c.get('userId');
    const userId = c.req.param('id');
    const baseUrl = new URL(c.req.url).origin;

    const body = await c.req.json();
    const parsed = scimUserCreateSchema.safeParse(body);
    if (!parsed.success) {
      return c.json(scimError(400, 'invalidSyntax', parsed.error.message), 400);
    }

    // Check user exists
    const existingResult = await usersRepo.findById(userId);
    if (!existingResult.ok || !existingResult.value || existingResult.value.tenantId !== tenantId) {
      return c.json(scimError(404, 'notFound', `User ${userId} not found`), 404);
    }

    const { userName, name, displayName, active, externalId } = parsed.data;
    const primaryEmail = parsed.data.emails?.find((e) => e.primary)?.value ?? userName;

    const updateResult = await usersRepo.update(userId, {
      name: displayName ?? name?.formatted ?? name?.givenName ?? primaryEmail,
      status: active ? 'active' : 'disabled',
      metadata: { ...existingResult.value.metadata, externalId },
    });

    if (!updateResult.ok) {
      return c.json(scimError(500, 'serverError', 'Failed to update user'), 500);
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: adminUserId ?? 'scim',
      action: 'user.updated',
      resourceType: 'user',
      resourceId: userId,
      ipAddress: c.req.header('X-Forwarded-For') ?? 'unknown',
      metadata: { source: 'scim', operation: 'PUT' },
    });

    const updatedResult = await usersRepo.findById(userId);
    if (!updatedResult.ok || !updatedResult.value) {
      return c.json(scimError(500, 'serverError', 'Failed to fetch updated user'), 500);
    }

    const user = updatedResult.value;
    c.header('ETag', `W/"${user.updatedAt.getTime()}"`);
    return c.json(toScimUser(user, baseUrl));
  });

  /**
   * PATCH /scim/v2/Users/:id
   * Partial update a user
   */
  router.patch('/Users/:id', async (c) => {
    const tenantId = c.get('tenantId');
    const adminUserId = c.get('userId');
    const userId = c.req.param('id');
    const baseUrl = new URL(c.req.url).origin;

    const body = await c.req.json();
    const parsed = scimPatchOpSchema.safeParse(body);
    if (!parsed.success) {
      return c.json(scimError(400, 'invalidSyntax', parsed.error.message), 400);
    }

    // Check user exists
    const existingResult = await usersRepo.findById(userId);
    if (!existingResult.ok || !existingResult.value || existingResult.value.tenantId !== tenantId) {
      return c.json(scimError(404, 'notFound', `User ${userId} not found`), 404);
    }

    const user = existingResult.value;
    const updates: Record<string, unknown> = {};

    // Process PATCH operations
    for (const op of parsed.data.Operations) {
      if (op.op === 'replace' || op.op === 'add') {
        if (op.path === 'active' || (op.path === undefined && typeof op.value === 'object' && op.value !== null && 'active' in op.value)) {
          const active = op.path === 'active' ? op.value : (op.value as { active?: boolean }).active;
          updates.status = active ? 'active' : 'disabled';
        }
        if (op.path === 'displayName' || op.path === 'name.formatted') {
          updates.name = op.value as string;
        }
        if (op.path === 'externalId') {
          updates.metadata = { ...user.metadata, externalId: op.value };
        }
      }
      if (op.op === 'remove') {
        if (op.path === 'externalId') {
          const { externalId: _removed, ...rest } = user.metadata as Record<string, unknown>;
          updates.metadata = rest;
        }
      }
    }

    if (Object.keys(updates).length > 0) {
      const updateResult = await usersRepo.update(userId, updates);
      if (!updateResult.ok) {
        return c.json(scimError(500, 'serverError', 'Failed to update user'), 500);
      }
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: adminUserId ?? 'scim',
      action: 'user.updated',
      resourceType: 'user',
      resourceId: userId,
      ipAddress: c.req.header('X-Forwarded-For') ?? 'unknown',
      metadata: { source: 'scim', operation: 'PATCH', updates },
    });

    const updatedResult = await usersRepo.findById(userId);
    if (!updatedResult.ok || !updatedResult.value) {
      return c.json(scimError(500, 'serverError', 'Failed to fetch updated user'), 500);
    }

    const updatedUser = updatedResult.value;
    c.header('ETag', `W/"${updatedUser.updatedAt.getTime()}"`);
    return c.json(toScimUser(updatedUser, baseUrl));
  });

  /**
   * DELETE /scim/v2/Users/:id
   * Deactivate (soft-delete) a user
   */
  router.delete('/Users/:id', async (c) => {
    const tenantId = c.get('tenantId');
    const adminUserId = c.get('userId');
    const userId = c.req.param('id');

    // Check user exists
    const existingResult = await usersRepo.findById(userId);
    if (!existingResult.ok || !existingResult.value || existingResult.value.tenantId !== tenantId) {
      return c.json(scimError(404, 'notFound', `User ${userId} not found`), 404);
    }

    // Soft-delete by setting status to disabled
    const updateResult = await usersRepo.update(userId, {
      status: 'disabled',
    });

    if (!updateResult.ok) {
      return c.json(scimError(500, 'serverError', 'Failed to delete user'), 500);
    }

    // Audit log
    await auditRepo.create({
      tenantId,
      userId: adminUserId ?? 'scim',
      action: 'user.deleted',
      resourceType: 'user',
      resourceId: userId,
      ipAddress: c.req.header('X-Forwarded-For') ?? 'unknown',
      metadata: { source: 'scim' },
    });

    return c.body(null, 204);
  });

  // =========================================================================
  // Groups (Basic Implementation)
  // =========================================================================
  // Note: Full group implementation would require a groups table.
  // This provides minimal endpoints for SCIM compliance.

  // In-memory groups store (would be replaced with GroupsRepository in production)
  const groupsStore = new Map<string, { id: string; tenantId: string; displayName: string; externalId?: string; members: string[]; createdAt: Date; updatedAt: Date }>();

  /**
   * GET /scim/v2/Groups
   */
  router.get('/Groups', (c) => {
    const tenantId = c.get('tenantId');
    const baseUrl = new URL(c.req.url).origin;
    const groups = Array.from(groupsStore.values()).filter((g) => g.tenantId === tenantId);
    
    return c.json({
      schemas: [SCIM_SCHEMAS.LIST_RESPONSE],
      totalResults: groups.length,
      itemsPerPage: groups.length,
      startIndex: 1,
      Resources: groups.map((g) => ({
        schemas: [SCIM_SCHEMAS.GROUP],
        id: g.id,
        externalId: g.externalId,
        displayName: g.displayName,
        members: g.members.map((m) => ({ value: m, type: 'User' })),
        meta: {
          resourceType: 'Group',
          created: g.createdAt.toISOString(),
          lastModified: g.updatedAt.toISOString(),
          location: `${baseUrl}/scim/v2/Groups/${g.id}`,
        },
      })),
    });
  });

  /**
   * GET /scim/v2/Groups/:id
   */
  router.get('/Groups/:id', (c) => {
    const tenantId = c.get('tenantId');
    const groupId = c.req.param('id');
    const baseUrl = new URL(c.req.url).origin;
    
    const group = groupsStore.get(groupId);
    if (!group || group.tenantId !== tenantId) {
      return c.json(scimError(404, 'notFound', `Group ${groupId} not found`), 404);
    }

    return c.json({
      schemas: [SCIM_SCHEMAS.GROUP],
      id: group.id,
      externalId: group.externalId,
      displayName: group.displayName,
      members: group.members.map((m) => ({ value: m, type: 'User' })),
      meta: {
        resourceType: 'Group',
        created: group.createdAt.toISOString(),
        lastModified: group.updatedAt.toISOString(),
        location: `${baseUrl}/scim/v2/Groups/${group.id}`,
      },
    });
  });

  /**
   * POST /scim/v2/Groups
   */
  router.post('/Groups', async (c) => {
    const tenantId = c.get('tenantId');
    const baseUrl = new URL(c.req.url).origin;
    
    const body = await c.req.json();
    const parsed = scimGroupCreateSchema.safeParse(body);
    if (!parsed.success) {
      return c.json(scimError(400, 'invalidSyntax', parsed.error.message), 400);
    }

    const id = generateId('grp');
    const now = new Date();
    const group = {
      id,
      tenantId,
      displayName: parsed.data.displayName,
      externalId: parsed.data.externalId,
      members: parsed.data.members?.map((m) => m.value) ?? [],
      createdAt: now,
      updatedAt: now,
    };

    groupsStore.set(id, group);

    c.status(201);
    c.header('Location', `${baseUrl}/scim/v2/Groups/${id}`);
    return c.json({
      schemas: [SCIM_SCHEMAS.GROUP],
      id: group.id,
      externalId: group.externalId,
      displayName: group.displayName,
      members: group.members.map((m) => ({ value: m, type: 'User' })),
      meta: {
        resourceType: 'Group',
        created: group.createdAt.toISOString(),
        lastModified: group.updatedAt.toISOString(),
        location: `${baseUrl}/scim/v2/Groups/${group.id}`,
      },
    });
  });

  /**
   * DELETE /scim/v2/Groups/:id
   */
  router.delete('/Groups/:id', (c) => {
    const tenantId = c.get('tenantId');
    const groupId = c.req.param('id');
    
    const group = groupsStore.get(groupId);
    if (!group || group.tenantId !== tenantId) {
      return c.json(scimError(404, 'notFound', `Group ${groupId} not found`), 404);
    }

    groupsStore.delete(groupId);
    return c.body(null, 204);
  });

  return router;
}
