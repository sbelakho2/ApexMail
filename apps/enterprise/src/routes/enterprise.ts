/**
 * Enterprise Routes
 * 
 * HTTP endpoints for enterprise features
 */

import { Hono } from 'hono';
import { Pool } from 'pg';
import type { Redis } from 'ioredis';
import { SSOService } from '../services/sso.js';
import { SubAccountService } from '../services/sub-accounts.js';
import { WhiteLabelService } from '../services/whitelabel.js';
import { TemplateApprovalService } from '../services/template-approval.js';
import { LogStreamingService } from '../services/log-streaming.js';
import { ComplianceService, ComplianceFramework } from '../services/compliance.js';
import { PrivateDeploymentService } from '../services/private-deploy.js';
import { SupportService, TicketStatus, TicketCategory } from '../services/support.js';
import { QBRService, QBRStatus } from '../services/qbr.js';
import { TemplateApprovalStatus, TicketPriority } from '../config.js';

// Type validation helpers
function isTemplateApprovalStatus(value: string | undefined): value is TemplateApprovalStatus {
  return value !== undefined && Object.values(TemplateApprovalStatus).includes(value as TemplateApprovalStatus);
}

function isTicketStatus(value: string | undefined): value is TicketStatus {
  return value !== undefined && Object.values(TicketStatus).includes(value as TicketStatus);
}

function isTicketPriority(value: string | undefined): value is TicketPriority {
  return value !== undefined && Object.values(TicketPriority).includes(value as TicketPriority);
}

function isTicketCategory(value: string | undefined): value is TicketCategory {
  return value !== undefined && Object.values(TicketCategory).includes(value as TicketCategory);
}

function isComplianceFramework(value: string | undefined): value is ComplianceFramework {
  return value !== undefined && Object.values(ComplianceFramework).includes(value as ComplianceFramework);
}

function isQBRStatus(value: string | undefined): value is QBRStatus {
  return value !== undefined && Object.values(QBRStatus).includes(value as QBRStatus);
}

const routes = new Hono();

export function createEnterpriseRoutes(pool: Pool, redis: Redis) {
  const ssoService = new SSOService(pool, redis);
  const subAccountService = new SubAccountService(pool, redis);
  const whiteLabelService = new WhiteLabelService(pool, redis);
  const templateApprovalService = new TemplateApprovalService(pool, redis);
  const logStreamingService = new LogStreamingService(pool, redis);
  const complianceService = new ComplianceService(pool, redis);
  const deploymentService = new PrivateDeploymentService(pool, redis);
  const supportService = new SupportService(pool, redis);
  const qbrService = new QBRService(pool, redis);

  // ==================== SSO Routes ====================

  routes.post('/sso/configure', async (c) => {
    const { accountId, ...config } = await c.req.json();
    const result = await ssoService.configureSSOWithSettings(accountId, config);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.get('/sso/config/:accountId', async (c) => {
    const accountId = c.req.param('accountId');
    const result = await ssoService.getSSOConfig(accountId);
    if (result.ok === false) return c.json({ error: result.error.message }, 404);
    return c.json(result.value);
  });

  routes.get('/sso/saml/login/:domain', async (c) => {
    const domain = c.req.param('domain');
    const result = await ssoService.initiateSAMLLogin(domain);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.redirect(result.value.redirectUrl);
  });

  routes.post('/sso/saml/callback', async (c) => {
    const body = await c.req.parseBody();
    const samlResponse = body.SAMLResponse as string;
    const result = await ssoService.processSAMLResponse(samlResponse);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.get('/sso/oidc/authorize/:domain', async (c) => {
    const domain = c.req.param('domain');
    const result = await ssoService.initiateOIDCLogin(domain);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.redirect(result.value.redirectUrl);
  });

  routes.get('/sso/oidc/callback', async (c) => {
    const code = c.req.query('code');
    const state = c.req.query('state');
    if (!code || !state) return c.json({ error: 'Missing code or state' }, 400);
    const result = await ssoService.processOIDCCallback(code, state);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  // ==================== Sub-Account Routes ====================

  routes.post('/sub-accounts', async (c) => {
    const { parentAccountId, ...data } = await c.req.json();
    const result = await subAccountService.createSubAccount(parentAccountId, data);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value, 201);
  });

  routes.get('/sub-accounts/:id', async (c) => {
    const id = c.req.param('id');
    const result = await subAccountService.getSubAccount(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    if (!result.value) return c.json({ error: 'Sub-account not found' }, 404);
    return c.json(result.value);
  });

  routes.get('/accounts/:parentId/sub-accounts', async (c) => {
    const parentId = c.req.param('parentId');
    const result = await subAccountService.listSubAccounts(parentId);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.patch('/sub-accounts/:id', async (c) => {
    const id = c.req.param('id');
    const updates = await c.req.json();
    const result = await subAccountService.updateSubAccount(id, updates);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/sub-accounts/:id/suspend', async (c) => {
    const id = c.req.param('id');
    const { reason } = await c.req.json();
    const result = await subAccountService.suspendSubAccount(id, reason);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json({ success: true });
  });

  routes.delete('/sub-accounts/:id', async (c) => {
    const id = c.req.param('id');
    const result = await subAccountService.deleteSubAccount(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json({ success: true });
  });

  routes.get('/accounts/:parentId/sub-accounts/stats', async (c) => {
    const parentId = c.req.param('parentId');
    const startDate = new Date(c.req.query('startDate') || Date.now() - 30 * 24 * 60 * 60 * 1000);
    const endDate = new Date(c.req.query('endDate') || Date.now());
    const result = await subAccountService.getAggregateStats(parentId, startDate, endDate);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/sub-accounts/:id/api-keys', async (c) => {
    const id = c.req.param('id');
    const { name, scopes, expiresAt } = await c.req.json();
    const result = await subAccountService.createAPIKey(id, name, scopes, expiresAt ? new Date(expiresAt) : undefined);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value, 201);
  });

  // ==================== White-Label Routes ====================

  routes.put('/whitelabel/config/:accountId', async (c) => {
    const accountId = c.req.param('accountId');
    const data = await c.req.json();
    const result = await whiteLabelService.upsertConfig(accountId, data);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.get('/whitelabel/config/:accountId', async (c) => {
    const accountId = c.req.param('accountId');
    const result = await whiteLabelService.getConfig(accountId);
    if (result.ok === false) return c.json({ error: result.error.message }, 404);
    return c.json(result.value);
  });

  routes.post('/whitelabel/domains', async (c) => {
    const { configId, domain, type, verificationMethod } = await c.req.json();
    const result = await whiteLabelService.addDomain(configId, domain, type, verificationMethod);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value, 201);
  });

  routes.post('/whitelabel/domains/:id/verify', async (c) => {
    const id = c.req.param('id');
    const result = await whiteLabelService.verifyDomain(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.delete('/whitelabel/domains/:id', async (c) => {
    const id = c.req.param('id');
    const result = await whiteLabelService.removeDomain(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json({ success: true });
  });

  routes.put('/whitelabel/templates/:accountId', async (c) => {
    const accountId = c.req.param('accountId');
    const data = await c.req.json();
    const result = await whiteLabelService.upsertEmailTemplate(accountId, data);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.get('/whitelabel/templates/:accountId', async (c) => {
    const accountId = c.req.param('accountId');
    const type = c.req.query('type');
    const result = await whiteLabelService.listEmailTemplates(accountId, type);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  // ==================== Template Approval Routes ====================

  routes.post('/templates/submit', async (c) => {
    const { accountId, submittedBy, ...data } = await c.req.json();
    const result = await templateApprovalService.submitTemplate(accountId, submittedBy, data);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value, 201);
  });

  routes.get('/templates/submissions/:id', async (c) => {
    const id = c.req.param('id');
    const result = await templateApprovalService.getSubmission(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 404);
    return c.json(result.value);
  });

  routes.get('/templates/submissions', async (c) => {
    const statusParam = c.req.query('status');
    const filters = {
      accountId: c.req.query('accountId'),
      status: isTemplateApprovalStatus(statusParam) ? statusParam : undefined,
      templateType: c.req.query('templateType'),
    };
    const page = parseInt(c.req.query('page') || '1', 10);
    const limit = parseInt(c.req.query('limit') || '20', 10);
    const result = await templateApprovalService.listSubmissions(filters, { page, limit });
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/templates/submissions/:id/approve', async (c) => {
    const id = c.req.param('id');
    const { reviewerId, notes } = await c.req.json();
    const result = await templateApprovalService.approveTemplate(id, reviewerId, notes);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/templates/submissions/:id/reject', async (c) => {
    const id = c.req.param('id');
    const { reviewerId, reason, notes } = await c.req.json();
    const result = await templateApprovalService.rejectTemplate(id, reviewerId, reason, notes);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/templates/submissions/:id/request-changes', async (c) => {
    const id = c.req.param('id');
    const { reviewerId, comments } = await c.req.json();
    const result = await templateApprovalService.requestChanges(id, reviewerId, comments);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.get('/templates/stats', async (c) => {
    const accountId = c.req.query('accountId');
    const result = await templateApprovalService.getStats(accountId);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  // ==================== Log Streaming Routes ====================

  routes.post('/log-streams', async (c) => {
    const { accountId, ...data } = await c.req.json();
    const result = await logStreamingService.createStream(accountId, data);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value, 201);
  });

  routes.get('/log-streams/:id', async (c) => {
    const id = c.req.param('id');
    const result = await logStreamingService.getStream(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 404);
    return c.json(result.value);
  });

  routes.get('/accounts/:accountId/log-streams', async (c) => {
    const accountId = c.req.param('accountId');
    const result = await logStreamingService.listStreams(accountId);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.patch('/log-streams/:id', async (c) => {
    const id = c.req.param('id');
    const updates = await c.req.json();
    const result = await logStreamingService.updateStream(id, updates);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/log-streams/:id/verify', async (c) => {
    const id = c.req.param('id');
    const result = await logStreamingService.verifyDestination(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/log-streams/:id/pause', async (c) => {
    const id = c.req.param('id');
    const result = await logStreamingService.pauseStream(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json({ success: true });
  });

  routes.post('/log-streams/:id/resume', async (c) => {
    const id = c.req.param('id');
    const result = await logStreamingService.resumeStream(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json({ success: true });
  });

  routes.delete('/log-streams/:id', async (c) => {
    const id = c.req.param('id');
    const result = await logStreamingService.deleteStream(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json({ success: true });
  });

  routes.get('/log-streams/:id/stats', async (c) => {
    const id = c.req.param('id');
    const startDate = new Date(c.req.query('startDate') || Date.now() - 7 * 24 * 60 * 60 * 1000);
    const endDate = new Date(c.req.query('endDate') || Date.now());
    const result = await logStreamingService.getStreamStats(id, startDate, endDate);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  // ==================== Compliance Routes ====================

  routes.post('/compliance/enable', async (c) => {
    const { accountId, frameworks, settings } = await c.req.json();
    const result = await complianceService.enableCompliance(accountId, frameworks, settings);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.get('/compliance/config/:accountId', async (c) => {
    const accountId = c.req.param('accountId');
    const result = await complianceService.getComplianceConfig(accountId);
    if (result.ok === false) return c.json({ error: result.error.message }, 404);
    return c.json(result.value);
  });

  routes.post('/compliance/baa/sign', async (c) => {
    const { accountId, ...data } = await c.req.json();
    const result = await complianceService.signBAA(accountId, data);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/compliance/zero-retention/:accountId', async (c) => {
    const accountId = c.req.param('accountId');
    const result = await complianceService.enableZeroRetention(accountId);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json({ success: true });
  });

  routes.get('/compliance/audit-logs/:accountId', async (c) => {
    const accountId = c.req.param('accountId');
    const filters = {
      userId: c.req.query('userId'),
      action: c.req.query('action'),
      resource: c.req.query('resource'),
      startDate: c.req.query('startDate') ? new Date(c.req.query('startDate')!) : undefined,
      endDate: c.req.query('endDate') ? new Date(c.req.query('endDate')!) : undefined,
    };
    const page = parseInt(c.req.query('page') || '1', 10);
    const limit = parseInt(c.req.query('limit') || '50', 10);
    const result = await complianceService.searchAuditLogs(accountId, filters, { page, limit });
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/compliance/data-access/request', async (c) => {
    const { accountId, requesterId, resourceType, resourceId, justification, durationMinutes } = await c.req.json();
    const result = await complianceService.requestDataAccess(accountId, requesterId, resourceType, resourceId, justification, durationMinutes);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value, 201);
  });

  routes.post('/compliance/data-access/:id/approve', async (c) => {
    const id = c.req.param('id');
    const { reviewerId, notes } = await c.req.json();
    const result = await complianceService.approveDataAccess(id, reviewerId, notes);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/compliance/data-deletion/request', async (c) => {
    const { accountId, requesterId, dataType, scope, identifiers, reason } = await c.req.json();
    const result = await complianceService.requestDataDeletion(accountId, requesterId, dataType, scope, identifiers, reason);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value, 201);
  });

  routes.get('/compliance/report/:accountId', async (c) => {
    const accountId = c.req.param('accountId');
    const frameworkParam = c.req.query('framework');
    const framework = isComplianceFramework(frameworkParam) ? frameworkParam : undefined;
    if (!framework) {
      return c.json({ error: 'Invalid or missing compliance framework parameter' }, 400);
    }
    const startDate = new Date(c.req.query('startDate') || Date.now() - 90 * 24 * 60 * 60 * 1000);
    const endDate = new Date(c.req.query('endDate') || Date.now());
    const result = await complianceService.generateComplianceReport(accountId, framework, startDate, endDate);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.get('/compliance/status/:accountId', async (c) => {
    const accountId = c.req.param('accountId');
    const result = await complianceService.checkComplianceStatus(accountId);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  // ==================== Private Deployment Routes ====================

  routes.post('/deployments', async (c) => {
    const { accountId, ...data } = await c.req.json();
    const result = await deploymentService.createDeployment(accountId, data);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value, 201);
  });

  routes.get('/deployments/:id', async (c) => {
    const id = c.req.param('id');
    const result = await deploymentService.getDeployment(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 404);
    return c.json(result.value);
  });

  routes.get('/accounts/:accountId/deployments', async (c) => {
    const accountId = c.req.param('accountId');
    const result = await deploymentService.listDeployments(accountId);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/deployments/:id/provision', async (c) => {
    const id = c.req.param('id');
    const result = await deploymentService.provisionDeployment(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.get('/deployments/:id/health', async (c) => {
    const id = c.req.param('id');
    const result = await deploymentService.getDeploymentHealth(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/dedicated-ips', async (c) => {
    const { accountId, deploymentId } = await c.req.json();
    const result = await deploymentService.addDedicatedIP(accountId, deploymentId);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value, 201);
  });

  routes.get('/dedicated-ips/:id', async (c) => {
    const id = c.req.param('id');
    const result = await deploymentService.getDedicatedIP(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 404);
    return c.json(result.value);
  });

  routes.get('/accounts/:accountId/dedicated-ips', async (c) => {
    const accountId = c.req.param('accountId');
    const result = await deploymentService.listDedicatedIPs(accountId);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.get('/dedicated-ips/:ip/reputation', async (c) => {
    const ip = c.req.param('ip');
    const result = await deploymentService.getIPReputation(ip);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/byoip', async (c) => {
    const { accountId, cidrBlock } = await c.req.json();
    const result = await deploymentService.registerBYOIP(accountId, cidrBlock);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value, 201);
  });

  routes.post('/byoip/:id/verify', async (c) => {
    const id = c.req.param('id');
    const result = await deploymentService.verifyBYOIP(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/byoip/:id/provision', async (c) => {
    const id = c.req.param('id');
    const result = await deploymentService.provisionBYOIP(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  // ==================== Support Routes ====================

  routes.post('/support/tickets', async (c) => {
    const { accountId, createdBy, ...data } = await c.req.json();
    const result = await supportService.createTicket(accountId, createdBy, data);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value, 201);
  });

  routes.get('/support/tickets/:id', async (c) => {
    const id = c.req.param('id');
    const result = await supportService.getTicket(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 404);
    return c.json(result.value);
  });

  routes.get('/support/tickets', async (c) => {
    const statusParam = c.req.query('status');
    const priorityParam = c.req.query('priority');
    const categoryParam = c.req.query('category');
    const filters = {
      accountId: c.req.query('accountId'),
      assignedTo: c.req.query('assignedTo'),
      status: isTicketStatus(statusParam) ? statusParam : undefined,
      priority: isTicketPriority(priorityParam) ? priorityParam : undefined,
      category: isTicketCategory(categoryParam) ? categoryParam : undefined,
    };
    const page = parseInt(c.req.query('page') || '1', 10);
    const limit = parseInt(c.req.query('limit') || '20', 10);
    const result = await supportService.listTickets(filters, { page, limit });
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.patch('/support/tickets/:id', async (c) => {
    const id = c.req.param('id');
    const updates = await c.req.json();
    const result = await supportService.updateTicket(id, updates);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/support/tickets/:id/comments', async (c) => {
    const ticketId = c.req.param('id');
    const { authorId, authorName, authorType, content, isInternal, attachments } = await c.req.json();
    const result = await supportService.addComment(ticketId, authorId, authorName, authorType, content, isInternal, attachments);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value, 201);
  });

  routes.get('/support/tickets/:id/comments', async (c) => {
    const ticketId = c.req.param('id');
    const includeInternal = c.req.query('includeInternal') === 'true';
    const result = await supportService.getComments(ticketId, includeInternal);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/support/tickets/:id/escalate', async (c) => {
    const id = c.req.param('id');
    const { reason, escalateTo } = await c.req.json();
    const result = await supportService.escalateTicket(id, reason, escalateTo);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/support/tickets/:id/satisfaction', async (c) => {
    const id = c.req.param('id');
    const { rating, comment } = await c.req.json();
    const result = await supportService.submitSatisfaction(id, rating, comment);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json({ success: true });
  });

  routes.get('/support/metrics', async (c) => {
    const startDate = new Date(c.req.query('startDate') || Date.now() - 30 * 24 * 60 * 60 * 1000);
    const endDate = new Date(c.req.query('endDate') || Date.now());
    const accountId = c.req.query('accountId');
    const result = await supportService.getMetrics(startDate, endDate, accountId);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.get('/support/agents/workload', async (c) => {
    const result = await supportService.getAgentWorkload();
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  // ==================== QBR Routes ====================

  routes.post('/qbr/schedule', async (c) => {
    const { accountId, quarter, scheduledDate, attendees } = await c.req.json();
    const result = await qbrService.scheduleQBR(accountId, quarter, new Date(scheduledDate), attendees);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value, 201);
  });

  routes.get('/qbr/:id', async (c) => {
    const id = c.req.param('id');
    const result = await qbrService.getQBR(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 404);
    return c.json(result.value);
  });

  routes.get('/accounts/:accountId/qbrs', async (c) => {
    const accountId = c.req.param('accountId');
    const statusParam = c.req.query('status');
    const status = isQBRStatus(statusParam) ? statusParam : undefined;
    const result = await qbrService.listQBRs(accountId, status);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/qbr/:id/generate', async (c) => {
    const id = c.req.param('id');
    const result = await qbrService.generateQBRData(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/qbr/:id/report', async (c) => {
    const id = c.req.param('id');
    const result = await qbrService.generateReport(id);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/qbr/:id/delivered', async (c) => {
    const id = c.req.param('id');
    const { deliveredBy } = await c.req.json();
    const result = await qbrService.markDelivered(id, deliveredBy);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  routes.post('/qbr/:id/feedback', async (c) => {
    const id = c.req.param('id');
    const feedback = await c.req.json();
    const result = await qbrService.submitFeedback(id, feedback);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json({ success: true });
  });

  routes.patch('/qbr/:qbrId/goals/:goalId', async (c) => {
    const qbrId = c.req.param('qbrId');
    const goalId = c.req.param('goalId');
    const { progress, status } = await c.req.json();
    const result = await qbrService.updateGoalProgress(qbrId, goalId, progress, status);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json({ success: true });
  });

  routes.get('/qbr/benchmarks', async (c) => {
    const industry = c.req.query('industry');
    const result = await qbrService.getBenchmarks(industry);
    if (result.ok === false) return c.json({ error: result.error.message }, 400);
    return c.json(result.value);
  });

  // ==================== Health Check ====================

  routes.get('/health', (c) => {
    return c.json({ status: 'healthy', service: 'enterprise', timestamp: new Date().toISOString() });
  });

  return routes;
}

export default routes;
