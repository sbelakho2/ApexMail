/**
 * Control Plane API Client
 * 
 * CRITICAL: This client ONLY connects to Control Plane services:
 * - Sales Autopilot API (port 3010)
 * - Compliance API (port 3011)
 * 
 * It does NOT and MUST NOT connect to Customer API (port 3001)
 * 
 * SECURITY: All requests include Control Plane authentication headers.
 * Customers cannot use this client even if they have access to the code.
 */

const AUTOPILOT_API_URL = process.env.NEXT_PUBLIC_AUTOPILOT_API_URL || 'http://localhost:3010';
const COMPLIANCE_API_URL = process.env.NEXT_PUBLIC_COMPLIANCE_API_URL || 'http://localhost:3011';

// Control Plane API key (server-side only)
const CONTROL_PLANE_API_KEY = process.env.CONTROL_PLANE_API_KEY;

// Validate URLs to ensure we're not accidentally connecting to customer API
function validateControlPlaneUrl(url: string): void {
    const forbidden = [':3001', '/v1/messages', '/v1/domains', '/v1/templates'];
    for (const pattern of forbidden) {
        if (url.includes(pattern)) {
            throw new Error(`Control Plane cannot connect to customer API. Attempted: ${url}`);
        }
    }
}

/**
 * Gets authentication headers for Control Plane API requests
 */
function getAuthHeaders(): HeadersInit {
    const headers: HeadersInit = {
        'Content-Type': 'application/json',
    };
    
    // Add API key if available (server-side)
    if (CONTROL_PLANE_API_KEY) {
        headers['x-control-plane-key'] = CONTROL_PLANE_API_KEY;
    }
    
    return headers;
}

/**
 * Makes an authenticated request to Control Plane APIs
 */
async function controlPlaneFetch(url: string, options: RequestInit = {}): Promise<Response> {
    validateControlPlaneUrl(url);
    
    const response = await fetch(url, {
        ...options,
        headers: {
            ...getAuthHeaders(),
            ...options.headers,
        },
        // Include credentials for session-based auth
        credentials: 'include',
    });
    
    // Check for auth errors
    if (response.status === 401) {
        throw new Error('Control Plane authentication failed. Please log in again.');
    }
    
    if (response.status === 403) {
        throw new Error('Access denied. You do not have permission to access this resource.');
    }
    
    return response;
}

export interface Lead {
    id: string;
    tenantId: string;
    companyName: string;
    domain: string;
    email: string | null;
    status: string;
    stage: string;
    score: number;
    createdAt: string;
}

export interface Campaign {
    id: string;
    tenantId: string;
    name: string;
    status: 'draft' | 'active' | 'paused' | 'completed';
    stats: {
        totalEnrolled: number;
        emailsSent: number;
        repliesReceived: number;
    };
}

export interface RiskProfile {
    tenantId: string;
    riskScore: number;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    flags: string[];
}

// ============================================
// Sales Autopilot API (Control Plane CRM)
// ============================================

export async function getLeads(tenantId: string): Promise<Lead[]> {
    const url = `${AUTOPILOT_API_URL}/api/v1/leads/${tenantId}`;
    
    const response = await controlPlaneFetch(url);
    const data = await response.json();
    return data.data;
}

export async function getCampaigns(tenantId: string): Promise<Campaign[]> {
    const url = `${AUTOPILOT_API_URL}/api/v1/campaigns/${tenantId}`;
    
    const response = await controlPlaneFetch(url);
    const data = await response.json();
    return data.data;
}

export async function getPipelineStats(tenantId: string): Promise<unknown> {
    const url = `${AUTOPILOT_API_URL}/api/v1/pipeline/${tenantId}`;
    
    const response = await controlPlaneFetch(url);
    const data = await response.json();
    return data.data;
}

export async function runLeadDiscovery(params: {
    tenantId: string;
    sources: string[];
    categories: string[];
}): Promise<unknown> {
    const url = `${AUTOPILOT_API_URL}/api/v1/discovery/run`;
    
    const response = await controlPlaneFetch(url, {
        method: 'POST',
        body: JSON.stringify(params),
    });
    const data = await response.json();
    return data.data;
}

// ============================================
// Compliance API (Control Plane Governance)
// ============================================

export async function getRiskProfile(tenantId: string): Promise<RiskProfile> {
    const url = `${COMPLIANCE_API_URL}/api/risk/${tenantId}`;
    
    const response = await controlPlaneFetch(url);
    return response.json();
}

export async function getAuditLogs(tenantId: string, options?: {
    action?: string;
    limit?: number;
}): Promise<unknown[]> {
    const params = new URLSearchParams();
    if (options?.action) params.set('action', options.action);
    if (options?.limit) params.set('limit', options.limit.toString());
    
    const url = `${COMPLIANCE_API_URL}/api/audit/${tenantId}?${params}`;
    
    const response = await controlPlaneFetch(url);
    const data = await response.json();
    return data.entries;
}

export async function getGDPRRequests(tenantId: string): Promise<unknown[]> {
    const url = `${COMPLIANCE_API_URL}/api/gdpr/${tenantId}`;
    
    const response = await controlPlaneFetch(url);
    const data = await response.json();
    return data.requests;
}

// ============================================
// Health Checks (public endpoints, no auth needed)
// ============================================

export async function checkAutopilotHealth(): Promise<{ status: string; service: string }> {
    const url = `${AUTOPILOT_API_URL}/health`;
    validateControlPlaneUrl(url);
    
    // Health checks don't need auth
    const response = await fetch(url);
    return response.json();
}

export async function checkComplianceHealth(): Promise<{ status: string }> {
    const url = `${COMPLIANCE_API_URL}/health`;
    validateControlPlaneUrl(url);
    
    // Health checks don't need auth
    const response = await fetch(url);
    return response.json();
}

// ============================================
// Extended Sales Autopilot API
// ============================================

export interface LeadDiscoveryParams {
    tenantId: string;
    sources: Array<'product_hunt' | 'g2' | 'capterra' | 'crunchbase'>;
    categories: string[];
    maxPagesPerSource?: number;
}

export interface LeadDiscoveryResult {
    leads: Lead[];
    stats: {
        totalFound: number;
        bySource: Record<string, number>;
    };
}

export async function runLeadDiscoveryJob(params: LeadDiscoveryParams): Promise<LeadDiscoveryResult> {
    const url = `${AUTOPILOT_API_URL}/api/v1/discovery/run`;
    
    const response = await controlPlaneFetch(url, {
        method: 'POST',
        body: JSON.stringify(params),
    });
    const data = await response.json();
    return data.data;
}

export async function updateLeadStage(leadId: string, stage: string): Promise<Lead> {
    const url = `${AUTOPILOT_API_URL}/api/v1/leads/${leadId}/stage`;
    
    const response = await controlPlaneFetch(url, {
        method: 'PATCH',
        body: JSON.stringify({ stage }),
    });
    const data = await response.json();
    return data.data;
}

export async function createCampaign(tenantId: string, campaign: {
    name: string;
    description?: string;
    fromEmail: string;
    fromName: string;
    replyTo?: string;
    templateId?: string;
}): Promise<Campaign> {
    const url = `${AUTOPILOT_API_URL}/api/v1/campaigns`;
    
    const response = await controlPlaneFetch(url, {
        method: 'POST',
        body: JSON.stringify({ tenantId, ...campaign }),
    });
    const data = await response.json();
    return data.data;
}

export async function updateCampaignStatus(
    campaignId: string,
    status: 'active' | 'paused'
): Promise<Campaign> {
    const url = `${AUTOPILOT_API_URL}/api/v1/campaigns/${campaignId}/status`;
    
    const response = await controlPlaneFetch(url, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
    });
    const data = await response.json();
    return data.data;
}

export async function enrollLeadInCampaign(
    campaignId: string,
    leadId: string
): Promise<{ enrollmentId: string }> {
    const url = `${AUTOPILOT_API_URL}/api/v1/campaigns/${campaignId}/enroll`;
    
    const response = await controlPlaneFetch(url, {
        method: 'POST',
        body: JSON.stringify({ leadId }),
    });
    const data = await response.json();
    return data.data;
}

// ============================================
// Extended Compliance API
// ============================================

export interface TenantRisk {
    tenantId: string;
    riskScore: number;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    flags: Array<{
        id: string;
        type: string;
        severity: 'warning' | 'critical';
        message: string;
        createdAt: string;
        resolved: boolean;
    }>;
    metrics: {
        bounceRate: number;
        complaintRate: number;
        dailyVolume: number;
    };
}

export async function getAllTenantRisks(): Promise<TenantRisk[]> {
    const url = `${COMPLIANCE_API_URL}/api/risk/all`;
    
    const response = await controlPlaneFetch(url);
    const data = await response.json();
    return data.profiles;
}

export async function getCriticalTenants(): Promise<TenantRisk[]> {
    const url = `${COMPLIANCE_API_URL}/api/risk/critical`;
    
    const response = await controlPlaneFetch(url);
    const data = await response.json();
    return data.profiles;
}

export async function resolveRiskFlag(
    tenantId: string,
    flagId: string,
    resolution: string
): Promise<void> {
    const url = `${COMPLIANCE_API_URL}/api/risk/${tenantId}/flags/${flagId}/resolve`;
    
    await controlPlaneFetch(url, {
        method: 'POST',
        body: JSON.stringify({ resolution }),
    });
}

export async function setTenantLimits(
    tenantId: string,
    limits: { daily?: number | null; hourly?: number | null }
): Promise<void> {
    const url = `${COMPLIANCE_API_URL}/api/risk/${tenantId}/limits`;
    
    await controlPlaneFetch(url, {
        method: 'PATCH',
        body: JSON.stringify(limits),
    });
}

export interface AuditEntry {
    id: string;
    timestamp: string;
    action: string;
    resource: string;
    resourceId: string;
    actorType: 'user' | 'system' | 'api';
    actorId: string;
    tenantId: string | null;
    status: 'success' | 'failure';
    ipAddress: string;
    details: Record<string, unknown>;
}

export async function getAuditLogsWithFilters(options: {
    tenantId?: string;
    action?: string;
    status?: string;
    startDate?: string;
    endDate?: string;
    limit?: number;
    offset?: number;
}): Promise<{ entries: AuditEntry[]; total: number }> {
    const params = new URLSearchParams();
    if (options.tenantId) params.set('tenantId', options.tenantId);
    if (options.action) params.set('action', options.action);
    if (options.status) params.set('status', options.status);
    if (options.startDate) params.set('startDate', options.startDate);
    if (options.endDate) params.set('endDate', options.endDate);
    if (options.limit) params.set('limit', options.limit.toString());
    if (options.offset) params.set('offset', options.offset.toString());
    
    const url = `${COMPLIANCE_API_URL}/api/audit?${params}`;
    
    const response = await controlPlaneFetch(url);
    return response.json();
}

export async function exportAuditLogs(options: {
    format: 'csv' | 'json';
    startDate?: string;
    endDate?: string;
    tenantId?: string;
}): Promise<{ exportId: string; downloadUrl: string }> {
    const url = `${COMPLIANCE_API_URL}/api/audit/export`;
    
    const response = await controlPlaneFetch(url, {
        method: 'POST',
        body: JSON.stringify(options),
    });
    return response.json();
}

export interface GDPRRequest {
    id: string;
    type: 'access' | 'deletion' | 'portability' | 'rectification' | 'restriction';
    status: 'pending' | 'verified' | 'processing' | 'completed' | 'rejected';
    email: string;
    tenantId: string;
    createdAt: string;
    completedAt: string | null;
    slaDeadline: string;
}

export async function getGDPRRequestsAll(): Promise<GDPRRequest[]> {
    const url = `${COMPLIANCE_API_URL}/api/gdpr/requests`;
    
    const response = await controlPlaneFetch(url);
    const data = await response.json();
    return data.requests;
}

export async function processGDPRRequest(
    requestId: string
): Promise<{ status: string; result?: Record<string, unknown> }> {
    const url = `${COMPLIANCE_API_URL}/api/gdpr/requests/${requestId}/process`;
    
    const response = await controlPlaneFetch(url, {
        method: 'POST',
    });
    return response.json();
}

export async function updateGDPRRequestStatus(
    requestId: string,
    status: GDPRRequest['status']
): Promise<GDPRRequest> {
    const url = `${COMPLIANCE_API_URL}/api/gdpr/requests/${requestId}`;
    
    const response = await controlPlaneFetch(url, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
    });
    return response.json();
}

export async function getComplianceStats(): Promise<{
    riskSummary: { low: number; medium: number; high: number; critical: number };
    gdprPending: number;
    auditEventsToday: number;
}> {
    const url = `${COMPLIANCE_API_URL}/api/stats`;
    
    const response = await controlPlaneFetch(url);
    return response.json();
}

// ============================================
// Secrets Management
// ============================================

export interface Secret {
    id: string;
    name: string;
    type: 'api_key' | 'smtp_password' | 'webhook_secret' | 'encryption_key';
    tenantId: string;
    createdAt: string;
    lastRotated: string;
    expiresAt: string | null;
}

export async function listSecrets(tenantId?: string): Promise<Secret[]> {
    const params = tenantId ? `?tenantId=${tenantId}` : '';
    const url = `${COMPLIANCE_API_URL}/api/secrets${params}`;
    
    const response = await controlPlaneFetch(url);
    return response.json();
}

export async function rotateSecret(secretId: string): Promise<{ secret: Secret; value: string }> {
    const url = `${COMPLIANCE_API_URL}/api/secrets/${secretId}/rotate`;
    
    const response = await controlPlaneFetch(url, {
        method: 'POST',
    });
    return response.json();
}

