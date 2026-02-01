/**
 * Compliance Type Definitions
 */

// Tenant Risk Assessment
export interface TenantRiskProfile {
    tenantId: string;
    riskScore: number;
    riskLevel: RiskLevel;
    factors: RiskFactor[];
    limits: TenantLimits;
    flags: RiskFlag[];
    lastAssessedAt: Date;
    nextAssessmentAt: Date;
    createdAt: Date;
    updatedAt: Date;
}

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface RiskFactor {
    type: RiskFactorType;
    score: number;
    weight: number;
    details: string;
    evidence: Record<string, unknown>;
}

export type RiskFactorType =
    | 'spam_complaints'
    | 'bounce_rate'
    | 'phishing_detection'
    | 'content_violation'
    | 'sending_pattern'
    | 'account_age'
    | 'verification_status'
    | 'payment_history'
    | 'list_quality'
    | 'engagement_rate';

export interface TenantLimits {
    maxDailyEmails: number;
    maxHourlyEmails: number;
    maxRecipients: number;
    maxAttachmentSizeMb: number;
    requireDoubleOptIn: boolean;
    requireUnsubscribeLink: boolean;
    allowedDomains: string[];
    blockedRecipientPatterns: string[];
}

export interface RiskFlag {
    type: RiskFlagType;
    severity: 'warning' | 'alert' | 'critical';
    message: string;
    raisedAt: Date;
    resolvedAt: Date | null;
    autoResolved: boolean;
}

export type RiskFlagType =
    | 'high_bounce_rate'
    | 'spam_trap_hit'
    | 'blocklist_detected'
    | 'unusual_sending_pattern'
    | 'phishing_content'
    | 'malware_attachment'
    | 'suspended_account'
    | 'payment_failed';

// Content Scanning
export interface ContentScanResult {
    id: string;
    tenantId: string;
    messageId: string;
    scannedAt: Date;
    results: {
        spam: SpamAnalysis;
        phishing: PhishingAnalysis;
        malware: MalwareAnalysis;
        policy: PolicyAnalysis;
    };
    overallVerdict: ScanVerdict;
    actions: ContentAction[];
}

export type ScanVerdict = 'clean' | 'suspicious' | 'blocked';

export interface SpamAnalysis {
    score: number;
    isSpam: boolean;
    triggers: SpamTrigger[];
}

export interface SpamTrigger {
    rule: string;
    score: number;
    description: string;
}

export interface PhishingAnalysis {
    score: number;
    isPhishing: boolean;
    indicators: PhishingIndicator[];
}

export interface PhishingIndicator {
    type: 'url' | 'content' | 'sender' | 'attachment';
    indicator: string;
    confidence: number;
    description: string;
}

export interface MalwareAnalysis {
    clean: boolean;
    threats: MalwareThreat[];
}

export interface MalwareThreat {
    name: string;
    type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    location: string;
}

export interface PolicyAnalysis {
    compliant: boolean;
    violations: PolicyViolation[];
}

export interface PolicyViolation {
    policy: string;
    rule: string;
    description: string;
    severity: 'warning' | 'error';
}

export interface ContentAction {
    action: 'allow' | 'quarantine' | 'reject' | 'modify';
    reason: string;
    appliedAt: Date;
}

// Audit Logging
export interface AuditLogEntry {
    id: string;
    tenantId: string | null;
    userId: string | null;
    sessionId: string | null;
    action: AuditAction;
    resource: AuditResource;
    resourceId: string | null;
    details: Record<string, unknown>;
    ipAddress: string | null;
    userAgent: string | null;
    outcome: 'success' | 'failure';
    errorMessage: string | null;
    timestamp: Date;
    hash: string;
    previousHash: string | null;
    signature: string;
}

export type AuditAction =
    | 'create'
    | 'read'
    | 'update'
    | 'delete'
    | 'login'
    | 'logout'
    | 'export'
    | 'import'
    | 'send'
    | 'receive'
    | 'configure'
    | 'approve'
    | 'reject'
    | 'escalate';

export type AuditResource =
    | 'tenant'
    | 'user'
    | 'domain'
    | 'api_key'
    | 'message'
    | 'campaign'
    | 'list'
    | 'subscriber'
    | 'template'
    | 'webhook'
    | 'settings'
    | 'billing'
    | 'consent';

export interface AuditLogQuery {
    tenantId?: string;
    userId?: string;
    action?: AuditAction;
    resource?: AuditResource;
    resourceId?: string;
    startDate?: Date;
    endDate?: Date;
    outcome?: 'success' | 'failure';
    limit?: number;
    offset?: number;
}

// GDPR & Privacy
export interface ConsentRecord {
    id: string;
    tenantId: string;
    subscriberId: string;
    email: string;
    consentType: ConsentType;
    granted: boolean;
    grantedAt: Date | null;
    revokedAt: Date | null;
    source: ConsentSource;
    ipAddress: string | null;
    userAgent: string | null;
    proofDocument: string | null;
    expiresAt: Date | null;
    metadata: Record<string, unknown>;
}

export type ConsentType =
    | 'marketing'
    | 'transactional'
    | 'analytics'
    | 'profiling'
    | 'third_party'
    | 'data_processing';

export type ConsentSource =
    | 'form'
    | 'api'
    | 'import'
    | 'double_opt_in'
    | 'preference_center';

export interface DataSubjectRequest {
    id: string;
    tenantId: string;
    requestType: DataSubjectRequestType;
    email: string;
    verificationToken: string;
    verified: boolean;
    verifiedAt: Date | null;
    status: RequestStatus;
    requestedAt: Date;
    processedAt: Date | null;
    completedAt: Date | null;
    expiresAt: Date;
    result: DataSubjectRequestResult | null;
}

export type DataSubjectRequestType =
    | 'access'
    | 'rectification'
    | 'erasure'
    | 'portability'
    | 'restriction'
    | 'objection';

export type RequestStatus =
    | 'pending_verification'
    | 'verified'
    | 'processing'
    | 'completed'
    | 'rejected'
    | 'expired';

export interface DataSubjectRequestResult {
    data?: Record<string, unknown>;
    exportUrl?: string;
    exportExpiresAt?: Date;
    deletedRecords?: number;
    modifiedRecords?: number;
    rejectionReason?: string;
}

// Secret Management
export interface Secret {
    id: string;
    tenantId: string;
    name: string;
    type: SecretType;
    encryptedValue: string;
    version: number;
    rotationSchedule: RotationSchedule | null;
    lastRotatedAt: Date | null;
    nextRotationAt: Date | null;
    createdBy: string;
    createdAt: Date;
    updatedAt: Date;
    expiresAt: Date | null;
}

export type SecretType =
    | 'api_key'
    | 'smtp_password'
    | 'webhook_secret'
    | 'encryption_key'
    | 'oauth_token'
    | 'certificate';

export interface RotationSchedule {
    intervalDays: number;
    autoRotate: boolean;
    notifyBeforeDays: number;
}

export interface SecretAccess {
    id: string;
    secretId: string;
    userId: string;
    accessType: 'read' | 'write' | 'admin';
    grantedBy: string;
    grantedAt: Date;
    expiresAt: Date | null;
    revokedAt: Date | null;
}

// Abuse Prevention
export interface AbuseReport {
    id: string;
    tenantId: string;
    reportType: AbuseReportType;
    reportedBy: string;
    reportedEmail: string | null;
    messageId: string | null;
    description: string;
    evidence: AbuseEvidence[];
    status: AbuseReportStatus;
    assignedTo: string | null;
    resolution: string | null;
    resolvedAt: Date | null;
    createdAt: Date;
    updatedAt: Date;
}

export type AbuseReportType =
    | 'spam'
    | 'phishing'
    | 'malware'
    | 'harassment'
    | 'fraud'
    | 'impersonation'
    | 'other';

export type AbuseReportStatus =
    | 'new'
    | 'investigating'
    | 'confirmed'
    | 'resolved'
    | 'dismissed';

export interface AbuseEvidence {
    type: 'email' | 'screenshot' | 'headers' | 'log' | 'other';
    content: string;
    timestamp: Date;
}

// Rate Limiting
export interface RateLimitConfig {
    tenantId: string;
    limits: RateLimitRule[];
    overrides: RateLimitOverride[];
    updatedAt: Date;
}

export interface RateLimitRule {
    name: string;
    resource: string;
    maxRequests: number;
    windowSeconds: number;
    action: 'throttle' | 'block' | 'queue';
}

export interface RateLimitOverride {
    reason: string;
    rule: string;
    multiplier: number;
    expiresAt: Date;
    grantedBy: string;
}
