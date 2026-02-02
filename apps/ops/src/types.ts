/**
 * @apexmail/ops - SLO Definitions and Types
 * 
 * Service Level Objective definitions, indicators, and monitoring types.
 */

import { z } from 'zod';

// ============================================================================
// SLO Core Types
// ============================================================================

export const SLOTargetSchema = z.object({
    percentage: z.number().min(0).max(100),
    windowDays: z.number().min(1).max(365),
});

export type SLOTarget = z.infer<typeof SLOTargetSchema>;

export const SLITypeSchema = z.enum([
    'availability',
    'latency',
    'throughput',
    'error_rate',
    'saturation',
]);

export type SLIType = z.infer<typeof SLITypeSchema>;

export interface ServiceLevelIndicator {
    id: string;
    name: string;
    description: string;
    type: SLIType;
    metric: string;
    goodThreshold: number;
    unit: string;
    aggregation: 'avg' | 'p50' | 'p90' | 'p95' | 'p99' | 'max' | 'min' | 'sum' | 'count';
}

export interface ServiceLevelObjective {
    id: string;
    name: string;
    description: string;
    service: string;
    sli: ServiceLevelIndicator;
    target: SLOTarget;
    errorBudget: number; // Calculated from target
    alerting: SLOAlertConfig;
    metadata: Record<string, string>;
}

export interface SLOAlertConfig {
    burnRateThresholds: BurnRateThreshold[];
    notificationChannels: string[];
    silenceDurationMinutes: number;
}

export interface BurnRateThreshold {
    windowMinutes: number;
    burnRate: number;
    severity: 'critical' | 'warning' | 'info';
}

// ============================================================================
// SLO Status Types
// ============================================================================

export interface SLOStatus {
    sloId: string;
    current: number;
    target: number;
    errorBudgetRemaining: number;
    errorBudgetConsumed: number;
    status: 'healthy' | 'warning' | 'critical' | 'exhausted';
    trend: 'improving' | 'degrading' | 'stable';
    lastUpdated: Date;
    windowStart: Date;
    windowEnd: Date;
}

export interface SLOBurnRate {
    sloId: string;
    shortWindow: { minutes: number; rate: number };
    longWindow: { minutes: number; rate: number };
    isAlerting: boolean;
    severity: 'critical' | 'warning' | 'info' | 'none';
}

export interface ErrorBudgetReport {
    sloId: string;
    period: { start: Date; end: Date };
    totalBudgetMinutes: number;
    consumedMinutes: number;
    remainingMinutes: number;
    consumptionRate: number;
    projectedExhaustionDate: Date | null;
    incidents: ErrorBudgetIncident[];
}

export interface ErrorBudgetIncident {
    id: string;
    startTime: Date;
    endTime: Date | null;
    durationMinutes: number;
    budgetConsumed: number;
    description: string;
}

// ============================================================================
// Metrics Types
// ============================================================================

export interface MetricDataPoint {
    timestamp: Date;
    value: number;
    labels: Record<string, string>;
}

export interface MetricTimeSeries {
    metric: string;
    labels: Record<string, string>;
    dataPoints: MetricDataPoint[];
}

export interface MetricQuery {
    metric: string;
    labels?: Record<string, string>;
    startTime: Date;
    endTime: Date;
    step?: string;
    aggregation?: string;
}

export interface MetricResult {
    query: MetricQuery;
    series: MetricTimeSeries[];
    error?: string;
}

// ============================================================================
// Alert Types
// ============================================================================

export type AlertChannel = 'slack' | 'email' | 'pagerduty' | 'webhook' | 'sms';
export type AlertSeverity = 'critical' | 'error' | 'warning' | 'info';
export type AlertStatus = 'firing' | 'pending' | 'resolved' | 'acknowledged' | 'silenced';

export interface NotificationPreferences {
    channels: AlertChannel[];
    quietHours?: { start: string; end: string };
    escalationPolicy?: string;
}

export interface AlertCondition {
    metric: string;
    operator: 'greater_than' | 'less_than' | 'equals' | 'not_equals';
    threshold: number;
    duration: number;
}

export interface Alert {
    id: string;
    ruleId?: string;
    name: string;
    severity: AlertSeverity;
    status: AlertStatus;
    sloId?: string;
    service?: string;
    description: string;
    startsAt: Date;
    endsAt?: Date;
    labels: Record<string, string>;
    annotations: Record<string, string>;
    generatorURL?: string;
    acknowledgedBy?: string;
    acknowledgedAt?: Date;
    silencedUntil?: Date;
}

export interface AlertRule {
    id: string;
    name: string;
    description?: string;
    expression?: string;
    condition?: AlertCondition;
    duration?: string;
    severity: AlertSeverity;
    channels?: AlertChannel[];
    labels: Record<string, string>;
    annotations?: Record<string, string>;
    enabled: boolean;
}

export interface AlertNotification {
    alertId: string;
    channel: string;
    sentAt: Date;
    acknowledged: boolean;
    acknowledgedBy?: string;
    acknowledgedAt?: Date;
}

// ============================================================================
// Incident Types
// ============================================================================

export type IncidentSeverity = 'critical' | 'high' | 'medium' | 'low' | 'sev1' | 'sev2' | 'sev3' | 'sev4';
export type IncidentStatus = 'investigating' | 'identified' | 'monitoring' | 'resolved';

export interface Incident {
    id: string;
    title: string;
    description: string;
    severity: IncidentSeverity;
    status: IncidentStatus;
    service?: string;
    affectedServices?: string[];
    affectedSLOs?: string[];
    startTime?: Date;
    endTime?: Date;
    createdAt?: Date;
    updatedAt?: Date;
    resolvedAt?: Date;
    resolvedBy?: string;
    acknowledgedAt?: Date;
    acknowledgedBy?: string;
    reportedBy?: string;
    timeline?: IncidentTimelineEntry[];
    responders?: string[];
    commander?: string;
    postmortemId?: string;
    metadata?: Record<string, string>;
}

export interface IncidentTimelineEntry {
    id?: string;
    timestamp: Date;
    author?: string;
    actor?: string;
    type: 'status_change' | 'update' | 'action' | 'resolution' | 'created' | 'note' | 'severity_change' | 'role_assigned' | 'communication' | 'communication';
    content?: string;
    description?: string;
    metadata?: Record<string, unknown>;
}

// Aliases for backwards compatibility
export type IncidentTimeline = {
    incidentId: string;
    events: IncidentTimelineEntry[];
};

export type IncidentTimelineEvent = IncidentTimelineEntry;

export interface IncidentSummary {
    totalIncidents: number;
    byStatus: Record<IncidentStatus, number>;
    bySeverity: Record<IncidentSeverity, number>;
    meanTimeToDetect: number;
    meanTimeToResolve: number;
    affectedServices: string[];
}

// ============================================================================
// Status Page Types
// ============================================================================

export type ComponentStatus = 'operational' | 'degraded' | 'partial_outage' | 'major_outage' | 'maintenance';

export interface StatusPageComponent {
    id: string;
    name: string;
    description: string;
    status: ComponentStatus;
    group?: string;
    order: number;
    visible: boolean;
}

export interface StatusPageGroup {
    id: string;
    name: string;
    description: string;
    components: StatusPageComponent[];
    status: ComponentStatus;
    order: number;
}

export interface StatusPageIncident {
    id: string;
    title: string;
    status: 'investigating' | 'identified' | 'monitoring' | 'resolved';
    impact: 'none' | 'minor' | 'major' | 'critical';
    affectedComponents: string[];
    createdAt: Date;
    updatedAt: Date;
    resolvedAt?: Date;
    updates: StatusPageUpdate[];
}

export interface StatusPageUpdate {
    id: string;
    status: string;
    body: string;
    createdAt: Date;
    author: string;
}

export interface MaintenanceWindow {
    id: string;
    title: string;
    description: string;
    scheduledStart: Date;
    scheduledEnd: Date;
    actualStart?: Date;
    actualEnd?: Date;
    status: 'scheduled' | 'in_progress' | 'completed' | 'cancelled';
    affectedComponents: string[];
}

export interface StatusPageData {
    overallStatus: ComponentStatus;
    components: StatusPageComponent[];
    groups: StatusPageGroup[];
    activeIncidents: StatusPageIncident[];
    scheduledMaintenance: MaintenanceWindow[];
    uptime: {
        daily: number;
        weekly: number;
        monthly: number;
    };
}

// ============================================================================
// Trust Center Types
// ============================================================================

export interface ComplianceCertification {
    id: string;
    name: string;
    issuer: string;
    validFrom: Date;
    validUntil: Date;
    documentUrl?: string;
    status: 'valid' | 'expiring' | 'expired';
}

export interface SecurityPractice {
    id: string;
    category: string;
    title: string;
    description: string;
    implemented: boolean;
    evidence?: string;
}

export interface DataProcessingInfo {
    region: string;
    dataTypes: string[];
    retentionPeriod: string;
    encryptionAtRest: boolean;
    encryptionInTransit: boolean;
    subProcessors: SubProcessor[];
}

export interface SubProcessor {
    id?: string;
    name: string;
    purpose: string;
    location: string;
    dataProcessed?: string[];
    dataCategories?: string[];
    website?: string;
    dpaUrl?: string;
    addedAt?: Date;
}

export interface TrustCenterData {
    company?: {
        name: string;
        legalEntity: string;
        supportEmail: string;
        dpoEmail: string;
    };
    certifications: TrustCenterCertification[] | ComplianceCertification[];
    documents?: TrustCenterDocument[];
    securityControls?: Record<string, unknown[]>;
    securityPractices?: SecurityPractice[];
    subProcessors?: SubProcessor[];
    dataPractices?: unknown[];
    dataProcessing?: DataProcessingInfo;
    faq?: { question: string; answer: string; category: string }[];
    lastAuditDate?: Date;
    lastUpdated?: Date;
    securityContact?: string;
    privacyPolicyUrl?: string;
    termsOfServiceUrl?: string;
}

export interface TrustCenterCertification {
    id: string;
    name: string;
    issuer: string;
    issuedAt?: Date;
    validFrom?: Date;
    validUntil?: Date;
    expiresAt?: Date;
    documentUrl?: string;
    status: 'valid' | 'expiring' | 'expired';
    description?: string;
}

export interface TrustCenterDocument {
    id: string;
    name: string;
    type?: string;
    description?: string;
    category?: string;
    version?: string;
    url?: string;
    lastUpdated?: Date;
    requiresNda?: boolean;
}

// ============================================================================
// Observability Types
// ============================================================================

export interface Span {
    traceId: string;
    spanId: string;
    parentSpanId?: string;
    operationName: string;
    serviceName: string;
    startTime: Date;
    endTime: Date;
    duration: number;
    status: 'ok' | 'error' | 'unset';
    attributes: Record<string, string | number | boolean>;
    events: SpanEvent[];
}

export interface SpanEvent {
    name: string;
    timestamp: Date;
    attributes: Record<string, string | number | boolean>;
}

export interface Trace {
    traceId: string;
    rootSpan: Span;
    spans: Span[];
    duration: number;
    services: string[];
    hasErrors: boolean;
}

export interface LogEntry {
    timestamp: Date;
    level: 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';
    message: string;
    service: string;
    traceId?: string;
    spanId?: string;
    attributes: Record<string, unknown>;
}

// ============================================================================
// Health Check Types
// ============================================================================

export type HealthStatus = 'healthy' | 'degraded' | 'unhealthy';

export interface HealthCheckResult {
    healthy: boolean;
    latency?: number;
    error?: string;
    details?: Record<string, unknown>;
}

export interface HealthCheck {
    name: string;
    status: HealthStatus;
    latency?: number;
    message?: string;
    lastCheck: Date;
}

export interface ServiceHealth {
    service: string;
    status: HealthStatus;
    version?: string;
    uptime?: number;
    checks?: HealthCheck[];
    dependencies?: DependencyHealth[];
    latency?: number;
    lastCheck?: Date;
    details?: Record<string, unknown>;
}

export interface DependencyHealth {
    name: string;
    type: 'database' | 'cache' | 'queue' | 'external_api' | 'storage';
    status: HealthStatus;
    latency?: number;
    error?: string;
}

export interface SystemHealth {
    timestamp: Date;
    overallStatus: HealthStatus;
    services: ServiceHealth[];
    alerts: Alert[];
}

// ============================================================================
// Configuration Types
// ============================================================================

export interface OpsConfig {
    environment: 'development' | 'staging' | 'production';
    services: ServiceConfig[];
    slos: ServiceLevelObjective[];
    alerting: AlertingConfig;
    statusPage: StatusPageConfig;
    telemetry: TelemetryConfig;
}

export interface ServiceConfig {
    name: string;
    url: string;
    healthEndpoint: string;
    metricsEndpoint: string;
    criticalDependencies: string[];
    team: string;
    oncall: string;
}

export interface AlertingConfig {
    defaultChannels: string[];
    escalationPolicy: EscalationPolicy;
    quietHours?: { start: string; end: string; timezone: string };
    pageOnlyForSeverity: AlertSeverity[];
}

export interface EscalationPolicy {
    levels: EscalationLevel[];
    repeatIntervalMinutes: number;
}

export interface EscalationLevel {
    delayMinutes: number;
    targets: string[];
    notifyPrevious: boolean;
}

export interface StatusPageConfig {
    enabled: boolean;
    publicUrl: string;
    allowSubscriptions: boolean;
    customDomain?: string;
    branding: {
        logo?: string;
        primaryColor?: string;
        companyName: string;
    };
}

export interface TelemetryConfig {
    metrics: {
        enabled: boolean;
        endpoint: string;
        interval: number;
    };
    tracing: {
        enabled: boolean;
        endpoint: string;
        sampleRate: number;
    };
    logging: {
        level: string;
        format: 'json' | 'text';
        destination: string;
    };
}
