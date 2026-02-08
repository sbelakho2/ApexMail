/**
 * Sales Autopilot Type Definitions
 */

// Lead Management Types
export interface Lead {
    id: string;
    tenantId: string;
    companyName: string;
    domain: string;
    website: string | null;
    email: string | null;
    emailVerified: boolean;
    phone: string | null;
    industry: string | null;
    employeeCount: string | null;
    revenue: string | null;
    technologies: string[];
    socialProfiles: SocialProfile[];
    location: LeadLocation | null;
    source: LeadSource;
    sourceUrl: string | null;
    score: number;
    status: LeadStatus;
    stage: PipelineStage;
    assignedTo: string | null;
    tags: string[];
    customFields: Record<string, unknown>;
    mxRecords: MxRecord[];
    emailProvider: string | null;
    lastContactedAt: Date | null;
    nextFollowUpAt: Date | null;
    createdAt: Date;
    updatedAt: Date;
}

export interface SocialProfile {
    platform: 'linkedin' | 'twitter' | 'facebook' | 'crunchbase' | 'github';
    url: string;
    handle: string | null;
}

export interface LeadLocation {
    country: string;
    countryCode: string;
    state: string | null;
    city: string | null;
    postalCode: string | null;
    timezone: string | null;
}

export interface MxRecord {
    exchange: string;
    priority: number;
}

export type LeadSource =
    | 'saas_directory'
    | 'product_hunt'
    | 'crunchbase'
    | 'linkedin'
    | 'manual'
    | 'csv_import'
    | 'api'
    | 'referral'
    | 'website';

export type LeadStatus =
    | 'new'
    | 'contacted'
    | 'qualified'
    | 'unqualified'
    | 'nurturing'
    | 'converted'
    | 'lost';

export type PipelineStage =
    | 'prospect'
    | 'outreach'
    | 'engaged'
    | 'demo_scheduled'
    | 'proposal'
    | 'negotiation'
    | 'closed_won'
    | 'closed_lost';

// Company Enrichment Types
export interface EnrichmentResult {
    companyName: string;
    domain: string;
    description: string | null;
    foundedYear: number | null;
    employeeRange: EmployeeRange | null;
    revenueRange: RevenueRange | null;
    industry: string | null;
    subIndustry: string | null;
    technologies: TechnologyStack[];
    socialProfiles: SocialProfile[];
    location: LeadLocation | null;
    funding: FundingInfo | null;
    contacts: ContactInfo[];
    keywords: string[];
    confidence: number;
    sources: EnrichmentSource[];
    enrichedAt: Date;
}

export interface EmployeeRange {
    min: number;
    max: number;
    label: string;
}

export interface RevenueRange {
    min: number;
    max: number;
    currency: string;
    label: string;
}

export interface TechnologyStack {
    name: string;
    category: string;
    confidence: number;
}

export interface FundingInfo {
    totalRaised: number | null;
    currency: string;
    lastRound: string | null;
    lastRoundDate: Date | null;
    investors: string[];
}

export interface ContactInfo {
    name: string;
    title: string | null;
    email: string | null;
    linkedin: string | null;
    confidence: number;
}

export interface EnrichmentSource {
    name: string;
    url: string;
    scrapedAt: Date;
}

// Drip Campaign Types
export interface DripCampaign {
    id: string;
    tenantId: string;
    name: string;
    description: string | null;
    status: CampaignStatus;
    fromEmail: string;
    fromName: string;
    replyTo: string | null;
    sequence: DripSequenceStep[];
    triggers: CampaignTrigger[];
    exitConditions: ExitCondition[];
    settings: CampaignSettings;
    stats: CampaignStats;
    createdBy: string;
    createdAt: Date;
    updatedAt: Date;
    startedAt: Date | null;
    pausedAt: Date | null;
}

export type CampaignStatus = 'draft' | 'active' | 'paused' | 'completed' | 'archived';

export interface DripSequenceStep {
    id: string;
    order: number;
    type: StepType;
    name: string;
    delay: StepDelay;
    content: StepContent;
    conditions: StepCondition[];
    abTest: AbTestConfig | null;
}

export type StepType = 'email' | 'wait' | 'condition' | 'action' | 'notification';

export interface StepDelay {
    value: number;
    unit: 'minutes' | 'hours' | 'days' | 'weeks';
    businessHoursOnly: boolean;
    jitterMinutes: number;
}

export interface StepContent {
    subject: string | null;
    htmlBody: string | null;
    textBody: string | null;
    templateId: string | null;
    variables: Record<string, string>;
}

export interface StepCondition {
    field: string;
    operator: ConditionOperator;
    value: unknown;
    thenStep: string | null;
    elseStep: string | null;
}

export type ConditionOperator =
    | 'equals'
    | 'not_equals'
    | 'contains'
    | 'not_contains'
    | 'greater_than'
    | 'less_than'
    | 'is_empty'
    | 'is_not_empty';

export interface AbTestConfig {
    enabled: boolean;
    variants: AbVariant[];
    winnerCriteria: 'open_rate' | 'click_rate' | 'reply_rate';
    testDurationHours: number;
}

export interface AbVariant {
    id: string;
    name: string;
    weight: number;
    subject: string;
    content: string;
}

export interface CampaignTrigger {
    type: TriggerType;
    config: Record<string, unknown>;
}

export type TriggerType =
    | 'lead_added'
    | 'tag_added'
    | 'stage_changed'
    | 'score_reached'
    | 'manual'
    | 'api'
    | 'schedule';

export interface ExitCondition {
    type: ExitConditionType;
    config: Record<string, unknown>;
}

export type ExitConditionType =
    | 'replied'
    | 'unsubscribed'
    | 'bounced'
    | 'converted'
    | 'tag_removed'
    | 'stage_changed'
    | 'manual';

export interface CampaignSettings {
    sendWindow: SendWindow;
    trackOpens: boolean;
    trackClicks: boolean;
    throttling: ThrottlingConfig;
    unsubscribeLink: boolean;
}

export interface SendWindow {
    enabled: boolean;
    timezone: string;
    days: number[]; // 0-6, Sunday = 0
    startHour: number;
    endHour: number;
}

export interface ThrottlingConfig {
    maxPerHour: number;
    maxPerDay: number;
    rampUp: boolean;
    rampUpDays: number;
}

export interface CampaignStats {
    totalEnrolled: number;
    activeCount: number;
    completedCount: number;
    exitedCount: number;
    emailsSent: number;
    emailsOpened: number;
    emailsClicked: number;
    repliesReceived: number;
    unsubscribed: number;
    bounced: number;
}

// Campaign Enrollment Types
export interface CampaignEnrollment {
    id: string;
    campaignId: string;
    leadId: string;
    status: EnrollmentStatus;
    currentStepId: string | null;
    completedSteps: string[];
    nextStepAt: Date | null;
    emailsSent: number;
    emailsOpened: number;
    emailsClicked: number;
    replied: boolean;
    exitReason: string | null;
    enrolledAt: Date;
    completedAt: Date | null;
    pausedAt: Date | null;
    metadata: Record<string, unknown>;
}

export type EnrollmentStatus = 'active' | 'paused' | 'completed' | 'exited';

// Inbox Sentinel Types
export interface InboxMessage {
    id: string;
    tenantId: string;
    leadId: string | null;
    campaignId: string | null;
    messageId: string;
    inReplyTo: string | null;
    from: EmailAddress;
    to: EmailAddress[];
    cc: EmailAddress[];
    subject: string;
    textBody: string | null;
    htmlBody: string | null;
    classification: MessageClassification;
    sentiment: SentimentAnalysis;
    intent: IntentAnalysis;
    suggestedAction: SuggestedAction | null;
    processed: boolean;
    processedAt: Date | null;
    receivedAt: Date;
    createdAt: Date;
}

export interface EmailAddress {
    email: string;
    name: string | null;
}

export type MessageClassification =
    | 'interested'
    | 'not_interested'
    | 'out_of_office'
    | 'bounce'
    | 'unsubscribe'
    | 'meeting_request'
    | 'question'
    | 'objection'
    | 'referral'
    | 'spam'
    | 'other';

export interface SentimentAnalysis {
    score: number; // -1 to 1
    label: 'negative' | 'neutral' | 'positive';
    confidence: number;
}

export interface IntentAnalysis {
    primary: string;
    secondary: string[];
    confidence: number;
}

export interface SuggestedAction {
    type: ActionType;
    description: string;
    priority: 'low' | 'medium' | 'high' | 'urgent';
    dueAt: Date | null;
}

export type ActionType =
    | 'follow_up'
    | 'schedule_demo'
    | 'send_info'
    | 'escalate'
    | 'close_lead'
    | 'update_crm'
    | 'no_action';

// Calendar & Scheduling Types
export interface DemoSlot {
    id: string;
    tenantId: string;
    userId: string;
    startTime: Date;
    endTime: Date;
    timezone: string;
    status: SlotStatus;
    bookedBy: string | null;
    leadId: string | null;
    meetingType: MeetingType;
    meetingLink: string | null;
    notes: string | null;
    createdAt: Date;
    updatedAt: Date;
}

export type SlotStatus = 'available' | 'booked' | 'cancelled' | 'completed';

export type MeetingType = 'demo' | 'discovery' | 'follow_up' | 'onboarding' | 'support';

export interface SchedulingPreferences {
    userId: string;
    defaultDuration: number;
    bufferBefore: number;
    bufferAfter: number;
    availableDays: number[];
    availableHours: AvailableHours[];
    timezone: string;
    maxBookingsPerDay: number;
    minNoticeHours: number;
    maxAdvanceDays: number;
}

export interface AvailableHours {
    dayOfWeek: number;
    startHour: number;
    startMinute: number;
    endHour: number;
    endMinute: number;
}

// Promotional Injection Types
export interface PromoConfig {
    id: string;
    tenantId: string;
    name: string;
    type: PromoType;
    placement: PromoPlacement;
    content: PromoContent;
    targeting: PromoTargeting;
    schedule: PromoSchedule;
    stats: PromoStats;
    active: boolean;
    createdAt: Date;
    updatedAt: Date;
}

export type PromoType = 'banner' | 'text_link' | 'cta_button' | 'signature' | 'ps_line';

export type PromoPlacement = 'header' | 'footer' | 'inline' | 'sidebar';

export interface PromoContent {
    text: string;
    html: string | null;
    link: string;
    imageUrl: string | null;
    ctaText: string | null;
}

export interface PromoTargeting {
    industries: string[];
    companySizes: string[];
    locations: string[];
    leadStages: PipelineStage[];
    excludeTags: string[];
}

export interface PromoSchedule {
    startDate: Date | null;
    endDate: Date | null;
    daysOfWeek: number[];
}

export interface PromoStats {
    impressions: number;
    clicks: number;
    conversions: number;
}

// CRM Pipeline Types
export interface PipelineConfig {
    id: string;
    tenantId: string;
    name: string;
    stages: PipelineStageConfig[];
    defaultStage: string;
    wonStage: string;
    lostStage: string;
    createdAt: Date;
    updatedAt: Date;
}

export interface PipelineStageConfig {
    id: string;
    name: string;
    order: number;
    color: string;
    probability: number;
    rottenDays: number | null;
    automations: StageAutomation[];
}

export interface StageAutomation {
    trigger: 'enter' | 'exit' | 'rotten';
    action: AutomationAction;
    config: Record<string, unknown>;
}

export type AutomationAction =
    | 'send_email'
    | 'create_task'
    | 'add_tag'
    | 'remove_tag'
    | 'assign_user'
    | 'start_campaign'
    | 'stop_campaign'
    | 'webhook';

// Activity Types
export interface LeadActivity {
    id: string;
    tenantId: string;
    leadId: string;
    type: ActivityType;
    description: string;
    data: Record<string, unknown>;
    userId: string | null;
    createdAt: Date;
}

export type ActivityType =
    | 'created'
    | 'updated'
    | 'stage_changed'
    | 'email_sent'
    | 'email_opened'
    | 'email_clicked'
    | 'email_replied'
    | 'call_logged'
    | 'meeting_scheduled'
    | 'meeting_completed'
    | 'note_added'
    | 'task_created'
    | 'task_completed'
    | 'tag_added'
    | 'tag_removed'
    | 'campaign_enrolled'
    | 'campaign_exited'
    | 'demo_rescheduled';

// Task Types
export interface LeadTask {
    id: string;
    tenantId: string;
    leadId: string;
    title: string;
    description: string | null;
    type: TaskType;
    priority: TaskPriority;
    status: TaskStatus;
    dueAt: Date | null;
    assignedTo: string | null;
    completedAt: Date | null;
    completedBy: string | null;
    createdBy: string;
    createdAt: Date;
    updatedAt: Date;
}

export type TaskType = 'call' | 'email' | 'meeting' | 'follow_up' | 'research' | 'other';

export type TaskPriority = 'low' | 'medium' | 'high' | 'urgent';

export type TaskStatus = 'pending' | 'in_progress' | 'completed' | 'cancelled';

// Export Types
export interface LeadExport {
    format: 'csv' | 'json' | 'xlsx';
    fields: string[];
    filters: LeadFilters;
    includeActivities: boolean;
    includeTasks: boolean;
}

export interface LeadFilters {
    status?: LeadStatus[];
    stage?: PipelineStage[];
    source?: LeadSource[];
    tags?: string[];
    assignedTo?: string[];
    createdAfter?: Date;
    createdBefore?: Date;
    lastContactedAfter?: Date;
    lastContactedBefore?: Date;
    scoreMin?: number;
    scoreMax?: number;
    search?: string;
}
