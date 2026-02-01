/**
 * Drip Campaign Engine
 * Manages automated email sequences with conditional logic
 */

import { CronJob } from 'cron';
import { createLogger, generateId } from '@apexmail/lib';
import { config } from '../config.js';
import type {
    DripCampaign,
    DripSequenceStep,
    CampaignEnrollment,
    Lead,
    StepDelay,
    StepCondition,
    CampaignStatus,
    AbVariant,
} from '../types.js';

const logger = createLogger({ name: 'drip-engine', level: 'info' });

// In-memory storage for demo - in production, use database
const campaigns = new Map<string, DripCampaign>();
const enrollments = new Map<string, CampaignEnrollment>();
const scheduledJobs = new Map<string, CronJob>();

/**
 * Creates a new drip campaign
 */
export function createCampaign(
    tenantId: string,
    data: Omit<
        DripCampaign,
        'id' | 'tenantId' | 'status' | 'stats' | 'createdAt' | 'updatedAt' | 'startedAt' | 'pausedAt'
    >
): DripCampaign {
    const campaign: DripCampaign = {
        id: generateId('campaign'),
        tenantId,
        status: 'draft',
        stats: {
            totalEnrolled: 0,
            activeCount: 0,
            completedCount: 0,
            exitedCount: 0,
            emailsSent: 0,
            emailsOpened: 0,
            emailsClicked: 0,
            repliesReceived: 0,
            unsubscribed: 0,
            bounced: 0,
        },
        createdAt: new Date(),
        updatedAt: new Date(),
        startedAt: null,
        pausedAt: null,
        ...data,
    };

    campaigns.set(campaign.id, campaign);
    logger.info('Created campaign', { campaignId: campaign.id, name: campaign.name });

    return campaign;
}

/**
 * Updates campaign status
 */
export function updateCampaignStatus(
    campaignId: string,
    status: CampaignStatus
): DripCampaign | null {
    const campaign = campaigns.get(campaignId);
    if (!campaign) {
        return null;
    }

    campaign.status = status;
    campaign.updatedAt = new Date();

    if (status === 'active' && !campaign.startedAt) {
        campaign.startedAt = new Date();
    } else if (status === 'paused') {
        campaign.pausedAt = new Date();
    }

    logger.info('Updated campaign status', { campaignId, status });

    return campaign;
}

/**
 * Adds a step to a campaign sequence
 */
export function addSequenceStep(
    campaignId: string,
    step: Omit<DripSequenceStep, 'id' | 'order'>
): DripSequenceStep | null {
    const campaign = campaigns.get(campaignId);
    if (!campaign || campaign.status !== 'draft') {
        return null;
    }

    const newStep: DripSequenceStep = {
        id: generateId('step'),
        order: campaign.sequence.length + 1,
        ...step,
    };

    campaign.sequence.push(newStep);
    campaign.updatedAt = new Date();

    return newStep;
}

/**
 * Calculates the next execution time for a step
 */
function calculateNextStepTime(delay: StepDelay, fromDate: Date = new Date()): Date {
    let delayMs: number;

    switch (delay.unit) {
        case 'minutes':
            delayMs = delay.value * 60 * 1000;
            break;
        case 'hours':
            delayMs = delay.value * 60 * 60 * 1000;
            break;
        case 'days':
            delayMs = delay.value * 24 * 60 * 60 * 1000;
            break;
        case 'weeks':
            delayMs = delay.value * 7 * 24 * 60 * 60 * 1000;
            break;
    }

    // Add jitter to prevent emails from being sent at exactly the same time
    const jitterMs = Math.random() * delay.jitterMinutes * 60 * 1000;
    const nextTime = new Date(fromDate.getTime() + delayMs + jitterMs);

    // If business hours only, adjust to next business day/hour
    if (delay.businessHoursOnly) {
        return adjustToBusinessHours(nextTime);
    }

    return nextTime;
}

/**
 * Adjusts a date to fall within business hours
 */
function adjustToBusinessHours(date: Date): Date {
    const adjusted = new Date(date);
    const hour = adjusted.getHours();
    const day = adjusted.getDay();

    // If weekend, move to Monday
    if (day === 0) {
        adjusted.setDate(adjusted.getDate() + 1);
    } else if (day === 6) {
        adjusted.setDate(adjusted.getDate() + 2);
    }

    // If before business hours, move to start
    if (hour < config.calendar.availableHoursStart) {
        adjusted.setHours(config.calendar.availableHoursStart, 0, 0, 0);
    }

    // If after business hours, move to next day start
    if (hour >= config.calendar.availableHoursEnd) {
        adjusted.setDate(adjusted.getDate() + 1);
        adjusted.setHours(config.calendar.availableHoursStart, 0, 0, 0);

        // Check if moved to weekend
        const newDay = adjusted.getDay();
        if (newDay === 0) {
            adjusted.setDate(adjusted.getDate() + 1);
        } else if (newDay === 6) {
            adjusted.setDate(adjusted.getDate() + 2);
        }
    }

    return adjusted;
}

/**
 * Evaluates step conditions
 */
function evaluateCondition(
    condition: StepCondition,
    lead: Lead,
    enrollment: CampaignEnrollment
): boolean {
    const fieldValue = getFieldValue(condition.field, lead, enrollment);

    switch (condition.operator) {
        case 'equals':
            return fieldValue === condition.value;
        case 'not_equals':
            return fieldValue !== condition.value;
        case 'contains':
            return String(fieldValue).includes(String(condition.value));
        case 'not_contains':
            return !String(fieldValue).includes(String(condition.value));
        case 'greater_than':
            return Number(fieldValue) > Number(condition.value);
        case 'less_than':
            return Number(fieldValue) < Number(condition.value);
        case 'is_empty':
            return fieldValue === null || fieldValue === undefined || fieldValue === '';
        case 'is_not_empty':
            return fieldValue !== null && fieldValue !== undefined && fieldValue !== '';
        default:
            return false;
    }
}

/**
 * Gets field value from lead or enrollment
 */
function getFieldValue(
    field: string,
    lead: Lead,
    enrollment: CampaignEnrollment
): unknown {
    if (field.startsWith('lead.')) {
        const leadField = field.substring(5) as keyof Lead;
        return lead[leadField];
    }

    if (field.startsWith('enrollment.')) {
        const enrollmentField = field.substring(11) as keyof CampaignEnrollment;
        return enrollment[enrollmentField];
    }

    // Check custom fields
    if (lead.customFields && field in lead.customFields) {
        return lead.customFields[field];
    }

    return undefined;
}

/**
 * Selects A/B test variant
 */
function selectAbVariant(abTest: { variants: AbVariant[] }): AbVariant {
    const totalWeight = abTest.variants.reduce((sum, v) => sum + v.weight, 0);
    let random = Math.random() * totalWeight;

    for (const variant of abTest.variants) {
        random -= variant.weight;
        if (random <= 0) {
            return variant;
        }
    }

    // variants array is never empty when called, return first element
    return abTest.variants[0]!;
}

/**
 * Enrolls a lead in a campaign
 */
export function enrollLead(
    campaignId: string,
    lead: Lead,
    metadata?: Record<string, unknown>
): CampaignEnrollment | null {
    const campaign = campaigns.get(campaignId);
    if (!campaign || campaign.status !== 'active') {
        return null;
    }

    // Check if already enrolled
    const existingEnrollment = Array.from(enrollments.values()).find(
        (e) => e.campaignId === campaignId && e.leadId === lead.id
    );

    if (existingEnrollment) {
        logger.debug('Lead already enrolled', { campaignId, leadId: lead.id });
        return existingEnrollment;
    }

    const firstStep = campaign.sequence[0];
    const nextStepAt = firstStep
        ? calculateNextStepTime(firstStep.delay)
        : null;

    const enrollment: CampaignEnrollment = {
        id: generateId('enrollment'),
        campaignId,
        leadId: lead.id,
        status: 'active',
        currentStepId: firstStep?.id || null,
        completedSteps: [],
        nextStepAt,
        emailsSent: 0,
        emailsOpened: 0,
        emailsClicked: 0,
        replied: false,
        exitReason: null,
        enrolledAt: new Date(),
        completedAt: null,
        pausedAt: null,
        metadata: metadata || {},
    };

    enrollments.set(enrollment.id, enrollment);

    // Update campaign stats
    campaign.stats.totalEnrolled++;
    campaign.stats.activeCount++;

    logger.info('Enrolled lead in campaign', {
        campaignId,
        leadId: lead.id,
        enrollmentId: enrollment.id,
    });

    return enrollment;
}

/**
 * Processes a single enrollment step
 */
export async function processEnrollmentStep(
    enrollmentId: string,
    lead: Lead,
    sendEmail: (params: {
        to: string;
        subject: string;
        htmlBody: string;
        textBody: string;
    }) => Promise<{ messageId: string }>
): Promise<{
    success: boolean;
    action: 'sent' | 'skipped' | 'completed' | 'exited';
    nextStepAt: Date | null;
}> {
    const enrollment = enrollments.get(enrollmentId);
    if (!enrollment || enrollment.status !== 'active') {
        return { success: false, action: 'skipped', nextStepAt: null };
    }

    const campaign = campaigns.get(enrollment.campaignId);
    if (!campaign || campaign.status !== 'active') {
        return { success: false, action: 'skipped', nextStepAt: null };
    }

    const currentStep = campaign.sequence.find(
        (s) => s.id === enrollment.currentStepId
    );

    if (!currentStep) {
        // No more steps, mark as completed
        enrollment.status = 'completed';
        enrollment.completedAt = new Date();
        campaign.stats.activeCount--;
        campaign.stats.completedCount++;

        return { success: true, action: 'completed', nextStepAt: null };
    }

    // Check exit conditions
    for (const exitCondition of campaign.exitConditions) {
        let shouldExit = false;

        switch (exitCondition.type) {
            case 'replied':
                shouldExit = enrollment.replied;
                break;
            case 'unsubscribed':
                shouldExit = false; // Would check actual unsubscribe status
                break;
            case 'bounced':
                shouldExit = false; // Would check actual bounce status
                break;
            case 'converted':
                shouldExit = lead.status === 'converted';
                break;
        }

        if (shouldExit) {
            enrollment.status = 'exited';
            enrollment.exitReason = exitCondition.type;
            campaign.stats.activeCount--;
            campaign.stats.exitedCount++;

            logger.info('Lead exited campaign', {
                enrollmentId,
                reason: exitCondition.type,
            });

            return { success: true, action: 'exited', nextStepAt: null };
        }
    }

    // Check step conditions
    if (currentStep.conditions.length > 0) {
        for (const condition of currentStep.conditions) {
            const result = evaluateCondition(condition, lead, enrollment);

            if (!result && condition.elseStep) {
                // Jump to else step
                enrollment.currentStepId = condition.elseStep;
                const elseStep = campaign.sequence.find(
                    (s) => s.id === condition.elseStep
                );
                enrollment.nextStepAt = elseStep
                    ? calculateNextStepTime(elseStep.delay)
                    : null;

                return {
                    success: true,
                    action: 'skipped',
                    nextStepAt: enrollment.nextStepAt,
                };
            }

            if (result && condition.thenStep) {
                enrollment.currentStepId = condition.thenStep;
                const thenStep = campaign.sequence.find(
                    (s) => s.id === condition.thenStep
                );
                enrollment.nextStepAt = thenStep
                    ? calculateNextStepTime(thenStep.delay)
                    : null;
            }
        }
    }

    // Process step based on type
    switch (currentStep.type) {
        case 'email': {
            // Select A/B variant if configured
            let subject = currentStep.content.subject || '';
            let htmlBody = currentStep.content.htmlBody || '';
            let textBody = currentStep.content.textBody || '';

            if (currentStep.abTest?.enabled) {
                const variant = selectAbVariant(currentStep.abTest);
                subject = variant.subject;
                htmlBody = variant.content;
                textBody = variant.content.replace(/<[^>]*>/g, '');
            }

            // Replace template variables
            subject = replaceVariables(subject, lead, enrollment);
            htmlBody = replaceVariables(htmlBody, lead, enrollment);
            textBody = replaceVariables(textBody, lead, enrollment);

            if (lead.email) {
                try {
                    await sendEmail({
                        to: lead.email,
                        subject,
                        htmlBody,
                        textBody,
                    });

                    enrollment.emailsSent++;
                    campaign.stats.emailsSent++;

                    logger.info('Sent drip email', {
                        enrollmentId,
                        stepId: currentStep.id,
                        to: lead.email,
                    });
                } catch (error) {
                    logger.error('Failed to send drip email', {
                        enrollmentId,
                        error,
                    });
                    return { success: false, action: 'skipped', nextStepAt: enrollment.nextStepAt };
                }
            }
            break;
        }

        case 'wait':
            // Wait steps just advance to next step
            break;

        case 'notification':
            // Would send internal notification
            logger.info('Drip notification', {
                enrollmentId,
                stepName: currentStep.name,
            });
            break;
    }

    // Move to next step
    enrollment.completedSteps.push(currentStep.id);
    const currentIndex = campaign.sequence.findIndex(
        (s) => s.id === currentStep.id
    );
    const nextStep = campaign.sequence[currentIndex + 1];

    if (nextStep) {
        enrollment.currentStepId = nextStep.id;
        enrollment.nextStepAt = calculateNextStepTime(nextStep.delay);

        return {
            success: true,
            action: 'sent',
            nextStepAt: enrollment.nextStepAt,
        };
    } else {
        // Campaign complete
        enrollment.status = 'completed';
        enrollment.completedAt = new Date();
        enrollment.currentStepId = null;
        enrollment.nextStepAt = null;
        campaign.stats.activeCount--;
        campaign.stats.completedCount++;

        return { success: true, action: 'completed', nextStepAt: null };
    }
}

/**
 * Replaces template variables in content
 */
function replaceVariables(
    content: string,
    lead: Lead,
    enrollment: CampaignEnrollment
): string {
    const variables: Record<string, string> = {
        '{{lead.company_name}}': lead.companyName || '',
        '{{lead.domain}}': lead.domain || '',
        '{{lead.email}}': lead.email || '',
        '{{lead.first_name}}': extractFirstName(lead.email) || '',
        '{{lead.industry}}': lead.industry || '',
        '{{lead.website}}': lead.website || '',
        '{{unsubscribe_link}}': `https://apexmail.ee/unsubscribe/${enrollment.id}`,
    };

    let result = content;
    for (const [key, value] of Object.entries(variables)) {
        result = result.replace(new RegExp(key, 'g'), value);
    }

    // Replace custom fields
    if (lead.customFields) {
        for (const [key, value] of Object.entries(lead.customFields)) {
            result = result.replace(
                new RegExp(`{{lead.custom.${key}}}`, 'g'),
                String(value)
            );
        }
    }

    return result;
}

/**
 * Extracts first name from email (basic heuristic)
 */
function extractFirstName(email: string | null): string | null {
    if (!email) return null;

    const local = email.split('@')[0];
    if (!local) return null;

    // Try common patterns: firstname.lastname, firstname_lastname, firstnamelastname
    const parts = local.split(/[._]/);
    const firstName = parts[0];
    if (firstName && firstName.length > 0) {
        return firstName.charAt(0).toUpperCase() + firstName.slice(1).toLowerCase();
    }

    return null;
}

/**
 * Gets enrollments ready to process
 */
export function getReadyEnrollments(): CampaignEnrollment[] {
    const now = new Date();

    return Array.from(enrollments.values()).filter(
        (e) =>
            e.status === 'active' &&
            e.nextStepAt !== null &&
            e.nextStepAt <= now
    );
}

/**
 * Gets campaign by ID
 */
export function getCampaign(campaignId: string): DripCampaign | null {
    return campaigns.get(campaignId) || null;
}

/**
 * Gets all campaigns for a tenant
 */
export function getTenantCampaigns(tenantId: string): DripCampaign[] {
    return Array.from(campaigns.values()).filter(
        (c) => c.tenantId === tenantId
    );
}

/**
 * Gets enrollment by ID
 */
export function getEnrollment(enrollmentId: string): CampaignEnrollment | null {
    return enrollments.get(enrollmentId) || null;
}

/**
 * Gets lead enrollments
 */
export function getLeadEnrollments(leadId: string): CampaignEnrollment[] {
    return Array.from(enrollments.values()).filter(
        (e) => e.leadId === leadId
    );
}

/**
 * Records engagement event
 */
export function recordEngagement(
    enrollmentId: string,
    event: 'opened' | 'clicked' | 'replied'
): void {
    const enrollment = enrollments.get(enrollmentId);
    if (!enrollment) return;

    const campaign = campaigns.get(enrollment.campaignId);
    if (!campaign) return;

    switch (event) {
        case 'opened':
            enrollment.emailsOpened++;
            campaign.stats.emailsOpened++;
            break;
        case 'clicked':
            enrollment.emailsClicked++;
            campaign.stats.emailsClicked++;
            break;
        case 'replied':
            enrollment.replied = true;
            campaign.stats.repliesReceived++;
            break;
    }

    logger.debug('Recorded engagement', { enrollmentId, event });
}

/**
 * Pauses an enrollment
 */
export function pauseEnrollment(enrollmentId: string): boolean {
    const enrollment = enrollments.get(enrollmentId);
    if (!enrollment || enrollment.status !== 'active') {
        return false;
    }

    enrollment.status = 'paused';
    enrollment.pausedAt = new Date();

    const campaign = campaigns.get(enrollment.campaignId);
    if (campaign) {
        campaign.stats.activeCount--;
    }

    return true;
}

/**
 * Resumes a paused enrollment
 */
export function resumeEnrollment(enrollmentId: string): boolean {
    const enrollment = enrollments.get(enrollmentId);
    if (!enrollment || enrollment.status !== 'paused') {
        return false;
    }

    enrollment.status = 'active';
    enrollment.pausedAt = null;

    // Recalculate next step time
    const campaign = campaigns.get(enrollment.campaignId);
    if (campaign) {
        const currentStep = campaign.sequence.find(
            (s) => s.id === enrollment.currentStepId
        );
        if (currentStep) {
            enrollment.nextStepAt = calculateNextStepTime(currentStep.delay);
        }
        campaign.stats.activeCount++;
    }

    return true;
}

/**
 * Starts the campaign processor job
 */
export function startCampaignProcessor(
    getLeadById: (id: string) => Promise<Lead | null>,
    sendEmail: (params: {
        to: string;
        subject: string;
        htmlBody: string;
        textBody: string;
    }) => Promise<{ messageId: string }>
): void {
    const job = new CronJob('*/1 * * * *', async () => {
        const readyEnrollments = getReadyEnrollments();

        logger.debug('Processing enrollments', { count: readyEnrollments.length });

        for (const enrollment of readyEnrollments) {
            try {
                const lead = await getLeadById(enrollment.leadId);
                if (!lead) {
                    logger.warn('Lead not found for enrollment', {
                        enrollmentId: enrollment.id,
                        leadId: enrollment.leadId,
                    });
                    continue;
                }

                await processEnrollmentStep(enrollment.id, lead, sendEmail);
            } catch (error) {
                logger.error('Error processing enrollment', {
                    enrollmentId: enrollment.id,
                    error,
                });
            }
        }
    });

    job.start();
    scheduledJobs.set('campaign-processor', job);

    logger.info('Campaign processor started');
}

/**
 * Stops the campaign processor
 */
export function stopCampaignProcessor(): void {
    const job = scheduledJobs.get('campaign-processor');
    if (job) {
        job.stop();
        scheduledJobs.delete('campaign-processor');
        logger.info('Campaign processor stopped');
    }
}
