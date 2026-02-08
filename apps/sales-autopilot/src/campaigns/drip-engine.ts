/**
 * Drip Campaign Engine
 * Manages automated email sequences with conditional logic
 */

import { CronJob } from 'cron';
import { createLogger, generateId } from '@apexmail/lib';
import { config } from '../config.js';
import type { CampaignRepository } from './repository.js';
import type {
    DripCampaign,
    DripSequenceStep,
    CampaignEnrollment,
    EnrollmentStatus,
    Lead,
    StepDelay,
    StepCondition,
    CampaignStatus,
    AbVariant,
} from '../types.js';

// Re-export types for API consumers
export type { CampaignEnrollment, EnrollmentStatus, CampaignStatus, DripSequenceStep };

const logger = createLogger({ name: 'drip-engine', level: 'info' });

// In-memory storage for demo - in production, use database via setCampaignRepository()
const campaigns = new Map<string, DripCampaign>();
const enrollments = new Map<string, CampaignEnrollment>();
const scheduledJobs = new Map<string, CronJob>();

/**
 * FIX-011: Composite-key index for O(1) enrollment dedup.
 * Previously used Array.from(enrollments.values()).find() which was O(N)
 * and had a TOCTOU race: two concurrent requests could both pass the
 * check before either inserted, creating duplicate enrollments.
 */
const enrollmentIndex = new Map<string, string>(); // 'campaignId|leadId' -> enrollmentId

/**
 * FIX-500-100: Secondary indexes for O(1) lookups instead of O(n) linear scans.
 */
/** tenantId -> Set of campaignIds */
const campaignsByTenant = new Map<string, Set<string>>();
/** leadId -> Set of enrollmentIds */
const enrollmentsByLead = new Map<string, Set<string>>();

/**
 * FIX-500-246: Periodic eviction of completed/exited enrollments from in-memory Maps.
 * Since these are also persisted to Postgres via the repository, completed enrollments
 * can safely be evicted from the cache to prevent unbounded memory growth.
 */
const ENROLLMENT_EVICTION_INTERVAL = 10 * 60 * 1000; // Every 10 minutes
setInterval(() => {
  const terminalStatuses = new Set(['completed', 'exited', 'unsubscribed']);
  let evicted = 0;
  for (const [id, enrollment] of enrollments) {
    if (terminalStatuses.has(enrollment.status)) {
      enrollments.delete(id);
      enrollmentIndex.delete(`${enrollment.campaignId}|${enrollment.leadId}`);
      const leadSet = enrollmentsByLead.get(enrollment.leadId);
      if (leadSet) {
        leadSet.delete(id);
        if (leadSet.size === 0) enrollmentsByLead.delete(enrollment.leadId);
      }
      evicted++;
    }
  }
  if (evicted > 0) {
    logger.info('Evicted terminal enrollments from cache', { evicted, remaining: enrollments.size });
  }
}, ENROLLMENT_EVICTION_INTERVAL).unref();

/**
 * IMP-006: Optional Postgres-backed repository. When wired in via
 * `setCampaignRepository()`, all campaign/enrollment mutations are
 * persisted to the database. The in-memory Maps act as a write-through
 * cache so that read-heavy hot paths (condition evaluation, step lookup)
 * remain fast.
 */
let repo: CampaignRepository | null = null;

/**
 * Wire a CampaignRepository for Postgres persistence.
 * Call this at startup before creating/enrolling anything.
 */
export function setCampaignRepository(repository: CampaignRepository): void {
  repo = repository;
  logger.info('CampaignRepository wired — drip engine will persist to Postgres');
}

/**
 * FIX-002: Hydrate in-memory caches from the database on startup.
 * Without this, every process restart permanently loses all active
 * campaign state — enrollments stop processing, stats reset to zero,
 * and leads may be re-enrolled and get duplicate emails.
 */
export async function hydrateCaches(): Promise<void> {
  if (!repo) {
    logger.warn('Cannot hydrate caches — no CampaignRepository wired');
    return;
  }

  try {
    const dbCampaigns = await repo.getAllCampaigns();
    for (const campaign of dbCampaigns) {
      campaigns.set(campaign.id, campaign);
      // FIX-500-100: Populate tenant secondary index
      let tenantSet = campaignsByTenant.get(campaign.tenantId);
      if (!tenantSet) { tenantSet = new Set(); campaignsByTenant.set(campaign.tenantId, tenantSet); }
      tenantSet.add(campaign.id);
    }

    const dbEnrollments = await repo.getAllActiveEnrollments();
    for (const enrollment of dbEnrollments) {
      enrollments.set(enrollment.id, enrollment);
      // Rebuild the composite-key dedup index
      enrollmentIndex.set(`${enrollment.campaignId}|${enrollment.leadId}`, enrollment.id);
      // FIX-500-100: Populate lead secondary index
      let leadSet = enrollmentsByLead.get(enrollment.leadId);
      if (!leadSet) { leadSet = new Set(); enrollmentsByLead.set(enrollment.leadId, leadSet); }
      leadSet.add(enrollment.id);
    }

    logger.info('Hydrated drip-engine caches from DB', {
      campaigns: dbCampaigns.length,
      enrollments: dbEnrollments.length,
    });
  } catch (err) {
    logger.error('Failed to hydrate drip-engine caches', { error: err });
  }
}

/**
 * Creates a new drip campaign
 */
export async function createCampaign(
    tenantId: string,
    data: Omit<
        DripCampaign,
        'id' | 'tenantId' | 'status' | 'stats' | 'createdAt' | 'updatedAt' | 'startedAt' | 'pausedAt'
    >
): Promise<DripCampaign> {
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

    // FIX-500-100: Maintain tenant secondary index
    let tenantSet = campaignsByTenant.get(tenantId);
    if (!tenantSet) { tenantSet = new Set(); campaignsByTenant.set(tenantId, tenantSet); }
    tenantSet.add(campaign.id);

    // FIX-003: Await DB persistence instead of fire-and-forget.
    // Previously .catch() swallowed errors silently — the caller got
    // success while the DB write may have failed entirely.
    if (repo) {
        try {
            await repo.createCampaign(campaign);
        } catch (err) {
            logger.error('Failed to persist campaign to DB', { campaignId: campaign.id, error: err });
            // FIX-500-494: Re-throw so caller knows the persist failed
            throw err;
        }
    }

    logger.info('Created campaign', { campaignId: campaign.id, name: campaign.name });

    return campaign;
}

/**
 * Updates campaign status
 */
export async function updateCampaignStatus(
    campaignId: string,
    status: CampaignStatus
): Promise<DripCampaign | null> {
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

    // FIX-003: Await DB persistence instead of fire-and-forget
    if (repo) {
        try {
            await repo.updateCampaign(campaignId, {
                status: campaign.status,
                startedAt: campaign.startedAt,
                pausedAt: campaign.pausedAt,
            });
        } catch (err) {
            logger.error('Failed to persist campaign status to DB', { campaignId, error: err });
        }
    }

    logger.info('Updated campaign status', { campaignId, status });

    return campaign;
}

/**
 * B-034: Adds a step to a campaign sequence.
 * Made async to persist to DB when repository is available.
 */
export async function addSequenceStep(
    campaignId: string,
    step: Omit<DripSequenceStep, 'id' | 'order'>
): Promise<DripSequenceStep | null> {
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

    // Persist campaign update to DB
    if (repo) {
        await repo.updateCampaign(campaignId, {
            sequence: campaign.sequence,
            updatedAt: campaign.updatedAt,
        });
    }

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
    // FIX-015: Guard against undefined jitterMinutes. If undefined, the
    // expression becomes NaN, making nextStepAt an invalid Date.
    // `nextStepAt <= now` is always false for invalid dates, so the
    // enrollment would be permanently stuck with no way to recover.
    const jitterMs = Math.random() * (delay.jitterMinutes ?? 0) * 60 * 1000;
    const nextTime = new Date(fromDate.getTime() + delayMs + jitterMs);

    // If business hours only, adjust to next business day/hour
    if (delay.businessHoursOnly) {
        return adjustToBusinessHours(nextTime);
    }

    return nextTime;
}

/**
 * Adjusts a date to fall within business hours
 *
 * FIX-017: Previously captured `hour` and `day` once from the original
 * date but then mutated `adjusted` without re-reading. A Saturday 22:00
 * would get pushed to Monday (weekend fix), then the stale `hour=22`
 * fired the after-hours check pushing to Tuesday — one day too late.
 * Now we use a loop that re-reads after each adjustment.
 */
function adjustToBusinessHours(date: Date): Date {
    const adjusted = new Date(date);

    // Loop until the date lands on a business day/hour.
    // Each iteration fixes one issue; at most 3 passes needed.
    for (let i = 0; i < 5; i++) {
        const day = adjusted.getDay();
        const hour = adjusted.getHours();

        if (day === 0) {
            // Sunday → Monday, keep same time (next pass checks hours)
            adjusted.setDate(adjusted.getDate() + 1);
            continue;
        }
        if (day === 6) {
            // Saturday → Monday
            adjusted.setDate(adjusted.getDate() + 2);
            continue;
        }
        if (hour < config.calendar.availableHoursStart) {
            adjusted.setHours(config.calendar.availableHoursStart, 0, 0, 0);
            continue;
        }
        if (hour >= config.calendar.availableHoursEnd) {
            adjusted.setDate(adjusted.getDate() + 1);
            adjusted.setHours(config.calendar.availableHoursStart, 0, 0, 0);
            continue;
        }

        // All checks pass — we're within business hours on a weekday
        break;
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
export async function enrollLead(
    campaignId: string,
    lead: Lead,
    metadata?: Record<string, unknown>
): Promise<CampaignEnrollment | null> {
    const campaign = campaigns.get(campaignId);
    if (!campaign || campaign.status !== 'active') {
        return null;
    }

    // FIX-011: O(1) enrollment dedup via composite-key index
    const enrollmentKey = `${campaignId}|${lead.id}`;
    const existingId = enrollmentIndex.get(enrollmentKey);
    if (existingId) {
        const existingEnrollment = enrollments.get(existingId);
        if (existingEnrollment) {
            logger.debug('Lead already enrolled', { campaignId, leadId: lead.id });
            return existingEnrollment;
        }
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
    // FIX-011: Maintain composite index for O(1) dedup
    enrollmentIndex.set(enrollmentKey, enrollment.id);
    // FIX-500-100: Maintain lead secondary index
    let leadSet = enrollmentsByLead.get(lead.id);
    if (!leadSet) { leadSet = new Set(); enrollmentsByLead.set(lead.id, leadSet); }
    leadSet.add(enrollment.id);

    // Update campaign stats
    campaign.stats.totalEnrolled++;
    campaign.stats.activeCount++;

    // FIX-003: Await DB persistence instead of fire-and-forget
    // FIX-500-312/313: Re-throw DB persist failures so callers know the write failed
    if (repo) {
        try {
            await Promise.all([
                repo.createEnrollment(enrollment),
                repo.updateCampaign(campaignId, { stats: campaign.stats }),
            ]);
        } catch (err) {
            logger.error('Failed to persist enrollment to DB', { enrollmentId: enrollment.id, error: err });
            throw err;
        }
    }

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

        // B-036 / E-137: Await persistence instead of fire-and-forget .catch()
        // FIX-500-312: Re-throw to propagate DB persist failure
        if (repo) {
            try {
                await Promise.all([
                    repo.updateEnrollment(enrollment.id, { status: 'completed', completedAt: enrollment.completedAt }),
                    repo.updateCampaign(campaign.id, { stats: campaign.stats }),
                ]);
            } catch (err) {
                logger.error('Failed to persist enrollment completion', { error: err });
                throw err;
            }
        }

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

            // B-036 / E-137: Await persistence instead of fire-and-forget .catch()
            // FIX-500-313: Re-throw to propagate DB persist failure
            if (repo) {
                try {
                    await Promise.all([
                        repo.updateEnrollment(enrollment.id, { status: 'exited', exitReason: exitCondition.type }),
                        repo.updateCampaign(campaign.id, { stats: campaign.stats }),
                    ]);
                } catch (err) {
                    logger.error('Failed to persist enrollment exit', { error: err });
                    throw err;
                }
            }

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

                    // E-165: Clear failure tracking on success
                    if (enrollment.metadata._stepFailures) {
                        delete (enrollment.metadata._stepFailures as Record<string, unknown>)[currentStep.id];
                    }

                    logger.info('Sent drip email', {
                        enrollmentId,
                        stepId: currentStep.id,
                        to: lead.email,
                    });
                } catch (error) {
                    // E-165: Error recovery for failed drip campaign steps.
                    // 1. Record the failure with attempt count
                    // 2. Retry after exponential backoff (up to MAX_STEP_RETRIES)
                    // 3. Skip to next step after max retries exhausted
                    const MAX_STEP_RETRIES = 3;
                    const BASE_RETRY_DELAY_MS = 5 * 60 * 1000; // 5 minutes

                    if (!enrollment.metadata._stepFailures) {
                        enrollment.metadata._stepFailures = {};
                    }
                    const failures = enrollment.metadata._stepFailures as Record<string, { count: number; lastError: string; lastFailedAt: string }>;
                    const prev = failures[currentStep.id];
                    const failCount = (prev?.count ?? 0) + 1;
                    failures[currentStep.id] = {
                        count: failCount,
                        lastError: error instanceof Error ? error.message : String(error),
                        lastFailedAt: new Date().toISOString(),
                    };

                    if (failCount < MAX_STEP_RETRIES) {
                        // Schedule retry with exponential backoff
                        const backoffMs = BASE_RETRY_DELAY_MS * Math.pow(2, failCount - 1);
                        enrollment.nextStepAt = new Date(Date.now() + backoffMs);

                        logger.warn('E-165: Drip email failed, scheduling retry', {
                            enrollmentId,
                            stepId: currentStep.id,
                            attempt: failCount,
                            maxRetries: MAX_STEP_RETRIES,
                            retryAt: enrollment.nextStepAt,
                            error: error instanceof Error ? error.message : String(error),
                        });

                        if (repo) {
                            try {
                                await repo.updateEnrollment(enrollment.id, {
                                    nextStepAt: enrollment.nextStepAt,
                                    metadata: enrollment.metadata,
                                });
                            } catch (err) {
                                logger.error('Failed to persist retry state', { error: err });
                            }
                        }

                        return { success: false, action: 'skipped', nextStepAt: enrollment.nextStepAt };
                    }

                    // Max retries exhausted — log and skip to next step
                    logger.error('E-165: Drip email failed after max retries, skipping step', {
                        enrollmentId,
                        stepId: currentStep.id,
                        totalAttempts: failCount,
                        error: error instanceof Error ? error.message : String(error),
                    });

                    // Fall through to advance to next step below
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

        // B-036 / E-137: Await persistence instead of fire-and-forget .catch()
        // FIX-500-312: Re-throw to propagate DB persist failure
        if (repo) {
            try {
                await Promise.all([
                    repo.updateEnrollment(enrollment.id, {
                        currentStepId: enrollment.currentStepId,
                        nextStepAt: enrollment.nextStepAt,
                        completedSteps: enrollment.completedSteps,
                        emailsSent: enrollment.emailsSent,
                    }),
                    repo.updateCampaign(campaign.id, { stats: campaign.stats }),
                ]);
            } catch (err) {
                logger.error('Failed to persist enrollment step', { error: err });
                throw err;
            }
        }

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

        // B-036 / E-137: Await persistence instead of fire-and-forget .catch()
        // FIX-500-313: Re-throw to propagate DB persist failure
        if (repo) {
            try {
                await Promise.all([
                    repo.updateEnrollment(enrollment.id, {
                        status: 'completed',
                        completedAt: enrollment.completedAt,
                        currentStepId: null,
                        nextStepAt: null,
                        completedSteps: enrollment.completedSteps,
                        emailsSent: enrollment.emailsSent,
                    }),
                    repo.updateCampaign(campaign.id, { stats: campaign.stats }),
                ]);
            } catch (err) {
                logger.error('Failed to persist enrollment completion', { error: err });
                throw err;
            }
        }

        return { success: true, action: 'completed', nextStepAt: null };
    }
}

// FIX-500-321: Removed compiled /g regexes. The /g flag makes .test() stateful
// (advances lastIndex), causing alternating true/false. replaceAll() with
// literal strings is used instead — simpler and no stateful pitfall.

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
        '{{lead.first_name}}': extractFirstName(lead) || '',
        '{{lead.industry}}': lead.industry || '',
        '{{lead.website}}': lead.website || '',
        '{{unsubscribe_link}}': `https://apexmail.ee/unsubscribe/${enrollment.id}`,
    };

    let result = content;
    for (const [key, value] of Object.entries(variables)) {
        // FIX-500-321: Use replaceAll with literal string instead of /g regex
        result = result.replaceAll(key, value);
    }

    // Replace custom fields
    if (lead.customFields) {
        // FIX-019: Block prototype-chain keys from custom field interpolation
        const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
        for (const [key, value] of Object.entries(lead.customFields)) {
            if (BLOCKED_KEYS.has(key)) continue;
            // FIX-500-033: Escape regex special characters in key to prevent ReDoS
            const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            result = result.replace(
                new RegExp(`{{lead.custom.${escapedKey}}}`, 'g'),
                String(value)
            );
        }
    }

    return result;
}

/**
 * Extracts first name, preferring enrichment/custom field data over email heuristic
 * FIX-500-324: Check lead's customFields and other properties for real names
 * before falling back to the email-based heuristic which produces garbage
 * like "Support" or "Info" for generic addresses.
 */
function extractFirstName(lead: Lead): string | null {
    // 1. Check customFields for a real first name
    if (lead.customFields) {
        const firstName = lead.customFields['firstName'] ?? lead.customFields['first_name'];
        if (typeof firstName === 'string' && firstName.trim().length > 0) {
            return firstName.trim();
        }
        // Check full name and take the first part
        const fullName = lead.customFields['name'] ?? lead.customFields['fullName'] ?? lead.customFields['contactName'];
        if (typeof fullName === 'string' && fullName.trim().length > 0) {
            const parts = fullName.trim().split(/\s+/);
            if (parts[0]) return parts[0];
        }
    }

    // 2. Fall back to email heuristic (but skip generic addresses)
    const email = lead.email;
    if (!email) return null;

    const local = email.split('@')[0];
    if (!local) return null;

    // Skip generic/role-based addresses that produce meaningless names
    const GENERIC_PREFIXES = new Set([
        'info', 'support', 'admin', 'hello', 'contact', 'sales', 'team',
        'help', 'billing', 'noreply', 'no-reply', 'office', 'mail',
        'service', 'webmaster', 'postmaster', 'enquiries', 'feedback',
    ]);
    const lowerLocal = local.toLowerCase();
    if (GENERIC_PREFIXES.has(lowerLocal)) return null;

    // Try common patterns: firstname.lastname, firstname_lastname
    const parts = local.split(/[._]/);
    const firstName = parts[0];
    if (firstName && firstName.length > 1) {
        return firstName.charAt(0).toUpperCase() + firstName.slice(1).toLowerCase();
    }

    return null;
}

/**
 * Gets enrollments ready to process
 * FIX-500-091: For in-memory usage this still scans the enrollments map,
 * but uses a straightforward iteration — the alternative (a separate
 * time-sorted data structure) adds complexity beyond what is needed.
 * For production, use a DB query: WHERE status='active' AND next_step_at <= NOW().
 */
export function getReadyEnrollments(): CampaignEnrollment[] {
    const now = new Date();
    const results: CampaignEnrollment[] = [];

    for (const e of enrollments.values()) {
        if (e.status === 'active' && e.nextStepAt !== null && e.nextStepAt <= now) {
            results.push(e);
        }
    }

    return results;
}

/**
 * Gets campaign by ID
 */
export function getCampaign(campaignId: string): DripCampaign | null {
    return campaigns.get(campaignId) || null;
}

/**
 * Gets all campaigns for a tenant
 * FIX-500-100: Uses secondary index campaignsByTenant for O(k) lookup
 * instead of O(n) full scan (where k = campaigns for this tenant).
 */
export function getTenantCampaigns(tenantId: string): DripCampaign[] {
    const ids = campaignsByTenant.get(tenantId);
    if (!ids || ids.size === 0) return [];

    const results: DripCampaign[] = [];
    for (const id of ids) {
        const campaign = campaigns.get(id);
        if (campaign) results.push(campaign);
    }
    return results;
}

/**
 * Gets enrollment by ID
 */
export function getEnrollment(enrollmentId: string): CampaignEnrollment | null {
    return enrollments.get(enrollmentId) || null;
}

/**
 * Gets lead enrollments
 * FIX-500-100: Uses secondary index enrollmentsByLead for O(k) lookup
 * instead of O(n) full scan (where k = enrollments for this lead).
 */
export function getLeadEnrollments(leadId: string): CampaignEnrollment[] {
    const ids = enrollmentsByLead.get(leadId);
    if (!ids || ids.size === 0) return [];

    const results: CampaignEnrollment[] = [];
    for (const id of ids) {
        const enrollment = enrollments.get(id);
        if (enrollment) results.push(enrollment);
    }
    return results;
}

/**
 * B-035 / E-137: Records engagement event.
 * Made async and awaits persistence instead of fire-and-forget.
 * FIX-500-308: Use atomic DB increment for campaign stats instead of
 * persisting the full in-memory stats blob (which loses updates under
 * concurrent writes).
 */
export async function recordEngagement(
    enrollmentId: string,
    event: 'opened' | 'clicked' | 'replied'
): Promise<void> {
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

    // FIX-009 + B-035: Persist engagement to DB — await instead of fire-and-forget
    // FIX-500-308: Use atomic SQL increment for the stats column instead of
    // overwriting the entire JSON blob (which causes lost updates under concurrency).
    if (repo) {
        try {
            await repo.updateEnrollment(enrollmentId, {
                emailsOpened: enrollment.emailsOpened,
                emailsClicked: enrollment.emailsClicked,
                replied: enrollment.replied,
            });
            await repo.incrementCampaignStat(enrollment.campaignId, event);
        } catch (err) {
            logger.error('Failed to persist engagement', { error: err, enrollmentId, event });
        }
    }

    logger.debug('Recorded engagement', { enrollmentId, event });
}

/**
 * E-136: Pauses an enrollment — await persistence instead of fire-and-forget.
 */
export async function pauseEnrollment(enrollmentId: string): Promise<boolean> {
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

    // FIX-009 + E-136: Persist pause to DB — await instead of fire-and-forget
    if (repo) {
        try {
            await repo.updateEnrollment(enrollmentId, { status: 'paused', pausedAt: enrollment.pausedAt });
            if (campaign) {
                await repo.updateCampaign(campaign.id, { stats: campaign.stats });
            }
        } catch (err) {
            logger.error('Failed to persist pause', { error: err, enrollmentId });
        }
    }

    return true;
}

/**
 * E-136: Resumes a paused enrollment — await persistence.
 */
export async function resumeEnrollment(enrollmentId: string): Promise<boolean> {
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

    // FIX-009 + E-136: Persist resume to DB — await instead of fire-and-forget
    if (repo) {
        try {
            await repo.updateEnrollment(enrollmentId, {
                status: 'active',
                pausedAt: null,
                nextStepAt: enrollment.nextStepAt,
            });
            if (campaign) {
                await repo.updateCampaign(campaign.id, { stats: campaign.stats });
            }
        } catch (err) {
            logger.error('Failed to persist resume', { error: err, enrollmentId });
        }
    }

    return true;
}

/**
 * Starts the campaign processor job
 * FIX-500-310: Process enrollments in parallel batches instead of sequentially.
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
    const CONCURRENCY = 10;

    const job = new CronJob('*/1 * * * *', async () => {
        const readyEnrollments = getReadyEnrollments();

        logger.debug('Processing enrollments', { count: readyEnrollments.length });

        // FIX-500-310: Process in parallel batches of CONCURRENCY
        for (let i = 0; i < readyEnrollments.length; i += CONCURRENCY) {
            const batch = readyEnrollments.slice(i, i + CONCURRENCY);
            await Promise.all(batch.map(async (enrollment) => {
                try {
                    const lead = await getLeadById(enrollment.leadId);
                    if (!lead) {
                        logger.warn('Lead not found for enrollment', {
                            enrollmentId: enrollment.id,
                            leadId: enrollment.leadId,
                        });
                        return;
                    }

                    await processEnrollmentStep(enrollment.id, lead, sendEmail);
                } catch (error) {
                    logger.error('Error processing enrollment', {
                        enrollmentId: enrollment.id,
                        error,
                    });
                }
            }));
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
