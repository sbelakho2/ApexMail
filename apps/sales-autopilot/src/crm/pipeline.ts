/**
 * CRM Pipeline Management
 * Handles lead stages, activities, and pipeline operations
 */

import { createLogger, generateId } from '@apexmail/lib';
import type {
    Lead,
    PipelineConfig,
    PipelineStageConfig,
    LeadActivity,
    LeadTask,
    PipelineStage,
    ActivityType,
    TaskType,
    TaskPriority,
    TaskStatus,
    StageAutomation,
    LeadFilters,
} from '../types.js';

const logger = createLogger({ name: 'crm-pipeline', level: 'info' });

// In-memory storage for demo - in production, use database
const pipelines = new Map<string, PipelineConfig>();
const leads = new Map<string, Lead>();
const activities = new Map<string, LeadActivity[]>();
const tasks = new Map<string, LeadTask[]>();

/**
 * Creates the default pipeline configuration
 */
export function createDefaultPipeline(tenantId: string): PipelineConfig {
    const pipeline: PipelineConfig = {
        id: generateId('pipeline'),
        tenantId,
        name: 'Sales Pipeline',
        stages: [
            {
                id: 'stage_prospect',
                name: 'Prospect',
                order: 1,
                color: '#6B7280',
                probability: 10,
                rottenDays: 14,
                automations: [],
            },
            {
                id: 'stage_outreach',
                name: 'Outreach',
                order: 2,
                color: '#3B82F6',
                probability: 20,
                rottenDays: 7,
                automations: [],
            },
            {
                id: 'stage_engaged',
                name: 'Engaged',
                order: 3,
                color: '#8B5CF6',
                probability: 40,
                rottenDays: 14,
                automations: [],
            },
            {
                id: 'stage_demo',
                name: 'Demo Scheduled',
                order: 4,
                color: '#F59E0B',
                probability: 60,
                rottenDays: 7,
                automations: [],
            },
            {
                id: 'stage_proposal',
                name: 'Proposal',
                order: 5,
                color: '#10B981',
                probability: 75,
                rottenDays: 14,
                automations: [],
            },
            {
                id: 'stage_negotiation',
                name: 'Negotiation',
                order: 6,
                color: '#EC4899',
                probability: 90,
                rottenDays: 21,
                automations: [],
            },
            {
                id: 'stage_closed_won',
                name: 'Closed Won',
                order: 7,
                color: '#22C55E',
                probability: 100,
                rottenDays: null,
                automations: [],
            },
            {
                id: 'stage_closed_lost',
                name: 'Closed Lost',
                order: 8,
                color: '#EF4444',
                probability: 0,
                rottenDays: null,
                automations: [],
            },
        ],
        defaultStage: 'stage_prospect',
        wonStage: 'stage_closed_won',
        lostStage: 'stage_closed_lost',
        createdAt: new Date(),
        updatedAt: new Date(),
    };

    pipelines.set(pipeline.id, pipeline);
    logger.info('Created default pipeline', { pipelineId: pipeline.id, tenantId });

    return pipeline;
}

/**
 * Gets pipeline for a tenant
 */
export function getPipeline(tenantId: string): PipelineConfig | null {
    return (
        Array.from(pipelines.values()).find((p) => p.tenantId === tenantId) || null
    );
}

/**
 * Adds a stage automation
 */
export function addStageAutomation(
    pipelineId: string,
    stageId: string,
    automation: StageAutomation
): boolean {
    const pipeline = pipelines.get(pipelineId);
    if (!pipeline) return false;

    const stage = pipeline.stages.find((s) => s.id === stageId);
    if (!stage) return false;

    stage.automations.push(automation);
    pipeline.updatedAt = new Date();

    return true;
}

/**
 * Stores a lead
 */
export function storeLead(lead: Lead): void {
    leads.set(lead.id, lead);
    activities.set(lead.id, []);
    tasks.set(lead.id, []);
}

/**
 * Gets a lead by ID
 */
export function getLead(leadId: string): Lead | null {
    return leads.get(leadId) || null;
}

/**
 * Updates a lead
 */
export function updateLead(
    leadId: string,
    updates: Partial<Lead>
): Lead | null {
    const lead = leads.get(leadId);
    if (!lead) return null;

    const oldLead = { ...lead };

    Object.assign(lead, updates, { updatedAt: new Date() });

    // Record activity for significant changes
    if (updates.stage && updates.stage !== oldLead.stage) {
        recordActivity(leadId, {
            type: 'stage_changed',
            description: `Stage changed from ${oldLead.stage} to ${updates.stage}`,
            data: { from: oldLead.stage, to: updates.stage },
            userId: null,
        });
    }

    if (updates.status && updates.status !== oldLead.status) {
        recordActivity(leadId, {
            type: 'updated',
            description: `Status changed from ${oldLead.status} to ${updates.status}`,
            data: { from: oldLead.status, to: updates.status },
            userId: null,
        });
    }

    return lead;
}

/**
 * Moves lead to a different stage
 */
export function moveLeadToStage(
    leadId: string,
    newStage: PipelineStage,
    userId?: string
): Lead | null {
    const lead = leads.get(leadId);
    if (!lead) return null;

    const pipeline = getPipeline(lead.tenantId);
    if (!pipeline) return null;

    const stageConfig = pipeline.stages.find(
        (s) => s.name.toLowerCase().replace(/\s+/g, '_') === newStage
    );

    const oldStage = lead.stage;
    lead.stage = newStage;
    lead.updatedAt = new Date();

    // Update status based on stage
    if (newStage === 'closed_won') {
        lead.status = 'converted';
    } else if (newStage === 'closed_lost') {
        lead.status = 'lost';
    } else if (newStage !== 'prospect') {
        lead.status = 'contacted';
    }

    // Record activity
    recordActivity(leadId, {
        type: 'stage_changed',
        description: `Moved from ${oldStage} to ${newStage}`,
        data: {
            from: oldStage,
            to: newStage,
            probability: stageConfig?.probability,
        },
        userId: userId || null,
    });

    // Execute stage automations
    if (stageConfig) {
        executeStageAutomations(lead, stageConfig, 'enter');
    }

    logger.info('Moved lead to stage', { leadId, oldStage, newStage });

    return lead;
}

/**
 * Executes automations for a stage
 */
function executeStageAutomations(
    lead: Lead,
    stageConfig: PipelineStageConfig,
    trigger: 'enter' | 'exit' | 'rotten'
): void {
    const automations = stageConfig.automations.filter((a) => a.trigger === trigger);

    for (const automation of automations) {
        switch (automation.action) {
            case 'create_task':
                createTask(lead.id, lead.tenantId, {
                    title: (automation.config['title'] as string) || `Follow up - ${stageConfig.name}`,
                    description: automation.config['description'] as string | undefined,
                    type: (automation.config['taskType'] as TaskType) || 'follow_up',
                    priority: (automation.config['priority'] as TaskPriority) || 'medium',
                    dueAt: automation.config['dueDays']
                        ? new Date(
                            Date.now() +
                            (automation.config['dueDays'] as number) * 24 * 60 * 60 * 1000
                        )
                        : null,
                    assignedTo: lead.assignedTo,
                });
                break;

            case 'add_tag':
                if (!lead.tags.includes(automation.config['tag'] as string)) {
                    lead.tags.push(automation.config['tag'] as string);
                    recordActivity(lead.id, {
                        type: 'tag_added',
                        description: `Tag added: ${automation.config['tag']}`,
                        data: { tag: automation.config['tag'] },
                        userId: null,
                    });
                }
                break;

            case 'remove_tag':
                const tagIndex = lead.tags.indexOf(automation.config['tag'] as string);
                if (tagIndex > -1) {
                    lead.tags.splice(tagIndex, 1);
                    recordActivity(lead.id, {
                        type: 'tag_removed',
                        description: `Tag removed: ${automation.config['tag']}`,
                        data: { tag: automation.config['tag'] },
                        userId: null,
                    });
                }
                break;

            case 'assign_user':
                lead.assignedTo = automation.config['userId'] as string;
                break;
        }
    }
}

/**
 * Records an activity for a lead
 */
export function recordActivity(
    leadId: string,
    params: {
        type: ActivityType;
        description: string;
        data: Record<string, unknown>;
        userId: string | null;
    }
): LeadActivity {
    const lead = leads.get(leadId);
    if (!lead) {
        throw new Error(`Lead not found: ${leadId}`);
    }

    const activity: LeadActivity = {
        id: generateId('activity'),
        tenantId: lead.tenantId,
        leadId,
        type: params.type,
        description: params.description,
        data: params.data,
        userId: params.userId,
        createdAt: new Date(),
    };

    const leadActivities = activities.get(leadId) || [];
    leadActivities.push(activity);
    activities.set(leadId, leadActivities);

    logger.debug('Recorded activity', { leadId, type: params.type });

    return activity;
}

/**
 * Gets activities for a lead
 */
export function getLeadActivities(
    leadId: string,
    options?: {
        limit?: number;
        types?: ActivityType[];
    }
): LeadActivity[] {
    let leadActivities = activities.get(leadId) || [];

    if (options?.types) {
        leadActivities = leadActivities.filter((a) =>
            options.types!.includes(a.type)
        );
    }

    // Sort by date descending
    leadActivities.sort(
        (a, b) => b.createdAt.getTime() - a.createdAt.getTime()
    );

    if (options?.limit) {
        leadActivities = leadActivities.slice(0, options.limit);
    }

    return leadActivities;
}

/**
 * Creates a task for a lead
 */
export function createTask(
    leadId: string,
    tenantId: string,
    params: {
        title: string;
        description?: string;
        type: TaskType;
        priority: TaskPriority;
        dueAt: Date | null;
        assignedTo: string | null;
        createdBy?: string;
    }
): LeadTask {
    const task: LeadTask = {
        id: generateId('task'),
        tenantId,
        leadId,
        title: params.title,
        description: params.description || null,
        type: params.type,
        priority: params.priority,
        status: 'pending',
        dueAt: params.dueAt,
        assignedTo: params.assignedTo,
        completedAt: null,
        completedBy: null,
        createdBy: params.createdBy || 'system',
        createdAt: new Date(),
        updatedAt: new Date(),
    };

    const leadTasks = tasks.get(leadId) || [];
    leadTasks.push(task);
    tasks.set(leadId, leadTasks);

    // Record activity
    recordActivity(leadId, {
        type: 'task_created',
        description: `Task created: ${params.title}`,
        data: { taskId: task.id, type: params.type },
        userId: params.createdBy || null,
    });

    logger.info('Created task', { leadId, taskId: task.id, type: params.type });

    return task;
}

/**
 * Updates a task
 */
export function updateTask(
    taskId: string,
    updates: Partial<Pick<LeadTask, 'title' | 'description' | 'priority' | 'dueAt' | 'assignedTo'>>
): LeadTask | null {
    for (const leadTasks of tasks.values()) {
        const task = leadTasks.find((t) => t.id === taskId);
        if (task) {
            Object.assign(task, updates, { updatedAt: new Date() });
            return task;
        }
    }
    return null;
}

/**
 * Completes a task
 */
export function completeTask(
    taskId: string,
    completedBy: string
): LeadTask | null {
    for (const leadTasks of tasks.values()) {
        const task = leadTasks.find((t) => t.id === taskId);
        if (task) {
            task.status = 'completed';
            task.completedAt = new Date();
            task.completedBy = completedBy;
            task.updatedAt = new Date();

            recordActivity(task.leadId, {
                type: 'task_completed',
                description: `Task completed: ${task.title}`,
                data: { taskId: task.id },
                userId: completedBy,
            });

            return task;
        }
    }
    return null;
}

/**
 * Gets tasks for a lead
 */
export function getLeadTasks(
    leadId: string,
    options?: {
        status?: TaskStatus[];
        type?: TaskType[];
    }
): LeadTask[] {
    let leadTasks = tasks.get(leadId) || [];

    if (options?.status) {
        leadTasks = leadTasks.filter((t) => options.status!.includes(t.status));
    }

    if (options?.type) {
        leadTasks = leadTasks.filter((t) => options.type!.includes(t.type));
    }

    // Sort by due date, then priority
    const priorityOrder = { urgent: 0, high: 1, medium: 2, low: 3 };
    leadTasks.sort((a, b) => {
        if (a.dueAt && b.dueAt) {
            return a.dueAt.getTime() - b.dueAt.getTime();
        }
        if (a.dueAt) return -1;
        if (b.dueAt) return 1;
        return priorityOrder[a.priority] - priorityOrder[b.priority];
    });

    return leadTasks;
}

/**
 * Gets overdue tasks across all leads
 */
export function getOverdueTasks(tenantId?: string): LeadTask[] {
    const now = new Date();
    const overdue: LeadTask[] = [];

    for (const leadTasks of tasks.values()) {
        for (const task of leadTasks) {
            if (
                task.status === 'pending' &&
                task.dueAt &&
                task.dueAt < now &&
                (!tenantId || task.tenantId === tenantId)
            ) {
                overdue.push(task);
            }
        }
    }

    return overdue;
}

/**
 * Filters leads based on criteria
 */
export function filterLeads(
    tenantId: string,
    filters: LeadFilters
): Lead[] {
    let results = Array.from(leads.values()).filter(
        (l) => l.tenantId === tenantId
    );

    if (filters.status?.length) {
        results = results.filter((l) => filters.status!.includes(l.status));
    }

    if (filters.stage?.length) {
        results = results.filter((l) => filters.stage!.includes(l.stage));
    }

    if (filters.source?.length) {
        results = results.filter((l) => filters.source!.includes(l.source));
    }

    if (filters.tags?.length) {
        results = results.filter((l) =>
            filters.tags!.some((tag) => l.tags.includes(tag))
        );
    }

    if (filters.assignedTo?.length) {
        results = results.filter(
            (l) => l.assignedTo && filters.assignedTo!.includes(l.assignedTo)
        );
    }

    if (filters.createdAfter) {
        results = results.filter((l) => l.createdAt >= filters.createdAfter!);
    }

    if (filters.createdBefore) {
        results = results.filter((l) => l.createdAt <= filters.createdBefore!);
    }

    if (filters.scoreMin !== undefined) {
        results = results.filter((l) => l.score >= filters.scoreMin!);
    }

    if (filters.scoreMax !== undefined) {
        results = results.filter((l) => l.score <= filters.scoreMax!);
    }

    if (filters.search) {
        const searchLower = filters.search.toLowerCase();
        results = results.filter(
            (l) =>
                l.companyName.toLowerCase().includes(searchLower) ||
                l.domain.toLowerCase().includes(searchLower) ||
                l.email?.toLowerCase().includes(searchLower)
        );
    }

    return results;
}

/**
 * Gets pipeline statistics
 */
export function getPipelineStats(tenantId: string): {
    byStage: Record<string, { count: number; value: number }>;
    totalLeads: number;
    totalValue: number;
    averageScore: number;
    conversionRate: number;
} {
    const tenantLeads = Array.from(leads.values()).filter(
        (l) => l.tenantId === tenantId
    );

    const byStage: Record<string, { count: number; value: number }> = {};
    let totalValue = 0;
    let totalScore = 0;
    let closedWon = 0;
    let closedTotal = 0;

    for (const lead of tenantLeads) {
        if (!byStage[lead.stage]) {
            byStage[lead.stage] = { count: 0, value: 0 };
        }
        const stageData = byStage[lead.stage];
        if (stageData) {
            stageData.count++;
        }
        totalScore += lead.score;

        if (lead.stage === 'closed_won') {
            closedWon++;
            closedTotal++;
        } else if (lead.stage === 'closed_lost') {
            closedTotal++;
        }
    }

    return {
        byStage,
        totalLeads: tenantLeads.length,
        totalValue,
        averageScore:
            tenantLeads.length > 0 ? totalScore / tenantLeads.length : 0,
        conversionRate: closedTotal > 0 ? closedWon / closedTotal : 0,
    };
}

/**
 * Gets leads needing follow-up (no contact in X days)
 */
export function getLeadsNeedingFollowUp(
    tenantId: string,
    daysSinceContact: number = 7
): Lead[] {
    const cutoff = new Date(Date.now() - daysSinceContact * 24 * 60 * 60 * 1000);

    return Array.from(leads.values()).filter(
        (l) =>
            l.tenantId === tenantId &&
            l.status !== 'converted' &&
            l.status !== 'lost' &&
            l.status !== 'unqualified' &&
            (!l.lastContactedAt || l.lastContactedAt < cutoff)
    );
}

/**
 * Gets "rotten" leads (in same stage too long)
 */
export function getRottenLeads(tenantId: string): Lead[] {
    const pipeline = getPipeline(tenantId);
    if (!pipeline) return [];

    const rotten: Lead[] = [];

    for (const lead of leads.values()) {
        if (lead.tenantId !== tenantId) continue;

        const stageConfig = pipeline.stages.find(
            (s) => s.name.toLowerCase().replace(/\s+/g, '_') === lead.stage
        );

        if (stageConfig?.rottenDays) {
            const rottenDate = new Date(
                lead.updatedAt.getTime() + stageConfig.rottenDays * 24 * 60 * 60 * 1000
            );

            if (new Date() > rottenDate) {
                rotten.push(lead);
            }
        }
    }

    return rotten;
}
