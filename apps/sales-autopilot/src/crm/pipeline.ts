/**
 * CRM Pipeline Management
 * Handles lead stages, activities, and pipeline operations
 */

import { createLogger, generateId } from '@apexmail/lib';
import type { Pool } from 'pg';
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

let dbPool: Pool | null = null;

export function initCrmDatabase(pool: Pool): void {
    dbPool = pool;
}

function requireDb(): Pool {
    if (!dbPool) {
        throw new Error('CRM database pool not initialized');
    }
    return dbPool;
}

function parseJsonValue<T>(value: unknown, fallback: T): T {
    if (value === null || value === undefined) {
        return fallback;
    }

    if (typeof value === 'string') {
        try {
            return JSON.parse(value) as T;
        } catch {
            return fallback;
        }
    }

    return value as T;
}

function mapLeadRow(row: Record<string, unknown>): Lead {
    const tagsJson = row.tags_json ?? row.tags ?? [];

    return {
        id: row.id as string,
        tenantId: row.tenant_id as string,
        companyName: row.company_name as string,
        domain: row.domain as string,
        website: (row.website as string | null) ?? null,
        email: (row.email as string | null) ?? (row.contact_email as string | null) ?? null,
        emailVerified: Boolean(row.email_verified),
        phone: (row.phone as string | null) ?? null,
        industry: (row.industry as string | null) ?? null,
        employeeCount: (row.employee_count as string | null) ?? (row.employees as string | null) ?? null,
        revenue: (row.revenue as string | null) ?? null,
        technologies: parseJsonValue((row.technologies as string) ?? row.technologies, []),
        socialProfiles: parseJsonValue((row.social_profiles as string) ?? row.social_profiles, []),
        location: row.location ? parseJsonValue(row.location, null) : null,
        source: row.source as Lead['source'],
        sourceUrl: (row.source_url as string | null) ?? null,
        score: Number(row.score ?? 0),
        status: row.status as Lead['status'],
        stage: (row.stage as Lead['stage']) ?? 'prospect',
        assignedTo: (row.assigned_to as string | null) ?? null,
        tags: parseJsonValue(tagsJson, []),
        customFields: parseJsonValue((row.custom_fields as string) ?? row.custom_fields, {}),
        mxRecords: parseJsonValue((row.mx_records as string) ?? row.mx_records, []),
        emailProvider: (row.email_provider as string | null) ?? null,
        lastContactedAt: (row.last_contacted_at as Date | null) ?? null,
        nextFollowUpAt: (row.next_follow_up_at as Date | null) ?? null,
        createdAt: row.created_at as Date,
        updatedAt: row.updated_at as Date,
    };
}

function mapPipelineRow(row: Record<string, unknown>): PipelineConfig {
    return {
        id: row.id as string,
        tenantId: row.tenant_id as string,
        name: row.name as string,
        stages: parseJsonValue(row.stages, []),
        defaultStage: row.default_stage as string,
        wonStage: row.won_stage as string,
        lostStage: row.lost_stage as string,
        createdAt: row.created_at as Date,
        updatedAt: row.updated_at as Date,
    };
}

function mapActivityRow(row: Record<string, unknown>): LeadActivity {
    return {
        id: row.id as string,
        tenantId: row.tenant_id as string,
        leadId: row.lead_id as string,
        type: row.type as ActivityType,
        description: row.description as string,
        data: parseJsonValue((row.data as string) ?? row.data, {}),
        userId: (row.user_id as string | null) ?? null,
        createdAt: row.created_at as Date,
    };
}

function mapTaskRow(row: Record<string, unknown>): LeadTask {
    return {
        id: row.id as string,
        tenantId: row.tenant_id as string,
        leadId: row.lead_id as string,
        title: row.title as string,
        description: (row.description as string | null) ?? null,
        type: row.type as TaskType,
        priority: row.priority as TaskPriority,
        status: row.status as TaskStatus,
        dueAt: (row.due_at as Date | null) ?? null,
        assignedTo: (row.assigned_to as string | null) ?? null,
        completedAt: (row.completed_at as Date | null) ?? null,
        completedBy: (row.completed_by as string | null) ?? null,
        createdBy: (row.created_by as string | null) ?? 'system',
        createdAt: row.created_at as Date,
        updatedAt: row.updated_at as Date,
    };
}

/**
 * Creates the default pipeline configuration
 */
export async function createDefaultPipeline(tenantId: string): Promise<PipelineConfig> {
    const db = requireDb();
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

    const existing = await db.query(
        'SELECT * FROM sales_pipelines WHERE tenant_id = $1',
        [tenantId]
    );

    if (existing.rows.length > 0) {
        return mapPipelineRow(existing.rows[0]);
    }

    const insertResult = await db.query(
        `INSERT INTO sales_pipelines (
            id, tenant_id, name, stages, default_stage, won_stage, lost_stage,
            created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        RETURNING *`,
        [
            pipeline.id,
            pipeline.tenantId,
            pipeline.name,
            JSON.stringify(pipeline.stages),
            pipeline.defaultStage,
            pipeline.wonStage,
            pipeline.lostStage,
        ]
    );

    logger.info('Created default pipeline', { pipelineId: pipeline.id, tenantId });
    return mapPipelineRow(insertResult.rows[0]);
}

/**
 * Gets pipeline for a tenant
 */
export async function getPipeline(tenantId: string): Promise<PipelineConfig | null> {
    const db = requireDb();
    const result = await db.query('SELECT * FROM sales_pipelines WHERE tenant_id = $1', [tenantId]);
    return result.rows[0] ? mapPipelineRow(result.rows[0]) : null;
}

/**
 * Adds a stage automation
 */
export async function addStageAutomation(
    pipelineId: string,
    stageId: string,
    automation: StageAutomation
): Promise<boolean> {
    const db = requireDb();

    const result = await db.query('SELECT * FROM sales_pipelines WHERE id = $1', [pipelineId]);
    const row = result.rows[0];
    if (!row) return false;
    const pipeline = mapPipelineRow(row);
    const stage = pipeline.stages.find((s) => s.id === stageId);
    if (!stage) return false;

    stage.automations.push(automation);

    await db.query(
        'UPDATE sales_pipelines SET stages = $2, updated_at = NOW() WHERE id = $1',
        [pipelineId, JSON.stringify(pipeline.stages)]
    );

    return true;
}

/**
 * Stores a lead
 */
export async function storeLead(lead: Lead): Promise<void> {
    const db = requireDb();
    try {
    await db.query(
        `INSERT INTO sales_leads (
            id, tenant_id, company_name, domain, website, email, email_verified,
            phone, industry, employee_count, revenue, technologies, social_profiles,
            location, source, source_url, score, status, stage, assigned_to,
            tags_json, custom_fields, mx_records, email_provider, last_contacted_at,
            next_follow_up_at, created_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11, $12, $13,
            $14, $15, $16, $17, $18, $19, $20,
            $21, $22, $23, $24, $25, $26, NOW(), NOW()
        )
        ON CONFLICT (id) DO UPDATE SET
            company_name = EXCLUDED.company_name,
            domain = EXCLUDED.domain,
            website = EXCLUDED.website,
            email = EXCLUDED.email,
            email_verified = EXCLUDED.email_verified,
            phone = EXCLUDED.phone,
            industry = EXCLUDED.industry,
            employee_count = EXCLUDED.employee_count,
            revenue = EXCLUDED.revenue,
            technologies = EXCLUDED.technologies,
            social_profiles = EXCLUDED.social_profiles,
            location = EXCLUDED.location,
            source = EXCLUDED.source,
            source_url = EXCLUDED.source_url,
            score = EXCLUDED.score,
            status = EXCLUDED.status,
            stage = EXCLUDED.stage,
            assigned_to = EXCLUDED.assigned_to,
            tags_json = EXCLUDED.tags_json,
            custom_fields = EXCLUDED.custom_fields,
            mx_records = EXCLUDED.mx_records,
            email_provider = EXCLUDED.email_provider,
            last_contacted_at = EXCLUDED.last_contacted_at,
            next_follow_up_at = EXCLUDED.next_follow_up_at,
            updated_at = NOW()
        `,
        [
            lead.id,
            lead.tenantId,
            lead.companyName,
            lead.domain,
            lead.website,
            lead.email,
            lead.emailVerified,
            lead.phone,
            lead.industry,
            lead.employeeCount,
            lead.revenue,
            JSON.stringify(lead.technologies),
            JSON.stringify(lead.socialProfiles),
            lead.location ? JSON.stringify(lead.location) : null,
            lead.source,
            lead.sourceUrl,
            lead.score,
            lead.status,
            lead.stage,
            lead.assignedTo,
            JSON.stringify(lead.tags),
            JSON.stringify(lead.customFields),
            JSON.stringify(lead.mxRecords),
            lead.emailProvider,
            lead.lastContactedAt,
            lead.nextFollowUpAt,
        ]
    );
    } catch (error) {
        // E-144: Log and rethrow — don't crash the process silently
        logger.error('Failed to store lead', { leadId: lead.id, error: error instanceof Error ? error.message : String(error) });
        throw error;
    }
}

/**
 * Gets a lead by ID
 * 
 * FIX-500-016: Added optional tenantId parameter for tenant-scoped lookups.
 * When tenantId is provided, the query is scoped to prevent cross-tenant
 * data access. Without it, behavior is unchanged for backward compatibility.
 */
export async function getLead(leadId: string, tenantId?: string): Promise<Lead | null> {
    const db = requireDb();
    if (tenantId) {
        const result = await db.query(
            'SELECT * FROM sales_leads WHERE id = $1 AND tenant_id = $2',
            [leadId, tenantId]
        );
        return result.rows[0] ? mapLeadRow(result.rows[0]) : null;
    }
    const result = await db.query('SELECT * FROM sales_leads WHERE id = $1', [leadId]);
    return result.rows[0] ? mapLeadRow(result.rows[0]) : null;
}

/**
 * Updates a lead
 */
export async function updateLead(
    leadId: string,
    updates: Partial<Lead>
): Promise<Lead | null> {
    const db = requireDb();
    const existingLead = await getLead(leadId);
    if (!existingLead) {
        return null;
    }
    const fields: string[] = [];
    const values: unknown[] = [leadId];
    let index = 2;

    const setField = (name: string, value: unknown) => {
        fields.push(`${name} = $${index++}`);
        values.push(value);
    };

    if (updates.companyName !== undefined) setField('company_name', updates.companyName);
    if (updates.domain !== undefined) setField('domain', updates.domain);
    if (updates.website !== undefined) setField('website', updates.website);
    if (updates.email !== undefined) setField('email', updates.email);
    if (updates.emailVerified !== undefined) setField('email_verified', updates.emailVerified);
    if (updates.phone !== undefined) setField('phone', updates.phone);
    if (updates.industry !== undefined) setField('industry', updates.industry);
    if (updates.employeeCount !== undefined) setField('employee_count', updates.employeeCount);
    if (updates.revenue !== undefined) setField('revenue', updates.revenue);
    if (updates.technologies !== undefined) setField('technologies', JSON.stringify(updates.technologies));
    if (updates.socialProfiles !== undefined) setField('social_profiles', JSON.stringify(updates.socialProfiles));
    if (updates.location !== undefined) setField('location', updates.location ? JSON.stringify(updates.location) : null);
    if (updates.source !== undefined) setField('source', updates.source);
    if (updates.sourceUrl !== undefined) setField('source_url', updates.sourceUrl);
    if (updates.score !== undefined) setField('score', updates.score);
    if (updates.status !== undefined) setField('status', updates.status);
    if (updates.stage !== undefined) setField('stage', updates.stage);
    if (updates.assignedTo !== undefined) setField('assigned_to', updates.assignedTo);
    if (updates.tags !== undefined) setField('tags_json', JSON.stringify(updates.tags));
    if (updates.customFields !== undefined) setField('custom_fields', JSON.stringify(updates.customFields));
    if (updates.mxRecords !== undefined) setField('mx_records', JSON.stringify(updates.mxRecords));
    if (updates.emailProvider !== undefined) setField('email_provider', updates.emailProvider);
    if (updates.lastContactedAt !== undefined) setField('last_contacted_at', updates.lastContactedAt);
    if (updates.nextFollowUpAt !== undefined) setField('next_follow_up_at', updates.nextFollowUpAt);

    if (fields.length === 0) {
        return existingLead;
    }

    const result = await db.query(
        `UPDATE sales_leads SET ${fields.join(', ')}, updated_at = NOW() WHERE id = $1 RETURNING *`,
        values
    );
    const updated = result.rows[0] ? mapLeadRow(result.rows[0]) : null;

    if (updated) {
        if (updates.stage && updates.stage !== existingLead.stage) {
            await recordActivity(leadId, {
                type: 'stage_changed',
                description: `Stage changed from ${existingLead.stage} to ${updates.stage}`,
                data: { from: existingLead.stage, to: updates.stage },
                userId: null,
            });
        }

        if (updates.status && updates.status !== existingLead.status) {
            await recordActivity(leadId, {
                type: 'updated',
                description: `Status changed from ${existingLead.status} to ${updates.status}`,
                data: { from: existingLead.status, to: updates.status },
                userId: null,
            });
        }
    }

    return updated;
}

/**
 * Moves lead to a different stage
 */
export async function moveLeadToStage(
    leadId: string,
    newStage: PipelineStage,
    userId?: string
): Promise<Lead | null> {
  try {
    const db = requireDb();
    const result = await db.query('SELECT * FROM sales_leads WHERE id = $1', [leadId]);
    if (result.rows.length === 0) return null;
    const lead = mapLeadRow(result.rows[0]);

    const pipeline = await getPipeline(lead.tenantId);
    if (!pipeline) return null;

    const stageConfig = pipeline.stages.find(
        // FIX-500-322: Match by stage ID instead of mangled name.
        // Stage IDs follow the pattern 'stage_<value>' (e.g. 'stage_prospect').
        // The lead.stage stores the enum value (e.g. 'prospect').
        (s) => s.id === `stage_${newStage}` || s.id === newStage
    );

    const oldStage = lead.stage;
    let status = lead.status;
    if (newStage === 'closed_won') {
        status = 'converted';
    } else if (newStage === 'closed_lost') {
        status = 'lost';
    } else if (newStage !== 'prospect') {
        status = 'contacted';
    }

    const updateResult = await db.query(
        `UPDATE sales_leads SET stage = $2, status = $3, updated_at = NOW() WHERE id = $1 RETURNING *`,
        [leadId, newStage, status]
    );

    const updatedLead = mapLeadRow(updateResult.rows[0]);

    await recordActivity(leadId, {
        type: 'stage_changed',
        description: `Moved from ${oldStage} to ${newStage}`,
        data: {
            from: oldStage,
            to: newStage,
            probability: stageConfig?.probability,
        },
        userId: userId || null,
    });

    if (stageConfig) {
        await executeStageAutomations(updatedLead, stageConfig, 'enter');
    }

    logger.info('Moved lead to stage', { leadId, oldStage, newStage });
    return updatedLead;
  } catch (error) {
    // E-144: Log error and return null — don't crash the process
    logger.error('Failed to move lead to stage', { leadId, newStage, error: error instanceof Error ? error.message : String(error) });
    return null;
  }
}

/**
 * Executes automations for a stage
 */
async function executeStageAutomations(
    lead: Lead,
    stageConfig: PipelineStageConfig,
    trigger: 'enter' | 'exit' | 'rotten'
): Promise<void> {
    const automations = stageConfig.automations.filter((a) => a.trigger === trigger);

    for (const automation of automations) {
      try {
        switch (automation.action) {
            case 'create_task':
                await createTask(lead.id, lead.tenantId, {
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
                    const nextTags = [...lead.tags, automation.config['tag'] as string];
                    await updateLead(lead.id, { tags: nextTags });
                    await recordActivity(lead.id, {
                        type: 'tag_added',
                        description: `Tag added: ${automation.config['tag']}`,
                        data: { tag: automation.config['tag'] },
                        userId: null,
                    });
                }
                break;

            case 'remove_tag': {
                const tagIndex = lead.tags.indexOf(automation.config['tag'] as string);
                if (tagIndex > -1) {
                    const nextTags = lead.tags.filter((tag) => tag !== automation.config['tag']);
                    await updateLead(lead.id, { tags: nextTags });
                    await recordActivity(lead.id, {
                        type: 'tag_removed',
                        description: `Tag removed: ${automation.config['tag']}`,
                        data: { tag: automation.config['tag'] },
                        userId: null,
                    });
                }
                break;
            }

            case 'assign_user':
                await updateLead(lead.id, { assignedTo: automation.config['userId'] as string });
                break;
        }
      } catch (error) {
        // E-144: Log automation error but continue processing remaining automations
        logger.error('Stage automation failed', {
            leadId: lead.id,
            stage: stageConfig.name,
            action: automation.action,
            error: error instanceof Error ? error.message : String(error),
        });
      }
    }
}

/**
 * Records an activity for a lead
 */
export async function recordActivity(
    leadId: string,
    params: {
        type: ActivityType;
        description: string;
        data: Record<string, unknown>;
        userId: string | null;
    }
): Promise<LeadActivity> {
    const db = requireDb();
    const leadResult = await db.query('SELECT tenant_id FROM sales_leads WHERE id = $1', [leadId]);
    if (leadResult.rows.length === 0) {
        throw new Error(`Lead not found: ${leadId}`);
    }

    const activity: LeadActivity = {
        id: generateId('activity'),
        tenantId: leadResult.rows[0].tenant_id as string,
        leadId,
        type: params.type,
        description: params.description,
        data: params.data,
        userId: params.userId,
        createdAt: new Date(),
    };

    const insertResult = await db.query(
        `INSERT INTO sales_lead_activities (
            id, lead_id, tenant_id, type, description, data, user_id, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        RETURNING *`,
        [
            activity.id,
            activity.leadId,
            activity.tenantId,
            activity.type,
            activity.description,
            JSON.stringify(activity.data || {}),
            activity.userId,
        ]
    );

    logger.debug('Recorded activity', { leadId, type: params.type });
    return mapActivityRow(insertResult.rows[0]);
}

/**
 * Gets activities for a lead
 */
export async function getLeadActivities(
    leadId: string,
    options?: {
        limit?: number;
        types?: ActivityType[];
    }
): Promise<LeadActivity[]> {
    const db = requireDb();
    const values: unknown[] = [leadId];
    const where: string[] = ['lead_id = $1'];
    let index = 2;

    if (options?.types?.length) {
        values.push(options.types);
        where.push(`type = ANY($${index++})`);
    }

    const limitClause = options?.limit ? `LIMIT ${options.limit}` : '';

    const result = await db.query(
        `SELECT * FROM sales_lead_activities WHERE ${where.join(' AND ')} ORDER BY created_at DESC ${limitClause}`,
        values
    );

    return result.rows.map(mapActivityRow);
}

/**
 * Creates a task for a lead
 */
export async function createTask(
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
): Promise<LeadTask> {
    const db = requireDb();
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

    const insertResult = await db.query(
        `INSERT INTO sales_lead_tasks (
            id, lead_id, tenant_id, type, priority, status, title, description, due_at,
            assigned_to, completed_by, created_by, completed_at, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW())
        RETURNING *`,
        [
            task.id,
            task.leadId,
            task.tenantId,
            task.type,
            task.priority,
            task.status,
            task.title,
            task.description,
            task.dueAt,
            task.assignedTo,
            task.completedBy,
            task.createdBy,
            task.completedAt,
        ]
    );

    await recordActivity(leadId, {
        type: 'task_created',
        description: `Task created: ${params.title}`,
        data: { taskId: task.id, type: params.type },
        userId: params.createdBy || null,
    });

    logger.info('Created task', { leadId, taskId: task.id, type: params.type });

    return mapTaskRow(insertResult.rows[0]);
}

/**
 * Updates a task
 */
export async function updateTask(
    taskId: string,
    updates: Partial<Pick<LeadTask, 'title' | 'description' | 'priority' | 'dueAt' | 'assignedTo'>>
): Promise<LeadTask | null> {
    const db = requireDb();
    const fields: string[] = [];
    const values: unknown[] = [taskId];
    let index = 2;

    const setField = (name: string, value: unknown) => {
        fields.push(`${name} = $${index++}`);
        values.push(value);
    };

    if (updates.title !== undefined) setField('title', updates.title);
    if (updates.description !== undefined) setField('description', updates.description);
    if (updates.priority !== undefined) setField('priority', updates.priority);
    if (updates.dueAt !== undefined) setField('due_at', updates.dueAt);
    if (updates.assignedTo !== undefined) setField('assigned_to', updates.assignedTo);

    if (fields.length === 0) {
        const existing = await db.query('SELECT * FROM sales_lead_tasks WHERE id = $1', [taskId]);
        return existing.rows[0] ? mapTaskRow(existing.rows[0]) : null;
    }

    const result = await db.query(
        `UPDATE sales_lead_tasks SET ${fields.join(', ')}, updated_at = NOW() WHERE id = $1 RETURNING *`,
        values
    );
    return result.rows[0] ? mapTaskRow(result.rows[0]) : null;
}

/**
 * Completes a task
 */
export async function completeTask(
    taskId: string,
    completedBy: string
): Promise<LeadTask | null> {
    const db = requireDb();
    const result = await db.query(
        `UPDATE sales_lead_tasks
        SET status = 'completed', completed_at = NOW(), completed_by = $2, updated_at = NOW()
        WHERE id = $1
        RETURNING *`,
        [taskId, completedBy]
    );

    if (!result.rows[0]) return null;

    const task = mapTaskRow(result.rows[0]);
    await recordActivity(task.leadId, {
        type: 'task_completed',
        description: `Task completed: ${task.title}`,
        data: { taskId: task.id },
        userId: completedBy,
    });

    return task;
}

/**
 * Gets tasks for a lead
 */
export async function getLeadTasks(
    leadId: string,
    options?: {
        status?: TaskStatus[];
        type?: TaskType[];
    }
): Promise<LeadTask[]> {
    const db = requireDb();
    const values: unknown[] = [leadId];
    const where: string[] = ['lead_id = $1'];
    let index = 2;

    if (options?.status?.length) {
        values.push(options.status);
        where.push(`status = ANY($${index++})`);
    }

    if (options?.type?.length) {
        values.push(options.type);
        where.push(`type = ANY($${index++})`);
    }

    const result = await db.query(
        `SELECT * FROM sales_lead_tasks WHERE ${where.join(' AND ')}
        ORDER BY due_at NULLS LAST, priority DESC, created_at DESC`,
        values
    );

    return result.rows.map(mapTaskRow);
}

/**
 * Gets overdue tasks across all leads
 */
export async function getOverdueTasks(tenantId?: string): Promise<LeadTask[]> {
    const db = requireDb();
    const values: unknown[] = [];
    const where: string[] = ["status = 'pending'", 'due_at IS NOT NULL', 'due_at < NOW()'];

    if (tenantId) {
        values.push(tenantId);
        where.push(`tenant_id = $${values.length}`);
    }

    const result = await db.query(
        `SELECT * FROM sales_lead_tasks WHERE ${where.join(' AND ')} ORDER BY due_at ASC`,
        values
    );

    return result.rows.map(mapTaskRow);
}

/**
 * Filters leads based on criteria
 * FIX-500-318: Added limit/offset pagination with a default LIMIT of 200.
 */
export async function filterLeads(
    tenantId: string,
    filters: LeadFilters,
    options?: { limit?: number; offset?: number }
): Promise<Lead[]> {
    const db = requireDb();
    const values: unknown[] = [tenantId];
    const where: string[] = ['tenant_id = $1'];
    let index = 2;

    if (filters.status?.length) {
        values.push(filters.status);
        where.push(`status = ANY($${index++})`);
    }

    if (filters.stage?.length) {
        values.push(filters.stage);
        where.push(`stage = ANY($${index++})`);
    }

    if (filters.source?.length) {
        values.push(filters.source);
        where.push(`source = ANY($${index++})`);
    }

    if (filters.tags?.length) {
        values.push(filters.tags);
        where.push(`tags_json ?| $${index++}`);
    }

    if (filters.assignedTo?.length) {
        values.push(filters.assignedTo);
        where.push(`assigned_to = ANY($${index++})`);
    }

    if (filters.createdAfter) {
        values.push(filters.createdAfter);
        where.push(`created_at >= $${index++}`);
    }

    if (filters.createdBefore) {
        values.push(filters.createdBefore);
        where.push(`created_at <= $${index++}`);
    }

    if (filters.scoreMin !== undefined) {
        values.push(filters.scoreMin);
        where.push(`score >= $${index++}`);
    }

    if (filters.scoreMax !== undefined) {
        values.push(filters.scoreMax);
        where.push(`score <= $${index++}`);
    }

    if (filters.search) {
        values.push(`%${filters.search}%`);
        where.push(`(company_name ILIKE $${index} OR domain ILIKE $${index} OR email ILIKE $${index})`);
        index += 1;
    }

    const result = await db.query(
        `SELECT * FROM sales_leads WHERE ${where.join(' AND ')} ORDER BY created_at DESC LIMIT $${index++} OFFSET $${index++}`,
        [...values, Math.min(options?.limit ?? 200, 1000), options?.offset ?? 0]
    );

    return result.rows.map(mapLeadRow);
}

/**
 * Gets pipeline statistics
 */
export async function getPipelineStats(tenantId: string): Promise<{
    byStage: Record<string, { count: number; value: number }>;
    totalLeads: number;
    totalValue: number;
    averageScore: number;
    conversionRate: number;
}> {
    const db = requireDb();
    const result = await db.query('SELECT * FROM sales_leads WHERE tenant_id = $1', [tenantId]);
    const tenantLeads = result.rows.map(mapLeadRow);

    const pipeline = await getPipeline(tenantId);
    const byStage: Record<string, { count: number; value: number }> = {};
    // FIX-500-323: Compute totalValue as weighted pipeline value
    // (lead score * stage probability) instead of always returning 0.
    let totalValue = 0;
    let totalScore = 0;
    let closedWon = 0;
    let closedTotal = 0;

    for (const lead of tenantLeads) {
        if (!byStage[lead.stage]) {
            byStage[lead.stage] = { count: 0, value: 0 };
        }
        const stageData = byStage[lead.stage];

        // Look up stage probability for weighted value
        const stageConfig = pipeline?.stages.find(
            (s) => s.id === `stage_${lead.stage}` || s.id === lead.stage
        );
        const probability = stageConfig?.probability ?? 0;
        const leadValue = lead.score * (probability / 100);

        if (stageData) {
            stageData.count++;
            stageData.value += leadValue;
        }
        totalValue += leadValue;
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
export async function getLeadsNeedingFollowUp(
    tenantId: string,
    daysSinceContact: number = 7
): Promise<Lead[]> {
    const cutoff = new Date(Date.now() - daysSinceContact * 24 * 60 * 60 * 1000);

    const db = requireDb();
    const result = await db.query(
        `SELECT * FROM sales_leads
        WHERE tenant_id = $1
        AND status NOT IN ('converted', 'lost', 'unqualified')
        AND (last_contacted_at IS NULL OR last_contacted_at < $2)`,
        [tenantId, cutoff]
    );

    return result.rows.map(mapLeadRow);
}

/**
 * Gets "rotten" leads (in same stage too long)
 * FIX-500-317: Push rotten filtering into SQL WHERE clause instead of
 * loading all leads into memory and filtering in JS.
 */
export async function getRottenLeads(tenantId: string): Promise<Lead[]> {
    const pipeline = await getPipeline(tenantId);
    if (!pipeline) return [];

    const db = requireDb();

    // Build SQL conditions from pipeline stage config
    const rottenConditions: string[] = [];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    for (const stage of pipeline.stages) {
        if (stage.rottenDays) {
            // Match by stage ID — e.g. 'stage_prospect' → 'prospect'
            const stageValue = stage.id.replace(/^stage_/, '');
            rottenConditions.push(
                `(stage = $${paramIndex} AND updated_at < NOW() - INTERVAL '1 day' * $${paramIndex + 1})`
            );
            values.push(stageValue, stage.rottenDays);
            paramIndex += 2;
        }
    }

    if (rottenConditions.length === 0) {
        return [];
    }

    const result = await db.query(
        `SELECT * FROM sales_leads
         WHERE tenant_id = $1
         AND (${rottenConditions.join(' OR ')})
         ORDER BY updated_at ASC
         LIMIT 500`,
        values
    );

    return result.rows.map(mapLeadRow);
}
