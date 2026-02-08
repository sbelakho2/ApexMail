/**
 * Campaign Repository - Database persistence for drip campaigns
 * Replaces in-memory Map storage for production use
 */

import type { Pool } from 'pg';
import type {
    DripCampaign,
    CampaignEnrollment,
    EnrollmentStatus,
    CampaignStatus,
} from '../types.js';

export class CampaignRepository {
    constructor(private readonly db: Pool) {}

    // =========================================================================
    // CAMPAIGNS
    // =========================================================================

    async createCampaign(campaign: DripCampaign): Promise<DripCampaign> {
        const result = await this.db.query(
            `INSERT INTO drip_campaigns (
                id, tenant_id, name, description, status, from_email, from_name,
                reply_to, sequence_steps, triggers, exit_conditions,
                settings, stats, created_by, started_at, paused_at, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
            RETURNING *`,
            [
                campaign.id,
                campaign.tenantId,
                campaign.name,
                campaign.description,
                campaign.status,
                campaign.fromEmail,
                campaign.fromName,
                campaign.replyTo,
                JSON.stringify(campaign.sequence),
                JSON.stringify(campaign.triggers),
                JSON.stringify(campaign.exitConditions),
                JSON.stringify(campaign.settings),
                JSON.stringify(campaign.stats),
                campaign.createdBy,
                campaign.startedAt,
                campaign.pausedAt,
                campaign.createdAt,
                campaign.updatedAt,
            ]
        );

        return this.rowToCampaign(result.rows[0]);
    }

    async getCampaign(campaignId: string, tenantId?: string): Promise<DripCampaign | null> {
        const sql = tenantId
            ? 'SELECT * FROM drip_campaigns WHERE id = $1 AND tenant_id = $2'
            : 'SELECT * FROM drip_campaigns WHERE id = $1';
        const params = tenantId ? [campaignId, tenantId] : [campaignId];
        const result = await this.db.query(sql, params);

        if (result.rows.length === 0) {
            return null;
        }

        return this.rowToCampaign(result.rows[0]);
    }

    async getCampaignsByTenant(tenantId: string): Promise<DripCampaign[]> {
        const result = await this.db.query(
            'SELECT * FROM drip_campaigns WHERE tenant_id = $1 ORDER BY created_at DESC',
            [tenantId]
        );

        return result.rows.map(row => this.rowToCampaign(row));
    }

    async getActiveCampaigns(tenantId?: string): Promise<DripCampaign[]> {
        const sql = tenantId
            ? "SELECT * FROM drip_campaigns WHERE status = 'active' AND tenant_id = $1"
            : "SELECT * FROM drip_campaigns WHERE status = 'active'";
        const params = tenantId ? [tenantId] : [];
        const result = await this.db.query(sql, params);

        return result.rows.map(row => this.rowToCampaign(row));
    }

    /**
     * FIX-002: Get all non-deleted campaigns for cache hydration on startup.
     */
    async getAllCampaigns(): Promise<DripCampaign[]> {
        const result = await this.db.query(
            "SELECT * FROM drip_campaigns WHERE status != 'deleted' ORDER BY created_at DESC"
        );

        return result.rows.map(row => this.rowToCampaign(row));
    }

    /**
     * FIX-002: Get all active/paused enrollments for cache hydration on startup.
     */
    async getAllActiveEnrollments(): Promise<CampaignEnrollment[]> {
        const result = await this.db.query(
            "SELECT * FROM campaign_enrollments WHERE status IN ('active', 'paused') ORDER BY enrolled_at DESC"
        );

        return result.rows.map(row => this.rowToEnrollment(row));
    }

    async updateCampaign(
        campaignId: string,
        updates: Partial<Pick<DripCampaign, 'name' | 'description' | 'status' | 'stats' | 'startedAt' | 'pausedAt' | 'sequence' | 'updatedAt'>>,
        tenantId?: string
    ): Promise<DripCampaign | null> {
        const setClauses: string[] = [];
        const values: unknown[] = [campaignId];
        let paramIndex = 2;

        if (updates.name !== undefined) {
            setClauses.push(`name = $${paramIndex++}`);
            values.push(updates.name);
        }
        if (updates.description !== undefined) {
            setClauses.push(`description = $${paramIndex++}`);
            values.push(updates.description);
        }
        if (updates.status !== undefined) {
            setClauses.push(`status = $${paramIndex++}`);
            values.push(updates.status);
        }
        if (updates.stats !== undefined) {
            setClauses.push(`stats = $${paramIndex++}`);
            values.push(JSON.stringify(updates.stats));
        }
        if (updates.startedAt !== undefined) {
            setClauses.push(`started_at = $${paramIndex++}`);
            values.push(updates.startedAt);
        }
        if (updates.pausedAt !== undefined) {
            setClauses.push(`paused_at = $${paramIndex++}`);
            values.push(updates.pausedAt);
        }
        // B-034: Support persisting sequence changes
        if (updates.sequence !== undefined) {
            setClauses.push(`sequence = $${paramIndex++}`);
            values.push(JSON.stringify(updates.sequence));
        }
        if (updates.updatedAt !== undefined) {
            setClauses.push(`updated_at = $${paramIndex++}`);
            values.push(updates.updatedAt);
        }

        if (setClauses.length === 0) {
            return this.getCampaign(campaignId, tenantId);
        }

        // A-019: Scope update to tenant when tenantId is provided
        let whereClause = 'WHERE id = $1';
        if (tenantId) {
            whereClause += ` AND tenant_id = $${paramIndex++}`;
            values.push(tenantId);
        }

        const result = await this.db.query(
            `UPDATE drip_campaigns SET ${setClauses.join(', ')}, updated_at = NOW() ${whereClause} RETURNING *`,
            values
        );

        if (result.rows.length === 0) {
            return null;
        }

        return this.rowToCampaign(result.rows[0]);
    }

    async deleteCampaign(campaignId: string, tenantId?: string): Promise<boolean> {
        const sql = tenantId
            ? 'DELETE FROM drip_campaigns WHERE id = $1 AND tenant_id = $2'
            : 'DELETE FROM drip_campaigns WHERE id = $1';
        const params = tenantId ? [campaignId, tenantId] : [campaignId];
        const result = await this.db.query(sql, params);

        return (result.rowCount ?? 0) > 0;
    }

    // =========================================================================
    // ENROLLMENTS
    // =========================================================================

    /**
     * B-042: Idempotent enrollment — the unique partial index
     * idx_enrollments_unique(campaign_id, lead_id) WHERE status NOT IN ('completed','exited')
     * prevents duplicate active enrollments.  ON CONFLICT returns the existing
     * row unchanged so callers always get a valid CampaignEnrollment back.
     */
    async createEnrollment(enrollment: CampaignEnrollment): Promise<CampaignEnrollment> {
        const result = await this.db.query(
            `INSERT INTO campaign_enrollments (
                id, campaign_id, lead_id, status, current_step_id,
                completed_steps, next_step_at, emails_sent, emails_opened,
                emails_clicked, replied, exit_reason, enrolled_at,
                completed_at, paused_at, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            ON CONFLICT (campaign_id, lead_id) WHERE status NOT IN ('completed', 'exited')
            DO UPDATE SET id = campaign_enrollments.id  -- no-op update to trigger RETURNING
            RETURNING *`,
            [
                enrollment.id,
                enrollment.campaignId,
                enrollment.leadId,
                enrollment.status,
                enrollment.currentStepId,
                JSON.stringify(enrollment.completedSteps),
                enrollment.nextStepAt,
                enrollment.emailsSent,
                enrollment.emailsOpened,
                enrollment.emailsClicked,
                enrollment.replied,
                enrollment.exitReason,
                enrollment.enrolledAt,
                enrollment.completedAt,
                enrollment.pausedAt,
                JSON.stringify(enrollment.metadata),
            ]
        );

        return this.rowToEnrollment(result.rows[0]);
    }

    async getEnrollment(enrollmentId: string, tenantId?: string): Promise<CampaignEnrollment | null> {
        // A-019: Join against campaigns to enforce tenant scoping for enrollments
        const sql = tenantId
            ? `SELECT e.* FROM campaign_enrollments e
               JOIN drip_campaigns c ON e.campaign_id = c.id
               WHERE e.id = $1 AND c.tenant_id = $2`
            : 'SELECT * FROM campaign_enrollments WHERE id = $1';
        const params = tenantId ? [enrollmentId, tenantId] : [enrollmentId];
        const result = await this.db.query(sql, params);

        if (result.rows.length === 0) {
            return null;
        }

        return this.rowToEnrollment(result.rows[0]);
    }

    async getEnrollmentsByCampaign(campaignId: string): Promise<CampaignEnrollment[]> {
        const result = await this.db.query(
            'SELECT * FROM campaign_enrollments WHERE campaign_id = $1 ORDER BY enrolled_at DESC',
            [campaignId]
        );

        return result.rows.map(row => this.rowToEnrollment(row));
    }

    async getActiveEnrollmentByLead(campaignId: string, leadId: string): Promise<CampaignEnrollment | null> {
        const result = await this.db.query(
            `SELECT * FROM campaign_enrollments 
             WHERE campaign_id = $1 AND lead_id = $2 AND status NOT IN ('completed', 'exited')
             LIMIT 1`,
            [campaignId, leadId]
        );

        if (result.rows.length === 0) {
            return null;
        }

        return this.rowToEnrollment(result.rows[0]);
    }

    async getScheduledEnrollments(beforeTime: Date): Promise<CampaignEnrollment[]> {
        const result = await this.db.query(
            `SELECT * FROM campaign_enrollments 
             WHERE status = 'active' AND next_step_at <= $1
             ORDER BY next_step_at`,
            [beforeTime]
        );

        return result.rows.map(row => this.rowToEnrollment(row));
    }

    async updateEnrollment(
        enrollmentId: string,
        updates: Partial<Pick<CampaignEnrollment, 
            'status' | 'currentStepId' | 'nextStepAt' | 
            'completedSteps' | 'emailsSent' | 'emailsOpened' |
            'emailsClicked' | 'replied' | 'exitReason' | 'completedAt' | 'pausedAt' | 'metadata'>>,
        tenantId?: string
    ): Promise<CampaignEnrollment | null> {
        const setClauses: string[] = [];
        const values: unknown[] = [enrollmentId];
        let paramIndex = 2;

        if (updates.status !== undefined) {
            setClauses.push(`status = $${paramIndex++}`);
            values.push(updates.status);
        }
        if (updates.currentStepId !== undefined) {
            setClauses.push(`current_step_id = $${paramIndex++}`);
            values.push(updates.currentStepId);
        }
        if (updates.nextStepAt !== undefined) {
            setClauses.push(`next_step_at = $${paramIndex++}`);
            values.push(updates.nextStepAt);
        }
        if (updates.completedSteps !== undefined) {
            setClauses.push(`completed_steps = $${paramIndex++}`);
            values.push(JSON.stringify(updates.completedSteps));
        }
        if (updates.emailsSent !== undefined) {
            setClauses.push(`emails_sent = $${paramIndex++}`);
            values.push(updates.emailsSent);
        }
        if (updates.emailsOpened !== undefined) {
            setClauses.push(`emails_opened = $${paramIndex++}`);
            values.push(updates.emailsOpened);
        }
        if (updates.emailsClicked !== undefined) {
            setClauses.push(`emails_clicked = $${paramIndex++}`);
            values.push(updates.emailsClicked);
        }
        if (updates.replied !== undefined) {
            setClauses.push(`replied = $${paramIndex++}`);
            values.push(updates.replied);
        }
        if (updates.exitReason !== undefined) {
            setClauses.push(`exit_reason = $${paramIndex++}`);
            values.push(updates.exitReason);
        }
        if (updates.completedAt !== undefined) {
            setClauses.push(`completed_at = $${paramIndex++}`);
            values.push(updates.completedAt);
        }
        if (updates.pausedAt !== undefined) {
            setClauses.push(`paused_at = $${paramIndex++}`);
            values.push(updates.pausedAt);
        }
        // E-165: Persist enrollment metadata (includes step failure tracking)
        if (updates.metadata !== undefined) {
            setClauses.push(`metadata = $${paramIndex++}`);
            values.push(JSON.stringify(updates.metadata));
        }

        if (setClauses.length === 0) {
            return this.getEnrollment(enrollmentId, tenantId);
        }

        // A-019: Scope update to tenant via campaign join when tenantId is provided
        let sql: string;
        if (tenantId) {
            sql = `UPDATE campaign_enrollments SET ${setClauses.join(', ')}
                   WHERE id = $1 AND campaign_id IN (
                       SELECT id FROM drip_campaigns WHERE tenant_id = $${paramIndex}
                   ) RETURNING *`;
            values.push(tenantId);
        } else {
            sql = `UPDATE campaign_enrollments SET ${setClauses.join(', ')} WHERE id = $1 RETURNING *`;
        }

        const result = await this.db.query(sql, values);

        if (result.rows.length === 0) {
            return null;
        }

        return this.rowToEnrollment(result.rows[0]);
    }

    async deleteEnrollment(enrollmentId: string, tenantId?: string): Promise<boolean> {
        // A-019: Scope deletion to tenant via campaign join when tenantId is provided
        const sql = tenantId
            ? `DELETE FROM campaign_enrollments WHERE id = $1
               AND campaign_id IN (SELECT id FROM drip_campaigns WHERE tenant_id = $2)`
            : 'DELETE FROM campaign_enrollments WHERE id = $1';
        const params = tenantId ? [enrollmentId, tenantId] : [enrollmentId];
        const result = await this.db.query(sql, params);

        return (result.rowCount ?? 0) > 0;
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    /**
     * FIX-500-308: Atomically increment a campaign stat counter in the DB.
     * Uses jsonb_set with a cast-based increment so two concurrent writers
     * cannot lose each other's update (unlike overwriting the full blob).
     */
    private static readonly STAT_FIELD_MAP: Record<string, string> = {
        opened: 'emailsOpened',
        clicked: 'emailsClicked',
        replied: 'repliesReceived',
        sent: 'emailsSent',
        enrolled: 'totalEnrolled',
        completed: 'completedCount',
        exited: 'exitedCount',
        bounced: 'bounced',
        unsubscribed: 'unsubscribed',
    };

    async incrementCampaignStat(
        campaignId: string,
        statKey: string,
        amount: number = 1
    ): Promise<void> {
        const field = CampaignRepository.STAT_FIELD_MAP[statKey] ?? statKey;
        await this.db.query(
            `UPDATE drip_campaigns
             SET stats = jsonb_set(
                 stats,
                 $2::text[],
                 to_jsonb(COALESCE((stats->>$3)::int, 0) + $4)
             ),
             updated_at = NOW()
             WHERE id = $1`,
            [campaignId, `{${field}}`, field, amount]
        );
    }

    private rowToCampaign(row: Record<string, unknown>): DripCampaign {
        return {
            id: row.id as string,
            tenantId: row.tenant_id as string,
            name: row.name as string,
            description: row.description as string | null,
            status: row.status as CampaignStatus,
            fromEmail: row.from_email as string,
            fromName: row.from_name as string,
            replyTo: row.reply_to as string | null,
            sequence: row.sequence_steps as DripCampaign['sequence'],
            triggers: row.triggers as DripCampaign['triggers'],
            exitConditions: row.exit_conditions as DripCampaign['exitConditions'],
            settings: row.settings as DripCampaign['settings'],
            stats: row.stats as DripCampaign['stats'],
            createdBy: row.created_by as string,
            startedAt: row.started_at as Date | null,
            pausedAt: row.paused_at as Date | null,
            createdAt: row.created_at as Date,
            updatedAt: row.updated_at as Date,
        };
    }

    private rowToEnrollment(row: Record<string, unknown>): CampaignEnrollment {
        return {
            id: row.id as string,
            campaignId: row.campaign_id as string,
            leadId: row.lead_id as string,
            status: row.status as EnrollmentStatus,
            currentStepId: row.current_step_id as string | null,
            completedSteps: row.completed_steps as string[],
            nextStepAt: row.next_step_at as Date | null,
            emailsSent: row.emails_sent as number,
            emailsOpened: row.emails_opened as number,
            emailsClicked: row.emails_clicked as number,
            replied: row.replied as boolean,
            exitReason: row.exit_reason as string | null,
            enrolledAt: row.enrolled_at as Date,
            completedAt: row.completed_at as Date | null,
            pausedAt: row.paused_at as Date | null,
            metadata: row.metadata as Record<string, unknown>,
        };
    }
}
