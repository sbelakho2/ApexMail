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

    async getCampaign(campaignId: string): Promise<DripCampaign | null> {
        const result = await this.db.query(
            'SELECT * FROM drip_campaigns WHERE id = $1',
            [campaignId]
        );

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

    async getActiveCampaigns(): Promise<DripCampaign[]> {
        const result = await this.db.query(
            "SELECT * FROM drip_campaigns WHERE status = 'active'"
        );

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
        updates: Partial<Pick<DripCampaign, 'name' | 'description' | 'status' | 'stats' | 'startedAt' | 'pausedAt'>>
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

        if (setClauses.length === 0) {
            return this.getCampaign(campaignId);
        }

        const result = await this.db.query(
            `UPDATE drip_campaigns SET ${setClauses.join(', ')}, updated_at = NOW() WHERE id = $1 RETURNING *`,
            values
        );

        if (result.rows.length === 0) {
            return null;
        }

        return this.rowToCampaign(result.rows[0]);
    }

    async deleteCampaign(campaignId: string): Promise<boolean> {
        const result = await this.db.query(
            'DELETE FROM drip_campaigns WHERE id = $1',
            [campaignId]
        );

        return (result.rowCount ?? 0) > 0;
    }

    // =========================================================================
    // ENROLLMENTS
    // =========================================================================

    async createEnrollment(enrollment: CampaignEnrollment): Promise<CampaignEnrollment> {
        const result = await this.db.query(
            `INSERT INTO campaign_enrollments (
                id, campaign_id, lead_id, status, current_step_id,
                completed_steps, next_step_at, emails_sent, emails_opened,
                emails_clicked, replied, exit_reason, enrolled_at,
                completed_at, paused_at, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
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

    async getEnrollment(enrollmentId: string): Promise<CampaignEnrollment | null> {
        const result = await this.db.query(
            'SELECT * FROM campaign_enrollments WHERE id = $1',
            [enrollmentId]
        );

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
            'emailsClicked' | 'replied' | 'exitReason' | 'completedAt' | 'pausedAt'>>
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

        if (setClauses.length === 0) {
            return this.getEnrollment(enrollmentId);
        }

        const result = await this.db.query(
            `UPDATE campaign_enrollments SET ${setClauses.join(', ')} WHERE id = $1 RETURNING *`,
            values
        );

        if (result.rows.length === 0) {
            return null;
        }

        return this.rowToEnrollment(result.rows[0]);
    }

    async deleteEnrollment(enrollmentId: string): Promise<boolean> {
        const result = await this.db.query(
            'DELETE FROM campaign_enrollments WHERE id = $1',
            [enrollmentId]
        );

        return (result.rowCount ?? 0) > 0;
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

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
