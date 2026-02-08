/**
 * Subscriptions Repository
 * 
 * Data access for subscription preferences and email categories
 */

import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { ok, err, type Result } from '@apexmail/lib';

// =============================================================================
// Types
// =============================================================================

export interface SubscriptionPreference {
    id: string;
    tenantId: string;
    email: string;
    category: string;
    subscribed: boolean;
    updatedAt: Date;
}

export interface EmailCategory {
    id: string;
    tenantId: string;
    name: string;
    description?: string;
    active: boolean;
    displayOrder: number;
    createdAt: Date;
}

export interface SubscriptionStatus {
    email: string;
    categories: Array<{
        name: string;
        subscribed: boolean;
        updatedAt: Date;
    }>;
    globalUnsubscribe: boolean;
}

// =============================================================================
// Repository
// =============================================================================

export class SubscriptionsRepository {
    constructor(private pool: Pool) {}

    // -------------------------------------------------------------------------
    // Email Categories
    // -------------------------------------------------------------------------

    async createCategory(tenantId: string, data: {
        name: string;
        description?: string;
        displayOrder?: number;
    }): Promise<Result<EmailCategory, Error>> {
        const id = randomUUID().replace(/-/g, '').slice(0, 26);

        try {
            const result = await this.pool.query<Record<string, unknown>>(
                `INSERT INTO email_categories (id, tenant_id, name, description, display_order)
                 VALUES ($1, $2, $3, $4, $5)
                 RETURNING *`,
                [id, tenantId, data.name, data.description, data.displayOrder ?? 0]
            );

            const row = result.rows[0];
            if (!row) {
                return err(new Error('Failed to create category'));
            }
            return ok(this.mapCategoryRow(row));
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    async findCategoryById(id: string, tenantId: string): Promise<EmailCategory | null> {
        const result = await this.pool.query<Record<string, unknown>>(
            `SELECT * FROM email_categories WHERE id = $1 AND tenant_id = $2`,
            [id, tenantId]
        );

        return result.rows[0] ? this.mapCategoryRow(result.rows[0]) : null;
    }

    async findCategoriesByTenant(tenantId: string): Promise<EmailCategory[]> {
        const result = await this.pool.query<Record<string, unknown>>(
            `SELECT * FROM email_categories 
             WHERE tenant_id = $1 AND active = true
             ORDER BY display_order, name`,
            [tenantId]
        );

        return result.rows.map(row => this.mapCategoryRow(row));
    }

    async updateCategory(id: string, tenantId: string, data: {
        name?: string;
        description?: string;
        active?: boolean;
        displayOrder?: number;
    }): Promise<Result<EmailCategory, Error>> {
        const fields: string[] = [];
        const values: unknown[] = [];
        let paramIndex = 1;

        if (data.name !== undefined) {
            fields.push(`name = $${paramIndex++}`);
            values.push(data.name);
        }
        if (data.description !== undefined) {
            fields.push(`description = $${paramIndex++}`);
            values.push(data.description);
        }
        if (data.active !== undefined) {
            fields.push(`active = $${paramIndex++}`);
            values.push(data.active);
        }
        if (data.displayOrder !== undefined) {
            fields.push(`display_order = $${paramIndex++}`);
            values.push(data.displayOrder);
        }

        if (fields.length === 0) {
            const existing = await this.findCategoryById(id, tenantId);
            return existing ? ok(existing) : err(new Error('Category not found'));
        }

        values.push(id, tenantId);

        try {
            const result = await this.pool.query<Record<string, unknown>>(
                `UPDATE email_categories 
                 SET ${fields.join(', ')}
                 WHERE id = $${paramIndex++} AND tenant_id = $${paramIndex}
                 RETURNING *`,
                values
            );

            if (result.rows.length === 0) {
                return err(new Error('Category not found'));
            }

            const row = result.rows[0];
            if (!row) {
                return err(new Error('Category not found'));
            }
            return ok(this.mapCategoryRow(row));
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    async deleteCategory(id: string, tenantId: string): Promise<boolean> {
        const result = await this.pool.query(
            `DELETE FROM email_categories WHERE id = $1 AND tenant_id = $2`,
            [id, tenantId]
        );

        return (result.rowCount ?? 0) > 0;
    }

    // -------------------------------------------------------------------------
    // Subscription Preferences
    // -------------------------------------------------------------------------

    async getPreferences(tenantId: string, email: string): Promise<SubscriptionStatus> {
        const normalizedEmail = email.toLowerCase().trim();

        // Get all categories for the tenant
        const categories = await this.findCategoriesByTenant(tenantId);

        // Get existing preferences
        const result = await this.pool.query<Record<string, unknown>>(
            `SELECT * FROM subscription_preferences
             WHERE tenant_id = $1 AND email = $2`,
            [tenantId, normalizedEmail]
        );

        const prefMap = new Map<string, { subscribed: boolean; updatedAt: Date }>();
        for (const row of result.rows) {
            prefMap.set(row.category as string, {
                subscribed: row.subscribed as boolean,
                updatedAt: new Date(row.updated_at as string)
            });
        }

        // Check for global unsubscribe
        const suppressionResult = await this.pool.query<{ count: string }>(
            `SELECT COUNT(*) as count FROM suppressions
             WHERE tenant_id = $1 AND email = $2 AND reason = 'unsubscribe'`,
            [tenantId, normalizedEmail]
        );
        const globalUnsubscribe = parseInt(suppressionResult.rows[0]?.count ?? '0', 10) > 0;

        return {
            email: normalizedEmail,
            categories: categories.map(cat => ({
                name: cat.name,
                subscribed: prefMap.get(cat.name)?.subscribed ?? true,
                updatedAt: prefMap.get(cat.name)?.updatedAt ?? cat.createdAt
            })),
            globalUnsubscribe
        };
    }

    async setPreference(tenantId: string, email: string, category: string, subscribed: boolean): Promise<Result<SubscriptionPreference, Error>> {
        const normalizedEmail = email.toLowerCase().trim();
        const id = randomUUID().replace(/-/g, '').slice(0, 26);

        try {
            const result = await this.pool.query<Record<string, unknown>>(
                `INSERT INTO subscription_preferences (id, tenant_id, email, category, subscribed)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (tenant_id, email, category)
                 DO UPDATE SET subscribed = EXCLUDED.subscribed, updated_at = NOW()
                 RETURNING *`,
                [id, tenantId, normalizedEmail, category, subscribed]
            );

            const row = result.rows[0];
            if (!row) {
                return err(new Error('Failed to set preference'));
            }
            return ok(this.mapPreferenceRow(row));
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    async setPreferences(tenantId: string, email: string, preferences: Record<string, boolean>): Promise<Result<SubscriptionPreference[], Error>> {
        const normalizedEmail = email.toLowerCase().trim();
        const results: SubscriptionPreference[] = [];

        const client = await this.pool.connect();
        try {
            await client.query('BEGIN');

            // FIX-500-055: Batch all preferences into a single multi-row INSERT instead of N round-trips
            const entries = Object.entries(preferences);
            if (entries.length > 0) {
                const ids = entries.map(() => randomUUID().replace(/-/g, '').slice(0, 26));
                const values: unknown[] = [];
                const placeholders: string[] = [];
                let paramIdx = 1;
                for (let i = 0; i < entries.length; i++) {
                    placeholders.push(`($${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++}, $${paramIdx++})`);
                    values.push(ids[i], tenantId, normalizedEmail, entries[i]![0], entries[i]![1]);
                }
                const result = await client.query<Record<string, unknown>>(
                    `INSERT INTO subscription_preferences (id, tenant_id, email, category, subscribed)
                     VALUES ${placeholders.join(', ')}
                     ON CONFLICT (tenant_id, email, category)
                     DO UPDATE SET subscribed = EXCLUDED.subscribed, updated_at = NOW()
                     RETURNING *`,
                    values
                );
                for (const row of result.rows) {
                    results.push(this.mapPreferenceRow(row));
                }
            }

            await client.query('COMMIT');
            return ok(results);
        } catch (error) {
            await client.query('ROLLBACK');
            return err(error instanceof Error ? error : new Error(String(error)));
        } finally {
            client.release();
        }
    }

    async unsubscribeFromCategory(tenantId: string, email: string, category: string): Promise<Result<void, Error>> {
        const result = await this.setPreference(tenantId, email, category, false);
        return result.ok ? ok(undefined) : err(result.error);
    }

    async resubscribeToCategory(tenantId: string, email: string, category: string): Promise<Result<void, Error>> {
        const result = await this.setPreference(tenantId, email, category, true);
        return result.ok ? ok(undefined) : err(result.error);
    }

    async isSubscribedToCategory(tenantId: string, email: string, category: string): Promise<boolean> {
        const normalizedEmail = email.toLowerCase().trim();

        // Check global unsubscribe first
        const suppressionResult = await this.pool.query<{ count: string }>(
            `SELECT COUNT(*) as count FROM suppressions
             WHERE tenant_id = $1 AND email = $2 AND reason = 'unsubscribe'`,
            [tenantId, normalizedEmail]
        );
        if (parseInt(suppressionResult.rows[0]?.count ?? '0', 10) > 0) {
            return false;
        }

        // Check category preference
        const result = await this.pool.query<{ subscribed: boolean }>(
            `SELECT subscribed FROM subscription_preferences
             WHERE tenant_id = $1 AND email = $2 AND category = $3`,
            [tenantId, normalizedEmail, category]
        );

        // Default to subscribed if no preference exists
        return result.rows[0]?.subscribed ?? true;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private mapCategoryRow(row: Record<string, unknown>): EmailCategory {
        return {
            id: row.id as string,
            tenantId: row.tenant_id as string,
            name: row.name as string,
            description: row.description as string | undefined,
            active: row.active as boolean,
            displayOrder: row.display_order as number,
            createdAt: new Date(row.created_at as string),
        };
    }

    private mapPreferenceRow(row: Record<string, unknown>): SubscriptionPreference {
        return {
            id: row.id as string,
            tenantId: row.tenant_id as string,
            email: row.email as string,
            category: row.category as string,
            subscribed: row.subscribed as boolean,
            updatedAt: new Date(row.updated_at as string),
        };
    }
}
