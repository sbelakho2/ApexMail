/**
 * SMTP Credentials Repository
 * 
 * Data access for SMTP authentication credentials
 */

import { randomUUID, randomInt } from 'node:crypto';
import { ok, err, type Result } from '@apexmail/lib';
import { hashPassword as hashSecret, verifyPassword as verifySecret } from '@apexmail/lib/crypto';
import type { DatabasePool } from '../pool.js';

// =============================================================================
// Types
// =============================================================================

export interface SmtpCredential {
    id: string;
    tenantId: string;
    username: string;
    isActive: boolean;
    createdAt: Date;
}

export interface SmtpCredentialWithSecret extends SmtpCredential {
    password: string; // Only returned on creation
}

// =============================================================================
// Repository
// =============================================================================

export class SmtpCredentialsRepository {
    constructor(private readonly db: DatabasePool) {}

    /**
     * Create new SMTP credentials for a tenant
     * Returns the plain password only once - it cannot be retrieved again
     */
    /**
     * A-015: Fix TOCTOU race on username uniqueness.
     * Use INSERT ... ON CONFLICT instead of SELECT-then-INSERT.
     */
    async create(tenantId: string, username?: string): Promise<Result<SmtpCredentialWithSecret, Error>> {
        const id = randomUUID().replace(/-/g, '').slice(0, 26);
        
        // Generate secure username if not provided
        const finalUsername = username ?? `smtp_${tenantId.slice(0, 8)}_${randomUUID().slice(0, 8)}`;
        
        // Generate secure random password
        const password = this.generateSecurePassword();
        const passwordHash = await this.hashPassword(password);

        try {
            const result = await this.db.query<Record<string, unknown>>(
                `INSERT INTO smtp_credentials (id, tenant_id, username, password_hash)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (username) DO NOTHING
                 RETURNING id, tenant_id, username, is_active, created_at`,
                [id, tenantId, finalUsername, passwordHash]
            );

            if (!result.ok) {
                return err(result.error);
            }

            if (result.value.rows.length === 0) {
                return err(new Error('Username already exists'));
            }

            const row = result.value.rows[0];
            if (!row) {
                return err(new Error('Failed to create credentials'));
            }
            return ok({
                ...this.mapRow(row),
                password
            });
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    /**
     * Verify SMTP credentials
     * Uses timing-safe comparison to prevent timing attacks
     */
    async verify(username: string, password: string): Promise<Result<{ tenantId: string; credentialId: string }, Error>> {
        try {
            const result = await this.db.query<Record<string, unknown>>(
                `SELECT id, tenant_id, password_hash, is_active
                 FROM smtp_credentials
                 WHERE username = $1`,
                [username]
            );

            if (!result.ok) {
                return err(result.error);
            }

            if (result.value.rows.length === 0) {
                // Perform dummy verification to keep timing similar
                await verifySecret(password, await this.hashPassword(password));
                return err(new Error('Invalid credentials'));
            }

            const row = result.value.rows[0];
            if (!row) {
                return err(new Error('Invalid credentials'));
            }
            const isActive = row.is_active as boolean;

            if (!isActive) {
                return err(new Error('Credentials are disabled'));
            }

            const storedHash = row.password_hash as string;
            const hashMatch = await verifySecret(password, storedHash);
            if (!hashMatch) {
                return err(new Error('Invalid credentials'));
            }

            return ok({
                tenantId: row.tenant_id as string,
                credentialId: row.id as string
            });
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    /**
     * Find all credentials for a tenant
     */
    async findByTenant(tenantId: string): Promise<SmtpCredential[]> {
        const result = await this.db.query<Record<string, unknown>>(
            `SELECT id, tenant_id, username, is_active, created_at
             FROM smtp_credentials
             WHERE tenant_id = $1
             ORDER BY created_at DESC`,
            [tenantId]
        );

        if (!result.ok) throw result.error;
        return result.value.rows.map(row => this.mapRow(row));
    }

    /**
     * Find credential by ID
     */
    async findById(id: string, tenantId: string): Promise<SmtpCredential | null> {
        const result = await this.db.query<Record<string, unknown>>(
            `SELECT id, tenant_id, username, is_active, created_at
             FROM smtp_credentials
             WHERE id = $1 AND tenant_id = $2`,
            [id, tenantId]
        );

        if (!result.ok) throw result.error;
        return result.value.rows[0] ? this.mapRow(result.value.rows[0]) : null;
    }

    /**
     * Enable or disable credentials
     */
    async setActive(id: string, tenantId: string, isActive: boolean): Promise<Result<SmtpCredential, Error>> {
        try {
            const result = await this.db.query<Record<string, unknown>>(
                `UPDATE smtp_credentials
                 SET is_active = $3
                 WHERE id = $1 AND tenant_id = $2
                 RETURNING id, tenant_id, username, is_active, created_at`,
                [id, tenantId, isActive]
            );

            if (!result.ok) {
                return err(result.error);
            }

            if (result.value.rows.length === 0) {
                return err(new Error('Credential not found'));
            }

            const row = result.value.rows[0];
            if (!row) {
                return err(new Error('Credential not found'));
            }
            return ok(this.mapRow(row));
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    /**
     * Regenerate password for existing credentials
     * Returns the new plain password only once
     */
    async regeneratePassword(id: string, tenantId: string): Promise<Result<{ password: string }, Error>> {
        const password = this.generateSecurePassword();
        const passwordHash = await this.hashPassword(password);

        try {
            const result = await this.db.query(
                `UPDATE smtp_credentials
                 SET password_hash = $3
                 WHERE id = $1 AND tenant_id = $2`,
                [id, tenantId, passwordHash]
            );

            if (!result.ok) {
                return err(result.error);
            }

            if ((result.value.rowCount ?? 0) === 0) {
                return err(new Error('Credential not found'));
            }

            return ok({ password });
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    /**
     * Delete credentials
     */
    async delete(id: string, tenantId: string): Promise<boolean> {
        const result = await this.db.query(
            `DELETE FROM smtp_credentials WHERE id = $1 AND tenant_id = $2`,
            [id, tenantId]
        );

        if (!result.ok) throw result.error;
        return (result.value.rowCount ?? 0) > 0;
    }

    /**
     * F-188: Find expired SMTP credentials (older than maxAgeDays, default 90)
     * Returns credentials that should be rotated for security.
     */
    async findExpired(maxAgeDays = 90): Promise<SmtpCredential[]> {
                const result = await this.db.query<Record<string, unknown>>(
            `SELECT id, tenant_id, username, is_active, created_at
             FROM smtp_credentials
             WHERE created_at < NOW() - INTERVAL '1 day' * $1
               AND is_active = true
             ORDER BY created_at ASC`,
            [maxAgeDays]
        );

                if (!result.ok) throw result.error;
                return result.value.rows.map(row => this.mapRow(row));
    }

    /**
     * F-188: Rotate an SMTP credential — generates a new password, updates the
     * hash, and returns the new plain-text password (shown once).
     * Unlike regeneratePassword, rotate also records the rotation timestamp
     * by resetting created_at so the credential won't be flagged as expired again.
     */
    async rotate(id: string, tenantId: string): Promise<Result<{ password: string }, Error>> {
        const password = this.generateSecurePassword();
        const passwordHash = await this.hashPassword(password);

        try {
            const result = await this.db.query(
                `UPDATE smtp_credentials
                 SET password_hash = $3,
                     created_at = NOW()
                 WHERE id = $1 AND tenant_id = $2 AND is_active = true`,
                [id, tenantId, passwordHash]
            );

            if (!result.ok) {
                return err(result.error);
            }

            if ((result.value.rowCount ?? 0) === 0) {
                return err(new Error('Credential not found or inactive'));
            }

            return ok({ password });
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    /**
     * Count credentials for a tenant
     */
    async countByTenant(tenantId: string): Promise<number> {
        const result = await this.db.query<{ count: string }>(
            `SELECT COUNT(*)::text as count FROM smtp_credentials WHERE tenant_id = $1`,
            [tenantId]
        );

        if (!result.ok) throw result.error;
        return parseInt(result.value.rows[0]?.count ?? '0', 10);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private generateSecurePassword(): string {
        // Generate a 32-character password with uniform distribution.
        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        const length = 32;
        let password = '';

        for (let i = 0; i < length; i++) {
            password += charset[randomInt(0, charset.length)];
        }

        return password;
    }

    private async hashPassword(password: string): Promise<string> {
        return hashSecret(password);
    }

    private mapRow(row: Record<string, unknown>): SmtpCredential {
        return {
            id: row.id as string,
            tenantId: row.tenant_id as string,
            username: row.username as string,
            isActive: row.is_active as boolean,
            createdAt: new Date(row.created_at as string),
        };
    }
}
