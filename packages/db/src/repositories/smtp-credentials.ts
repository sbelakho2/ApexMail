/**
 * SMTP Credentials Repository
 * 
 * Data access for SMTP authentication credentials
 */

import { randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import type { Pool } from 'pg';
import { ok, err, type Result } from '@apexmail/lib';

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
    constructor(private pool: Pool) {}

    /**
     * Create new SMTP credentials for a tenant
     * Returns the plain password only once - it cannot be retrieved again
     */
    async create(tenantId: string, username?: string): Promise<Result<SmtpCredentialWithSecret, Error>> {
        const id = randomUUID().replace(/-/g, '').slice(0, 26);
        
        // Generate secure username if not provided
        const finalUsername = username ?? `smtp_${tenantId.slice(0, 8)}_${randomUUID().slice(0, 8)}`;
        
        // Generate secure random password
        const password = this.generateSecurePassword();
        const passwordHash = this.hashPassword(password);

        try {
            // Check for existing username
            const existing = await this.pool.query(
                `SELECT id FROM smtp_credentials WHERE username = $1`,
                [finalUsername]
            );

            if (existing.rows.length > 0) {
                return err(new Error('Username already exists'));
            }

            const result = await this.pool.query<Record<string, unknown>>(
                `INSERT INTO smtp_credentials (id, tenant_id, username, password_hash)
                 VALUES ($1, $2, $3, $4)
                 RETURNING id, tenant_id, username, is_active, created_at`,
                [id, tenantId, finalUsername, passwordHash]
            );

            const row = result.rows[0];
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
            const result = await this.pool.query<Record<string, unknown>>(
                `SELECT id, tenant_id, password_hash, is_active
                 FROM smtp_credentials
                 WHERE username = $1`,
                [username]
            );

            if (result.rows.length === 0) {
                // Perform dummy hash comparison to prevent timing attacks
                this.hashPassword(password);
                return err(new Error('Invalid credentials'));
            }

            const row = result.rows[0];
            if (!row) {
                return err(new Error('Invalid credentials'));
            }
            const isActive = row.is_active as boolean;

            if (!isActive) {
                return err(new Error('Credentials are disabled'));
            }

            const storedHash = row.password_hash as string;
            const providedHash = this.hashPassword(password);

            // Timing-safe comparison
            const storedBuffer = Buffer.from(storedHash, 'hex');
            const providedBuffer = Buffer.from(providedHash, 'hex');

            if (storedBuffer.length !== providedBuffer.length) {
                return err(new Error('Invalid credentials'));
            }

            if (!timingSafeEqual(storedBuffer, providedBuffer)) {
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
        const result = await this.pool.query<Record<string, unknown>>(
            `SELECT id, tenant_id, username, is_active, created_at
             FROM smtp_credentials
             WHERE tenant_id = $1
             ORDER BY created_at DESC`,
            [tenantId]
        );

        return result.rows.map(row => this.mapRow(row));
    }

    /**
     * Find credential by ID
     */
    async findById(id: string, tenantId: string): Promise<SmtpCredential | null> {
        const result = await this.pool.query<Record<string, unknown>>(
            `SELECT id, tenant_id, username, is_active, created_at
             FROM smtp_credentials
             WHERE id = $1 AND tenant_id = $2`,
            [id, tenantId]
        );

        return result.rows[0] ? this.mapRow(result.rows[0]) : null;
    }

    /**
     * Enable or disable credentials
     */
    async setActive(id: string, tenantId: string, isActive: boolean): Promise<Result<SmtpCredential, Error>> {
        try {
            const result = await this.pool.query<Record<string, unknown>>(
                `UPDATE smtp_credentials
                 SET is_active = $3
                 WHERE id = $1 AND tenant_id = $2
                 RETURNING id, tenant_id, username, is_active, created_at`,
                [id, tenantId, isActive]
            );

            if (result.rows.length === 0) {
                return err(new Error('Credential not found'));
            }

            const row = result.rows[0];
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
        const passwordHash = this.hashPassword(password);

        try {
            const result = await this.pool.query(
                `UPDATE smtp_credentials
                 SET password_hash = $3
                 WHERE id = $1 AND tenant_id = $2`,
                [id, tenantId, passwordHash]
            );

            if ((result.rowCount ?? 0) === 0) {
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
        const result = await this.pool.query(
            `DELETE FROM smtp_credentials WHERE id = $1 AND tenant_id = $2`,
            [id, tenantId]
        );

        return (result.rowCount ?? 0) > 0;
    }

    /**
     * Count credentials for a tenant
     */
    async countByTenant(tenantId: string): Promise<number> {
        const result = await this.pool.query<{ count: string }>(
            `SELECT COUNT(*)::text as count FROM smtp_credentials WHERE tenant_id = $1`,
            [tenantId]
        );

        return parseInt(result.rows[0]?.count ?? '0', 10);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private generateSecurePassword(): string {
        // Generate a 32-character password with mixed characters
        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        const bytes = Buffer.alloc(32);
        
        // Use crypto for secure random bytes
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const crypto = require('node:crypto');
        crypto.randomFillSync(bytes);
        
        let password = '';
        for (let i = 0; i < 32; i++) {
            const byte = bytes[i];
            if (byte !== undefined) {
                password += charset[byte % charset.length];
            }
        }
        
        return password;
    }

    private hashPassword(password: string): string {
        // Use SHA-256 with a static salt (in production, use bcrypt or argon2)
        const salt = process.env.SMTP_PASSWORD_SALT ?? 'apexmail-smtp-default-salt';
        return createHash('sha256')
            .update(salt + password)
            .digest('hex');
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
