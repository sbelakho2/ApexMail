/**
 * Secret Manager
 *
 * Secure management of API keys, passwords, tokens, and other
 * sensitive credentials with encryption, rotation scheduling,
 * and access control.
 */

import * as CryptoJS from 'crypto-js';
import { Pool } from 'pg';
import { Redis } from 'ioredis';
import {
    Secret,
    SecretType,
    RotationSchedule,
    SecretAccess,
} from '../types';
import { complianceConfig } from '../config';
import { randomUUID, randomBytes } from 'crypto';

interface SecretCreateInput {
    tenantId: string;
    name: string;
    type: SecretType;
    value: string;
    rotationSchedule?: RotationSchedule;
    expiresAt?: Date;
    createdBy: string;
}

interface SecretUpdateInput {
    value?: string;
    rotationSchedule?: RotationSchedule | null;
    expiresAt?: Date | null;
}

export class SecretManager {
    private db: Pool;
    private redis: Redis;
    private config = complianceConfig.secrets;
    private encryptionKey: string;

    constructor(db: Pool, redis: Redis, encryptionKey: string) {
        this.db = db;
        this.redis = redis;
        this.encryptionKey = encryptionKey;
    }

    /**
     * Create a new secret
     */
    async createSecret(input: SecretCreateInput): Promise<Secret> {
        const id = randomUUID();
        const encryptedValue = this.encrypt(input.value);
        const now = new Date();

        let nextRotationAt: Date | null = null;
        if (input.rotationSchedule) {
            nextRotationAt = new Date(
                now.getTime() + input.rotationSchedule.intervalDays * 24 * 60 * 60 * 1000
            );
        }

        const secret: Secret = {
            id,
            tenantId: input.tenantId,
            name: input.name,
            type: input.type,
            encryptedValue,
            version: 1,
            rotationSchedule: input.rotationSchedule || null,
            lastRotatedAt: null,
            nextRotationAt,
            createdBy: input.createdBy,
            createdAt: now,
            updatedAt: now,
            expiresAt: input.expiresAt || null,
        };

        await this.db.query(
            `INSERT INTO secrets (
                id, tenant_id, name, type, encrypted_value, version,
                rotation_schedule, last_rotated_at, next_rotation_at,
                created_by, created_at, updated_at, expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
            [
                secret.id,
                secret.tenantId,
                secret.name,
                secret.type,
                secret.encryptedValue,
                secret.version,
                secret.rotationSchedule ? JSON.stringify(secret.rotationSchedule) : null,
                secret.lastRotatedAt,
                secret.nextRotationAt,
                secret.createdBy,
                secret.createdAt,
                secret.updatedAt,
                secret.expiresAt,
            ]
        );

        // Store version history
        await this.storeVersionHistory(secret.id, 1, encryptedValue);

        return secret;
    }

    /**
     * Get a secret by ID (decrypted)
     */
    async getSecret(
        secretId: string,
        userId: string
    ): Promise<{ secret: Secret; value: string } | null> {
        // Check access
        const hasAccess = await this.checkAccess(secretId, userId, 'read');
        if (!hasAccess) {
            throw new Error('Access denied to secret');
        }

        const result = await this.db.query(
            `SELECT * FROM secrets WHERE id = $1`,
            [secretId]
        );

        if (result.rows.length === 0) return null;

        const secret = this.mapRowToSecret(result.rows[0]);

        // Check if expired
        if (secret.expiresAt && new Date() > secret.expiresAt) {
            throw new Error('Secret has expired');
        }

        const value = this.decrypt(secret.encryptedValue);

        // Log access
        await this.logAccess(secretId, userId, 'read');

        return { secret, value };
    }

    /**
     * Get a secret by name
     */
    async getSecretByName(
        tenantId: string,
        name: string,
        userId: string
    ): Promise<{ secret: Secret; value: string } | null> {
        const result = await this.db.query(
            `SELECT id FROM secrets WHERE tenant_id = $1 AND name = $2`,
            [tenantId, name]
        );

        if (result.rows.length === 0) return null;

        return this.getSecret(result.rows[0].id, userId);
    }

    /**
     * Update a secret
     */
    async updateSecret(
        secretId: string,
        userId: string,
        update: SecretUpdateInput
    ): Promise<Secret> {
        // Check access
        const hasAccess = await this.checkAccess(secretId, userId, 'write');
        if (!hasAccess) {
            throw new Error('Access denied to modify secret');
        }

        const existing = await this.db.query(
            `SELECT * FROM secrets WHERE id = $1`,
            [secretId]
        );

        if (existing.rows.length === 0) {
            throw new Error('Secret not found');
        }

        const currentSecret = this.mapRowToSecret(existing.rows[0]);
        const now = new Date();

        let encryptedValue = currentSecret.encryptedValue;
        let version = currentSecret.version;
        let lastRotatedAt = currentSecret.lastRotatedAt;

        if (update.value) {
            encryptedValue = this.encrypt(update.value);
            version = currentSecret.version + 1;
            lastRotatedAt = now;

            // Store version history
            await this.storeVersionHistory(secretId, version, encryptedValue);
        }

        let nextRotationAt = currentSecret.nextRotationAt;
        const rotationSchedule =
            update.rotationSchedule === null
                ? null
                : update.rotationSchedule || currentSecret.rotationSchedule;

        if (rotationSchedule && update.value) {
            nextRotationAt = new Date(
                now.getTime() + rotationSchedule.intervalDays * 24 * 60 * 60 * 1000
            );
        }

        await this.db.query(
            `UPDATE secrets SET
                encrypted_value = $2,
                version = $3,
                rotation_schedule = $4,
                last_rotated_at = $5,
                next_rotation_at = $6,
                updated_at = $7,
                expires_at = COALESCE($8, expires_at)
            WHERE id = $1`,
            [
                secretId,
                encryptedValue,
                version,
                rotationSchedule ? JSON.stringify(rotationSchedule) : null,
                lastRotatedAt,
                nextRotationAt,
                now,
                update.expiresAt,
            ]
        );

        // Clear cache
        await this.redis.del(`secret:${secretId}`);

        // Log modification
        await this.logAccess(secretId, userId, 'write');

        return {
            ...currentSecret,
            encryptedValue,
            version,
            rotationSchedule,
            lastRotatedAt,
            nextRotationAt,
            updatedAt: now,
            expiresAt: update.expiresAt !== undefined ? update.expiresAt : currentSecret.expiresAt,
        };
    }

    /**
     * Rotate a secret (generate new value)
     */
    async rotateSecret(
        secretId: string,
        userId: string,
        newValue?: string
    ): Promise<{ secret: Secret; value: string }> {
        const hasAccess = await this.checkAccess(secretId, userId, 'write');
        if (!hasAccess) {
            throw new Error('Access denied to rotate secret');
        }

        // Generate new value if not provided
        const value = newValue || this.generateSecretValue();

        const secret = await this.updateSecret(secretId, userId, { value });

        return { secret, value };
    }

    /**
     * Delete a secret
     */
    async deleteSecret(secretId: string, userId: string): Promise<void> {
        const hasAccess = await this.checkAccess(secretId, userId, 'admin');
        if (!hasAccess) {
            throw new Error('Access denied to delete secret');
        }

        // Archive the secret
        await this.db.query(
            `INSERT INTO secrets_archive SELECT * FROM secrets WHERE id = $1`,
            [secretId]
        );

        // Delete version history
        await this.db.query(
            `DELETE FROM secret_versions WHERE secret_id = $1`,
            [secretId]
        );

        // Delete access grants
        await this.db.query(
            `DELETE FROM secret_access WHERE secret_id = $1`,
            [secretId]
        );

        // Delete the secret
        await this.db.query(`DELETE FROM secrets WHERE id = $1`, [secretId]);

        // Clear cache
        await this.redis.del(`secret:${secretId}`);

        // Log deletion
        await this.logAccess(secretId, userId, 'delete');
    }

    /**
     * List secrets for a tenant (without values)
     */
    async listSecrets(
        tenantId: string,
        type?: SecretType
    ): Promise<Omit<Secret, 'encryptedValue'>[]> {
        let query = `SELECT * FROM secrets WHERE tenant_id = $1`;
        const params: unknown[] = [tenantId];

        if (type) {
            query += ` AND type = $2`;
            params.push(type);
        }

        query += ` ORDER BY name`;

        const result = await this.db.query(query, params);

        return result.rows.map((row) => {
            const secret = this.mapRowToSecret(row);
            const { encryptedValue, ...rest } = secret;
            return rest;
        });
    }

    /**
     * Grant access to a secret
     */
    async grantAccess(
        secretId: string,
        userId: string,
        accessType: 'read' | 'write' | 'admin',
        grantedBy: string,
        expiresAt?: Date
    ): Promise<SecretAccess> {
        const hasAccess = await this.checkAccess(secretId, grantedBy, 'admin');
        if (!hasAccess) {
            throw new Error('Access denied to grant secret access');
        }

        const id = randomUUID();
        const now = new Date();

        const access: SecretAccess = {
            id,
            secretId,
            userId,
            accessType,
            grantedBy,
            grantedAt: now,
            expiresAt: expiresAt || null,
            revokedAt: null,
        };

        await this.db.query(
            `INSERT INTO secret_access (
                id, secret_id, user_id, access_type, granted_by, granted_at, expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (secret_id, user_id) DO UPDATE SET
                access_type = EXCLUDED.access_type,
                granted_by = EXCLUDED.granted_by,
                granted_at = EXCLUDED.granted_at,
                expires_at = EXCLUDED.expires_at,
                revoked_at = NULL`,
            [id, secretId, userId, accessType, grantedBy, now, expiresAt]
        );

        return access;
    }

    /**
     * Revoke access to a secret
     */
    async revokeAccess(
        secretId: string,
        userId: string,
        revokedBy: string
    ): Promise<void> {
        const hasAccess = await this.checkAccess(secretId, revokedBy, 'admin');
        if (!hasAccess) {
            throw new Error('Access denied to revoke secret access');
        }

        await this.db.query(
            `UPDATE secret_access SET revoked_at = NOW()
            WHERE secret_id = $1 AND user_id = $2`,
            [secretId, userId]
        );
    }

    /**
     * Check if user has access to a secret
     */
    async checkAccess(
        secretId: string,
        userId: string,
        requiredAccess: 'read' | 'write' | 'admin' | 'delete'
    ): Promise<boolean> {
        // Check if user is the creator (always has admin access)
        const secretResult = await this.db.query(
            `SELECT created_by FROM secrets WHERE id = $1`,
            [secretId]
        );

        if (secretResult.rows.length > 0 && secretResult.rows[0].created_by === userId) {
            return true;
        }

        // Check explicit access grants
        const result = await this.db.query(
            `SELECT access_type FROM secret_access
            WHERE secret_id = $1 AND user_id = $2
            AND revoked_at IS NULL
            AND (expires_at IS NULL OR expires_at > NOW())`,
            [secretId, userId]
        );

        if (result.rows.length === 0) return false;

        const accessType = result.rows[0].access_type;

        // Check access hierarchy
        const accessLevels = { read: 1, write: 2, admin: 3, delete: 3 };
        const requiredLevel = accessLevels[requiredAccess];
        const grantedLevel = accessLevels[accessType as keyof typeof accessLevels];

        return grantedLevel >= requiredLevel;
    }

    /**
     * Get secrets due for rotation
     */
    async getSecretsForRotation(): Promise<Secret[]> {
        const result = await this.db.query(
            `SELECT * FROM secrets
            WHERE next_rotation_at IS NOT NULL
            AND next_rotation_at <= NOW()
            AND (expires_at IS NULL OR expires_at > NOW())`,
            []
        );

        return result.rows.map(this.mapRowToSecret);
    }

    /**
     * Process automatic rotations
     */
    async processAutoRotations(): Promise<{
        rotated: string[];
        notified: string[];
        errors: Array<{ id: string; error: string }>;
    }> {
        const secrets = await this.getSecretsForRotation();
        const rotated: string[] = [];
        const notified: string[] = [];
        const errors: Array<{ id: string; error: string }> = [];

        for (const secret of secrets) {
            try {
                if (secret.rotationSchedule?.autoRotate) {
                    // Auto-rotate
                    const newValue = this.generateSecretValue(secret.type);
                    await this.updateSecret(secret.id, 'system', { value: newValue });
                    rotated.push(secret.id);

                    // Notify about rotation
                    await this.notifyRotation(secret);
                } else {
                    // Just notify, don't auto-rotate
                    await this.notifyRotationDue(secret);
                    notified.push(secret.id);
                }
            } catch (err) {
                errors.push({
                    id: secret.id,
                    error: err instanceof Error ? err.message : 'Unknown error',
                });
            }
        }

        return { rotated, notified, errors };
    }

    /**
     * Get secret version history
     */
    async getVersionHistory(
        secretId: string,
        userId: string
    ): Promise<Array<{ version: number; createdAt: Date }>> {
        const hasAccess = await this.checkAccess(secretId, userId, 'read');
        if (!hasAccess) {
            throw new Error('Access denied to secret history');
        }

        const result = await this.db.query(
            `SELECT version, created_at FROM secret_versions
            WHERE secret_id = $1 ORDER BY version DESC`,
            [secretId]
        );

        return result.rows.map((row) => ({
            version: row.version,
            createdAt: new Date(row.created_at),
        }));
    }

    /**
     * Rollback to a previous version
     */
    async rollbackToVersion(
        secretId: string,
        version: number,
        userId: string
    ): Promise<Secret> {
        const hasAccess = await this.checkAccess(secretId, userId, 'write');
        if (!hasAccess) {
            throw new Error('Access denied to rollback secret');
        }

        const result = await this.db.query(
            `SELECT encrypted_value FROM secret_versions
            WHERE secret_id = $1 AND version = $2`,
            [secretId, version]
        );

        if (result.rows.length === 0) {
            throw new Error('Version not found');
        }

        const encryptedValue = result.rows[0].encrypted_value;
        const value = this.decrypt(encryptedValue);

        return this.updateSecret(secretId, userId, { value });
    }

    /**
     * Encrypt a value
     */
    private encrypt(value: string): string {
        const iv = CryptoJS.lib.WordArray.random(16);
        const encrypted = CryptoJS.AES.encrypt(value, this.encryptionKey, {
            iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
        });

        // Combine IV and ciphertext
        const combined = iv.concat(encrypted.ciphertext);
        return combined.toString(CryptoJS.enc.Base64);
    }

    /**
     * Decrypt a value
     */
    private decrypt(encryptedValue: string): string {
        const combined = CryptoJS.enc.Base64.parse(encryptedValue);
        const iv = CryptoJS.lib.WordArray.create(combined.words.slice(0, 4), 16);
        const ciphertext = CryptoJS.lib.WordArray.create(
            combined.words.slice(4),
            combined.sigBytes - 16
        );

        const decrypted = CryptoJS.AES.decrypt(
            { ciphertext } as CryptoJS.lib.CipherParams,
            this.encryptionKey,
            {
                iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7,
            }
        );

        return decrypted.toString(CryptoJS.enc.Utf8);
    }

    /**
     * Generate a secure random secret value
     */
    private generateSecretValue(type?: SecretType): string {
        switch (type) {
            case 'api_key':
                return `apx_${randomBytes(32).toString('hex')}`;
            case 'webhook_secret':
                return `whsec_${randomBytes(32).toString('hex')}`;
            case 'encryption_key':
                return randomBytes(32).toString('base64');
            default:
                return randomBytes(32).toString('hex');
        }
    }

    /**
     * Store version in history
     */
    private async storeVersionHistory(
        secretId: string,
        version: number,
        encryptedValue: string
    ): Promise<void> {
        await this.db.query(
            `INSERT INTO secret_versions (secret_id, version, encrypted_value, created_at)
            VALUES ($1, $2, $3, NOW())`,
            [secretId, version, encryptedValue]
        );

        // Keep only last N versions
        await this.db.query(
            `DELETE FROM secret_versions
            WHERE secret_id = $1 AND version NOT IN (
                SELECT version FROM secret_versions
                WHERE secret_id = $1
                ORDER BY version DESC
                LIMIT $2
            )`,
            [secretId, this.config.maxVersionsToKeep]
        );
    }

    /**
     * Log secret access
     */
    private async logAccess(
        secretId: string,
        userId: string,
        action: string
    ): Promise<void> {
        await this.db.query(
            `INSERT INTO secret_access_log (secret_id, user_id, action, timestamp)
            VALUES ($1, $2, $3, NOW())`,
            [secretId, userId, action]
        );
    }

    /**
     * Notify about completed rotation
     */
    private async notifyRotation(secret: Secret): Promise<void> {
        await this.redis.lpush(
            'notifications:queue',
            JSON.stringify({
                type: 'secret_rotated',
                secretId: secret.id,
                secretName: secret.name,
                tenantId: secret.tenantId,
                timestamp: new Date().toISOString(),
            })
        );
    }

    /**
     * Notify that rotation is due
     */
    private async notifyRotationDue(secret: Secret): Promise<void> {
        await this.redis.lpush(
            'notifications:queue',
            JSON.stringify({
                type: 'secret_rotation_due',
                secretId: secret.id,
                secretName: secret.name,
                tenantId: secret.tenantId,
                dueAt: secret.nextRotationAt?.toISOString(),
                timestamp: new Date().toISOString(),
            })
        );
    }

    /**
     * Map database row to Secret
     */
    private mapRowToSecret(row: Record<string, unknown>): Secret {
        return {
            id: row.id as string,
            tenantId: row.tenant_id as string,
            name: row.name as string,
            type: row.type as SecretType,
            encryptedValue: row.encrypted_value as string,
            version: row.version as number,
            rotationSchedule: row.rotation_schedule as RotationSchedule | null,
            lastRotatedAt: row.last_rotated_at
                ? new Date(row.last_rotated_at as string)
                : null,
            nextRotationAt: row.next_rotation_at
                ? new Date(row.next_rotation_at as string)
                : null,
            createdBy: row.created_by as string,
            createdAt: new Date(row.created_at as string),
            updatedAt: new Date(row.updated_at as string),
            expiresAt: row.expires_at ? new Date(row.expires_at as string) : null,
        };
    }
}

export default SecretManager;
