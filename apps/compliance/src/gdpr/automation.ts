/**
 * GDPR Automation
 *
 * Automated handling of GDPR data subject requests including
 * right to access, rectification, erasure, portability, and
 * consent management.
 */

import { Pool } from 'pg';
import { Redis } from 'ioredis';
import {
    DataSubjectRequest,
    DataSubjectRequestType,
    RequestStatus,
    DataSubjectRequestResult,
    ConsentRecord,
    ConsentType,
    ConsentSource,
} from '../types';
import { complianceConfig } from '../config';
import { generateUUID, randomToken, sha256 } from '@apexmail/lib/crypto';

interface DataExport {
    subscriber: Record<string, unknown>;
    messages: Array<Record<string, unknown>>;
    events: Array<Record<string, unknown>>;
    consents: Array<Record<string, unknown>>;
    preferences: Record<string, unknown>;
    [key: string]: unknown;
}

export class GDPRAutomation {
    private db: Pool;
    private redis: Redis;
    private config = complianceConfig.gdpr;

    constructor(db: Pool, redis: Redis) {
        this.db = db;
        this.redis = redis;
    }

    // ==================== Data Subject Requests ====================

    /**
     * Create a new data subject request
     */
    async createRequest(
        tenantId: string,
        requestType: DataSubjectRequestType,
        email: string
    ): Promise<DataSubjectRequest> {
        const id = generateUUID();
        const verificationToken = randomToken(32);
        const now = new Date();
        const expiresAt = new Date(
            now.getTime() + this.config.requestExpirationDays * 24 * 60 * 60 * 1000
        );

        const request: DataSubjectRequest = {
            id,
            tenantId,
            requestType,
            email,
            verificationToken: this.hashToken(verificationToken),
            verified: false,
            verifiedAt: null,
            status: 'pending_verification',
            requestedAt: now,
            processedAt: null,
            completedAt: null,
            expiresAt,
            result: null,
        };

        await this.db.query(
            `INSERT INTO data_subject_requests (
                id, tenant_id, request_type, email, verification_token,
                verified, verified_at, status, requested_at, processed_at,
                completed_at, expires_at, result
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
            [
                request.id,
                request.tenantId,
                request.requestType,
                request.email,
                request.verificationToken,
                request.verified,
                request.verifiedAt,
                request.status,
                request.requestedAt,
                request.processedAt,
                request.completedAt,
                request.expiresAt,
                null,
            ]
        );

        // Send verification email
        await this.sendVerificationEmail(request.email, verificationToken, request.id);

        return request;
    }

    /**
     * Verify a data subject request
     */
    async verifyRequest(
        requestId: string,
        token: string
    ): Promise<DataSubjectRequest | null> {
        const result = await this.db.query(
            `SELECT * FROM data_subject_requests WHERE id = $1`,
            [requestId]
        );

        if (result.rows.length === 0) return null;

        const request = this.mapRowToRequest(result.rows[0]);

        // Check if already verified
        if (request.verified) {
            return request;
        }

        // Check expiration
        if (new Date() > request.expiresAt) {
            await this.updateRequestStatus(requestId, 'expired');
            return null;
        }

        // Verify token
        if (this.hashToken(token) !== request.verificationToken) {
            return null;
        }

        // Mark as verified
        const now = new Date();
        await this.db.query(
            `UPDATE data_subject_requests
            SET verified = true, verified_at = $2, status = 'verified'
            WHERE id = $1`,
            [requestId, now]
        );

        // Queue for processing
        await this.queueForProcessing(requestId);

        return {
            ...request,
            verified: true,
            verifiedAt: now,
            status: 'verified',
        };
    }

    /**
     * Get a data subject request by ID
     */
    async getRequest(requestId: string): Promise<DataSubjectRequest | null> {
        const result = await this.db.query(
            `SELECT * FROM data_subject_requests WHERE id = $1`,
            [requestId]
        );

        if (result.rows.length === 0) return null;

        return this.mapRowToRequest(result.rows[0]);
    }

    /**
     * Process a data subject request
     */
    async processRequest(requestId: string): Promise<DataSubjectRequestResult> {
        const result = await this.db.query(
            `SELECT * FROM data_subject_requests WHERE id = $1`,
            [requestId]
        );

        if (result.rows.length === 0) {
            throw new Error('Request not found');
        }

        const request = this.mapRowToRequest(result.rows[0]);

        if (!request.verified) {
            throw new Error('Request not verified');
        }

        if (request.status === 'completed') {
            return request.result!;
        }

        // Update status to processing
        await this.updateRequestStatus(requestId, 'processing');

        let requestResult: DataSubjectRequestResult;

        try {
            switch (request.requestType) {
                case 'access':
                    requestResult = await this.processAccessRequest(request);
                    break;
                case 'erasure':
                    requestResult = await this.processErasureRequest(request);
                    break;
                case 'portability':
                    requestResult = await this.processPortabilityRequest(request);
                    break;
                case 'rectification':
                    requestResult = await this.processRectificationRequest(request);
                    break;
                case 'restriction':
                    requestResult = await this.processRestrictionRequest(request);
                    break;
                case 'objection':
                    requestResult = await this.processObjectionRequest(request);
                    break;
                default:
                    throw new Error(`Unknown request type: ${request.requestType}`);
            }

            // Update request with result
            await this.db.query(
                `UPDATE data_subject_requests
                SET status = 'completed', completed_at = NOW(), result = $2
                WHERE id = $1`,
                [requestId, JSON.stringify(requestResult)]
            );

            // Notify data subject
            await this.sendCompletionNotification(request, requestResult);

            return requestResult;
        } catch (err) {
            await this.updateRequestStatus(requestId, 'rejected');
            throw err;
        }
    }

    /**
     * Process access request (Right to Access)
     */
    private async processAccessRequest(
        request: DataSubjectRequest
    ): Promise<DataSubjectRequestResult> {
        const data = await this.collectSubjectData(request.tenantId, request.email);

        // Generate export
        const exportData = JSON.stringify(data, null, 2);
        const exportUrl = await this.storeExport(request.id, exportData);
        const exportExpiresAt = new Date(
            Date.now() + this.config.exportExpirationDays * 24 * 60 * 60 * 1000
        );

        return {
            data,
            exportUrl,
            exportExpiresAt,
        };
    }

    /**
     * Process erasure request (Right to be Forgotten)
     */
    private async processErasureRequest(
        request: DataSubjectRequest
    ): Promise<DataSubjectRequestResult> {
        let deletedRecords = 0;

        // Delete subscriber data
        const subscriberResult = await this.db.query(
            `DELETE FROM subscribers WHERE tenant_id = $1 AND email = $2`,
            [request.tenantId, request.email]
        );
        deletedRecords += subscriberResult.rowCount || 0;

        // Delete messages
        const messagesResult = await this.db.query(
            `DELETE FROM messages WHERE tenant_id = $1 AND recipient_email = $2`,
            [request.tenantId, request.email]
        );
        deletedRecords += messagesResult.rowCount || 0;

        // Delete events
        const eventsResult = await this.db.query(
            `DELETE FROM events WHERE tenant_id = $1 AND email = $2`,
            [request.tenantId, request.email]
        );
        deletedRecords += eventsResult.rowCount || 0;

        // Delete consents
        const consentsResult = await this.db.query(
            `DELETE FROM consent_records WHERE tenant_id = $1 AND email = $2`,
            [request.tenantId, request.email]
        );
        deletedRecords += consentsResult.rowCount || 0;

        // Delete from campaign enrollments
        const enrollmentsResult = await this.db.query(
            `DELETE FROM campaign_enrollments
            WHERE subscriber_id IN (
                SELECT id FROM subscribers WHERE tenant_id = $1 AND email = $2
            )`,
            [request.tenantId, request.email]
        );
        deletedRecords += enrollmentsResult.rowCount || 0;

        // GDPR-001 FIX: Delete from backup tables
        const backupsResult = await this.db.query(
            `DELETE FROM subscriber_backups WHERE tenant_id = $1 AND email = $2`,
            [request.tenantId, request.email]
        );
        deletedRecords += backupsResult.rowCount || 0;

        // GDPR-001 FIX: Delete from audit/activity logs containing PII
        const logsResult = await this.db.query(
            `DELETE FROM activity_logs WHERE tenant_id = $1 AND 
            (metadata->>'email' = $2 OR metadata->>'subscriber_email' = $2)`,
            [request.tenantId, request.email]
        );
        deletedRecords += logsResult.rowCount || 0;

        // GDPR-001 FIX: Clear from cache (Redis)
        const cacheKeys = [
            `subscriber:${request.tenantId}:${request.email}`,
            `preferences:${request.tenantId}:${request.email}`,
            `consent:${request.tenantId}:${request.email}`,
        ];
        for (const key of cacheKeys) {
            await this.redis.del(key);
        }

        // E-167: Generate detailed deletion confirmation receipt
        const deletionConfirmation = await this.createDeletionConfirmation(
            request,
            deletedRecords,
            {
                subscribers: subscriberResult.rowCount || 0,
                messages: messagesResult.rowCount || 0,
                events: eventsResult.rowCount || 0,
                consents: consentsResult.rowCount || 0,
                campaignEnrollments: enrollmentsResult.rowCount || 0,
                backups: backupsResult.rowCount || 0,
                activityLogs: logsResult.rowCount || 0,
                cacheKeys: cacheKeys.length,
            },
        );

        // Log the deletion
        await this.logDeletion(request.tenantId, request.email, deletedRecords);

        return {
            deletedRecords,
            deletionConfirmation,
        };
    }

    /**
     * Process portability request (Right to Data Portability)
     */
    private async processPortabilityRequest(
        request: DataSubjectRequest
    ): Promise<DataSubjectRequestResult> {
        const data = await this.collectSubjectData(request.tenantId, request.email);

        // Generate machine-readable export (JSON)
        const exportData = JSON.stringify(data, null, 2);
        const exportUrl = await this.storeExport(request.id, exportData);
        const exportExpiresAt = new Date(
            Date.now() + this.config.exportExpirationDays * 24 * 60 * 60 * 1000
        );

        return {
            exportUrl,
            exportExpiresAt,
        };
    }

    /**
     * Process rectification request
     */
    private async processRectificationRequest(
        request: DataSubjectRequest
    ): Promise<DataSubjectRequestResult> {
        // Mark subscriber for manual review
        await this.db.query(
            `UPDATE subscribers SET needs_rectification = true, rectification_request_id = $3
            WHERE tenant_id = $1 AND email = $2`,
            [request.tenantId, request.email, request.id]
        );

        // Notify tenant admin
        await this.notifyTenantAdmin(request.tenantId, 'rectification', request);

        return {
            modifiedRecords: 1,
        };
    }

    /**
     * Process restriction request
     */
    private async processRestrictionRequest(
        request: DataSubjectRequest
    ): Promise<DataSubjectRequestResult> {
        // Restrict processing of subscriber data
        await this.db.query(
            `UPDATE subscribers SET processing_restricted = true, restriction_request_id = $3
            WHERE tenant_id = $1 AND email = $2`,
            [request.tenantId, request.email, request.id]
        );

        // Remove from active campaigns
        const enrollmentsResult = await this.db.query(
            `UPDATE campaign_enrollments SET status = 'paused'
            WHERE subscriber_id IN (
                SELECT id FROM subscribers WHERE tenant_id = $1 AND email = $2
            )
            AND status = 'active'`,
            [request.tenantId, request.email]
        );

        return {
            modifiedRecords: (enrollmentsResult.rowCount || 0) + 1,
        };
    }

    /**
     * Process objection request
     */
    private async processObjectionRequest(
        request: DataSubjectRequest
    ): Promise<DataSubjectRequestResult> {
        // Record the objection
        await this.db.query(
            `INSERT INTO processing_objections (tenant_id, email, request_id, created_at)
            VALUES ($1, $2, $3, NOW())`,
            [request.tenantId, request.email, request.id]
        );

        // Unsubscribe from all lists
        const unsubResult = await this.db.query(
            `UPDATE list_subscribers SET unsubscribed = true, unsubscribed_at = NOW()
            WHERE subscriber_id IN (
                SELECT id FROM subscribers WHERE tenant_id = $1 AND email = $2
            )`,
            [request.tenantId, request.email]
        );

        return {
            modifiedRecords: (unsubResult.rowCount || 0) + 1,
        };
    }

    /**
     * Collect all data for a subject
     */
    private async collectSubjectData(
        tenantId: string,
        email: string
    ): Promise<DataExport> {
        // Get subscriber info
        const subscriberResult = await this.db.query(
            `SELECT * FROM subscribers WHERE tenant_id = $1 AND email = $2`,
            [tenantId, email]
        );

        // Get messages sent to this subscriber
        const messagesResult = await this.db.query(
            `SELECT id, subject, sent_at, status FROM messages
            WHERE tenant_id = $1 AND recipient_email = $2
            ORDER BY sent_at DESC LIMIT 1000`,
            [tenantId, email]
        );

        // Get events (opens, clicks, etc.)
        const eventsResult = await this.db.query(
            `SELECT type, timestamp, metadata FROM events
            WHERE tenant_id = $1 AND email = $2
            ORDER BY timestamp DESC LIMIT 1000`,
            [tenantId, email]
        );

        // Get consent records
        const consentsResult = await this.db.query(
            `SELECT * FROM consent_records WHERE tenant_id = $1 AND email = $2`,
            [tenantId, email]
        );

        // Get preferences
        const preferencesResult = await this.db.query(
            `SELECT * FROM subscriber_preferences
            WHERE subscriber_id IN (
                SELECT id FROM subscribers WHERE tenant_id = $1 AND email = $2
            )`,
            [tenantId, email]
        );

        return {
            subscriber: this.sanitizeForExport(subscriberResult.rows[0] || {}, [
                'id', 'tenant_id', 'created_by', 'updated_by',
                'password_hash', 'api_key', 'internal_notes',
                'rectification_request_id', 'restriction_request_id',
            ]),
            messages: messagesResult.rows.map(row => this.sanitizeForExport(row, [
                'tenant_id', 'internal_id', 'worker_id', 'queue_id',
                'smtp_response', 'server_ip', 'mta_id',
            ])),
            events: eventsResult.rows.map(row => this.sanitizeForExport(row, [
                'tenant_id', 'internal_id', 'server_id', 'worker_id',
                'ip_address', 'raw_headers',
            ])),
            consents: consentsResult.rows.map(this.mapRowToConsent).map(c =>
                this.sanitizeForExport(c as unknown as Record<string, unknown>, [
                    'tenantId', 'subscriberId', 'proofDocument',
                ])
            ),
            preferences: this.sanitizeForExport(preferencesResult.rows[0] || {}, [
                'id', 'tenant_id', 'subscriber_id',
            ]),
        };
    }

    // ==================== Consent Management ====================

    /**
     * Record consent
     */
    async recordConsent(
        tenantId: string,
        subscriberId: string,
        email: string,
        consentType: ConsentType,
        granted: boolean,
        source: ConsentSource,
        ipAddress?: string,
        userAgent?: string,
        proofDocument?: string,
        expiresAt?: Date,
        metadata?: Record<string, unknown>
    ): Promise<ConsentRecord> {
        const id = generateUUID();
        const now = new Date();

        const consent: ConsentRecord = {
            id,
            tenantId,
            subscriberId,
            email,
            consentType,
            granted,
            grantedAt: granted ? now : null,
            revokedAt: !granted ? now : null,
            source,
            ipAddress: ipAddress || null,
            userAgent: userAgent || null,
            proofDocument: proofDocument || null,
            expiresAt: expiresAt || null,
            metadata: metadata || {},
        };

        await this.db.query(
            `INSERT INTO consent_records (
                id, tenant_id, subscriber_id, email, consent_type, granted,
                granted_at, revoked_at, source, ip_address, user_agent,
                proof_document, expires_at, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            ON CONFLICT (tenant_id, subscriber_id, consent_type)
            DO UPDATE SET
                granted = EXCLUDED.granted,
                granted_at = CASE WHEN EXCLUDED.granted THEN NOW() ELSE consent_records.granted_at END,
                revoked_at = CASE WHEN NOT EXCLUDED.granted THEN NOW() ELSE NULL END,
                source = EXCLUDED.source,
                ip_address = EXCLUDED.ip_address,
                user_agent = EXCLUDED.user_agent`,
            [
                consent.id,
                consent.tenantId,
                consent.subscriberId,
                consent.email,
                consent.consentType,
                consent.granted,
                consent.grantedAt,
                consent.revokedAt,
                consent.source,
                consent.ipAddress,
                consent.userAgent,
                consent.proofDocument,
                consent.expiresAt,
                JSON.stringify(consent.metadata),
            ]
        );

        // Log consent change
        await this.logConsentChange(consent);

        return consent;
    }

    /**
     * Revoke consent
     */
    async revokeConsent(
        tenantId: string,
        subscriberId: string,
        consentType: ConsentType
    ): Promise<void> {
        await this.db.query(
            `UPDATE consent_records
            SET granted = false, revoked_at = NOW()
            WHERE tenant_id = $1 AND subscriber_id = $2 AND consent_type = $3`,
            [tenantId, subscriberId, consentType]
        );

        // If revoking marketing consent, remove from campaigns
        if (consentType === 'marketing') {
            await this.db.query(
                `UPDATE campaign_enrollments SET status = 'removed'
                WHERE subscriber_id = $1 AND status = 'active'`,
                [subscriberId]
            );
        }
    }

    /**
     * Check if consent is granted
     */
    async hasConsent(
        tenantId: string,
        subscriberId: string,
        consentType: ConsentType
    ): Promise<boolean> {
        const result = await this.db.query(
            `SELECT granted, expires_at FROM consent_records
            WHERE tenant_id = $1 AND subscriber_id = $2 AND consent_type = $3`,
            [tenantId, subscriberId, consentType]
        );

        if (result.rows.length === 0) return false;

        const { granted, expires_at } = result.rows[0];

        // Check if expired
        if (expires_at && new Date(expires_at) < new Date()) {
            return false;
        }

        return granted;
    }

    /**
     * Get all consents for a subscriber
     */
    async getConsents(
        tenantId: string,
        subscriberId: string
    ): Promise<ConsentRecord[]> {
        const result = await this.db.query(
            `SELECT * FROM consent_records
            WHERE tenant_id = $1 AND subscriber_id = $2`,
            [tenantId, subscriberId]
        );

        return result.rows.map(this.mapRowToConsent);
    }

    /**
     * Process double opt-in
     */
    async sendDoubleOptIn(
        tenantId: string,
        subscriberId: string,
        email: string,
        consentTypes: ConsentType[]
    ): Promise<string> {
        const token = randomToken(32);
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

        await this.db.query(
            `INSERT INTO double_optin_tokens (
                token, tenant_id, subscriber_id, email, consent_types, expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6)`,
            [this.hashToken(token), tenantId, subscriberId, email, JSON.stringify(consentTypes), expiresAt]
        );

        // Send double opt-in email
        await this.sendDoubleOptInEmail(email, token, tenantId);

        return token;
    }

    /**
     * Confirm double opt-in
     */
    async confirmDoubleOptIn(token: string): Promise<boolean> {
        const result = await this.db.query(
            `SELECT * FROM double_optin_tokens
            WHERE token = $1 AND confirmed_at IS NULL AND expires_at > NOW()`,
            [this.hashToken(token)]
        );

        if (result.rows.length === 0) return false;

        const row = result.rows[0];
        const consentTypes = row.consent_types as ConsentType[];

        // Record consents
        for (const consentType of consentTypes) {
            await this.recordConsent(
                row.tenant_id,
                row.subscriber_id,
                row.email,
                consentType,
                true,
                'double_opt_in'
            );
        }

        // Mark token as used
        await this.db.query(
            `UPDATE double_optin_tokens SET confirmed_at = NOW() WHERE token = $1`,
            [this.hashToken(token)]
        );

        return true;
    }

    // ==================== Helper Methods ====================

    /**
     * F-201: Sanitize a record for data export by stripping internal fields.
     * Ensures no internal IDs, credentials, or infrastructure details
     * are leaked in GDPR data exports.
     */
    private sanitizeForExport(
        record: Record<string, unknown>,
        fieldsToRemove: string[]
    ): Record<string, unknown> {
        const sanitized = { ...record };
        for (const field of fieldsToRemove) {
            delete sanitized[field];
        }
        return sanitized;
    }

    /**
     * Hash a token for secure storage
     */
    private hashToken(token: string): string {
        return sha256(token);
    }

    /**
     * Update request status
     */
    private async updateRequestStatus(
        requestId: string,
        status: RequestStatus
    ): Promise<void> {
        await this.db.query(
            `UPDATE data_subject_requests SET status = $2, processed_at = NOW()
            WHERE id = $1`,
            [requestId, status]
        );
    }

    /**
     * Queue request for processing
     */
    private async queueForProcessing(requestId: string): Promise<void> {
        await this.redis.lpush(
            'gdpr:requests:queue',
            JSON.stringify({ requestId, queuedAt: new Date().toISOString() })
        );
    }

    /**
     * Store export file
     */
    private async storeExport(requestId: string, data: string): Promise<string> {
        const filename = `exports/gdpr/${requestId}.json`;
        // GDPR-002 FIX: Generate a secure access token and hash it before storage
        const accessToken = randomToken(32);
        const hashedToken = this.hashToken(accessToken);

        // In production, upload to S3/GCS
        await this.db.query(
            `INSERT INTO gdpr_exports (request_id, filename, data, access_token_hash, created_at)
            VALUES ($1, $2, $3, $4, NOW())`,
            [requestId, filename, data, hashedToken]
        );

        // Return URL with unhashed token for one-time use
        return `${this.config.exportBaseUrl}/${filename}?token=${accessToken}`;
    }

    /**
     * Send verification email
     */
    private async sendVerificationEmail(
        email: string,
        token: string,
        requestId: string
    ): Promise<void> {
        await this.redis.lpush(
            'email:queue',
            JSON.stringify({
                type: 'gdpr_verification',
                to: email,
                data: {
                    verifyUrl: `${this.config.verifyBaseUrl}/verify/${requestId}?token=${token}`,
                    expiresIn: '72 hours',
                },
            })
        );
    }

    /**
     * Send completion notification
     */
    private async sendCompletionNotification(
        request: DataSubjectRequest,
        result: DataSubjectRequestResult
    ): Promise<void> {
        await this.redis.lpush(
            'email:queue',
            JSON.stringify({
                type: 'gdpr_completion',
                to: request.email,
                data: {
                    requestType: request.requestType,
                    exportUrl: result.exportUrl,
                    deletedRecords: result.deletedRecords,
                },
            })
        );
    }

    /**
     * Send double opt-in email
     */
    private async sendDoubleOptInEmail(
        email: string,
        token: string,
        tenantId: string
    ): Promise<void> {
        await this.redis.lpush(
            'email:queue',
            JSON.stringify({
                type: 'double_optin',
                to: email,
                tenantId,
                data: {
                    confirmUrl: `${this.config.verifyBaseUrl}/confirm-optin?token=${token}`,
                },
            })
        );
    }

    /**
     * Notify tenant admin
     */
    private async notifyTenantAdmin(
        tenantId: string,
        type: string,
        request: DataSubjectRequest
    ): Promise<void> {
        await this.redis.lpush(
            'notifications:queue',
            JSON.stringify({
                type: `gdpr_${type}_request`,
                tenantId,
                requestId: request.id,
                email: request.email,
                timestamp: new Date().toISOString(),
            })
        );
    }

    /**
     * E-167: Create a detailed deletion confirmation receipt.
     * Records what was deleted, when, and who requested it for GDPR compliance.
     */
    private async createDeletionConfirmation(
        request: DataSubjectRequest,
        totalRecords: number,
        breakdown: Record<string, number>,
    ): Promise<Record<string, unknown>> {
        const confirmationId = generateUUID();
        const deletedAt = new Date();

        const confirmation = {
            confirmationId,
            requestId: request.id,
            tenantId: request.tenantId,
            dataSubjectEmail: request.email,
            requestedAt: request.requestedAt.toISOString(),
            deletedAt: deletedAt.toISOString(),
            totalRecordsDeleted: totalRecords,
            breakdown,
            requestType: request.requestType,
            legalBasis: 'GDPR Article 17 — Right to Erasure',
        };

        // Persist the confirmation receipt for auditability
        await this.db.query(
            `INSERT INTO gdpr_deletion_confirmations (
                id, request_id, tenant_id, email, deleted_at,
                total_records, breakdown, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
            [
                confirmationId,
                request.id,
                request.tenantId,
                request.email,
                deletedAt,
                totalRecords,
                JSON.stringify(breakdown),
            ],
        );

        return confirmation;
    }

    /**
     * Log deletion for audit
     */
    private async logDeletion(
        tenantId: string,
        email: string,
        recordCount: number
    ): Promise<void> {
        await this.db.query(
            `INSERT INTO gdpr_deletion_log (tenant_id, email, records_deleted, deleted_at)
            VALUES ($1, $2, $3, NOW())`,
            [tenantId, email, recordCount]
        );
    }

    /**
     * Log consent change
     */
    private async logConsentChange(consent: ConsentRecord): Promise<void> {
        await this.db.query(
            `INSERT INTO consent_changelog (
                consent_id, tenant_id, email, consent_type, granted, changed_at
            ) VALUES ($1, $2, $3, $4, $5, NOW())`,
            [consent.id, consent.tenantId, consent.email, consent.consentType, consent.granted]
        );
    }

    /**
     * Map database row to request
     */
    private mapRowToRequest(row: Record<string, unknown>): DataSubjectRequest {
        return {
            id: row.id as string,
            tenantId: row.tenant_id as string,
            requestType: row.request_type as DataSubjectRequestType,
            email: row.email as string,
            verificationToken: row.verification_token as string,
            verified: row.verified as boolean,
            verifiedAt: row.verified_at ? new Date(row.verified_at as string) : null,
            status: row.status as RequestStatus,
            requestedAt: new Date(row.requested_at as string),
            processedAt: row.processed_at ? new Date(row.processed_at as string) : null,
            completedAt: row.completed_at ? new Date(row.completed_at as string) : null,
            expiresAt: new Date(row.expires_at as string),
            result: row.result as DataSubjectRequestResult | null,
        };
    }

    /**
     * Map database row to consent
     */
    private mapRowToConsent(row: Record<string, unknown>): ConsentRecord {
        return {
            id: row.id as string,
            tenantId: row.tenant_id as string,
            subscriberId: row.subscriber_id as string,
            email: row.email as string,
            consentType: row.consent_type as ConsentType,
            granted: row.granted as boolean,
            grantedAt: row.granted_at ? new Date(row.granted_at as string) : null,
            revokedAt: row.revoked_at ? new Date(row.revoked_at as string) : null,
            source: row.source as ConsentSource,
            ipAddress: row.ip_address as string | null,
            userAgent: row.user_agent as string | null,
            proofDocument: row.proof_document as string | null,
            expiresAt: row.expires_at ? new Date(row.expires_at as string) : null,
            metadata: row.metadata as Record<string, unknown>,
        };
    }

    /**
     * Get request statistics
     */
    async getStats(
        tenantId?: string,
        startDate?: Date,
        endDate?: Date
    ): Promise<{
        total: number;
        byType: Record<DataSubjectRequestType, number>;
        byStatus: Record<RequestStatus, number>;
        avgProcessingTimeHours: number;
    }> {
        let query = `
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE request_type = 'access') as type_access,
                COUNT(*) FILTER (WHERE request_type = 'erasure') as type_erasure,
                COUNT(*) FILTER (WHERE request_type = 'portability') as type_portability,
                COUNT(*) FILTER (WHERE request_type = 'rectification') as type_rectification,
                COUNT(*) FILTER (WHERE request_type = 'restriction') as type_restriction,
                COUNT(*) FILTER (WHERE request_type = 'objection') as type_objection,
                COUNT(*) FILTER (WHERE status = 'pending_verification') as status_pending,
                COUNT(*) FILTER (WHERE status = 'verified') as status_verified,
                COUNT(*) FILTER (WHERE status = 'processing') as status_processing,
                COUNT(*) FILTER (WHERE status = 'completed') as status_completed,
                COUNT(*) FILTER (WHERE status = 'rejected') as status_rejected,
                COUNT(*) FILTER (WHERE status = 'expired') as status_expired,
                AVG(EXTRACT(EPOCH FROM (completed_at - requested_at)) / 3600)
                    FILTER (WHERE completed_at IS NOT NULL) as avg_hours
            FROM data_subject_requests
            WHERE 1=1
        `;

        const params: unknown[] = [];
        let paramIndex = 1;

        if (tenantId) {
            query += ` AND tenant_id = $${paramIndex++}`;
            params.push(tenantId);
        }

        if (startDate) {
            query += ` AND requested_at >= $${paramIndex++}`;
            params.push(startDate);
        }

        if (endDate) {
            query += ` AND requested_at <= $${paramIndex++}`;
            params.push(endDate);
        }

        const result = await this.db.query(query, params);
        const row = result.rows[0];

        return {
            total: parseInt(row.total, 10),
            byType: {
                access: parseInt(row.type_access, 10),
                erasure: parseInt(row.type_erasure, 10),
                portability: parseInt(row.type_portability, 10),
                rectification: parseInt(row.type_rectification, 10),
                restriction: parseInt(row.type_restriction, 10),
                objection: parseInt(row.type_objection, 10),
            },
            byStatus: {
                pending_verification: parseInt(row.status_pending, 10),
                verified: parseInt(row.status_verified, 10),
                processing: parseInt(row.status_processing, 10),
                completed: parseInt(row.status_completed, 10),
                rejected: parseInt(row.status_rejected, 10),
                expired: parseInt(row.status_expired, 10),
            },
            avgProcessingTimeHours: parseFloat(row.avg_hours || '0'),
        };
    }
}

export default GDPRAutomation;
