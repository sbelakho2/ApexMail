/**
 * Attachments Storage Service
 * 
 * Provides storage for email attachments with support for:
 * - Local filesystem storage
 * - S3-compatible storage (AWS S3, R2, MinIO)
 * - Content-addressed storage (deduplication)
 * - Automatic cleanup of expired attachments
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, HeadObjectCommand } from '@aws-sdk/client-s3';
import { createLogger } from '../logger/index.js';

const logger = createLogger({ name: 'attachments' });

// ============================================================================
// Types
// ============================================================================

export interface AttachmentMetadata {
    id: string;
    filename: string;
    contentType: string;
    size: number;
    hash: string;
    uploadedAt: Date;
    expiresAt?: Date;
    tenantId: string;
    messageId?: string;
}

export interface AttachmentUploadResult {
    id: string;
    url: string;
    hash: string;
    size: number;
}

export interface AttachmentStorageConfig {
    type: 'local' | 's3';
    /** For local storage */
    localPath?: string;
    /** For S3 storage */
    s3?: {
        bucket: string;
        region: string;
        endpoint?: string; // For R2, MinIO, etc.
        accessKeyId: string;
        secretAccessKey: string;
        sessionToken?: string;
        forcePathStyle?: boolean; // For MinIO
    };
    /** Max attachment size in bytes (default: 25MB) */
    maxSize?: number;
    /** Allowed content types (default: all) */
    allowedTypes?: string[];
    /** Auto-expire attachments after N days */
    expirationDays?: number;
    /** Base URL for serving attachments */
    baseUrl?: string;
}

export interface AttachmentStorage {
    upload(
        content: Buffer | string,
        filename: string,
        contentType: string,
        tenantId: string,
        messageId?: string
    ): Promise<AttachmentUploadResult>;
    
    download(id: string): Promise<{ content: Buffer; metadata: AttachmentMetadata }>;
    
    delete(id: string): Promise<void>;
    
    getMetadata(id: string): Promise<AttachmentMetadata | null>;
    
    getUrl(id: string): string;
    
    cleanupExpired(): Promise<number>;
}

// ============================================================================
// Local Filesystem Storage
// ============================================================================

export class LocalAttachmentStorage implements AttachmentStorage {
    private basePath: string;
    private metadataPath: string;
    private baseUrl: string;
    private maxSize: number;
    private allowedTypes: string[] | null;
    private expirationDays: number | null;
    // FIX-500-377: Mutex to prevent concurrent cleanup races
    private cleanupInProgress = false;
    
    constructor(config: AttachmentStorageConfig) {
        this.basePath = config.localPath || './data/attachments';
        this.metadataPath = path.join(this.basePath, '.metadata');
        this.baseUrl = config.baseUrl || '/attachments';
        this.maxSize = config.maxSize || 25 * 1024 * 1024; // 25MB
        this.allowedTypes = config.allowedTypes || null;
        this.expirationDays = config.expirationDays || null;
    }
    
    async init(): Promise<void> {
        await fs.mkdir(this.basePath, { recursive: true });
        await fs.mkdir(this.metadataPath, { recursive: true });
        logger.info('Local attachment storage initialized', { path: this.basePath });
    }
    
    async upload(
        content: Buffer | string,
        filename: string,
        contentType: string,
        tenantId: string,
        messageId?: string
    ): Promise<AttachmentUploadResult> {
        const buffer = typeof content === 'string' ? Buffer.from(content, 'base64') : content;
        
        // Validate size
        if (buffer.length > this.maxSize) {
            throw new Error(`Attachment exceeds maximum size of ${this.maxSize} bytes`);
        }
        
        // Validate content type
        if (this.allowedTypes && !this.allowedTypes.includes(contentType)) {
            throw new Error(`Content type ${contentType} is not allowed`);
        }
        
        // Generate content hash for deduplication
        const hash = crypto.createHash('sha256').update(buffer).digest('hex');
        
        // Generate content-addressed ID for deduplication
        const id = this.buildAttachmentId(tenantId, hash);
        
        // Ensure directories exist
        await fs.mkdir(this.basePath, { recursive: true });
        await fs.mkdir(this.metadataPath, { recursive: true });
        
        // Create tenant directory
        const tenantPath = path.join(this.basePath, tenantId);
        await fs.mkdir(tenantPath, { recursive: true });
        
        // Save file
        const filePath = path.join(tenantPath, id);
        await fs.writeFile(filePath, buffer);
        
        // Save metadata
        const metadata: AttachmentMetadata = {
            id,
            filename: this.sanitizeFilename(filename),
            contentType,
            size: buffer.length,
            hash,
            uploadedAt: new Date(),
            expiresAt: this.expirationDays 
                ? new Date(Date.now() + this.expirationDays * 24 * 60 * 60 * 1000)
                : undefined,
            tenantId,
            messageId,
        };
        
        await fs.writeFile(
            path.join(this.metadataPath, `${id}.json`),
            JSON.stringify(metadata, null, 2)
        );
        
        logger.info('Attachment uploaded', { id, filename, size: buffer.length, tenantId });
        
        return {
            id,
            url: this.getUrl(id),
            hash,
            size: buffer.length,
        };
    }
    
    async download(id: string): Promise<{ content: Buffer; metadata: AttachmentMetadata }> {
        this.validateAttachmentId(id);
        const metadata = await this.getMetadata(id);
        if (!metadata) {
            throw new Error(`Attachment not found: ${id}`);
        }
        
        const filePath = path.join(this.basePath, metadata.tenantId, id);
        const resolved = path.resolve(filePath);
        if (!resolved.startsWith(path.resolve(this.basePath))) {
            throw new Error('Invalid attachment path');
        }
        const content = await fs.readFile(filePath);
        
        return { content, metadata };
    }
    
    async delete(id: string): Promise<void> {
        this.validateAttachmentId(id);
        const metadata = await this.getMetadata(id);
        if (!metadata) {
            throw new Error(`Attachment not found: ${id}`);
        }
        
        const filePath = path.join(this.basePath, metadata.tenantId, id);
        const resolved = path.resolve(filePath);
        if (!resolved.startsWith(path.resolve(this.basePath))) {
            throw new Error('Invalid attachment path');
        }
        const metadataFilePath = path.join(this.metadataPath, `${id}.json`);
        
        await fs.unlink(filePath).catch(() => {});
        await fs.unlink(metadataFilePath).catch(() => {});
        
        logger.info('Attachment deleted', { id });
    }
    
    async getMetadata(id: string): Promise<AttachmentMetadata | null> {
        this.validateAttachmentId(id);
        try {
            const metadataPath = path.join(this.metadataPath, `${id}.json`);
            const resolved = path.resolve(metadataPath);
            if (!resolved.startsWith(path.resolve(this.metadataPath))) {
                throw new Error('Invalid metadata path');
            }
            const content = await fs.readFile(metadataPath, 'utf-8');
            return JSON.parse(content);
        } catch {
            return null;
        }
    }

    /** Reject IDs containing path traversal characters. */
    private validateAttachmentId(id: string): void {
        if (/[/\\]|\.\./.test(id)) {
            throw new Error('Invalid attachment ID');
        }
    }

    private validateTenantId(tenantId: string): void {
        if (!/^[a-zA-Z0-9_-]+$/.test(tenantId)) {
            throw new Error('Invalid tenant ID');
        }
    }

    private buildAttachmentId(tenantId: string, hash: string): string {
        this.validateTenantId(tenantId);
        return `${tenantId}_${hash}`;
    }
    
    getUrl(id: string): string {
        return `${this.baseUrl}/${id}`;
    }
    
    async cleanupExpired(): Promise<number> {
        // FIX-500-377: Concurrency guard — prevent overlapping cleanup runs
        if (this.cleanupInProgress) {
            logger.info('Cleanup already in progress, skipping');
            return 0;
        }
        this.cleanupInProgress = true;
        let deleted = 0;
        
        try {
            const files = await fs.readdir(this.metadataPath);
            const now = new Date();
            const batchSize = 20;
            
            for (let i = 0; i < files.length; i += batchSize) {
                const batch = files.slice(i, i + batchSize);
                const results = await Promise.all(batch.map(async (file) => {
                    if (!file.endsWith('.json')) return 0;
                    
                    const metadataPath = path.join(this.metadataPath, file);
                    const content = await fs.readFile(metadataPath, 'utf-8');
                    let metadata: AttachmentMetadata;
                    try { metadata = JSON.parse(content); }
                    catch { return 0; }
                    
                    if (metadata.expiresAt && new Date(metadata.expiresAt) < now) {
                        await this.delete(metadata.id);
                        return 1;
                    }
                    return 0;
                }));

                deleted += results.reduce((sum, value) => sum + value, 0);
            }
        } catch (err) {
            logger.error('Error during cleanup', { error: err });
        } finally {
            this.cleanupInProgress = false;
        }
        
        if (deleted > 0) {
            logger.info('Expired attachments cleaned up', { count: deleted });
        }
        
        return deleted;
    }
    
    private sanitizeFilename(filename: string): string {
        // Remove path separators and dangerous characters
        return filename
            .replace(/[/\\]/g, '_')
            .replace(/\.\./g, '_')
            .replace(/[<>:"|?*]/g, '_')
            .slice(0, 255);
    }
}

// ============================================================================
// S3-Compatible Storage
// ============================================================================

export class S3AttachmentStorage implements AttachmentStorage {
    private config: NonNullable<AttachmentStorageConfig['s3']>;
    private baseUrl: string;
    private maxSize: number;
    private allowedTypes: string[] | null;
    private expirationDays: number | null;
    private client: S3Client;
    
    constructor(config: AttachmentStorageConfig) {
        if (!config.s3) {
            throw new Error('S3 configuration is required');
        }
        this.config = config.s3;
        this.baseUrl = config.baseUrl || `https://${config.s3.bucket}.s3.${config.s3.region}.amazonaws.com`;
        this.maxSize = config.maxSize || 25 * 1024 * 1024;
        this.allowedTypes = config.allowedTypes || null;
        this.expirationDays = config.expirationDays || null;
        this.client = new S3Client({
            region: this.config.region,
            endpoint: this.config.endpoint,
            forcePathStyle: this.config.forcePathStyle,
            credentials: {
                accessKeyId: this.config.accessKeyId,
                secretAccessKey: this.config.secretAccessKey,
                sessionToken: this.config.sessionToken,
            },
        });
    }
    
    async upload(
        content: Buffer | string,
        filename: string,
        contentType: string,
        tenantId: string,
        messageId?: string
    ): Promise<AttachmentUploadResult> {
        const buffer = typeof content === 'string' ? Buffer.from(content, 'base64') : content;
        
        if (buffer.length > this.maxSize) {
            throw new Error(`Attachment exceeds maximum size of ${this.maxSize} bytes`);
        }
        
        if (this.allowedTypes && !this.allowedTypes.includes(contentType)) {
            throw new Error(`Content type ${contentType} is not allowed`);
        }
        
        this.validateTenantId(tenantId);
        const hash = crypto.createHash('sha256').update(buffer).digest('hex');
        const id = `${tenantId}/${hash}`;
        
        const metadata: Record<string, string> = {};
        if (this.expirationDays) {
            const expires = new Date(Date.now() + this.expirationDays * 24 * 60 * 60 * 1000);
            metadata['expires'] = expires.toISOString();
        }

        const command = new PutObjectCommand({
            Bucket: this.config.bucket,
            Key: id,
            Body: buffer,
            ContentType: contentType,
            ContentLength: buffer.length,
            Metadata: metadata,
        });
        await this.client.send(command);
        
        logger.info('Attachment uploaded to S3', { id, filename, size: buffer.length, tenantId, messageId });
        
        return {
            id,
            url: this.getUrl(id),
            hash,
            size: buffer.length,
        };
    }
    
    async download(id: string): Promise<{ content: Buffer; metadata: AttachmentMetadata }> {
        this.validateObjectKey(id);
        const response = await this.client.send(new GetObjectCommand({
            Bucket: this.config.bucket,
            Key: id,
        }));

        if (!response.Body) {
            throw new Error(`Attachment not found: ${id}`);
        }

        const content = await this.readStreamToBuffer(response.Body as NodeJS.ReadableStream);
        const contentType = response.ContentType || 'application/octet-stream';
        const expiresHeader = response.Metadata?.['expires'];
        
        const metadata: AttachmentMetadata = {
            id,
            filename: id.split('/').pop() || id,
            contentType,
            size: content.length,
            hash: crypto.createHash('sha256').update(content).digest('hex'),
            uploadedAt: new Date(),
            expiresAt: expiresHeader ? new Date(expiresHeader) : undefined,
            tenantId: id.split('/')[0] || 'unknown',
        };
        
        return { content, metadata };
    }
    
    async delete(id: string): Promise<void> {
        this.validateObjectKey(id);
        await this.client.send(new DeleteObjectCommand({
            Bucket: this.config.bucket,
            Key: id,
        }));
        
        logger.info('Attachment deleted from S3', { id });
    }
    
    async getMetadata(id: string): Promise<AttachmentMetadata | null> {
        this.validateObjectKey(id);
        let response;
        try {
            response = await this.client.send(new HeadObjectCommand({
                Bucket: this.config.bucket,
                Key: id,
            }));
        } catch {
            return null;
        }

        const contentType = response.ContentType || 'application/octet-stream';
        const contentLength = response.ContentLength ?? 0;
        const expiresHeader = response.Metadata?.['expires'];
        
        return {
            id,
            filename: id.split('/').pop() || id,
            contentType,
            size: contentLength,
            hash: '',
            uploadedAt: new Date(),
            expiresAt: expiresHeader ? new Date(expiresHeader) : undefined,
            tenantId: id.split('/')[0] || 'unknown',
        };
    }
    
    getUrl(id: string): string {
        return `${this.baseUrl}/${id}`;
    }
    
    async cleanupExpired(): Promise<number> {
        // S3 lifecycle rules handle this automatically
        // This is a no-op for S3
        logger.info('S3 lifecycle rules handle expiration automatically');
        return 0;
    }
    
    private getInternalUrl(id: string): string {
        const endpoint = this.config.endpoint || `https://${this.config.bucket}.s3.${this.config.region}.amazonaws.com`;
        return `${endpoint}${this.config.forcePathStyle ? `/${this.config.bucket}` : ''}/${id}`;
    }

    private validateTenantId(tenantId: string): void {
        if (!/^[a-zA-Z0-9_-]+$/.test(tenantId)) {
            throw new Error('Invalid tenant ID');
        }
    }

    private validateObjectKey(key: string): void {
        if (!key || key.startsWith('/') || /\\/.test(key) || key.includes('..')) {
            throw new Error('Invalid attachment key');
        }
    }

    private async readStreamToBuffer(stream: NodeJS.ReadableStream): Promise<Buffer> {
        const chunks: Buffer[] = [];
        for await (const chunk of stream) {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        }
        return Buffer.concat(chunks);
    }
}

// ============================================================================
// Factory
// ============================================================================

export function createAttachmentStorage(config: AttachmentStorageConfig): AttachmentStorage {
    if (config.type === 's3') {
        return new S3AttachmentStorage(config);
    }
    return new LocalAttachmentStorage(config);
}
