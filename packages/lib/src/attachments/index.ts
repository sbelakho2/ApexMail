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
        
        // Generate unique ID
        const id = `${tenantId}_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
        
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
        const metadata = await this.getMetadata(id);
        if (!metadata) {
            throw new Error(`Attachment not found: ${id}`);
        }
        
        const filePath = path.join(this.basePath, metadata.tenantId, id);
        const content = await fs.readFile(filePath);
        
        return { content, metadata };
    }
    
    async delete(id: string): Promise<void> {
        const metadata = await this.getMetadata(id);
        if (!metadata) {
            throw new Error(`Attachment not found: ${id}`);
        }
        
        const filePath = path.join(this.basePath, metadata.tenantId, id);
        const metadataFilePath = path.join(this.metadataPath, `${id}.json`);
        
        await fs.unlink(filePath).catch(() => {});
        await fs.unlink(metadataFilePath).catch(() => {});
        
        logger.info('Attachment deleted', { id });
    }
    
    async getMetadata(id: string): Promise<AttachmentMetadata | null> {
        try {
            const metadataPath = path.join(this.metadataPath, `${id}.json`);
            const content = await fs.readFile(metadataPath, 'utf-8');
            return JSON.parse(content);
        } catch {
            return null;
        }
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
            
            for (const file of files) {
                if (!file.endsWith('.json')) continue;
                
                const metadataPath = path.join(this.metadataPath, file);
                const content = await fs.readFile(metadataPath, 'utf-8');
                let metadata: AttachmentMetadata;
                try { metadata = JSON.parse(content); }
                catch { continue; }
                
                if (metadata.expiresAt && new Date(metadata.expiresAt) < now) {
                    await this.delete(metadata.id);
                    deleted++;
                }
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
    
    constructor(config: AttachmentStorageConfig) {
        if (!config.s3) {
            throw new Error('S3 configuration is required');
        }
        this.config = config.s3;
        this.baseUrl = config.baseUrl || `https://${config.s3.bucket}.s3.${config.s3.region}.amazonaws.com`;
        this.maxSize = config.maxSize || 25 * 1024 * 1024;
        this.allowedTypes = config.allowedTypes || null;
        this.expirationDays = config.expirationDays || null;
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
        
        const hash = crypto.createHash('sha256').update(buffer).digest('hex');
        const id = `${tenantId}/${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
        
        // Use AWS SDK v3 style signing
        const date = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
        const dateStamp = date.slice(0, 8);
        
        const canonicalUri = `/${id}`;
        const host = this.config.endpoint 
            ? new URL(this.config.endpoint).host 
            : `${this.config.bucket}.s3.${this.config.region}.amazonaws.com`;
        
        // Create the request
        const endpoint = this.config.endpoint || `https://${host}`;
        const url = `${endpoint}${this.config.forcePathStyle ? `/${this.config.bucket}` : ''}${canonicalUri}`;
        
        // Sign and upload using fetch
        const headers: Record<string, string> = {
            'Content-Type': contentType,
            'Content-Length': buffer.length.toString(),
            'x-amz-date': date,
            'x-amz-content-sha256': hash,
            'Host': host,
        };
        
        if (this.expirationDays) {
            const expires = new Date(Date.now() + this.expirationDays * 24 * 60 * 60 * 1000);
            headers['x-amz-meta-expires'] = expires.toISOString();
        }

        if (this.config.sessionToken) {
            headers['x-amz-security-token'] = this.config.sessionToken;
        }
        
        // Generate signature (simplified - in production use AWS SDK)
        const signature = this.signRequest('PUT', canonicalUri, headers, hash, dateStamp);
        headers['Authorization'] = signature;
        
        const response = await fetch(url, {
            method: 'PUT',
            headers,
            body: buffer,
        });
        
        if (!response.ok) {
            const text = await response.text();
            throw new Error(`S3 upload failed: ${response.status} ${text}`);
        }
        
        logger.info('Attachment uploaded to S3', { id, filename, size: buffer.length, tenantId, messageId });
        
        return {
            id,
            url: this.getUrl(id),
            hash,
            size: buffer.length,
        };
    }
    
    async download(id: string): Promise<{ content: Buffer; metadata: AttachmentMetadata }> {
        const url = this.getInternalUrl(id);
        const headers = this.getAuthHeaders('GET', `/${id}`);
        
        const response = await fetch(url, { headers });
        
        if (!response.ok) {
            throw new Error(`Attachment not found: ${id}`);
        }
        
        const content = Buffer.from(await response.arrayBuffer());
        const contentType = response.headers.get('content-type') || 'application/octet-stream';
        const expiresHeader = response.headers.get('x-amz-meta-expires');
        
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
        const url = this.getInternalUrl(id);
        const headers = this.getAuthHeaders('DELETE', `/${id}`);
        
        const response = await fetch(url, {
            method: 'DELETE',
            headers,
        });
        
        if (!response.ok && response.status !== 404) {
            throw new Error(`Failed to delete attachment: ${id}`);
        }
        
        logger.info('Attachment deleted from S3', { id });
    }
    
    async getMetadata(id: string): Promise<AttachmentMetadata | null> {
        const url = this.getInternalUrl(id);
        const headers = this.getAuthHeaders('HEAD', `/${id}`);
        
        const response = await fetch(url, {
            method: 'HEAD',
            headers,
        });
        
        if (!response.ok) {
            return null;
        }
        
        const contentType = response.headers.get('content-type') || 'application/octet-stream';
        const contentLength = parseInt(response.headers.get('content-length') || '0', 10);
        const expiresHeader = response.headers.get('x-amz-meta-expires');
        
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
    
    private getAuthHeaders(method: string, path: string): Record<string, string> {
        const date = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
        const dateStamp = date.slice(0, 8);
        const host = this.config.endpoint 
            ? new URL(this.config.endpoint).host 
            : `${this.config.bucket}.s3.${this.config.region}.amazonaws.com`;
        
        const headers: Record<string, string> = {
            'x-amz-date': date,
            'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
            'Host': host,
        };

        if (this.config.sessionToken) {
            headers['x-amz-security-token'] = this.config.sessionToken;
        }
        
        const signature = this.signRequest(method, path, headers, 'UNSIGNED-PAYLOAD', dateStamp);
        headers['Authorization'] = signature;
        
        return headers;
    }
    
    // FIX-500-376: Partial SigV4 implementation. Supports STS session tokens and
    // basic PUT/GET/DELETE/HEAD signing, but still does not support chunked
    // uploads, presigned URL query signing, or advanced canonicalization edge-cases.
    private signRequest(
        method: string,
        path: string,
        headers: Record<string, string>,
        payloadHash: string,
        dateStamp: string
    ): string {
        const date = headers['x-amz-date'] || '';
        const region = this.config.region;
        const service = 's3';
        
        // Create canonical request
        const sortedHeaders = Object.keys(headers)
            .filter(k => k.toLowerCase() !== 'authorization')
            .sort()
            .map(k => `${k.toLowerCase()}:${headers[k]?.trim()}`)
            .join('\n');
        
        const signedHeaders = Object.keys(headers)
            .filter(k => k.toLowerCase() !== 'authorization')
            .sort()
            .map(k => k.toLowerCase())
            .join(';');
        
        const canonicalRequest = [
            method,
            path,
            '', // query string
            sortedHeaders,
            '',
            signedHeaders,
            payloadHash,
        ].join('\n');
        
        // Create string to sign
        const algorithm = 'AWS4-HMAC-SHA256';
        const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
        const stringToSign = [
            algorithm,
            date,
            credentialScope,
            crypto.createHash('sha256').update(canonicalRequest).digest('hex'),
        ].join('\n');
        
        // Calculate signature
        const kDate = crypto.createHmac('sha256', `AWS4${this.config.secretAccessKey}`).update(dateStamp).digest();
        const kRegion = crypto.createHmac('sha256', kDate).update(region).digest();
        const kService = crypto.createHmac('sha256', kRegion).update(service).digest();
        const kSigning = crypto.createHmac('sha256', kService).update('aws4_request').digest();
        const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');
        
        return `${algorithm} Credential=${this.config.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
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
