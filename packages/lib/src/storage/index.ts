/**
 * Storage Wrapper - Thin Interface for File/Object Storage
 * 
 * Provides:
 * - Local filesystem storage
 * - S3-compatible storage (MinIO)
 * - Streaming uploads/downloads
 * - Automatic compression
 * 
 * SECURITY: Path traversal protection implemented
 */

import { createReadStream, createWriteStream, promises as fs } from 'node:fs';
import { createGzip, createGunzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { join, dirname, resolve, normalize } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, HeadObjectCommand, ListObjectsV2Command, CopyObjectCommand } from '@aws-sdk/client-s3';
import { Result } from '../result.js';

/**
 * SECURITY: Comprehensive path sanitization to prevent directory traversal attacks
 * 
 * Handles:
 * - Literal `..` sequences
 * - URL-encoded sequences (%2e%2e, %252e%252e double encoding)
 * - Backslash variations (Windows)
 * - Null bytes
 * - Unicode normalization attacks
 * - Absolute path injection
 */
function sanitizePath(key: string, basePath: string): string {
  if (!key || typeof key !== 'string') {
    throw new Error('Invalid storage key');
  }

  // Step 1: Remove null bytes (can bypass string checks)
  let sanitized = key.replace(/\0/g, '');
  
  // Step 2: URL decode multiple times to catch double/triple encoding
  // %2e = '.', %2f = '/', %5c = '\\'
  for (let i = 0; i < 3; i++) {
    try {
      const decoded = decodeURIComponent(sanitized);
      if (decoded === sanitized) break;
      sanitized = decoded;
    } catch {
      // Invalid encoding, continue with current value
      break;
    }
  }
  
  // Step 3: Normalize unicode (some chars can normalize to '.')
  sanitized = sanitized.normalize('NFKC');
  
  // Step 4: Replace backslashes with forward slashes (Windows compatibility)
  sanitized = sanitized.replace(/\\/g, '/');
  
  // Step 5: Normalize slashes and strip leading/trailing separators
  sanitized = sanitized
    .replace(/\/+/g, '/')         // Multiple slashes
    .replace(/^\/+/, '')          // Leading slashes
    .replace(/\/$/,'');           // Trailing slash
  
  // Step 6: Split and filter path components
  const parts = sanitized.split('/').filter(part => {
    // Remove empty parts and explicit current/parent directory markers.
    if (!part || part === '.' || part === '..') return false;
    // Disallow parts that are only whitespace.
    if (/^\s*$/.test(part)) return false;
    return true;
  });
  
  // Step 7: Rejoin and resolve the full path
  const safePath = parts.join('/');
  const fullPath = resolve(basePath, safePath);
  
  // Step 8: CRITICAL - Verify the resolved path is within basePath
  const normalizedBasePath = normalize(resolve(basePath));
  const normalizedFullPath = normalize(fullPath);
  
  if (!normalizedFullPath.startsWith(normalizedBasePath + '/') && normalizedFullPath !== normalizedBasePath) {
    throw new Error('Path traversal detected - access denied');
  }
  
  return fullPath;
}

export interface StorageMetadata {
  contentType?: string;
  contentLength?: number;
  lastModified?: Date;
  etag?: string;
  customMetadata?: Record<string, string>;
}

export interface StorageObject {
  key: string;
  data: Buffer;
  metadata: StorageMetadata;
}

export interface ListResult {
  keys: string[];
  continuationToken?: string;
  isTruncated: boolean;
}

export interface StorageProvider {
  put(key: string, data: Buffer | Readable, metadata?: StorageMetadata): Promise<Result<void, Error>>;
  get(key: string): Promise<Result<StorageObject, Error>>;
  getStream(key: string): Promise<Result<Readable, Error>>;
  delete(key: string): Promise<Result<void, Error>>;
  exists(key: string): Promise<boolean>;
  list(prefix: string, maxKeys?: number, continuationToken?: string): Promise<Result<ListResult, Error>>;
  getMetadata(key: string): Promise<Result<StorageMetadata, Error>>;
  copy(sourceKey: string, destKey: string): Promise<Result<void, Error>>;
}

/**
 * Local filesystem storage provider
 */
export class LocalStorageProvider implements StorageProvider {
  private readonly basePath: string;

  constructor(basePath: string) {
    this.basePath = basePath;
  }

  private getFullPath(key: string): string {
    // SECURITY: Use comprehensive path sanitization
    return sanitizePath(key, this.basePath);
  }

  async put(
    key: string,
    data: Buffer | Readable,
    metadata?: StorageMetadata
  ): Promise<Result<void, Error>> {
    try {
      const fullPath = this.getFullPath(key);
      await fs.mkdir(dirname(fullPath), { recursive: true });

      if (Buffer.isBuffer(data)) {
        await fs.writeFile(fullPath, data);
      } else {
        const writeStream = createWriteStream(fullPath);
        await pipeline(data, writeStream);
      }

      // Store metadata in sidecar file
      if (metadata) {
        const metadataPath = `${fullPath}.meta.json`;
        await fs.writeFile(metadataPath, JSON.stringify(metadata));
      }

      return Result.ok(undefined);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async get(key: string): Promise<Result<StorageObject, Error>> {
    try {
      const fullPath = this.getFullPath(key);
      const data = await fs.readFile(fullPath);
      const metadata = await this.getMetadata(key);

      return Result.ok({
        key,
        data,
        metadata: metadata.ok ? metadata.value : {},
      });
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async getStream(key: string): Promise<Result<Readable, Error>> {
    try {
      const fullPath = this.getFullPath(key);

      try {
        await fs.access(fullPath);
      } catch {
        return Result.err(new Error(`Object not found: ${key}`));
      }

      const stream = createReadStream(fullPath);
      return Result.ok(stream);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async delete(key: string): Promise<Result<void, Error>> {
    try {
      const fullPath = this.getFullPath(key);
      await fs.unlink(fullPath);

      // Also delete metadata sidecar if exists
      const metadataPath = `${fullPath}.meta.json`;
      try {
        await fs.unlink(metadataPath);
      } catch {
        // Ignore if metadata file doesn't exist
      }

      return Result.ok(undefined);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async exists(key: string): Promise<boolean> {
    try {
      const fullPath = this.getFullPath(key);
      await fs.access(fullPath);
      return true;
    } catch {
      return false;
    }
  }

  async list(
    prefix: string,
    maxKeys = 1000,
    _continuationToken?: string
  ): Promise<Result<ListResult, Error>> {
    try {
      const fullPath = this.getFullPath(prefix);
      const keys: string[] = [];
      const maxDepth = 10;

      const listDir = async (dir: string, base: string, depth: number): Promise<void> => {
        try {
          if (depth > maxDepth) {
            return;
          }
          const entries = await fs.readdir(dir, { withFileTypes: true });
          for (const entry of entries) {
            if (keys.length >= maxKeys) break;

            const entryPath = join(dir, entry.name);
            const relativePath = join(base, entry.name);

            if (entry.isDirectory()) {
              await listDir(entryPath, relativePath, depth + 1);
            } else if (!entry.name.endsWith('.meta.json')) {
              keys.push(relativePath);
            }
          }
        } catch {
          // Directory doesn't exist or is not readable
        }
      };

      await listDir(fullPath, prefix, 0);

      return Result.ok({
        keys,
        isTruncated: keys.length >= maxKeys,
      });
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async getMetadata(key: string): Promise<Result<StorageMetadata, Error>> {
    try {
      const fullPath = this.getFullPath(key);
      const metadataPath = `${fullPath}.meta.json`;

      const stat = await fs.stat(fullPath);
      let customMetadata: Record<string, string> = {};

      try {
        const metaContent = await fs.readFile(metadataPath, 'utf8');
        const parsed = JSON.parse(metaContent) as StorageMetadata;
        customMetadata = parsed.customMetadata ?? {};
      } catch {
        // No metadata file
      }

      return Result.ok({
        contentLength: stat.size,
        lastModified: stat.mtime,
        customMetadata,
      });
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async copy(sourceKey: string, destKey: string): Promise<Result<void, Error>> {
    try {
      const sourcePath = this.getFullPath(sourceKey);
      const destPath = this.getFullPath(destKey);

      await fs.mkdir(dirname(destPath), { recursive: true });
      await fs.copyFile(sourcePath, destPath);

      // Also copy metadata if exists
      const sourceMetaPath = `${sourcePath}.meta.json`;
      const destMetaPath = `${destPath}.meta.json`;
      try {
        await fs.copyFile(sourceMetaPath, destMetaPath);
      } catch {
        // Ignore if no metadata
      }

      return Result.ok(undefined);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }
}

interface S3StorageConfig {
  bucket: string;
  region: string;
  endpoint?: string;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  forcePathStyle?: boolean;
}

export class S3StorageProvider implements StorageProvider {
  private readonly config: S3StorageConfig;
  private readonly client: S3Client;

  constructor(config: S3StorageConfig) {
    this.config = config;
    this.client = new S3Client({
      region: config.region,
      endpoint: config.endpoint,
      forcePathStyle: config.forcePathStyle,
      credentials: {
        accessKeyId: config.accessKeyId,
        secretAccessKey: config.secretAccessKey,
        sessionToken: config.sessionToken,
      },
    });
  }

  async put(
    key: string,
    data: Buffer | Readable,
    metadata?: StorageMetadata
  ): Promise<Result<void, Error>> {
    try {
      const payload = Buffer.isBuffer(data) ? data : data;
      const command = new PutObjectCommand({
        Bucket: this.config.bucket,
        Key: key,
        Body: payload,
        ContentType: metadata?.contentType,
        ContentLength: Buffer.isBuffer(payload) ? payload.length : undefined,
        Metadata: metadata?.customMetadata,
      });

      await this.client.send(command);

      return Result.ok(undefined);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async get(key: string): Promise<Result<StorageObject, Error>> {
    try {
      const command = new GetObjectCommand({
        Bucket: this.config.bucket,
        Key: key,
      });
      const response = await this.client.send(command);

      if (!response.Body) {
        return Result.err(new Error(`Empty response body for ${key}`));
      }

      const data = await this.readStreamToBuffer(response.Body as Readable);
      const metadata: StorageMetadata = {
        contentType: response.ContentType,
        contentLength: data.length,
        lastModified: response.LastModified,
        etag: response.ETag?.replace(/"/g, ''),
        customMetadata: response.Metadata ?? {},
      };

      return Result.ok({ key, data, metadata });
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async getStream(key: string): Promise<Result<Readable, Error>> {
    try {
      const command = new GetObjectCommand({
        Bucket: this.config.bucket,
        Key: key,
      });
      const response = await this.client.send(command);

      if (!response.Body) {
        return Result.err(new Error(`Empty response body for ${key}`));
      }

      return Result.ok(response.Body as Readable);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async delete(key: string): Promise<Result<void, Error>> {
    try {
      const command = new DeleteObjectCommand({
        Bucket: this.config.bucket,
        Key: key,
      });
      await this.client.send(command);

      return Result.ok(undefined);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async exists(key: string): Promise<boolean> {
    try {
      const command = new HeadObjectCommand({
        Bucket: this.config.bucket,
        Key: key,
      });
      await this.client.send(command);
      return true;
    } catch {
      return false;
    }
  }

  async list(
    prefix: string,
    maxKeys = 1000,
    continuationToken?: string
  ): Promise<Result<ListResult, Error>> {
    try {
      const command = new ListObjectsV2Command({
        Bucket: this.config.bucket,
        Prefix: prefix,
        MaxKeys: maxKeys,
        ContinuationToken: continuationToken,
      });
      const response = await this.client.send(command);
      const keys = (response.Contents ?? [])
        .map((item) => item.Key)
        .filter((key): key is string => Boolean(key));

      return Result.ok({
        keys,
        continuationToken: response.NextContinuationToken,
        isTruncated: response.IsTruncated ?? false,
      });
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async getMetadata(key: string): Promise<Result<StorageMetadata, Error>> {
    try {
      const command = new HeadObjectCommand({
        Bucket: this.config.bucket,
        Key: key,
      });
      const response = await this.client.send(command);

      return Result.ok({
        contentType: response.ContentType,
        contentLength: response.ContentLength,
        lastModified: response.LastModified,
        etag: response.ETag?.replace(/"/g, ''),
        customMetadata: response.Metadata ?? {},
      });
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async copy(sourceKey: string, destKey: string): Promise<Result<void, Error>> {
    try {
      const encodedSourceKey = sourceKey
        .split('/')
        .map((part) => encodeURIComponent(part))
        .join('/');
      const copySource = `/${this.config.bucket}/${encodedSourceKey}`;
      const command = new CopyObjectCommand({
        Bucket: this.config.bucket,
        Key: destKey,
        CopySource: copySource,
      });
      await this.client.send(command);

      return Result.ok(undefined);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  private async readStreamToBuffer(stream: Readable): Promise<Buffer> {
    const chunks: Buffer[] = [];
    for await (const chunk of stream) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  }
}

/**
 * Compressed storage wrapper - adds gzip compression
 */
export class CompressedStorageProvider implements StorageProvider {
  private readonly underlying: StorageProvider;

  constructor(underlying: StorageProvider) {
    this.underlying = underlying;
  }

  async put(
    key: string,
    data: Buffer | Readable,
    metadata?: StorageMetadata
  ): Promise<Result<void, Error>> {
    const compressedKey = `${key}.gz`;
    
    if (Buffer.isBuffer(data)) {
      const readable = Readable.from(data);
      const gzip = createGzip();
      const chunks: Buffer[] = [];
      
      await pipeline(readable, gzip, new Writable({
        write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void) {
          chunks.push(chunk);
          callback();
        },
      }));
      
      const compressed = Buffer.concat(chunks);
      return this.underlying.put(compressedKey, compressed, {
        ...metadata,
        customMetadata: {
          ...metadata?.customMetadata,
          'x-compressed': 'gzip',
        },
      });
    }
    
    const gzip = createGzip();
    const passthrough = data.pipe(gzip);
    return this.underlying.put(compressedKey, passthrough, {
      ...metadata,
      customMetadata: {
        ...metadata?.customMetadata,
        'x-compressed': 'gzip',
      },
    });
  }

  async get(key: string): Promise<Result<StorageObject, Error>> {
    const compressedKey = `${key}.gz`;
    const result = await this.underlying.get(compressedKey);
    
    if (!result.ok) {
      // Try uncompressed
      return this.underlying.get(key);
    }

    const gunzip = createGunzip();
    const chunks: Buffer[] = [];
    
    await pipeline(Readable.from(result.value.data), gunzip, new Writable({
      write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void) {
        chunks.push(chunk);
        callback();
      },
    }));

    return Result.ok({
      key,
      data: Buffer.concat(chunks),
      metadata: result.value.metadata,
    });
  }

  async getStream(key: string): Promise<Result<Readable, Error>> {
    const compressedKey = `${key}.gz`;
    const result = await this.underlying.getStream(compressedKey);
    
    if (!result.ok) {
      return this.underlying.getStream(key);
    }

    const gunzip = createGunzip();
    return Result.ok(result.value.pipe(gunzip));
  }

  async delete(key: string): Promise<Result<void, Error>> {
    const compressedKey = `${key}.gz`;
    // Try both compressed and uncompressed
    await this.underlying.delete(compressedKey);
    return this.underlying.delete(key);
  }

  async exists(key: string): Promise<boolean> {
    const compressedKey = `${key}.gz`;
    return (await this.underlying.exists(compressedKey)) || 
           (await this.underlying.exists(key));
  }

  async list(
    prefix: string,
    maxKeys?: number,
    continuationToken?: string
  ): Promise<Result<ListResult, Error>> {
    return this.underlying.list(prefix, maxKeys, continuationToken);
  }

  async getMetadata(key: string): Promise<Result<StorageMetadata, Error>> {
    const compressedKey = `${key}.gz`;
    const result = await this.underlying.getMetadata(compressedKey);
    if (result.ok) return result;
    return this.underlying.getMetadata(key);
  }

  async copy(sourceKey: string, destKey: string): Promise<Result<void, Error>> {
    const compressedResult = await this.underlying.copy(`${sourceKey}.gz`, `${destKey}.gz`);
    if (compressedResult.ok) return compressedResult;
    return this.underlying.copy(sourceKey, destKey);
  }
}

// Factory function
export function createStorage(config: {
  type: 'local' | 's3';
  basePath?: string;
  s3?: {
    bucket: string;
    region: string;
    endpoint?: string;
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken?: string;
    forcePathStyle?: boolean;
  };
  compression?: boolean;
}): StorageProvider {
  let provider: StorageProvider;

  if (config.type === 'local') {
    provider = new LocalStorageProvider(config.basePath ?? './data/storage');
  } else {
    if (!config.s3) {
      throw new Error('S3 configuration is required when storage type is s3');
    }

    provider = new S3StorageProvider(config.s3);
  }

  if (config.compression) {
    return new CompressedStorageProvider(provider);
  }

  return provider;
}
