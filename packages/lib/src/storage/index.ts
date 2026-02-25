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
import { createHash, createHmac } from 'node:crypto';
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
      const exists = await this.exists(key);
      
      if (!exists) {
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

      const listDir = async (dir: string, base: string): Promise<void> => {
        try {
          const entries = await fs.readdir(dir, { withFileTypes: true });
          for (const entry of entries) {
            if (keys.length >= maxKeys) break;

            const entryPath = join(dir, entry.name);
            const relativePath = join(base, entry.name);

            if (entry.isDirectory()) {
              await listDir(entryPath, relativePath);
            } else if (!entry.name.endsWith('.meta.json')) {
              keys.push(relativePath);
            }
          }
        } catch {
          // Directory doesn't exist or is not readable
        }
      };

      await listDir(fullPath, prefix);

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

  constructor(config: S3StorageConfig) {
    this.config = config;
  }

  async put(
    key: string,
    data: Buffer | Readable,
    metadata?: StorageMetadata
  ): Promise<Result<void, Error>> {
    try {
      const payload = Buffer.isBuffer(data) ? data : await this.readStreamToBuffer(data);
      const payloadHash = this.sha256Hex(payload);

      const headers: Record<string, string> = {
        'Content-Length': String(payload.length),
        'x-amz-content-sha256': payloadHash,
      };

      if (metadata?.contentType) {
        headers['Content-Type'] = metadata.contentType;
      }

      if (metadata?.customMetadata) {
        for (const [metaKey, metaValue] of Object.entries(metadata.customMetadata)) {
          headers[`x-amz-meta-${metaKey.toLowerCase()}`] = metaValue;
        }
      }

      const response = await this.sendSignedRequest('PUT', key, '', headers, payload, payloadHash);

      if (!response.ok) {
        return Result.err(new Error(`S3 put failed (${response.status}): ${await response.text()}`));
      }

      return Result.ok(undefined);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async get(key: string): Promise<Result<StorageObject, Error>> {
    try {
      const response = await this.sendSignedRequest('GET', key, '', {
        'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
      }, undefined, 'UNSIGNED-PAYLOAD');

      if (!response.ok) {
        return Result.err(new Error(`Object not found: ${key}`));
      }

      const data = Buffer.from(await response.arrayBuffer());
      const metadata = this.extractMetadataFromHeaders(response.headers, data.length);

      return Result.ok({ key, data, metadata });
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async getStream(key: string): Promise<Result<Readable, Error>> {
    try {
      const response = await this.sendSignedRequest('GET', key, '', {
        'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
      }, undefined, 'UNSIGNED-PAYLOAD');

      if (!response.ok) {
        return Result.err(new Error(`Object not found: ${key}`));
      }

      if (!response.body) {
        return Result.err(new Error(`Empty response body for ${key}`));
      }

      const stream = Readable.fromWeb(response.body as unknown as ReadableStream<Uint8Array>);
      return Result.ok(stream);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async delete(key: string): Promise<Result<void, Error>> {
    try {
      const response = await this.sendSignedRequest('DELETE', key, '', {
        'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
      }, undefined, 'UNSIGNED-PAYLOAD');

      if (!response.ok && response.status !== 404) {
        return Result.err(new Error(`S3 delete failed (${response.status}): ${await response.text()}`));
      }

      return Result.ok(undefined);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async exists(key: string): Promise<boolean> {
    try {
      const response = await this.sendSignedRequest('HEAD', key, '', {
        'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
      }, undefined, 'UNSIGNED-PAYLOAD');
      return response.ok;
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
      const queryParams = new URLSearchParams({
        'list-type': '2',
        'prefix': prefix,
        'max-keys': String(maxKeys),
      });

      if (continuationToken) {
        queryParams.set('continuation-token', continuationToken);
      }

      const query = queryParams.toString();
      const response = await this.sendSignedRequest('GET', '', query, {
        'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
      }, undefined, 'UNSIGNED-PAYLOAD');

      if (!response.ok) {
        return Result.err(new Error(`S3 list failed (${response.status}): ${await response.text()}`));
      }

      const xml = await response.text();
      const keys = Array.from(xml.matchAll(/<Key>(.*?)<\/Key>/g)).map((match) => this.decodeXml(match[1] ?? ''));
      const isTruncated = /<IsTruncated>true<\/IsTruncated>/.test(xml);
      const nextContinuationTokenMatch = xml.match(/<NextContinuationToken>(.*?)<\/NextContinuationToken>/);

      return Result.ok({
        keys,
        continuationToken: nextContinuationTokenMatch ? this.decodeXml(nextContinuationTokenMatch[1] ?? '') : undefined,
        isTruncated,
      });
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async getMetadata(key: string): Promise<Result<StorageMetadata, Error>> {
    try {
      const response = await this.sendSignedRequest('HEAD', key, '', {
        'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
      }, undefined, 'UNSIGNED-PAYLOAD');

      if (!response.ok) {
        return Result.err(new Error(`Object not found: ${key}`));
      }

      const contentLength = Number(response.headers.get('content-length') ?? '0');
      return Result.ok(this.extractMetadataFromHeaders(response.headers, contentLength));
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async copy(sourceKey: string, destKey: string): Promise<Result<void, Error>> {
    try {
      const encodedCopySource = this.config.forcePathStyle
        ? `/${this.config.bucket}/${sourceKey}`
        : `/${this.config.bucket}/${sourceKey}`;

      const response = await this.sendSignedRequest('PUT', destKey, '', {
        'x-amz-content-sha256': this.sha256Hex(Buffer.alloc(0)),
        'x-amz-copy-source': encodedCopySource,
      }, Buffer.alloc(0), this.sha256Hex(Buffer.alloc(0)));

      if (!response.ok) {
        return Result.err(new Error(`S3 copy failed (${response.status}): ${await response.text()}`));
      }

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

  private extractMetadataFromHeaders(headers: Headers, contentLength: number): StorageMetadata {
    const customMetadata: Record<string, string> = {};

    headers.forEach((value, key) => {
      if (key.toLowerCase().startsWith('x-amz-meta-')) {
        customMetadata[key.slice('x-amz-meta-'.length)] = value;
      }
    });

    return {
      contentType: headers.get('content-type') ?? undefined,
      contentLength,
      lastModified: headers.get('last-modified') ? new Date(headers.get('last-modified') as string) : undefined,
      etag: headers.get('etag')?.replace(/"/g, ''),
      customMetadata,
    };
  }

  private decodeXml(value: string): string {
    return value
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
  }

  private sha256Hex(payload: Buffer): string {
    return createHash('sha256').update(payload).digest('hex');
  }

  private getHost(): string {
    if (this.config.endpoint) {
      return new URL(this.config.endpoint).host;
    }

    if (this.config.forcePathStyle) {
      return `s3.${this.config.region}.amazonaws.com`;
    }

    return `${this.config.bucket}.s3.${this.config.region}.amazonaws.com`;
  }

  private getRequestUrl(key: string, query = ''): string {
    const endpoint = this.config.endpoint
      ? this.config.endpoint.replace(/\/$/, '')
      : `https://${this.getHost()}`;

    const encodedKey = key
      .split('/')
      .map((part) => encodeURIComponent(part))
      .join('/');
    const keyPath = encodedKey ? `/${encodedKey}` : '/';

    const basePath = this.config.forcePathStyle ? `/${this.config.bucket}${keyPath}` : keyPath;
    return query ? `${endpoint}${basePath}?${query}` : `${endpoint}${basePath}`;
  }

  private getCanonicalUri(key: string): string {
    const encodedKey = key
      .split('/')
      .map((part) => encodeURIComponent(part))
      .join('/');
    const keyPath = encodedKey ? `/${encodedKey}` : '/';
    return this.config.forcePathStyle ? `/${this.config.bucket}${keyPath}` : keyPath;
  }

  private canonicalizeQuery(query: string): string {
    if (!query) return '';

    const params = new URLSearchParams(query);
    return Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([name, value]) => `${encodeURIComponent(name)}=${encodeURIComponent(value)}`)
      .join('&');
  }

  private signRequest(
    method: string,
    canonicalUri: string,
    canonicalQuery: string,
    headers: Record<string, string>,
    payloadHash: string,
    amzDate: string,
    dateStamp: string,
  ): string {
    const normalizedHeaders = Object.entries(headers)
      .map(([name, value]) => [name.toLowerCase(), value.trim()] as const)
      .filter(([name]) => name !== 'authorization')
      .sort(([a], [b]) => a.localeCompare(b));

    const canonicalHeaders = normalizedHeaders
      .map(([name, value]) => `${name}:${value}`)
      .join('\n');

    const signedHeaders = normalizedHeaders.map(([name]) => name).join(';');

    const canonicalRequest = [
      method,
      canonicalUri,
      canonicalQuery,
      canonicalHeaders,
      '',
      signedHeaders,
      payloadHash,
    ].join('\n');

    const credentialScope = `${dateStamp}/${this.config.region}/s3/aws4_request`;
    const stringToSign = [
      'AWS4-HMAC-SHA256',
      amzDate,
      credentialScope,
      createHash('sha256').update(canonicalRequest).digest('hex'),
    ].join('\n');

    const kDate = createHmac('sha256', `AWS4${this.config.secretAccessKey}`).update(dateStamp).digest();
    const kRegion = createHmac('sha256', kDate).update(this.config.region).digest();
    const kService = createHmac('sha256', kRegion).update('s3').digest();
    const kSigning = createHmac('sha256', kService).update('aws4_request').digest();
    const signature = createHmac('sha256', kSigning).update(stringToSign).digest('hex');

    return `AWS4-HMAC-SHA256 Credential=${this.config.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  }

  private async sendSignedRequest(
    method: 'GET' | 'PUT' | 'HEAD' | 'DELETE',
    key: string,
    query: string,
    extraHeaders: Record<string, string>,
    body?: Buffer,
    payloadHash = 'UNSIGNED-PAYLOAD',
  ): Promise<Response> {
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.slice(0, 8);

    const canonicalUri = this.getCanonicalUri(key);
    const canonicalQuery = this.canonicalizeQuery(query);

    const headers: Record<string, string> = {
      Host: this.getHost(),
      'x-amz-date': amzDate,
      ...extraHeaders,
    };

    if (this.config.sessionToken) {
      headers['x-amz-security-token'] = this.config.sessionToken;
    }

    const signature = this.signRequest(method, canonicalUri, canonicalQuery, headers, payloadHash, amzDate, dateStamp);
    headers.Authorization = signature;

    const url = this.getRequestUrl(key, canonicalQuery);
    return fetch(url, {
      method,
      headers,
      body,
    });
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
