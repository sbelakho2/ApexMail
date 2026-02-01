/**
 * Storage Wrapper - Thin Interface for File/Object Storage
 * 
 * Provides:
 * - Local filesystem storage
 * - S3-compatible storage (MinIO)
 * - Streaming uploads/downloads
 * - Automatic compression
 */

import { createReadStream, createWriteStream, promises as fs } from 'node:fs';
import { createGzip, createGunzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { join, dirname } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { Result } from '../result.js';

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
    // Sanitize key to prevent directory traversal
    const sanitized = key.replace(/\.\./g, '').replace(/^\//, '');
    return join(this.basePath, sanitized);
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
        write(chunk: Buffer, _encoding, callback) {
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
      write(chunk: Buffer, _encoding, callback) {
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
    return this.underlying.copy(`${sourceKey}.gz`, `${destKey}.gz`);
  }
}

// Factory function
export function createStorage(config: {
  type: 'local' | 's3';
  basePath?: string;
  compression?: boolean;
}): StorageProvider {
  let provider: StorageProvider;

  if (config.type === 'local') {
    provider = new LocalStorageProvider(config.basePath ?? './data/storage');
  } else {
    // S3 provider would be implemented here
    throw new Error('S3 storage not yet implemented');
  }

  if (config.compression) {
    return new CompressedStorageProvider(provider);
  }

  return provider;
}
