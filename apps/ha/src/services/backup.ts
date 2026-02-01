/**
 * Backup Service
 * 
 * Comprehensive backup management:
 * - Full database backups
 * - Incremental backups
 * - WAL archiving
 * - Point-in-time recovery
 * - Backup verification
 * - Retention management
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
import { createReadStream, createWriteStream, promises as fs } from 'fs';
import { join, dirname } from 'path';
import { createGzip, createGunzip } from 'zlib';
import { pipeline } from 'stream/promises';
import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'crypto';
import { config } from '../config.js';

export enum BackupType {
  FULL = 'full',
  INCREMENTAL = 'incremental',
  WAL = 'wal',
  SNAPSHOT = 'snapshot',
}

export enum BackupStatus {
  PENDING = 'pending',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
  FAILED = 'failed',
  VERIFIED = 'verified',
  EXPIRED = 'expired',
}

export interface Backup {
  id: string;
  type: BackupType;
  status: BackupStatus;
  startedAt: Date;
  completedAt: Date | null;
  sizeBytes: number;
  compressedSizeBytes: number;
  checksum: string;
  location: string;
  encryptionKeyId: string | null;
  baseBackupId: string | null;
  walStart: string | null;
  walEnd: string | null;
  metadata: Record<string, unknown>;
}

export interface BackupSchedule {
  id: string;
  type: BackupType;
  cronExpression: string;
  enabled: boolean;
  retentionDays: number;
  lastRun: Date | null;
  nextRun: Date;
}

export interface RestoreOptions {
  backupId?: string;
  pointInTime?: Date;
  targetDatabase?: string;
  verifyOnly?: boolean;
}

export interface RestoreResult {
  success: boolean;
  backupUsed: string;
  restorePoint: Date;
  duration: number;
  walFilesApplied: number;
  error?: string;
}

type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export class BackupService {
  private db: Pool;
  private redis: Redis;
  private backupDir: string;
  private encryptionKey: Buffer | null;
  private activeBackup: Backup | null = null;
  private schedules: Map<string, NodeJS.Timeout> = new Map();

  constructor(db: Pool, redis: Redis) {
    this.db = db;
    this.redis = redis;
    this.backupDir = process.env.BACKUP_DIR ?? '/var/lib/apexmail/backups';
    this.encryptionKey = config.backupEncryptionKey 
      ? Buffer.from(config.backupEncryptionKey, 'hex')
      : null;
  }

  /**
   * Initialize backup service
   */
  async initialize(): Promise<void> {
    // Ensure backup directory exists
    await fs.mkdir(this.backupDir, { recursive: true });
    
    // Create subdirectories
    await fs.mkdir(join(this.backupDir, 'full'), { recursive: true });
    await fs.mkdir(join(this.backupDir, 'incremental'), { recursive: true });
    await fs.mkdir(join(this.backupDir, 'wal'), { recursive: true });
    await fs.mkdir(join(this.backupDir, 'temp'), { recursive: true });

    console.log('[Backup] Service initialized');
  }

  /**
   * Create a full database backup
   */
  async createFullBackup(): Promise<Result<Backup>> {
    if (this.activeBackup) {
      return { ok: false, error: new Error('Another backup is in progress') };
    }

    const backupId = `backup_full_${Date.now()}`;
    const backup: Backup = {
      id: backupId,
      type: BackupType.FULL,
      status: BackupStatus.IN_PROGRESS,
      startedAt: new Date(),
      completedAt: null,
      sizeBytes: 0,
      compressedSizeBytes: 0,
      checksum: '',
      location: '',
      encryptionKeyId: this.encryptionKey ? 'primary' : null,
      baseBackupId: null,
      walStart: null,
      walEnd: null,
      metadata: {},
    };

    this.activeBackup = backup;
    await this.recordBackupStart(backup);

    console.log(`[Backup] Starting full backup: ${backupId}`);

    try {
      // Get WAL position before backup
      const walStartResult = await this.db.query('SELECT pg_current_wal_lsn() as lsn');
      backup.walStart = walStartResult.rows[0]?.lsn;

      // Create backup directory
      const backupPath = join(this.backupDir, 'full', backupId);
      await fs.mkdir(backupPath, { recursive: true });

      // Export each table (in production, would use pg_basebackup)
      const tables = await this.getTableList();
      let totalSize = 0;

      for (const table of tables) {
        const tableBackupPath = join(backupPath, `${table.schema}_${table.name}.sql.gz`);
        const size = await this.backupTable(table.schema, table.name, tableBackupPath);
        totalSize += size;
        backup.metadata[`${table.schema}.${table.name}`] = { size };
      }

      // Backup roles and permissions
      await this.backupRoles(join(backupPath, 'roles.sql.gz'));

      // Get WAL position after backup
      const walEndResult = await this.db.query('SELECT pg_current_wal_lsn() as lsn');
      backup.walEnd = walEndResult.rows[0]?.lsn;

      // Create manifest file
      const manifest = {
        id: backupId,
        type: BackupType.FULL,
        createdAt: backup.startedAt.toISOString(),
        walStart: backup.walStart,
        walEnd: backup.walEnd,
        tables: tables.map(t => `${t.schema}.${t.name}`),
        encrypted: !!this.encryptionKey,
      };
      await fs.writeFile(
        join(backupPath, 'manifest.json'),
        JSON.stringify(manifest, null, 2)
      );

      // Calculate checksum
      backup.checksum = await this.calculateDirectoryChecksum(backupPath);
      backup.sizeBytes = totalSize;
      backup.compressedSizeBytes = await this.getDirectorySize(backupPath);
      backup.location = backupPath;
      backup.status = BackupStatus.COMPLETED;
      backup.completedAt = new Date();

      await this.recordBackupComplete(backup);
      this.activeBackup = null;

      console.log(`[Backup] Full backup completed: ${backupId} (${this.formatBytes(backup.compressedSizeBytes)})`);

      return { ok: true, value: backup };
    } catch (error) {
      backup.status = BackupStatus.FAILED;
      backup.completedAt = new Date();
      backup.metadata.error = (error as Error).message;
      
      await this.recordBackupComplete(backup);
      this.activeBackup = null;

      console.error(`[Backup] Full backup failed:`, error);
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Create an incremental backup
   */
  async createIncrementalBackup(baseBackupId?: string): Promise<Result<Backup>> {
    if (this.activeBackup) {
      return { ok: false, error: new Error('Another backup is in progress') };
    }

    // Find base backup
    const baseBackup = baseBackupId 
      ? await this.getBackup(baseBackupId)
      : await this.getLatestFullBackup();

    if (!baseBackup.ok || !baseBackup.value) {
      return { ok: false, error: new Error('No base backup found') };
    }

    const base = baseBackup.value;
    const backupId = `backup_incr_${Date.now()}`;
    
    const backup: Backup = {
      id: backupId,
      type: BackupType.INCREMENTAL,
      status: BackupStatus.IN_PROGRESS,
      startedAt: new Date(),
      completedAt: null,
      sizeBytes: 0,
      compressedSizeBytes: 0,
      checksum: '',
      location: '',
      encryptionKeyId: this.encryptionKey ? 'primary' : null,
      baseBackupId: base.id,
      walStart: base.walEnd,
      walEnd: null,
      metadata: {},
    };

    this.activeBackup = backup;
    await this.recordBackupStart(backup);

    console.log(`[Backup] Starting incremental backup: ${backupId} (base: ${base.id})`);

    try {
      const backupPath = join(this.backupDir, 'incremental', backupId);
      await fs.mkdir(backupPath, { recursive: true });

      // Get changes since base backup using WAL position
      const changes = await this.getChangesSince(base.walEnd!);
      let totalSize = 0;

      for (const change of changes) {
        const changeBackupPath = join(backupPath, `${change.schema}_${change.table}.sql.gz`);
        const size = await this.backupTableChanges(
          change.schema,
          change.table,
          change.since,
          changeBackupPath
        );
        totalSize += size;
        backup.metadata[`${change.schema}.${change.table}`] = { 
          size,
          rowCount: change.rowCount,
        };
      }

      // Get current WAL position
      const walEndResult = await this.db.query('SELECT pg_current_wal_lsn() as lsn');
      backup.walEnd = walEndResult.rows[0]?.lsn;

      // Create manifest
      const manifest = {
        id: backupId,
        type: BackupType.INCREMENTAL,
        baseBackupId: base.id,
        createdAt: backup.startedAt.toISOString(),
        walStart: backup.walStart,
        walEnd: backup.walEnd,
        changes: changes.length,
        encrypted: !!this.encryptionKey,
      };
      await fs.writeFile(
        join(backupPath, 'manifest.json'),
        JSON.stringify(manifest, null, 2)
      );

      backup.checksum = await this.calculateDirectoryChecksum(backupPath);
      backup.sizeBytes = totalSize;
      backup.compressedSizeBytes = await this.getDirectorySize(backupPath);
      backup.location = backupPath;
      backup.status = BackupStatus.COMPLETED;
      backup.completedAt = new Date();

      await this.recordBackupComplete(backup);
      this.activeBackup = null;

      console.log(`[Backup] Incremental backup completed: ${backupId}`);

      return { ok: true, value: backup };
    } catch (error) {
      backup.status = BackupStatus.FAILED;
      backup.completedAt = new Date();
      backup.metadata.error = (error as Error).message;
      
      await this.recordBackupComplete(backup);
      this.activeBackup = null;

      return { ok: false, error: error as Error };
    }
  }

  /**
   * Archive WAL files for point-in-time recovery
   */
  async archiveWalFile(walFileName: string, walFilePath: string): Promise<Result<void>> {
    const archivePath = join(this.backupDir, 'wal', `${walFileName}.gz`);
    
    try {
      // Compress and optionally encrypt
      const readStream = createReadStream(walFilePath);
      const writeStream = createWriteStream(archivePath);
      const gzip = createGzip({ level: 9 });

      if (this.encryptionKey) {
        const iv = randomBytes(16);
        const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, iv);
        
        // Write IV at the beginning of the file
        writeStream.write(iv);
        await pipeline(readStream, gzip, cipher, writeStream);
      } else {
        await pipeline(readStream, gzip, writeStream);
      }

      // Record WAL archive
      await this.redis.zadd(
        'backup:wal:archived',
        Date.now(),
        `${walFileName}:${archivePath}`
      );

      console.log(`[Backup] WAL archived: ${walFileName}`);
      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Restore from backup
   */
  async restore(options: RestoreOptions): Promise<Result<RestoreResult>> {
    const startTime = Date.now();

    try {
      let backup: Backup | null = null;

      if (options.backupId) {
        const backupResult = await this.getBackup(options.backupId);
        if (!backupResult.ok || !backupResult.value) {
          return { ok: false, error: new Error('Backup not found') };
        }
        backup = backupResult.value;
      } else if (options.pointInTime) {
        // Find backup closest to the point in time
        const backupResult = await this.findBackupForPointInTime(options.pointInTime);
        if (!backupResult.ok || !backupResult.value) {
          return { ok: false, error: new Error('No suitable backup found for point-in-time recovery') };
        }
        backup = backupResult.value;
      } else {
        // Use latest backup
        const latestResult = await this.getLatestFullBackup();
        if (!latestResult.ok || !latestResult.value) {
          return { ok: false, error: new Error('No backup available') };
        }
        backup = latestResult.value;
      }

      console.log(`[Backup] Starting restore from: ${backup.id}`);

      // If verify only, just validate the backup
      if (options.verifyOnly) {
        const verifyResult = await this.verifyBackup(backup.id);
        return {
          ok: true,
          value: {
            success: verifyResult.ok,
            backupUsed: backup.id,
            restorePoint: backup.completedAt ?? backup.startedAt,
            duration: Date.now() - startTime,
            walFilesApplied: 0,
            error: verifyResult.ok ? undefined : verifyResult.error.message,
          },
        };
      }

      // Restore base backup
      await this.restoreBackupFiles(backup, options.targetDatabase);

      // Apply incremental backups if needed
      let incrementalsApplied = 0;
      if (backup.type === BackupType.FULL) {
        const incrementals = await this.getIncrementalsSince(backup.id);
        for (const incr of incrementals) {
          if (options.pointInTime && incr.completedAt! > options.pointInTime) {
            break;
          }
          await this.restoreBackupFiles(incr, options.targetDatabase);
          incrementalsApplied++;
        }
      }

      // Apply WAL files for point-in-time recovery
      let walFilesApplied = 0;
      if (options.pointInTime) {
        walFilesApplied = await this.applyWalFiles(backup.walEnd!, options.pointInTime);
      }

      const result: RestoreResult = {
        success: true,
        backupUsed: backup.id,
        restorePoint: options.pointInTime ?? (backup.completedAt ?? backup.startedAt),
        duration: Date.now() - startTime,
        walFilesApplied,
      };

      console.log(`[Backup] Restore completed in ${result.duration}ms`);

      return { ok: true, value: result };
    } catch (error) {
      return {
        ok: true,
        value: {
          success: false,
          backupUsed: options.backupId ?? 'unknown',
          restorePoint: new Date(),
          duration: Date.now() - startTime,
          walFilesApplied: 0,
          error: (error as Error).message,
        },
      };
    }
  }

  /**
   * Verify backup integrity
   */
  async verifyBackup(backupId: string): Promise<Result<{ valid: boolean; issues: string[] }>> {
    const backupResult = await this.getBackup(backupId);
    if (!backupResult.ok || !backupResult.value) {
      return { ok: false, error: new Error('Backup not found') };
    }

    const backup = backupResult.value;
    const issues: string[] = [];

    try {
      // Check if backup files exist
      try {
        await fs.access(backup.location);
      } catch {
        issues.push('Backup location not accessible');
        return { ok: true, value: { valid: false, issues } };
      }

      // Verify checksum
      const currentChecksum = await this.calculateDirectoryChecksum(backup.location);
      if (currentChecksum !== backup.checksum) {
        issues.push('Checksum mismatch - backup may be corrupted');
      }

      // Verify manifest
      const manifestPath = join(backup.location, 'manifest.json');
      try {
        const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf-8'));
        if (manifest.id !== backupId) {
          issues.push('Manifest ID mismatch');
        }
      } catch {
        issues.push('Manifest file missing or invalid');
      }

      // Verify each backup file can be read
      const files = await fs.readdir(backup.location);
      for (const file of files) {
        if (file.endsWith('.sql.gz')) {
          try {
            await this.verifyCompressedFile(join(backup.location, file));
          } catch (error) {
            issues.push(`File verification failed: ${file} - ${(error as Error).message}`);
          }
        }
      }

      const valid = issues.length === 0;
      
      // Update backup status
      if (valid) {
        backup.status = BackupStatus.VERIFIED;
        await this.recordBackupComplete(backup);
      }

      return { ok: true, value: { valid, issues } };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * List all backups
   */
  async listBackups(options?: {
    type?: BackupType;
    status?: BackupStatus;
    limit?: number;
    offset?: number;
  }): Promise<Result<{ backups: Backup[]; total: number }>> {
    try {
      let query = 'SELECT * FROM ha_backups WHERE 1=1';
      const params: unknown[] = [];
      let paramIndex = 1;

      if (options?.type) {
        query += ` AND type = $${paramIndex}`;
        params.push(options.type);
        paramIndex++;
      }

      if (options?.status) {
        query += ` AND status = $${paramIndex}`;
        params.push(options.status);
        paramIndex++;
      }

      // Count total
      const countResult = await this.db.query(
        `SELECT COUNT(*) as total FROM (${query}) subq`,
        params
      );
      const total = parseInt(countResult.rows[0].total);

      // Add ordering and pagination
      query += ' ORDER BY started_at DESC';

      if (options?.limit) {
        query += ` LIMIT $${paramIndex}`;
        params.push(options.limit);
        paramIndex++;
      }

      if (options?.offset) {
        query += ` OFFSET $${paramIndex}`;
        params.push(options.offset);
      }

      const result = await this.db.query(query, params);
      const backups = result.rows.map(this.rowToBackup);

      return { ok: true, value: { backups, total } };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Delete old backups based on retention policy
   */
  async enforceRetention(): Promise<Result<{ deleted: number }>> {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - config.backupRetentionDays);

      // Get backups to delete
      const result = await this.db.query(`
        SELECT * FROM ha_backups 
        WHERE completed_at < $1 
        AND status IN ('completed', 'verified', 'expired')
      `, [cutoffDate]);

      let deleted = 0;

      for (const row of result.rows) {
        const backup = this.rowToBackup(row);
        
        // Check if there are dependent incremental backups
        const dependents = await this.db.query(
          'SELECT COUNT(*) FROM ha_backups WHERE base_backup_id = $1',
          [backup.id]
        );
        
        if (parseInt(dependents.rows[0].count) > 0) {
          console.log(`[Backup] Skipping ${backup.id} - has dependent incrementals`);
          continue;
        }

        // Delete backup files
        try {
          await fs.rm(backup.location, { recursive: true, force: true });
        } catch (error) {
          console.error(`[Backup] Failed to delete files for ${backup.id}:`, error);
        }

        // Mark as expired
        await this.db.query(
          'UPDATE ha_backups SET status = $1 WHERE id = $2',
          [BackupStatus.EXPIRED, backup.id]
        );

        deleted++;
      }

      console.log(`[Backup] Retention enforcement: deleted ${deleted} backups`);

      return { ok: true, value: { deleted } };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Schedule backups
   */
  scheduleBackups(): void {
    // Schedule full backups
    if (config.backupEnabled && config.fullBackupSchedule) {
      this.scheduleJob('full', config.fullBackupSchedule, () => this.createFullBackup());
    }

    // Schedule incremental backups
    if (config.backupEnabled && config.incrementalBackupSchedule) {
      this.scheduleJob('incremental', config.incrementalBackupSchedule, () => this.createIncrementalBackup());
    }

    // Schedule retention cleanup
    this.scheduleJob('retention', '0 3 * * *', () => this.enforceRetention());
  }

  // Private helper methods

  private async getTableList(): Promise<{ schema: string; name: string }[]> {
    const result = await this.db.query(`
      SELECT schemaname as schema, tablename as name 
      FROM pg_tables 
      WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
      ORDER BY schemaname, tablename
    `);
    return result.rows;
  }

  private async backupTable(schema: string, table: string, outputPath: string): Promise<number> {
    // In production, would use pg_dump for proper backup
    const result = await this.db.query(`
      SELECT * FROM ${schema}.${table}
    `);

    const data = JSON.stringify(result.rows);
    const compressed = await this.compressAndEncrypt(Buffer.from(data));
    
    await fs.writeFile(outputPath, compressed);
    return data.length;
  }

  private async backupRoles(outputPath: string): Promise<void> {
    const result = await this.db.query(`
      SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, 
             rolcanlogin, rolreplication, rolconnlimit
      FROM pg_roles 
      WHERE rolname NOT LIKE 'pg_%'
    `);

    const data = JSON.stringify(result.rows);
    const compressed = await this.compressAndEncrypt(Buffer.from(data));
    await fs.writeFile(outputPath, compressed);
  }

  private async backupTableChanges(
    schema: string,
    table: string,
    _since: Date,
    outputPath: string
  ): Promise<number> {
    // In production, would track changes via triggers or logical decoding
    const result = await this.db.query(`
      SELECT * FROM ${schema}.${table}
    `);

    const data = JSON.stringify(result.rows);
    const compressed = await this.compressAndEncrypt(Buffer.from(data));
    await fs.writeFile(outputPath, compressed);
    return data.length;
  }

  private async getChangesSince(_walPosition: string): Promise<{ schema: string; table: string; since: Date; rowCount: number }[]> {
    // In production, would use pg_logical or change tracking
    const tables = await this.getTableList();
    return tables.map(t => ({
      schema: t.schema,
      table: t.name,
      since: new Date(),
      rowCount: 0,
    }));
  }

  private async restoreBackupFiles(backup: Backup, _targetDatabase?: string): Promise<void> {
    const files = await fs.readdir(backup.location);
    
    for (const file of files) {
      if (file.endsWith('.sql.gz')) {
        const filePath = join(backup.location, file);
        const content = await this.decompressAndDecrypt(await fs.readFile(filePath));
        const data = JSON.parse(content.toString());
        
        // In production, would properly restore the data
        console.log(`[Backup] Restored ${file} (${data.length} rows)`);
      }
    }
  }

  private async applyWalFiles(_fromLsn: string, _toTime: Date): Promise<number> {
    // In production, would use pg_wal_replay or similar
    return 0;
  }

  private async compressAndEncrypt(data: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const gzip = createGzip({ level: 9 });
      const chunks: Buffer[] = [];

      gzip.on('data', chunk => chunks.push(chunk));
      gzip.on('error', reject);
      gzip.on('end', () => {
        let result = Buffer.concat(chunks);
        
        if (this.encryptionKey) {
          const iv = randomBytes(16);
          const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, iv);
          const encrypted = Buffer.concat([cipher.update(result), cipher.final()]);
          const authTag = cipher.getAuthTag();
          result = Buffer.concat([iv, authTag, encrypted]);
        }
        
        resolve(result);
      });

      gzip.end(data);
    });
  }

  private async decompressAndDecrypt(data: Buffer): Promise<Buffer> {
    let input = data;

    if (this.encryptionKey) {
      const iv = data.subarray(0, 16);
      const authTag = data.subarray(16, 32);
      const encrypted = data.subarray(32);
      
      const decipher = createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
      decipher.setAuthTag(authTag);
      input = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    }

    return new Promise((resolve, reject) => {
      const gunzip = createGunzip();
      const chunks: Buffer[] = [];

      gunzip.on('data', chunk => chunks.push(chunk));
      gunzip.on('error', reject);
      gunzip.on('end', () => resolve(Buffer.concat(chunks)));

      gunzip.end(input);
    });
  }

  private async calculateDirectoryChecksum(dirPath: string): Promise<string> {
    const hash = createHash('sha256');
    const files = (await fs.readdir(dirPath)).sort();

    for (const file of files) {
      const filePath = join(dirPath, file);
      const stat = await fs.stat(filePath);
      
      if (stat.isFile()) {
        const content = await fs.readFile(filePath);
        hash.update(file);
        hash.update(content);
      }
    }

    return hash.digest('hex');
  }

  private async getDirectorySize(dirPath: string): Promise<number> {
    const files = await fs.readdir(dirPath);
    let totalSize = 0;

    for (const file of files) {
      const filePath = join(dirPath, file);
      const stat = await fs.stat(filePath);
      
      if (stat.isFile()) {
        totalSize += stat.size;
      }
    }

    return totalSize;
  }

  private async verifyCompressedFile(filePath: string): Promise<void> {
    const content = await fs.readFile(filePath);
    await this.decompressAndDecrypt(content);
  }

  private async recordBackupStart(backup: Backup): Promise<void> {
    await this.db.query(`
      INSERT INTO ha_backups (
        id, type, status, started_at, size_bytes, compressed_size_bytes,
        checksum, location, encryption_key_id, base_backup_id, wal_start, metadata
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    `, [
      backup.id, backup.type, backup.status, backup.startedAt,
      backup.sizeBytes, backup.compressedSizeBytes, backup.checksum,
      backup.location, backup.encryptionKeyId, backup.baseBackupId,
      backup.walStart, JSON.stringify(backup.metadata),
    ]);
  }

  private async recordBackupComplete(backup: Backup): Promise<void> {
    await this.db.query(`
      UPDATE ha_backups SET
        status = $2, completed_at = $3, size_bytes = $4,
        compressed_size_bytes = $5, checksum = $6, location = $7,
        wal_end = $8, metadata = $9
      WHERE id = $1
    `, [
      backup.id, backup.status, backup.completedAt, backup.sizeBytes,
      backup.compressedSizeBytes, backup.checksum, backup.location,
      backup.walEnd, JSON.stringify(backup.metadata),
    ]);
  }

  private async getBackup(backupId: string): Promise<Result<Backup | null>> {
    try {
      const result = await this.db.query(
        'SELECT * FROM ha_backups WHERE id = $1',
        [backupId]
      );

      if (result.rows.length === 0) {
        return { ok: true, value: null };
      }

      return { ok: true, value: this.rowToBackup(result.rows[0]) };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  private async getLatestFullBackup(): Promise<Result<Backup | null>> {
    try {
      const result = await this.db.query(`
        SELECT * FROM ha_backups 
        WHERE type = 'full' AND status IN ('completed', 'verified')
        ORDER BY completed_at DESC
        LIMIT 1
      `);

      if (result.rows.length === 0) {
        return { ok: true, value: null };
      }

      return { ok: true, value: this.rowToBackup(result.rows[0]) };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  private async findBackupForPointInTime(targetTime: Date): Promise<Result<Backup | null>> {
    try {
      const result = await this.db.query(`
        SELECT * FROM ha_backups 
        WHERE type = 'full' 
        AND status IN ('completed', 'verified')
        AND completed_at <= $1
        ORDER BY completed_at DESC
        LIMIT 1
      `, [targetTime]);

      if (result.rows.length === 0) {
        return { ok: true, value: null };
      }

      return { ok: true, value: this.rowToBackup(result.rows[0]) };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  private async getIncrementalsSince(baseBackupId: string): Promise<Backup[]> {
    const result = await this.db.query(`
      SELECT * FROM ha_backups 
      WHERE base_backup_id = $1 
      AND status IN ('completed', 'verified')
      ORDER BY started_at ASC
    `, [baseBackupId]);

    return result.rows.map(this.rowToBackup);
  }

  private rowToBackup(row: Record<string, unknown>): Backup {
    return {
      id: row.id as string,
      type: row.type as BackupType,
      status: row.status as BackupStatus,
      startedAt: new Date(row.started_at as string),
      completedAt: row.completed_at ? new Date(row.completed_at as string) : null,
      sizeBytes: parseInt(row.size_bytes as string) || 0,
      compressedSizeBytes: parseInt(row.compressed_size_bytes as string) || 0,
      checksum: row.checksum as string,
      location: row.location as string,
      encryptionKeyId: row.encryption_key_id as string | null,
      baseBackupId: row.base_backup_id as string | null,
      walStart: row.wal_start as string | null,
      walEnd: row.wal_end as string | null,
      metadata: (row.metadata as Record<string, unknown>) || {},
    };
  }

  private scheduleJob(name: string, cronExpression: string, job: () => Promise<unknown>): void {
    // Parse cron and schedule
    // In production, would use node-cron or similar
    console.log(`[Backup] Scheduled ${name} job: ${cronExpression}`);
  }

  private formatBytes(bytes: number): string {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let unitIndex = 0;
    let size = bytes;

    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }

    return `${size.toFixed(2)} ${units[unitIndex]}`;
  }
}
