#!/usr/bin/env node
/**
 * ApexMail Custom Migration Engine
 * 
 * Features:
 * - Advisory Locks (PostgreSQL pg_advisory_lock)
 * - Checksums (SHA256 of migration files)
 * - Dry-Run mode
 * - Audit Table tracking
 * 
 * Evidence Required: Log output showing a successful migration apply with locking and audit record creation.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { Pool } from 'pg';

interface MigrationFile {
    version: string;
    name: string;
    filename: string;
    path: string;
    checksum: string;
    sql: string;
}

interface MigrationRecord {
    version: string;
    name: string;
    checksum: string;
    applied_at: Date;
    applied_by: string;
    execution_time_ms: number;
}

// Advisory lock ID for migrations
const MIGRATION_LOCK_ID = 12345;

class MigrationEngine {
    private pool: Pool;
    private migrationsDir: string;
    private dryRun: boolean;
    private verbose: boolean;

    constructor(options: {
        connectionString?: string;
        migrationsDir?: string;
        dryRun?: boolean;
        verbose?: boolean;
    } = {}) {
        const connectionString = options.connectionString || 
            process.env.DATABASE_URL ||
            'postgresql://localhost:5432/apexmail';
        
        this.pool = new Pool({ connectionString });
        this.migrationsDir = options.migrationsDir || 
            path.join(process.cwd(), 'tools', 'migrations');
        this.dryRun = options.dryRun ?? false;
        this.verbose = options.verbose ?? true;
    }

    private log(message: string): void {
        if (this.verbose) {
            console.log(`[migrate] ${new Date().toISOString()} - ${message}`);
        }
    }

    private calculateChecksum(content: string): string {
        return crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
    }

    private async acquireLock(): Promise<boolean> {
        this.log('Acquiring advisory lock...');
        const result = await this.pool.query(
            'SELECT pg_try_advisory_lock($1) as acquired',
            [MIGRATION_LOCK_ID]
        );
        const acquired = result.rows[0]?.acquired ?? false;
        if (acquired) {
            this.log('Advisory lock acquired');
        } else {
            this.log('Failed to acquire lock - another migration is running');
        }
        return acquired;
    }

    private async releaseLock(): Promise<void> {
        await this.pool.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_ID]);
        this.log('Advisory lock released');
    }

    private async ensureAuditTable(): Promise<void> {
        await this.pool.query(`
            CREATE TABLE IF NOT EXISTS _migrations (
                version VARCHAR(14) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                checksum VARCHAR(16) NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                applied_by VARCHAR(255) NOT NULL DEFAULT current_user,
                execution_time_ms INTEGER NOT NULL
            );
            
            CREATE INDEX IF NOT EXISTS idx_migrations_applied_at 
            ON _migrations(applied_at);
        `);
        this.log('Migration audit table ready');
    }

    private async getAppliedMigrations(): Promise<Map<string, MigrationRecord>> {
        const result = await this.pool.query<MigrationRecord>(
            'SELECT * FROM _migrations ORDER BY version'
        );
        return new Map(result.rows.map(row => [row.version, row]));
    }

    private loadMigrationFiles(): MigrationFile[] {
        if (!fs.existsSync(this.migrationsDir)) {
            this.log(`Migrations directory not found: ${this.migrationsDir}`);
            return [];
        }

        const files = fs.readdirSync(this.migrationsDir)
            .filter(f => f.endsWith('.sql'))
            .sort();

        return files.map(filename => {
            const match = filename.match(/^(\d{3,14})_(.+)\.sql$/);
            if (!match) {
                throw new Error(`Invalid migration filename: ${filename}`);
            }

            const filePath = path.join(this.migrationsDir, filename);
            const sql = fs.readFileSync(filePath, 'utf-8');

            return {
                version: match[1],
                name: match[2],
                filename,
                path: filePath,
                checksum: this.calculateChecksum(sql),
                sql,
            };
        });
    }

    async migrate(): Promise<{ applied: number; skipped: number }> {
        const client = await this.pool.connect();
        let applied = 0;
        let skipped = 0;

        try {
            // Acquire lock
            if (!this.dryRun) {
                const locked = await this.acquireLock();
                if (!locked) {
                    throw new Error('Could not acquire migration lock');
                }
            }

            await this.ensureAuditTable();

            const appliedMigrations = await this.getAppliedMigrations();
            const migrationFiles = this.loadMigrationFiles();

            this.log(`Found ${migrationFiles.length} migration files`);
            this.log(`${appliedMigrations.size} migrations already applied`);

            for (const migration of migrationFiles) {
                const existing = appliedMigrations.get(migration.version);

                if (existing) {
                    // Verify checksum
                    if (existing.checksum !== migration.checksum) {
                        throw new Error(
                            `Checksum mismatch for migration ${migration.version}: ` +
                            `expected ${existing.checksum}, got ${migration.checksum}`
                        );
                    }
                    skipped++;
                    continue;
                }

                this.log(`Applying migration ${migration.version}_${migration.name}...`);

                if (this.dryRun) {
                    this.log(`[DRY RUN] Would apply: ${migration.filename}`);
                    this.log(`[DRY RUN] SQL preview:\n${migration.sql.slice(0, 200)}...`);
                    applied++;
                    continue;
                }

                const startTime = Date.now();

                await client.query('BEGIN');
                try {
                    await client.query(migration.sql);

                    await client.query(
                        `INSERT INTO _migrations (version, name, checksum, execution_time_ms)
                         VALUES ($1, $2, $3, $4)`,
                        [
                            migration.version,
                            migration.name,
                            migration.checksum,
                            Date.now() - startTime,
                        ]
                    );

                    await client.query('COMMIT');
                    this.log(`✓ Applied ${migration.version} (${Date.now() - startTime}ms)`);
                    applied++;
                } catch (error) {
                    await client.query('ROLLBACK');
                    throw error;
                }
            }

            this.log(`Migration complete: ${applied} applied, ${skipped} skipped`);
            return { applied, skipped };

        } finally {
            if (!this.dryRun) {
                await this.releaseLock();
            }
            client.release();
        }
    }

    async status(): Promise<void> {
        await this.ensureAuditTable();
        
        const appliedMigrations = await this.getAppliedMigrations();
        const migrationFiles = this.loadMigrationFiles();

        console.log('\nMigration Status:');
        console.log('=================\n');

        for (const file of migrationFiles) {
            const applied = appliedMigrations.get(file.version);
            const status = applied ? '✓' : '○';
            const checksumMatch = applied && applied.checksum === file.checksum;
            const checksumStatus = applied 
                ? (checksumMatch ? '' : ' [CHECKSUM MISMATCH!]')
                : '';
            
            console.log(`${status} ${file.version}_${file.name}${checksumStatus}`);
        }

        console.log(`\nTotal: ${migrationFiles.length} migrations, ${appliedMigrations.size} applied`);
    }

    async close(): Promise<void> {
        await this.pool.end();
    }
}

// CLI
async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const command = args[0] || 'migrate';
    const dryRun = args.includes('--dry-run');
    const verbose = !args.includes('--quiet');

    const engine = new MigrationEngine({ dryRun, verbose });

    try {
        switch (command) {
            case 'migrate':
            case 'up':
                await engine.migrate();
                break;
            case 'status':
                await engine.status();
                break;
            default:
                console.log('Usage: migrate [migrate|status] [--dry-run] [--quiet]');
        }
    } finally {
        await engine.close();
    }
}

// Export for programmatic use
export { MigrationEngine };

// Run CLI if executed directly
if (require.main === module) {
    main().catch(error => {
        console.error('Migration failed:', error.message);
        process.exit(1);
    });
}
