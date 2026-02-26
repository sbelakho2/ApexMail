/**
 * Shared database connection pool for Control Plane API routes.
 * 
 * Centralizes the DB pool configuration so all API routes
 * use a single connection pool instead of creating their own.
 */

import '@/lib/console-guard';

type Pool = import('pg').Pool;

let pool: Pool | null = null;
let migrationCheckStarted = false;

export interface SqlFragment {
    text: string;
    values: unknown[];
}

export function sql(strings: TemplateStringsArray, ...values: unknown[]): SqlFragment {
    let text = '';
    for (let i = 0; i < strings.length; i += 1) {
        text += strings[i] ?? '';
        if (i < values.length) {
            text += `$${i + 1}`;
        }
    }

    return { text, values };
}

async function verifyMigrationSystem(dbPool: Pool): Promise<void> {
    if (migrationCheckStarted) {
        return;
    }
    migrationCheckStarted = true;

    try {
        const result = await dbPool.query<{ has_migration_tracking: boolean }>(
            `SELECT EXISTS (
               SELECT 1
               FROM information_schema.tables
               WHERE table_schema = 'public'
                 AND table_name IN ('_prisma_migrations', 'schema_migrations')
             ) AS has_migration_tracking`
        );

        if (!result.rows[0]?.has_migration_tracking) {
            console.warn('[CONTROL_PLANE] No migration tracking table detected (_prisma_migrations/schema_migrations)');
        }
    } catch (error) {
        console.warn('[CONTROL_PLANE] Failed to verify migration tracking table', {
            error: error instanceof Error ? error.message : String(error),
        });
    }
}

export async function getPool(): Promise<Pool> {
    if (!pool) {
        const { Pool: PgPool } = await import('pg');
        pool = new PgPool({
            host: process.env.DB_HOST || 'localhost',
            port: parseInt(process.env.DB_PORT || '5432', 10),
            database: process.env.DB_NAME || 'apexmail',
            user: process.env.DB_USER || 'postgres',
            password: process.env.DB_PASSWORD,
            max: parseInt(process.env.CONTROL_PLANE_DB_POOL_MAX || '20', 10),
            idleTimeoutMillis: 30000,
            connectionTimeoutMillis: 5000,
        });

        await verifyMigrationSystem(pool);
    }
    return pool;
}

/**
 * FIX-500-243: Close the DB connection pool for graceful shutdown.
 */
export async function closePool(): Promise<void> {
    if (pool) {
        await pool.end();
        pool = null;
    }
}

/**
 * Helper to run a query with automatic client release.
 * Returns the rows from the query result.
 */
export async function query<T = Record<string, unknown>>(
    statement: string | SqlFragment,
    params?: unknown[]
): Promise<T[]> {
    const dbPool = await getPool();
    const text = typeof statement === 'string' ? statement : statement.text;
    const values = typeof statement === 'string' ? params : statement.values;
    const result = await dbPool.query(text, values);
    return result.rows as T[];
}
