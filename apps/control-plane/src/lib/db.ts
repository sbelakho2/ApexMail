/**
 * Shared database connection pool for Control Plane API routes.
 * 
 * Centralizes the DB pool configuration so all API routes
 * use a single connection pool instead of creating their own.
 */

type Pool = import('pg').Pool;

let pool: Pool | null = null;

export async function getPool(): Promise<Pool> {
    if (!pool) {
        const { Pool: PgPool } = await import('pg');
        pool = new PgPool({
            host: process.env.DB_HOST || 'localhost',
            port: parseInt(process.env.DB_PORT || '5432', 10),
            database: process.env.DB_NAME || 'apexmail',
            user: process.env.DB_USER || 'postgres',
            password: process.env.DB_PASSWORD || '',
            max: 5,
            idleTimeoutMillis: 30000,
            connectionTimeoutMillis: 5000,
        });
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
    sql: string,
    params?: unknown[]
): Promise<T[]> {
    const dbPool = await getPool();
    const result = await dbPool.query(sql, params);
    return result.rows as T[];
}
