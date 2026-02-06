/**
 * Sales Autopilot Database Pool
 */

import { Pool } from 'pg';
import { config } from './config.js';

let pool: Pool | null = null;

export function getDbPool(): Pool {
    if (!pool) {
        pool = new Pool({
            host: config.database.host,
            port: config.database.port,
            database: config.database.name,
            user: config.database.user,
            password: config.database.password,
            max: config.database.maxConnections,
        });
    }

    return pool;
}

export async function closeDbPool(): Promise<void> {
    if (pool) {
        await pool.end();
        pool = null;
    }
}
