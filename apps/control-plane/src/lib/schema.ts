import { query } from '@/lib/db';

const DEFAULT_SCHEMA_CACHE_TTL_MS = 5 * 60 * 1000;
const schemaExistsCache = new Map<string, { value: boolean; expiresAt: number }>();

async function getCachedSchemaFlag(cacheKey: string, loader: () => Promise<boolean>, ttlMs = DEFAULT_SCHEMA_CACHE_TTL_MS): Promise<boolean> {
    const now = Date.now();
    const cached = schemaExistsCache.get(cacheKey);
    if (cached && cached.expiresAt > now) {
        return cached.value;
    }

    const value = await loader();
    schemaExistsCache.set(cacheKey, {
        value,
        expiresAt: now + ttlMs,
    });
    return value;
}

export async function tableExists(tableName: string): Promise<boolean> {
    return getCachedSchemaFlag(`table:${tableName}`, async () => {
        const rows = await query<{ exists: boolean }>(
            `SELECT to_regclass($1) IS NOT NULL as exists`,
            [`public.${tableName}`]
        );
        return rows[0]?.exists ?? false;
    });
}

export async function columnExists(tableName: string, columnName: string): Promise<boolean> {
    return getCachedSchemaFlag(`column:${tableName}:${columnName}`, async () => {
        const rows = await query<{ exists: boolean }>(
            `SELECT EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = $1
                  AND column_name = $2
            ) as exists`,
            [tableName, columnName]
        );
        return rows[0]?.exists ?? false;
    });
}
