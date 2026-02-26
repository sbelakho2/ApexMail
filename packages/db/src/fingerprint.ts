/**
 * Schema Fingerprinting
 * 
 * Calculates a deterministic hash of the database schema for:
 * - Startup validation (reject if schema doesn't match expected)
 * - Migration verification
 * - Drift detection
 */

import { sha256 } from '@apexmail/lib/crypto';
import { Result } from '@apexmail/lib';
import type { DatabasePool } from './pool.js';

export interface SchemaObject {
  type: 'table' | 'index' | 'constraint' | 'function' | 'trigger';
  schema: string;
  name: string;
  definition: string;
}

export interface SchemaFingerprint {
  hash: string;
  version: string;
  tables: number;
  indexes: number;
  constraints: number;
  functions: number;
  triggers: number;
  generatedAt: string;
}

export interface SchemaDiff {
  added: SchemaObject[];
  removed: SchemaObject[];
  modified: SchemaObject[];
}

/**
 * Extract all schema objects from the database
 */
async function extractSchemaObjects(db: DatabasePool): Promise<Result<SchemaObject[], Error>> {
  const objects: SchemaObject[] = [];
  const pool = db.getPool();

  try {
    // Get all tables with column definitions
    const tablesResult = await pool.query<{
      table_schema: string;
      table_name: string;
      column_definitions: string;
    }>(`
      SELECT 
        n.nspname as table_schema,
        c.relname as table_name,
        string_agg(
          a.attname || ' ' || pg_catalog.format_type(a.atttypid, a.atttypmod) ||
          CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE '' END ||
          COALESCE(' DEFAULT ' || pg_get_expr(ad.adbin, ad.adrelid), ''),
          ', ' ORDER BY a.attnum
        ) as column_definitions
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_attribute a ON a.attrelid = c.oid
        AND a.attnum > 0
        AND NOT a.attisdropped
      LEFT JOIN pg_attrdef ad ON ad.adrelid = c.oid AND ad.adnum = a.attnum
      WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
        AND c.relkind IN ('r', 'p')
      GROUP BY n.nspname, c.relname
      ORDER BY n.nspname, c.relname
    `);

    for (const row of tablesResult.rows) {
      objects.push({
        type: 'table',
        schema: row.table_schema,
        name: row.table_name,
        definition: row.column_definitions,
      });
    }

    // Get all indexes
    const indexesResult = await pool.query<{
      schemaname: string;
      indexname: string;
      indexdef: string;
    }>(`
      SELECT schemaname, indexname, indexdef
      FROM pg_indexes
      WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
      ORDER BY schemaname, indexname
    `);

    for (const row of indexesResult.rows) {
      objects.push({
        type: 'index',
        schema: row.schemaname,
        name: row.indexname,
        definition: row.indexdef,
      });
    }

    // Get all constraints
    const constraintsResult = await pool.query<{
      nspname: string;
      conname: string;
      consrc: string;
    }>(`
      SELECT 
        n.nspname,
        c.conname,
        pg_get_constraintdef(c.oid) as consrc
      FROM pg_constraint c
      JOIN pg_namespace n ON n.oid = c.connamespace
      WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      ORDER BY n.nspname, c.conname
    `);

    for (const row of constraintsResult.rows) {
      objects.push({
        type: 'constraint',
        schema: row.nspname,
        name: row.conname,
        definition: row.consrc,
      });
    }

    // Get all functions
    const functionsResult = await pool.query<{
      nspname: string;
      proname: string;
      prosrc: string;
    }>(`
      SELECT 
        n.nspname,
        p.proname,
        md5(pg_get_functiondef(p.oid)) as prosrc
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
        AND p.prokind = 'f'
      ORDER BY n.nspname, p.proname
    `);

    for (const row of functionsResult.rows) {
      objects.push({
        type: 'function',
        schema: row.nspname,
        name: row.proname,
        definition: row.prosrc,
      });
    }

    // Get all triggers
    const triggersResult = await pool.query<{
      trigger_schema: string;
      trigger_name: string;
      action_statement: string;
    }>(`
      SELECT 
        trigger_schema,
        trigger_name,
        action_statement
      FROM information_schema.triggers
      WHERE trigger_schema NOT IN ('pg_catalog', 'information_schema')
      ORDER BY trigger_schema, trigger_name
    `);

    for (const row of triggersResult.rows) {
      objects.push({
        type: 'trigger',
        schema: row.trigger_schema,
        name: row.trigger_name,
        definition: row.action_statement,
      });
    }

    return Result.ok(objects);
  } catch (error) {
    return Result.err(error instanceof Error ? error : new Error(String(error)));
  }
}

/**
 * Calculate a fingerprint of the current database schema
 */
export async function calculateSchemaFingerprint(
  db: DatabasePool
): Promise<Result<SchemaFingerprint, Error>> {
  const objectsResult = await extractSchemaObjects(db);
  
  if (!objectsResult.ok) {
    return objectsResult;
  }

  const objects: SchemaObject[] = objectsResult.value;
  
  // Create deterministic string representation
  const schemaString = objects
    .map((obj) => `${obj.type}:${obj.schema}.${obj.name}:${obj.definition}`)
    .join('\n');

  const hash = sha256(schemaString);

  // Get migration version
  let version = '0';
  try {
    const pool = db.getPool();
    const versionResult = await pool.query<{ version: string }>(`
      SELECT version FROM schema_migrations 
      ORDER BY applied_at DESC 
      LIMIT 1
    `);
    if (versionResult.rows[0]) {
      version = versionResult.rows[0].version;
    }
  } catch {
    // Table might not exist yet
  }

  const counts = objects.reduce<Record<string, number>>(
    (acc, obj) => {
      acc[obj.type]++;
      return acc;
    },
    { table: 0, index: 0, constraint: 0, function: 0, trigger: 0 }
  );

  return Result.ok({
    hash,
    version,
    tables: counts['table'] ?? 0,
    indexes: counts['index'] ?? 0,
    constraints: counts['constraint'] ?? 0,
    functions: counts['function'] ?? 0,
    triggers: counts['trigger'] ?? 0,
    generatedAt: new Date().toISOString(),
  });
}

/**
 * Validate schema fingerprint matches expected
 */
export async function validateSchemaFingerprint(
  db: DatabasePool,
  expectedHash: string
): Promise<Result<boolean, Error>> {
  const fingerprint = await calculateSchemaFingerprint(db);
  
  if (!fingerprint.ok) {
    return fingerprint;
  }

  return Result.ok(fingerprint.value.hash === expectedHash);
}

/**
 * Compare two schema states and return differences
 */
export async function compareSchemas(
  db: DatabasePool,
  previousObjects: SchemaObject[]
): Promise<Result<SchemaDiff, Error>> {
  const currentResult = await extractSchemaObjects(db);
  
  if (!currentResult.ok) {
    return currentResult;
  }

  const current: SchemaObject[] = currentResult.value;
  const currentMap = new Map<string, SchemaObject>(
    current.map((obj) => [`${obj.type}:${obj.schema}.${obj.name}`, obj] as [string, SchemaObject])
  );
  const previousMap = new Map<string, SchemaObject>(
    previousObjects.map((obj) => [`${obj.type}:${obj.schema}.${obj.name}`, obj] as [string, SchemaObject])
  );

  const added: SchemaObject[] = [];
  const removed: SchemaObject[] = [];
  const modified: SchemaObject[] = [];

  // Find added and modified
  for (const [key, obj] of currentMap) {
    const prev = previousMap.get(key);
    if (!prev) {
      added.push(obj);
    } else if (prev.definition !== obj.definition) {
      modified.push(obj);
    }
  }

  // Find removed
  for (const [key, obj] of previousMap) {
    if (!currentMap.has(key)) {
      removed.push(obj);
    }
  }

  return Result.ok({ added, removed, modified });
}

/**
 * Check for required schema objects (critical path validation)
 */
export async function validateRequiredSchema(
  db: DatabasePool,
  requirements: { tables: string[]; indexes: string[] }
): Promise<Result<{ valid: boolean; missing: string[] }, Error>> {
  const objectsResult = await extractSchemaObjects(db);
  
  if (!objectsResult.ok) {
    return objectsResult;
  }

  const objects: SchemaObject[] = objectsResult.value;
  const tableNames = new Set(
    objects.filter((o) => o.type === 'table').map((o) => `${o.schema}.${o.name}`)
  );
  const indexNames = new Set(
    objects.filter((o) => o.type === 'index').map((o) => `${o.schema}.${o.name}`)
  );

  const missing: string[] = [];

  for (const table of requirements.tables) {
    // Check with and without schema prefix
    if (!tableNames.has(table) && !tableNames.has(`public.${table}`)) {
      missing.push(`table:${table}`);
    }
  }

  for (const index of requirements.indexes) {
    if (!indexNames.has(index) && !indexNames.has(`public.${index}`)) {
      missing.push(`index:${index}`);
    }
  }

  return Result.ok({
    valid: missing.length === 0,
    missing,
  });
}
