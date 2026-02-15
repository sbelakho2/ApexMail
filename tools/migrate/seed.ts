/**
 * Database Seeder
 * Seeds the database with initial test/development data
 */

import { Pool } from 'pg';
import { randomBytes, createHash, scryptSync } from 'crypto';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/apexmail',
});

interface SeedOptions {
  tenants?: number;
  users?: number;
  domains?: number;
}

async function seed(options: SeedOptions = {}) {
  const {
    tenants = 1,
    users = 2,
    domains = 1,
  } = options;

  console.log('🌱 Seeding database...');
  console.log(`   Tenants: ${tenants}`);
  console.log(`   Users: ${users}`);
  console.log(`   Domains: ${domains}`);

  try {
    // Start transaction
    await pool.query('BEGIN');

    // Create test tenant
    const tenantId = generateId('ten');
    await pool.query(`
      INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
      VALUES ($1, 'Test Organization', 'test-org', 'growth', 'active', NOW(), NOW())
    `, [tenantId]);
    console.log(`✓ Created tenant: ${tenantId}`);

    // Create test user
    const userId = generateId('usr');
    await pool.query(`
      INSERT INTO users (id, tenant_id, email, password_hash, name, role, status, created_at, updated_at)
      VALUES ($1, $2, 'admin@test.com', $3, 'Admin User', 'admin', 'active', NOW(), NOW())
    `, [userId, tenantId, hashPassword('password123')]);
    console.log(`✓ Created user: admin@test.com`);

    // Create test API key
    const apiKeyId = generateId('key');
    const apiKeyHash = hashApiKey('am_test_' + randomBytes(32).toString('base64url'));
    await pool.query(`
      INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash, prefix, scopes, is_active, created_at, updated_at)
      VALUES ($1, $2, $3, 'Test API Key', $4, 'am_test_', $5, true, NOW(), NOW())
    `, [apiKeyId, tenantId, userId, apiKeyHash, JSON.stringify(['send:email', 'manage:domains'])]);
    console.log(`✓ Created API key`);

    // Create test domain
    const domainId = generateId('dom');
    await pool.query(`
      INSERT INTO domains (id, tenant_id, domain, status, is_verified, created_at, updated_at)
      VALUES ($1, $2, 'test.example.com', 'verified', true, NOW(), NOW())
    `, [domainId, tenantId]);
    console.log(`✓ Created domain: test.example.com`);

    // Commit transaction
    await pool.query('COMMIT');
    console.log('✅ Seeding complete!');
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('❌ Seeding failed:', error);
    throw error;
  } finally {
    await pool.end();
  }
}

function generateId(prefix: string): string {
  return `${prefix}_${randomBytes(13).toString('base64url')}`;
}

function hashPassword(password: string): string {
  const salt = randomBytes(16).toString('hex');
  const derived = scryptSync(password, salt, 64).toString('hex');
  return `scrypt:${salt}:${derived}`;
}

function hashApiKey(key: string): string {
  return createHash('sha256').update(key).digest('hex');
}

// Run if executed directly
if (import.meta.url === new URL(process.argv[1], 'file:').href) {
  seed().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}

export { seed };
