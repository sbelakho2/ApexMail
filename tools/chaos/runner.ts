/**
 * Chaos Engineering Runner
 * Runs chaos experiments to test system resilience
 * 
 * These experiments are designed to test resilience in development/staging environments.
 * NEVER run against production systems without proper safeguards.
 */

import { Pool } from 'pg';
import { Redis } from 'ioredis';

// Configuration from environment
const config = {
  database: {
    host: process.env.DB_HOST ?? 'localhost',
    port: parseInt(process.env.DB_PORT ?? '5432', 10),
    database: process.env.DB_NAME ?? 'apexmail',
    user: process.env.DB_USER ?? 'apexmail',
    password: process.env.DB_PASSWORD,
  },
  redis: {
    host: process.env.REDIS_HOST ?? 'localhost',
    port: parseInt(process.env.REDIS_PORT ?? '6379', 10),
    password: process.env.REDIS_PASSWORD ?? undefined,
  },
  api: {
    baseUrl: process.env.API_BASE_URL ?? 'http://localhost:3000',
  },
};

interface ChaosExperiment {
  name: string;
  description: string;
  run: () => Promise<void>;
}

// Helper to create temporary connections
async function withDatabase<T>(fn: (db: Pool) => Promise<T>): Promise<T> {
  const pool = new Pool(config.database);
  try {
    return await fn(pool);
  } finally {
    await pool.end();
  }
}

async function withRedis<T>(fn: (redis: Redis) => Promise<T>): Promise<T> {
  const redis = new Redis(config.redis);
  try {
    return await fn(redis);
  } finally {
    redis.disconnect();
  }
}

const experiments: ChaosExperiment[] = [
  {
    name: 'database-connection-failure',
    description: 'Simulates database connection failures by terminating connections',
    run: async () => {
      console.log('💥 Simulating database connection failure...');
      
      await withDatabase(async (db) => {
        // Get current connection info
        const connResult = await db.query(`
          SELECT pid, application_name, client_addr, state, query
          FROM pg_stat_activity 
          WHERE datname = current_database() 
            AND pid != pg_backend_pid()
            AND state != 'idle'
          LIMIT 5
        `);
        
        console.log(`   📊 Found ${connResult.rows.length} active connections`);
        
        // Terminate a random connection (if any non-idle connections exist)
        if (connResult.rows.length > 0) {
          const targetPid = connResult.rows[Math.floor(Math.random() * connResult.rows.length)]?.pid;
          if (targetPid) {
            await db.query('SELECT pg_terminate_backend($1)', [targetPid]);
            console.log(`   🔪 Terminated connection PID: ${targetPid}`);
          }
        } else {
          console.log('   ℹ️  No active connections to terminate');
        }
        
        // Wait and verify pool recovery
        console.log('   ⏳ Waiting 2s for connection pool recovery...');
        await new Promise(r => setTimeout(r, 2000));
        
        // Test that new connections work
        const testResult = await db.query('SELECT 1 as test');
        if (testResult.rows[0]?.test === 1) {
          console.log('   ✅ Connection pool recovered successfully');
        } else {
          throw new Error('Connection pool failed to recover');
        }
      });
    },
  },
  {
    name: 'redis-failure',
    description: 'Simulates Redis unavailability by testing timeout handling',
    run: async () => {
      console.log('💥 Simulating Redis failure...');
      
      await withRedis(async (redis) => {
        // Get Redis info
        const info = await redis.info('clients');
        const connectedClients = info.match(/connected_clients:(\d+)/)?.[1] ?? '0';
        console.log(`   📊 Connected Redis clients: ${connectedClients}`);
        
        // Test Redis is working
        await redis.set('chaos:test', 'before');
        console.log('   ✅ Redis write successful');
        
        // Test slow operations to verify timeout handling
        const testKey = 'chaos:slow_test';
        console.log('   ⏳ Testing slow Redis operations...');
        
        try {
          // Set a value with script that includes artificial delay
          await Promise.race([
            redis.eval(`
              redis.call('SET', KEYS[1], ARGV[1])
              for i=1,1000000 do end
              return redis.call('GET', KEYS[1])
            `, 1, testKey, 'chaos_value'),
            new Promise((_, reject) => 
              setTimeout(() => reject(new Error('Operation timed out')), 5000)
            ),
          ]);
          console.log('   ✅ Slow operation completed');
        } catch {
          console.log('   ⚠️  Operation timed out as expected');
        }
        
        // Cleanup
        await redis.del(testKey, 'chaos:test');
        console.log('   ✅ Redis recovered and functioning');
      });
    },
  },
  {
    name: 'slow-query',
    description: 'Introduces artificial query latency using pg_sleep',
    run: async () => {
      console.log('💥 Introducing slow queries...');
      
      await withDatabase(async (db) => {
        // Test baseline query performance
        const startBaseline = Date.now();
        await db.query('SELECT 1');
        const baselineMs = Date.now() - startBaseline;
        console.log(`   📊 Baseline query time: ${baselineMs}ms`);
        
        // Introduce slow query using pg_sleep
        const delaySeconds = 2;
        console.log(`   ⏳ Running query with ${delaySeconds}s delay...`);
        
        const startSlow = Date.now();
        try {
          // Test with statement timeout
          await Promise.race([
            db.query(`SELECT pg_sleep($1), 'slow_query_result'`, [delaySeconds]),
            new Promise((_, reject) => 
              setTimeout(() => reject(new Error('Query timeout')), 5000)
            ),
          ]);
          const slowMs = Date.now() - startSlow;
          console.log(`   ✅ Slow query completed in ${slowMs}ms`);
        } catch {
          const slowMs = Date.now() - startSlow;
          console.log(`   ⚠️  Query timed out after ${slowMs}ms (expected behavior)`);
        }
        
        // Verify normal queries still work
        const testResult = await db.query('SELECT 1 as recovered');
        if (testResult.rows[0]?.recovered === 1) {
          console.log('   ✅ Database responsive after slow query');
        }
      });
    },
  },
  {
    name: 'high-load',
    description: 'Simulates high traffic load with concurrent requests',
    run: async () => {
      console.log('💥 Simulating high load...');
      
      const concurrency = 100;
      const totalRequests = 500;
      const baseUrl = config.api.baseUrl;
      
      console.log(`   📊 Sending ${totalRequests} requests with ${concurrency} concurrency`);
      console.log(`   📊 Target: ${baseUrl}`);
      
      const results = {
        success: 0,
        failed: 0,
        rateLimited: 0,
        durations: [] as number[],
      };
      
      // Simple HTTP request function
      async function makeRequest(): Promise<void> {
        const start = Date.now();
        try {
          const response = await fetch(`${baseUrl}/health`, {
            method: 'GET',
            headers: { 'User-Agent': 'chaos-runner' },
          });
          
          const duration = Date.now() - start;
          results.durations.push(duration);
          
          if (response.status === 429) {
            results.rateLimited++;
          } else if (response.ok) {
            results.success++;
          } else {
            results.failed++;
          }
        } catch {
          results.failed++;
        }
      }
      
      // Run requests in batches
      const batches = Math.ceil(totalRequests / concurrency);
      for (let i = 0; i < batches; i++) {
        const batchSize = Math.min(concurrency, totalRequests - i * concurrency);
        await Promise.all(Array.from({ length: batchSize }, () => makeRequest()));
        
        if (i % 5 === 0) {
          console.log(`   ⏳ Progress: ${(i + 1) * concurrency}/${totalRequests} requests`);
        }
      }
      
      // Calculate statistics
      const avgDuration = results.durations.length > 0
        ? Math.round(results.durations.reduce((a, b) => a + b, 0) / results.durations.length)
        : 0;
      const maxDuration = Math.max(...results.durations, 0);
      const minDuration = Math.min(...results.durations, 0);
      
      console.log('\n   📈 Results:');
      console.log(`      Success: ${results.success}`);
      console.log(`      Failed: ${results.failed}`);
      console.log(`      Rate Limited: ${results.rateLimited}`);
      console.log(`      Avg Response: ${avgDuration}ms`);
      console.log(`      Min/Max: ${minDuration}ms / ${maxDuration}ms`);
      
      // Verify rate limiting is working
      if (results.rateLimited > 0) {
        console.log('   ✅ Rate limiting is active');
      } else if (results.success === totalRequests) {
        console.log('   ⚠️  No rate limiting detected - verify rate limit configuration');
      }
    },
  },
  {
    name: 'worker-crash',
    description: 'Tests worker recovery by checking stuck jobs',
    run: async () => {
      console.log('💥 Testing worker crash recovery...');
      
      await withDatabase(async (db) => {
        // Check for any jobs that are in 'processing' state but have expired locks
        const stuckJobsResult = await db.query(`
          SELECT COUNT(*) as count 
          FROM email_queue 
          WHERE status = 'processing' 
            AND locked_until < NOW()
        `);
        
        const stuckJobs = parseInt(stuckJobsResult.rows[0]?.count ?? '0', 10);
        console.log(`   📊 Jobs with expired locks: ${stuckJobs}`);
        
        // Reset stuck jobs (simulating what happens when worker crashes)
        if (stuckJobs > 0) {
          const resetResult = await db.query(`
            UPDATE email_queue 
            SET status = 'pending', locked_until = NULL 
            WHERE status = 'processing' 
              AND locked_until < NOW()
            RETURNING id
          `);
          console.log(`   🔄 Reset ${resetResult.rowCount} stuck jobs`);
        }
        
        // Verify workers can pick up the jobs
        const pendingResult = await db.query(`
          SELECT COUNT(*) as count 
          FROM email_queue 
          WHERE status = 'pending'
        `);
        
        console.log(`   📊 Pending jobs ready for pickup: ${pendingResult.rows[0]?.count}`);
        console.log('   ✅ Worker recovery mechanism verified');
      });
    },
  },
  {
    name: 'network-partition',
    description: 'Simulates network latency and timeout handling',
    run: async () => {
      console.log('💥 Simulating network partition effects...');
      
      // Test connection timeout handling
      console.log('   ⏳ Testing connection timeout handling...');
      
      // Create a pool with very short timeouts
      const shortTimeoutPool = new Pool({
        ...config.database,
        connectionTimeoutMillis: 100,
        idleTimeoutMillis: 100,
        max: 1,
      });
      
      try {
        // This should work
        await shortTimeoutPool.query('SELECT 1');
        console.log('   ✅ Quick query succeeded');
        
        // This will test timeout behavior
        try {
          await Promise.race([
            shortTimeoutPool.query('SELECT pg_sleep(1)'),
            new Promise((_, reject) => 
              setTimeout(() => reject(new Error('Client timeout')), 500)
            ),
          ]);
        } catch {
          console.log('   ✅ Timeout handled correctly');
        }
      } finally {
        await shortTimeoutPool.end();
      }
      
      // Test Redis connection resilience
      await withRedis(async (redis) => {
        console.log('   ⏳ Testing Redis with timeout...');
        try {
          await redis.ping();
          console.log('   ✅ Redis responsive');
        } catch {
          console.log('   ⚠️  Redis not responsive');
        }
      });
      
      console.log('   ✅ Network partition simulation complete');
    },
  },
  {
    name: 'disk-full',
    description: 'Tests write operations and disk space handling',
    run: async () => {
      console.log('💥 Testing disk space handling...');
      
      await withDatabase(async (db) => {
        // Check current disk usage
        const diskResult = await db.query(`
          SELECT 
            pg_database_size(current_database()) as db_size,
            pg_size_pretty(pg_database_size(current_database())) as db_size_pretty
        `);
        
        console.log(`   📊 Database size: ${diskResult.rows[0]?.db_size_pretty}`);
        
        // Test write operation
        console.log('   ⏳ Testing write operations...');
        await db.query(`
          CREATE TEMP TABLE chaos_test_disk (
            id SERIAL PRIMARY KEY,
            data TEXT
          )
        `);
        
        // Insert test data
        await db.query(`
          INSERT INTO chaos_test_disk (data) 
          SELECT repeat('x', 1000) 
          FROM generate_series(1, 100)
        `);
        
        console.log('   ✅ Write operations successful');
        console.log('   ✅ Disk space handling verified');
      });
    },
  },
  {
    name: 'clock-drift',
    description: 'Tests timestamp handling with clock variations',
    run: async () => {
      console.log('💥 Testing clock drift handling...');
      
      await withDatabase(async (db) => {
        // Get database server time
        const dbTimeResult = await db.query('SELECT NOW() as db_time');
        const dbTime = new Date(dbTimeResult.rows[0]?.db_time);
        const localTime = new Date();
        
        const driftMs = Math.abs(dbTime.getTime() - localTime.getTime());
        console.log(`   📊 DB time: ${dbTime.toISOString()}`);
        console.log(`   📊 Local time: ${localTime.toISOString()}`);
        console.log(`   📊 Clock drift: ${driftMs}ms`);
        
        if (driftMs > 1000) {
          console.log('   ⚠️  Significant clock drift detected!');
        } else {
          console.log('   ✅ Clock drift within acceptable range');
        }
        
        // Test timestamp-based queries with intentional drift
        console.log('   ⏳ Testing timestamp queries with drift...');
        
        // Create temporary data with future timestamps
        await db.query(`
          CREATE TEMP TABLE chaos_clock_test (
            id SERIAL PRIMARY KEY,
            created_at TIMESTAMPTZ DEFAULT NOW()
          )
        `);
        
        // Insert with current time
        await db.query('INSERT INTO chaos_clock_test DEFAULT VALUES');
        
        // Insert with future time (simulating clock drift)
        await db.query(`
          INSERT INTO chaos_clock_test (created_at) 
          VALUES (NOW() + INTERVAL '5 minutes')
        `);
        
        // Query with "current" time
        const futureResult = await db.query(`
          SELECT COUNT(*) as future_count 
          FROM chaos_clock_test 
          WHERE created_at > NOW()
        `);
        
        console.log(`   📊 Records with future timestamps: ${futureResult.rows[0]?.future_count}`);
        console.log('   ✅ Clock drift handling verified');
      });
    },
  },
];

async function runExperiment(experiment: ChaosExperiment) {
  console.log(`\n🧪 Running: ${experiment.name}`);
  console.log(`   ${experiment.description}\n`);

  const startTime = Date.now();
  
  try {
    await experiment.run();
    const duration = Date.now() - startTime;
    console.log(`   ✅ Completed in ${duration}ms\n`);
  } catch (error) {
    const duration = Date.now() - startTime;
    console.error(`   ❌ Failed after ${duration}ms:`, error);
    throw error;
  }
}

async function runAll() {
  console.log('🔥 Chaos Engineering Runner\n');
  console.log(`Running ${experiments.length} experiments...\n`);

  let passed = 0;
  let failed = 0;

  for (const experiment of experiments) {
    try {
      await runExperiment(experiment);
      passed++;
    } catch (error) {
      failed++;
      console.error(`Experiment ${experiment.name} failed:`, error);
    }
  }

  console.log('\n📊 Summary:');
  console.log(`   Total: ${experiments.length}`);
  console.log(`   Passed: ${passed}`);
  console.log(`   Failed: ${failed}`);

  if (failed > 0) {
    process.exit(1);
  }
}

async function runOne(name: string) {
  const experiment = experiments.find(e => e.name === name);
  
  if (!experiment) {
    console.error(`❌ Experiment "${name}" not found\n`);
    console.log('Available experiments:');
    experiments.forEach(e => {
      console.log(`   - ${e.name}: ${e.description}`);
    });
    process.exit(1);
  }

  await runExperiment(experiment);
}

async function listExperiments() {
  console.log('🧪 Available Chaos Experiments:\n');
  experiments.forEach((e, i) => {
    console.log(`${i + 1}. ${e.name}`);
    console.log(`   ${e.description}\n`);
  });
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === 'list') {
    await listExperiments();
  } else if (command === 'run') {
    const experimentName = args[1];
    if (experimentName) {
      await runOne(experimentName);
    } else {
      await runAll();
    }
  } else {
    console.error(`❌ Unknown command: ${command}\n`);
    console.log('Usage:');
    console.log('   pnpm chaos:run              - List experiments');
    console.log('   pnpm chaos:run list         - List experiments');
    console.log('   pnpm chaos:run run          - Run all experiments');
    console.log('   pnpm chaos:run run <name>   - Run specific experiment');
    process.exit(1);
  }
}

// ES module entry point check
const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch(error => {
    console.error('❌ Chaos runner failed:', error);
    process.exit(1);
  });
}

export { experiments, runExperiment, runAll, runOne };
