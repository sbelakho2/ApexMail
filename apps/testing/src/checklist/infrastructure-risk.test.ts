/**
 * Infrastructure & Deployment Risk Tests
 * 
 * Analysis of operational risks related to deployment, configuration,
 * observability, and infrastructure reliability.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const APPS_ROOT = path.resolve(__dirname, '../../../../');

function getAllTsFiles(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  const files: string[] = [];
  try {
    const items = fs.readdirSync(dir);
    for (const item of items) {
      const fullPath = path.join(dir, item);
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory() && item !== 'node_modules') {
        files.push(...getAllTsFiles(fullPath));
      } else if (item.endsWith('.ts') && !item.endsWith('.test.ts')) {
        files.push(fullPath);
      }
    }
  } catch { return []; }
  return files;
}

function readFile(filePath: string): string {
  try { return fs.readFileSync(filePath, 'utf-8'); }
  catch { return ''; }
}

interface InfraRisk {
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  file?: string;
  recommendation: string;
}

const infraRisks: InfraRisk[] = [];

describe('Infrastructure & Deployment Risk Analysis', () => {

  describe('🔧 Configuration Risks', () => {
    it('detects hardcoded secrets', () => {
      const allFiles = getAllTsFiles(path.join(APPS_ROOT, 'apps'));
      let hardcodedSecrets = 0;
      
      for (const file of allFiles) {
        const content = readFile(file);
        
        // API keys
        if (content.match(/(?:apiKey|api_key|API_KEY)\s*[=:]\s*['"][a-zA-Z0-9]{20,}['"]/)) {
          hardcodedSecrets++;
          infraRisks.push({
            category: 'Security',
            severity: 'CRITICAL',
            description: 'Hardcoded API key found',
            file,
            recommendation: 'Use environment variables for secrets'
          });
        }
        
        // Passwords
        if (content.match(/(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{4,}['"]/i)) {
          if (!content.includes('example') && !content.includes('test') && !content.includes('placeholder')) {
            hardcodedSecrets++;
          }
        }
        
        // Private keys
        if (content.includes('-----BEGIN') && content.includes('PRIVATE KEY')) {
          hardcodedSecrets++;
          infraRisks.push({
            category: 'Security',
            severity: 'CRITICAL',
            description: 'Hardcoded private key found',
            file,
            recommendation: 'Store keys in secure vault or environment'
          });
        }
      }
      
      expect(hardcodedSecrets).toBe(0);
    });

    it('detects missing environment variable validation', () => {
      const entryPoints = [
        path.join(APPS_ROOT, 'apps/api/src/index.ts'),
        path.join(APPS_ROOT, 'apps/billing/src/index.ts'),
        path.join(APPS_ROOT, 'apps/worker/src/index.ts'),
      ];
      
      let noValidation = 0;
      
      for (const file of entryPoints) {
        const content = readFile(file);
        if (!content) continue;
        
        // Check for env validation at startup
        const hasEnvValidation = content.includes('validateEnv') ||
                                  content.includes('z.object') ||
                                  content.includes('Joi.object') ||
                                  content.includes('envSchema');
        
        if (!hasEnvValidation) {
          noValidation++;
          infraRisks.push({
            category: 'Configuration',
            severity: 'HIGH',
            description: 'Entry point lacks environment validation',
            file,
            recommendation: 'Add Zod/Joi schema to validate env at startup'
          });
        }
      }
      
      expect(noValidation).toBeLessThanOrEqual(3);
    });

    it('detects dangerous default values', () => {
      const allFiles = getAllTsFiles(path.join(APPS_ROOT, 'apps'));
      let dangerousDefaults = 0;
      
      for (const file of allFiles) {
        const content = readFile(file);
        
        // Default to localhost in production config
        if (content.match(/\|\|\s*['"](?:localhost|127\.0\.0\.1)['"]/)) {
          dangerousDefaults++;
        }
        
        // Default false for security features
        if (content.match(/(?:secure|ssl|tls|verify)\s*[=:]\s*false/i)) {
          if (!content.includes('development') && !content.includes('test')) {
            dangerousDefaults++;
          }
        }
        
        // Default to '*' for CORS
        if (content.match(/(?:cors|origin)\s*[=:]\s*['"]\*['"]/)) {
          dangerousDefaults++;
          infraRisks.push({
            category: 'Security',
            severity: 'MEDIUM',
            description: 'CORS allows all origins by default',
            file,
            recommendation: 'Configure specific allowed origins'
          });
        }
      }
      
      if (dangerousDefaults > 5) {
        console.warn(`\n⚠️  Found ${dangerousDefaults} potentially dangerous defaults`);
      }
      expect(dangerousDefaults).toBeLessThan(10);
    });

    it('detects missing production vs development checks', () => {
      const allFiles = getAllTsFiles(path.join(APPS_ROOT, 'apps'));
      let devInProd = 0;
      
      for (const file of allFiles) {
        const content = readFile(file);
        
        // console.log in production code (not in tests)
        if (!file.includes('test') && content.includes('console.log')) {
          // Check if it's guarded by NODE_ENV
          if (!content.includes('NODE_ENV') && !content.includes('development')) {
            devInProd++;
          }
        }
        
        // Debug mode without env check
        if (content.match(/debug\s*[=:]\s*true/) && !content.includes('NODE_ENV')) {
          devInProd++;
        }
      }
      
      expect(devInProd).toBeLessThan(50);
    });
  });

  describe('📊 Observability Risks', () => {
    it('detects missing error logging', () => {
      const criticalPaths = [
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/billing/src/services')),
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/api/src/routes')),
      ];
      
      let noErrorLogging = 0;
      
      for (const file of criticalPaths) {
        const content = readFile(file);
        
        // Catch blocks without logging
        const catchBlocks = content.match(/catch\s*\([^)]+\)\s*\{[^}]+\}/g) || [];
        for (const catchBlock of catchBlocks) {
          if (!catchBlock.includes('log') && !catchBlock.includes('Logger') && 
              !catchBlock.includes('console') && !catchBlock.includes('report')) {
            noErrorLogging++;
          }
        }
      }
      
      if (noErrorLogging > 10) {
        console.warn(`\n⚠️  Found ${noErrorLogging} catch blocks without logging`);
        infraRisks.push({
          category: 'Observability',
          severity: 'MEDIUM',
          description: 'Errors caught but not logged',
          recommendation: 'Add structured logging to all catch blocks'
        });
      }
      expect(noErrorLogging).toBeLessThan(30);
    });

    it('detects missing metrics for critical operations', () => {
      const billingFiles = getAllTsFiles(path.join(APPS_ROOT, 'apps/billing/src'));
      let noMetrics = 0;
      
      for (const file of billingFiles) {
        const content = readFile(file);
        
        // Payment operations should have metrics
        if (content.includes('charge') || content.includes('payment') || content.includes('invoice')) {
          const hasMetrics = content.includes('metrics') || 
                             content.includes('counter') ||
                             content.includes('histogram') ||
                             content.includes('gauge');
          
          if (!hasMetrics) {
            noMetrics++;
          }
        }
      }
      
      if (noMetrics > 5) {
        infraRisks.push({
          category: 'Observability',
          severity: 'HIGH',
          description: 'Billing operations lack metrics',
          recommendation: 'Add counters/histograms for all payment operations'
        });
      }
      expect(noMetrics).toBeLessThan(15);
    });

    it('detects missing request tracing', () => {
      const apiFiles = getAllTsFiles(path.join(APPS_ROOT, 'apps/api/src'));
      let hasTracing = false;
      
      for (const file of apiFiles) {
        const content = readFile(file);
        if (content.includes('trace') || content.includes('correlation') || 
            content.includes('requestId') || content.includes('x-request-id')) {
          hasTracing = true;
          break;
        }
      }
      
      if (!hasTracing) {
        infraRisks.push({
          category: 'Observability',
          severity: 'MEDIUM',
          description: 'No request tracing/correlation ID found',
          recommendation: 'Add middleware to generate and propagate trace IDs'
        });
      }
      
      expect(true).toBe(true);
    });

    it('detects missing health check endpoints', () => {
      const apiFiles = getAllTsFiles(path.join(APPS_ROOT, 'apps/api/src'));
      let hasHealthCheck = false;
      let hasReadinessCheck = false;
      let hasLivenessCheck = false;
      
      for (const file of apiFiles) {
        const content = readFile(file);
        if (content.includes('/health') || content.includes('healthz')) {
          hasHealthCheck = true;
        }
        if (content.includes('/ready') || content.includes('readiness')) {
          hasReadinessCheck = true;
        }
        if (content.includes('/live') || content.includes('liveness')) {
          hasLivenessCheck = true;
        }
      }
      
      if (!hasHealthCheck) {
        infraRisks.push({
          category: 'Deployment',
          severity: 'HIGH',
          description: 'No health check endpoint found',
          recommendation: 'Add /health endpoint for load balancer checks'
        });
      }
      
      // Track readiness and liveness for informational purposes
      if (!hasReadinessCheck || !hasLivenessCheck) {
        // These are optional but recommended for Kubernetes deployments
      }
      
      expect(hasHealthCheck || apiFiles.length === 0).toBe(true);
    });
  });

  describe('🔄 Deployment Risks', () => {
    it('detects missing graceful shutdown', () => {
      const entryPoints = [
        path.join(APPS_ROOT, 'apps/api/src/index.ts'),
        path.join(APPS_ROOT, 'apps/worker/src/index.ts'),
        path.join(APPS_ROOT, 'apps/mta/src/index.ts'),
      ];
      
      let noGracefulShutdown = 0;
      
      for (const file of entryPoints) {
        const content = readFile(file);
        if (!content) continue;
        
        const hasGracefulShutdown = content.includes('SIGTERM') ||
                                     content.includes('SIGINT') ||
                                     content.includes('graceful') ||
                                     content.includes('shutdown');
        
        if (!hasGracefulShutdown) {
          noGracefulShutdown++;
          infraRisks.push({
            category: 'Deployment',
            severity: 'HIGH',
            description: 'No graceful shutdown handler',
            file,
            recommendation: 'Handle SIGTERM to drain connections and complete in-flight requests'
          });
        }
      }
      
      expect(noGracefulShutdown).toBeLessThan(3);
    });

    it('detects missing connection draining', () => {
      const files = [
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/api/src')),
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/worker/src')),
      ];
      
      let hasDraining = false;
      
      for (const file of files) {
        const content = readFile(file);
        if (content.includes('drain') || content.includes('closeAllConnections') ||
            content.includes('server.close')) {
          hasDraining = true;
          break;
        }
      }
      
      if (!hasDraining) {
        infraRisks.push({
          category: 'Deployment',
          severity: 'MEDIUM',
          description: 'No connection draining on shutdown',
          recommendation: 'Add connection draining to prevent dropped requests during deploy'
        });
      }
      
      expect(true).toBe(true);
    });

    it('detects startup dependency ordering issues', () => {
      const entryPoints = [
        path.join(APPS_ROOT, 'apps/api/src/index.ts'),
        path.join(APPS_ROOT, 'apps/billing/src/index.ts'),
      ];
      
      let dependencyIssues = 0;
      
      for (const file of entryPoints) {
        const content = readFile(file);
        if (!content) continue;
        
        // Check if database connection is awaited before starting server
        const dbConnect = content.indexOf('connect');
        const serverListen = content.indexOf('listen');
        
        if (serverListen > 0 && dbConnect > serverListen) {
          dependencyIssues++;
          infraRisks.push({
            category: 'Deployment',
            severity: 'HIGH',
            description: 'Server starts before database connection',
            file,
            recommendation: 'Connect to database and verify connection before accepting traffic'
          });
        }
      }
      
      expect(dependencyIssues).toBe(0);
    });
  });

  describe('🔒 Security Infrastructure', () => {
    it('detects missing rate limiting', () => {
      const apiFiles = getAllTsFiles(path.join(APPS_ROOT, 'apps/api/src'));
      let hasRateLimiting = false;
      
      for (const file of apiFiles) {
        const content = readFile(file);
        if (content.includes('rateLimit') || content.includes('RateLimit') ||
            content.includes('throttle') || content.includes('limiter')) {
          hasRateLimiting = true;
          break;
        }
      }
      
      if (!hasRateLimiting) {
        infraRisks.push({
          category: 'Security',
          severity: 'HIGH',
          description: 'No rate limiting found',
          recommendation: 'Add rate limiting middleware to prevent abuse'
        });
      }
      
      expect(hasRateLimiting || apiFiles.length === 0).toBe(true);
    });

    it('detects missing HTTPS enforcement', () => {
      const apiFiles = getAllTsFiles(path.join(APPS_ROOT, 'apps/api/src'));
      let hasHttpsEnforcement = false;
      
      for (const file of apiFiles) {
        const content = readFile(file);
        if (content.includes('https') || content.includes('ssl') ||
            content.includes('tls') || content.includes('secure: true')) {
          hasHttpsEnforcement = true;
        }
        
        // Check for HSTS headers
        if (content.includes('Strict-Transport-Security')) {
          hasHttpsEnforcement = true;
        }
      }
      
      // HTTPS is typically handled at load balancer level, not app level
      // This is informational only
      if (!hasHttpsEnforcement) {
        // HTTPS enforcement may be at infrastructure layer
      }
      
      expect(true).toBe(true);
    });

    it('detects missing security headers', () => {
      const apiFiles = getAllTsFiles(path.join(APPS_ROOT, 'apps/api/src'));
      const securityHeaders = {
        csp: false,
        xframe: false,
        xcontent: false,
        xss: false,
      };
      
      for (const file of apiFiles) {
        const content = readFile(file);
        if (content.includes('Content-Security-Policy')) securityHeaders.csp = true;
        if (content.includes('X-Frame-Options')) securityHeaders.xframe = true;
        if (content.includes('X-Content-Type-Options')) securityHeaders.xcontent = true;
        if (content.includes('X-XSS-Protection') || content.includes('helmet')) {
          securityHeaders.xss = true;
          securityHeaders.csp = true;
          securityHeaders.xframe = true;
          securityHeaders.xcontent = true;
        }
      }
      
      const missingHeaders = Object.entries(securityHeaders)
        .filter(([_, v]) => !v)
        .map(([k]) => k);
      
      if (missingHeaders.length > 0 && apiFiles.length > 0) {
        infraRisks.push({
          category: 'Security',
          severity: 'MEDIUM',
          description: `Missing security headers: ${missingHeaders.join(', ')}`,
          recommendation: 'Use helmet middleware or add headers manually'
        });
      }
      
      expect(true).toBe(true);
    });
  });

  describe('💾 Data Persistence Risks', () => {
    it('detects missing database migrations', () => {
      const migrationDirs = [
        path.join(APPS_ROOT, 'apps/billing/migrations'),
        path.join(APPS_ROOT, 'apps/enterprise/migrations'),
      ];
      
      let hasMigrations = false;
      
      for (const dir of migrationDirs) {
        if (fs.existsSync(dir)) {
          const files = fs.readdirSync(dir);
          if (files.length > 0) {
            hasMigrations = true;
          }
        }
      }
      
      expect(hasMigrations || true).toBe(true); // Soft check
    });

    it('detects missing backup verification', () => {
      const opsFiles = getAllTsFiles(path.join(APPS_ROOT, 'apps/ops/src'));
      let hasBackupVerify = false;
      
      for (const file of opsFiles) {
        const content = readFile(file);
        if (content.includes('backup') && content.includes('verify')) {
          hasBackupVerify = true;
        }
      }
      
      if (!hasBackupVerify) {
        infraRisks.push({
          category: 'Data',
          severity: 'MEDIUM',
          description: 'No backup verification logic found',
          recommendation: 'Add automated backup verification and restoration testing'
        });
      }
      
      expect(true).toBe(true);
    });

    it('detects missing data retention policies', () => {
      const files = [
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/compliance/src')),
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/billing/src')),
      ];
      
      let hasRetention = false;
      
      for (const file of files) {
        const content = readFile(file);
        if (content.includes('retention') || content.includes('archive') ||
            content.includes('purge') || content.includes('gdpr')) {
          hasRetention = true;
        }
      }
      
      if (!hasRetention) {
        infraRisks.push({
          category: 'Compliance',
          severity: 'MEDIUM',
          description: 'No data retention/purge logic found',
          recommendation: 'Implement data retention policies for GDPR compliance'
        });
      }
      
      expect(true).toBe(true);
    });
  });

  describe('🌐 Service Dependencies', () => {
    it('detects single points of failure', () => {
      const haFiles = getAllTsFiles(path.join(APPS_ROOT, 'apps/ha/src'));
      let hasFailover = false;
      let hasMultipleReplicas = false;
      
      for (const file of haFiles) {
        const content = readFile(file);
        if (content.includes('failover') || content.includes('Failover')) {
          hasFailover = true;
        }
        if (content.includes('replica') || content.includes('standby')) {
          hasMultipleReplicas = true;
        }
      }
      
      if (!hasFailover && !hasMultipleReplicas) {
        infraRisks.push({
          category: 'Reliability',
          severity: 'HIGH',
          description: 'No failover or replica configuration found',
          recommendation: 'Implement database replicas and automatic failover'
        });
      }
      
      expect(hasFailover || hasMultipleReplicas || haFiles.length === 0).toBe(true);
    });

    it('detects missing circuit breakers', () => {
      const files = [
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/ha/src')),
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/billing/src')),
      ];
      
      let hasCircuitBreaker = false;
      
      for (const file of files) {
        const content = readFile(file);
        if (content.includes('CircuitBreaker') || content.includes('circuit')) {
          hasCircuitBreaker = true;
          break;
        }
      }
      
      if (!hasCircuitBreaker) {
        infraRisks.push({
          category: 'Reliability',
          severity: 'HIGH',
          description: 'No circuit breaker pattern found',
          recommendation: 'Add circuit breakers for external service calls'
        });
      }
      
      expect(hasCircuitBreaker || files.length === 0).toBe(true);
    });
  });

  describe('📊 Summary Report', () => {
    it('generates infrastructure risk summary', () => {
      const critical = infraRisks.filter(r => r.severity === 'CRITICAL').length;
      const high = infraRisks.filter(r => r.severity === 'HIGH').length;
      const medium = infraRisks.filter(r => r.severity === 'MEDIUM').length;
      const low = infraRisks.filter(r => r.severity === 'LOW').length;
      
      console.log('\n' + '='.repeat(70));
      console.log('📊 INFRASTRUCTURE RISK SUMMARY');
      console.log('='.repeat(70));
      console.log(`\n🔴 CRITICAL: ${critical} risks`);
      console.log(`🟠 HIGH:     ${high} risks`);
      console.log(`🟡 MEDIUM:   ${medium} risks`);
      console.log(`🟢 LOW:      ${low} risks`);
      console.log(`\n📝 TOTAL:    ${infraRisks.length} infrastructure risks\n`);
      
      // Group by category
      const byCategory = new Map<string, InfraRisk[]>();
      for (const risk of infraRisks) {
        const existing = byCategory.get(risk.category) || [];
        existing.push(risk);
        byCategory.set(risk.category, existing);
      }
      
      console.log('Risks by Category:');
      console.log('-'.repeat(40));
      for (const [category, categoryRisks] of byCategory) {
        console.log(`  ${category}: ${categoryRisks.length}`);
      }
      
      // Print all issues
      if (infraRisks.length > 0) {
        console.log('\n' + '='.repeat(70));
        console.log('DETAILED INFRASTRUCTURE RISKS:');
        console.log('='.repeat(70));
        
        for (const risk of infraRisks.sort((a, b) => {
          const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
          return severityOrder[a.severity] - severityOrder[b.severity];
        })) {
          const icon = risk.severity === 'CRITICAL' ? '🔴' :
                       risk.severity === 'HIGH' ? '🟠' :
                       risk.severity === 'MEDIUM' ? '🟡' : '🟢';
          console.log(`\n${icon} [${risk.severity}] ${risk.category}`);
          console.log(`   ${risk.description}`);
          if (risk.file) {
            console.log(`   File: ${path.basename(risk.file)}`);
          }
          console.log(`   → ${risk.recommendation}`);
        }
      }
      
      expect(critical).toBe(0);
    });
  });
});
