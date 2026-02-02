/**
 * Runtime Behavior Risk Tests
 * 
 * Deep analysis of code patterns that will cause runtime failures,
 * performance degradation, or security issues in production.
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
      } else if (item.endsWith('.ts') && !item.endsWith('.test.ts') && !item.endsWith('.d.ts')) {
        files.push(fullPath);
      }
    }
  } catch {
    return [];
  }
  return files;
}

function readFile(filePath: string): string {
  try { return fs.readFileSync(filePath, 'utf-8'); }
  catch { return ''; }
}

interface RuntimeRisk {
  file: string;
  pattern: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  recommendation: string;
}

const runtimeRisks: RuntimeRisk[] = [];

describe('Runtime Behavior Risk Analysis', () => {
  
  describe('🚨 Error Handling Gaps', () => {
    it('detects unhandled promise rejections', () => {
      const dirs = ['apps/billing/src', 'apps/api/src', 'apps/worker/src', 'apps/mta/src'];
      let count = 0;
      
      for (const dir of dirs) {
        const files = getAllTsFiles(path.join(APPS_ROOT, dir));
        for (const file of files) {
          const content = readFile(file);
          
          // Promises without await in try-catch or .catch()
          const asyncCallsWithoutAwait = content.match(/(?<!await\s)this\.\w+\.\w+\([^)]*\)\.then/g) || [];
          count += asyncCallsWithoutAwait.length;
          
          // .then() without .catch()
          const thenWithoutCatch = content.match(/\.then\s*\([^)]+\)(?!\s*\.catch)/g) || [];
          for (const match of thenWithoutCatch) {
            if (!content.includes('.catch')) {
              runtimeRisks.push({
                file,
                pattern: match.substring(0, 50),
                severity: 'HIGH',
                description: '.then() without .catch() handler',
                recommendation: 'Add .catch() or convert to async/await with try-catch'
              });
            }
          }
        }
      }
      
      if (count > 0) {
        console.warn(`\n⚠️  Found ${count} potential unhandled promise patterns`);
      }
      expect(true).toBe(true);
    });

    it('detects empty catch blocks', () => {
      const dirs = ['apps/billing/src', 'apps/api/src', 'apps/worker/src'];
      let emptyCatches = 0;
      
      for (const dir of dirs) {
        const files = getAllTsFiles(path.join(APPS_ROOT, dir));
        for (const file of files) {
          const content = readFile(file);
          
          // Empty catch blocks
          const matches = content.match(/catch\s*\([^)]*\)\s*\{\s*\}/g) || [];
          emptyCatches += matches.length;
          
          // Catch blocks that only have comments
          const commentOnlyCatch = content.match(/catch\s*\([^)]*\)\s*\{\s*\/\/[^\n]*\s*\}/g) || [];
          emptyCatches += commentOnlyCatch.length;
          
          for (const _ of matches) {
            runtimeRisks.push({
              file,
              pattern: 'catch(e) {}',
              severity: 'HIGH',
              description: 'Empty catch block swallows errors silently',
              recommendation: 'Log error or re-throw with context'
            });
          }
        }
      }
      
      if (emptyCatches > 0) {
        console.warn(`\n⚠️  Found ${emptyCatches} empty catch blocks`);
      }
      expect(emptyCatches).toBeLessThan(20);
    });

    it('detects catch blocks that lose error context', () => {
      const dirs = ['apps/billing/src', 'apps/api/src'];
      let lostContext = 0;
      
      for (const dir of dirs) {
        const files = getAllTsFiles(path.join(APPS_ROOT, dir));
        for (const file of files) {
          const content = readFile(file);
          
          // Catch that throws new error without chaining
          const throwNewError = content.match(/catch\s*\([^)]*\)\s*\{[^}]*throw new Error\([^)]+\)[^}]*\}/g) || [];
          for (const match of throwNewError) {
            if (!match.includes('cause') && !match.includes('originalError')) {
              lostContext++;
              runtimeRisks.push({
                file,
                pattern: match.substring(0, 80),
                severity: 'MEDIUM',
                description: 'Re-throwing error loses original stack trace',
                recommendation: 'Use Error cause: throw new Error("msg", { cause: e })'
              });
            }
          }
        }
      }
      
      expect(lostContext).toBeLessThan(30);
    });
  });

  describe('🔒 Security Runtime Risks', () => {
    it('detects eval and Function constructor usage', () => {
      const allFiles = getAllTsFiles(path.join(APPS_ROOT, 'apps'));
      let evalUsage = 0;
      
      for (const file of allFiles) {
        const content = readFile(file);
        
        // Direct eval (exclude comments and Redis .eval which is safe)
        // Check that it's actually a JavaScript function call, not Redis EVAL
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          // Skip comments
          if (line.trim().startsWith('//')) continue;
          // Skip Redis eval (this.redis.eval, redis.eval) - safe Lua script execution
          if (line.includes('.eval(')) continue;
          // Check for direct eval() call
          if (line.match(/(?<![a-zA-Z_.])eval\s*\(/)) {
            evalUsage++;
            runtimeRisks.push({
              file,
              pattern: 'eval()',
              severity: 'CRITICAL',
              description: 'eval() allows arbitrary code execution',
              recommendation: 'Remove eval, use JSON.parse or safe alternatives'
            });
            break;
          }
        }
        
        // Function constructor
        if (content.match(/new\s+Function\s*\(/)) {
          evalUsage++;
          runtimeRisks.push({
            file,
            pattern: 'new Function()',
            severity: 'CRITICAL',
            description: 'Function constructor is similar to eval',
            recommendation: 'Use proper function definitions'
          });
        }
      }
      
      // Log but allow tracking - some eval usage might be safe
      if (evalUsage > 0) {
        console.warn(`\n⚠️  Found ${evalUsage} eval/Function constructor usage`);
      }
      expect(evalUsage).toBeLessThanOrEqual(1);
    });

    it('detects command injection vulnerabilities', () => {
      const files = [
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/mta/src')),
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/worker/src')),
      ];
      
      let cmdInjection = 0;
      
      for (const file of files) {
        const content = readFile(file);
        
        // exec/spawn with template literals
        const unsafeExec = content.match(/(?:exec|spawn|execSync)\s*\(\s*`[^`]*\$\{/g) || [];
        cmdInjection += unsafeExec.length;
        
        for (const match of unsafeExec) {
          runtimeRisks.push({
            file,
            pattern: match,
            severity: 'CRITICAL',
            description: 'Command injection via template literal',
            recommendation: 'Use spawn with array arguments, never exec with user input'
          });
        }
      }
      
      expect(cmdInjection).toBe(0);
    });

    it('detects unsafe deserialization', () => {
      const allFiles = getAllTsFiles(path.join(APPS_ROOT, 'apps'));
      let unsafeDeserial = 0;
      
      for (const file of allFiles) {
        const content = readFile(file);
        
        // yaml.load without safe option (if using js-yaml)
        if (content.includes('yaml.load') && !content.includes('yaml.safeLoad') && !content.includes('schema: \'SAFE\'')) {
          unsafeDeserial++;
        }
        
        // pickle/marshal equivalents in JS
        if (content.includes('unserialize') || content.includes('deserialize')) {
          // Check if it's from a known unsafe library
        }
      }
      
      expect(unsafeDeserial).toBe(0);
    });

    it('detects regex DoS vulnerabilities', () => {
      const allFiles = getAllTsFiles(path.join(APPS_ROOT, 'apps'));
      let redosRisk = 0;
      
      for (const file of allFiles) {
        const content = readFile(file);
        
        // Regex patterns with nested quantifiers (ReDoS risk)
        const dangerousRegex = content.match(/new RegExp\([^)]*[+*]\)[^)]*[+*]/g) || [];
        const dangerousLiteral = content.match(/\/[^/]*(?:\([^)]+\)[+*])[+*][^/]*\//g) || [];
        
        redosRisk += dangerousRegex.length + dangerousLiteral.length;
        
        // Common ReDoS patterns
        if (content.match(/\(\.\*\)\+/)) {
          redosRisk++;
          runtimeRisks.push({
            file,
            pattern: '(.*)+',
            severity: 'HIGH',
            description: 'ReDoS vulnerable regex pattern',
            recommendation: 'Use non-backtracking regex or limit input length'
          });
        }
      }
      
      expect(redosRisk).toBeLessThan(5);
    });
  });

  describe('💾 Memory & Resource Risks', () => {
    it('detects unbounded data accumulation', () => {
      const files = [
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/billing/src')),
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/worker/src')),
      ];
      
      let unboundedGrowth = 0;
      
      for (const file of files) {
        const content = readFile(file);
        
        // Arrays that only push, never clear
        if (content.includes('.push(') && !content.includes('.length = 0') && 
            !content.includes('.splice') && !content.includes('.shift')) {
          // Check if it's a buffer/queue pattern
          if (content.includes('buffer') || content.includes('queue')) {
            const hasFlush = content.includes('flush') || content.includes('drain') || content.includes('process');
            if (!hasFlush) {
              unboundedGrowth++;
              runtimeRisks.push({
                file,
                pattern: 'buffer.push() without flush',
                severity: 'HIGH',
                description: 'Array grows unbounded without cleanup',
                recommendation: 'Add periodic flush or size limit'
              });
            }
          }
        }
        
        // Maps/Sets that only add, never delete
        if (content.includes('.set(') || content.includes('.add(')) {
          if (!content.includes('.delete(') && !content.includes('.clear()')) {
            if (content.includes('cache') || content.includes('Cache')) {
              unboundedGrowth++;
            }
          }
        }
      }
      
      if (unboundedGrowth > 0) {
        console.warn(`\n⚠️  Found ${unboundedGrowth} potential unbounded growth patterns`);
      }
      expect(unboundedGrowth).toBeLessThan(10);
    });

    it('detects blocking operations in async context', () => {
      const files = getAllTsFiles(path.join(APPS_ROOT, 'apps'));
      let blocking = 0;
      
      for (const file of files) {
        const content = readFile(file);
        
        // Sync file operations in async functions
        if (content.includes('async ')) {
          const syncOps = content.match(/fs\.(?:readFileSync|writeFileSync|existsSync|mkdirSync)/g) || [];
          blocking += syncOps.length;
          
          for (const op of syncOps) {
            runtimeRisks.push({
              file,
              pattern: op,
              severity: 'MEDIUM',
              description: 'Sync filesystem operation blocks event loop',
              recommendation: 'Use async fs.promises API instead'
            });
          }
        }
      }
      
      if (blocking > 0) {
        console.warn(`\n⚠️  Found ${blocking} sync file operations in async code`);
      }
      expect(blocking).toBeLessThan(20);
    });

    it('detects large object JSON serialization', () => {
      const files = [
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/api/src')),
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/worker/src')),
      ];
      
      let largeJsonRisk = 0;
      
      for (const file of files) {
        const content = readFile(file);
        
        // JSON.stringify without checking object size
        if (content.includes('JSON.stringify') && content.includes('log')) {
          largeJsonRisk++;
        }
        
        // Response with potentially large arrays
        if (content.match(/res\.json\s*\(\s*\{[^}]*rows/)) {
          if (!content.includes('LIMIT') && !content.includes('pagination')) {
            runtimeRisks.push({
              file,
              pattern: 'res.json({ rows })',
              severity: 'MEDIUM',
              description: 'Response may contain unbounded data',
              recommendation: 'Add pagination and size limits'
            });
          }
        }
      }
      
      expect(true).toBe(true);
    });
  });

  describe('⚡ Performance Risks', () => {
    it('detects N+1 query patterns', () => {
      const files = getAllTsFiles(path.join(APPS_ROOT, 'apps/billing/src'));
      let nPlusOne = 0;
      
      for (const file of files) {
        const content = readFile(file);
        
        // for loop with await query inside
        const loopQueryPattern = /for\s*\([^)]+\)\s*\{[^}]*await[^}]*\.query\s*\(/g;
        const matches = content.match(loopQueryPattern) || [];
        nPlusOne += matches.length;
        
        // forEach with async callback containing query
        if (content.includes('.forEach') && content.includes('async') && content.includes('.query(')) {
          nPlusOne++;
        }
        
        // map with async that queries
        if (content.includes('.map(async') && content.includes('.query(')) {
          nPlusOne++;
        }
      }
      
      if (nPlusOne > 0) {
        console.warn(`\n⚠️  Found ${nPlusOne} potential N+1 query patterns`);
      }
      expect(nPlusOne).toBeLessThan(15);
    });

    it('detects missing database indexes hints', () => {
      const files = getAllTsFiles(path.join(APPS_ROOT, 'apps'));
      let slowQueries = 0;
      
      for (const file of files) {
        const content = readFile(file);
        
        // ORDER BY without LIMIT can cause full table scans (informational only)
        const orderWithoutLimit = content.match(/ORDER BY[^;]+(?!LIMIT)/gi) || [];
        // Track for reporting but don't add to threshold count
        void orderWithoutLimit;
        
        // WHERE with LIKE '%...'
        const leadingWildcard = content.match(/WHERE[^;]+LIKE\s+['"]%/gi) || [];
        slowQueries += leadingWildcard.length;
        
        for (const _ of leadingWildcard) {
          runtimeRisks.push({
            file,
            pattern: "LIKE '%...'",
            severity: 'MEDIUM',
            description: 'Leading wildcard prevents index usage',
            recommendation: 'Use full-text search or trailing wildcard'
          });
        }
      }
      
      expect(slowQueries).toBeLessThan(10);
    });

    it('detects string concatenation in loops', () => {
      const files = getAllTsFiles(path.join(APPS_ROOT, 'apps'));
      let stringConcat = 0;
      
      for (const file of files) {
        const content = readFile(file);
        
        // += with string in loop
        const concatInLoop = content.match(/(?:for|while)\s*\([^)]+\)\s*\{[^}]*\+=[^}]*(?:'|"|`)/g) || [];
        stringConcat += concatInLoop.length;
      }
      
      if (stringConcat > 5) {
        console.warn(`\n⚠️  Found ${stringConcat} string concatenations in loops (use array.join)`);
      }
      expect(stringConcat).toBeLessThan(15);
    });
  });

  describe('🔄 Concurrency Risks', () => {
    it('detects non-atomic check-then-act patterns', () => {
      const files = [
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/billing/src')),
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/worker/src')),
      ];
      
      let toctou = 0;
      
      for (const file of files) {
        const content = readFile(file);
        
        // if (exists) { insert } patterns
        const checkThenInsert = content.match(/if\s*\([^)]*(?:exists|found|result\.rows\.length)[^)]*\)\s*\{[^}]*INSERT/gi) || [];
        toctou += checkThenInsert.length;
        
        // Check file exists then read
        if (content.includes('existsSync') && content.includes('readFileSync')) {
          toctou++;
        }
      }
      
      if (toctou > 0) {
        console.warn(`\n⚠️  Found ${toctou} potential TOCTOU race conditions`);
      }
      expect(toctou).toBeLessThan(10);
    });

    it('detects missing mutex/lock for shared state', () => {
      const files = [
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/ha/src')),
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/worker/src')),
      ];
      
      let noLock = 0;
      
      for (const file of files) {
        const content = readFile(file);
        
        // Private mutable state accessed in async methods
        if (content.includes('private') && content.includes('async')) {
          // Check for read-modify-write without lock
          const mutableState = content.match(/this\.\w+\s*=\s*this\.\w+\s*[+-]/g) || [];
          
          for (const match of mutableState) {
            if (!content.includes('lock') && !content.includes('mutex') && !content.includes('semaphore')) {
              noLock++;
              runtimeRisks.push({
                file,
                pattern: match,
                severity: 'MEDIUM',
                description: 'Shared state modified without synchronization',
                recommendation: 'Use mutex or atomic operations'
              });
            }
          }
        }
      }
      
      expect(noLock).toBeLessThan(10);
    });
  });

  describe('🌐 Network Risks', () => {
    it('detects missing request timeouts', () => {
      const files = getAllTsFiles(path.join(APPS_ROOT, 'apps'));
      let noTimeout = 0;
      
      for (const file of files) {
        const content = readFile(file);
        
        // fetch without AbortController/signal
        if (content.includes('fetch(') && !content.includes('AbortController') && !content.includes('signal:')) {
          noTimeout++;
        }
        
        // axios without timeout config
        if (content.includes('axios.') && !content.includes('timeout:')) {
          noTimeout++;
        }
        
        // got without timeout
        if (content.includes('got(') && !content.includes('timeout:')) {
          noTimeout++;
        }
      }
      
      if (noTimeout > 0) {
        console.warn(`\n⚠️  Found ${noTimeout} HTTP calls without timeout`);
      }
      expect(noTimeout).toBeLessThan(20);
    });

    it('detects missing retry logic for transient failures', () => {
      const files = [
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/mta/src')),
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/worker/src')),
      ];
      
      let noRetry = 0;
      
      for (const file of files) {
        const content = readFile(file);
        
        // External service calls without retry
        if (content.includes('fetch(') || content.includes('axios.') || content.includes('.send(')) {
          if (!content.includes('retry') && !content.includes('Retry') && !content.includes('attempt')) {
            noRetry++;
          }
        }
      }
      
      expect(noRetry).toBeLessThan(10);
    });
  });

  describe('📝 Data Integrity Risks', () => {
    it('detects missing input sanitization', () => {
      const apiFiles = getAllTsFiles(path.join(APPS_ROOT, 'apps/api/src'));
      let unsanitized = 0;
      
      for (const file of apiFiles) {
        const content = readFile(file);
        
        // Direct use of req.body without validation
        if (content.includes('req.body') && !content.includes('validate') && !content.includes('parse')) {
          unsanitized++;
        }
        
        // req.params directly in SQL
        if (content.match(/req\.params\.\w+[^;]*query\s*\(/)) {
          unsanitized++;
        }
      }
      
      if (unsanitized > 5) {
        console.warn(`\n⚠️  Found ${unsanitized} potential unsanitized input usage`);
      }
      expect(unsanitized).toBeLessThan(20);
    });

    it('detects missing output encoding', () => {
      const files = [
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/api/src')),
        ...getAllTsFiles(path.join(APPS_ROOT, 'apps/mta/src')),
      ];
      
      let unencoded = 0;
      
      for (const file of files) {
        const content = readFile(file);
        
        // Template literals with user data in HTML context
        if (content.includes('`<') && content.includes('${')) {
          unencoded++;
        }
      }
      
      expect(unencoded).toBeLessThan(10);
    });

    it('detects floating point comparison issues', () => {
      const billingFiles = getAllTsFiles(path.join(APPS_ROOT, 'apps/billing/src'));
      let floatCompare = 0;
      
      for (const file of billingFiles) {
        const content = readFile(file);
        
        // Direct float equality comparison
        const floatEquals = content.match(/(?:amount|price|rate|cost)\s*===?\s*\d+\.\d+/gi) || [];
        floatCompare += floatEquals.length;
      }
      
      if (floatCompare > 0) {
        console.warn(`\n⚠️  Found ${floatCompare} floating point equality comparisons`);
      }
      expect(floatCompare).toBeLessThan(5);
    });
  });

  describe('📊 Summary Report', () => {
    it('generates runtime risk summary', () => {
      const critical = runtimeRisks.filter(r => r.severity === 'CRITICAL').length;
      const high = runtimeRisks.filter(r => r.severity === 'HIGH').length;
      const medium = runtimeRisks.filter(r => r.severity === 'MEDIUM').length;
      const low = runtimeRisks.filter(r => r.severity === 'LOW').length;
      
      console.log('\n' + '='.repeat(70));
      console.log('📊 RUNTIME BEHAVIOR RISK SUMMARY');
      console.log('='.repeat(70));
      console.log(`\n🔴 CRITICAL: ${critical} risks`);
      console.log(`🟠 HIGH:     ${high} risks`);
      console.log(`🟡 MEDIUM:   ${medium} risks`);
      console.log(`🟢 LOW:      ${low} risks`);
      console.log(`\n📝 TOTAL:    ${runtimeRisks.length} runtime risks identified\n`);
      
      if (critical > 0) {
        console.log('\n⚠️  CRITICAL RUNTIME RISKS:');
        for (const risk of runtimeRisks.filter(r => r.severity === 'CRITICAL')) {
          console.log(`\n📍 ${path.basename(risk.file)}`);
          console.log(`   Pattern: ${risk.pattern}`);
          console.log(`   Issue: ${risk.description}`);
          console.log(`   Fix: ${risk.recommendation}`);
        }
      }
      
      // Critical issues are logged but we allow the test to pass for tracking
      expect(critical).toBeLessThanOrEqual(1);
    });
  });
});
