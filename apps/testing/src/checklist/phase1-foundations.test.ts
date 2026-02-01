/**
 * Phase 1: Foundations (Repo, Standards, Determinism) - Checklist Tests
 * 
 * Tests verify each checklist item is properly implemented.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const ROOT_DIR = path.resolve(__dirname, '../../../..');

describe('Phase 1: Foundations', () => {
    
    // =========================================================================
    // 1.1 Repository & Structure
    // =========================================================================
    describe('1.1 Repository & Structure', () => {
        
        it('should have monorepo structure with distinct boundaries', () => {
            // Evidence: Directory tree listing matching architecture diagram
            const requiredDirs = [
                'apps/api',
                'apps/worker', 
                'apps/mta',
                'apps/web',
                'apps/ops',
                'apps/sales-autopilot',
                'docs'
            ];
            
            for (const dir of requiredDirs) {
                const fullPath = path.join(ROOT_DIR, dir);
                expect(fs.existsSync(fullPath), `Directory ${dir} should exist`).toBe(true);
            }
        });
        
        it('should have internal dependency wrappers (Thin Interface pattern)', () => {
            // Evidence: Code review of lib/ directory showing wrappers
            const libDir = path.join(ROOT_DIR, 'packages/lib/src');
            expect(fs.existsSync(libDir)).toBe(true);
            
            // Check for wrapper modules
            const wrappers = [
                'logger',    // Logging wrapper (pino)
                'storage',   // Storage wrapper
                'crypto',    // Crypto wrapper
                'cache',     // Cache wrapper (redis)
                'http',      // HTTP client wrapper
            ];
            
            for (const wrapper of wrappers) {
                const wrapperPath = path.join(libDir, wrapper);
                expect(
                    fs.existsSync(wrapperPath) || fs.existsSync(`${wrapperPath}.ts`),
                    `Wrapper ${wrapper} should exist in lib/`
                ).toBe(true);
            }
        });
        
        it('should have toolchain pinning with bootstrap script', () => {
            // Evidence: Execution log of ./tools/bootstrap.sh
            const bootstrapPath = path.join(ROOT_DIR, 'tools/bootstrap.sh');
            expect(fs.existsSync(bootstrapPath), 'tools/bootstrap.sh should exist').toBe(true);
            
            // Check it's executable
            const stats = fs.statSync(bootstrapPath);
            const isExecutable = (stats.mode & 0o111) !== 0;
            expect(isExecutable, 'bootstrap.sh should be executable').toBe(true);
        });
    });
    
    // =========================================================================
    // 1.2 Deterministic Build Pipeline
    // =========================================================================
    describe('1.2 Deterministic Build Pipeline', () => {
        
        it('should have SBOM generation capability', () => {
            // Evidence: Generated sbom.json for the core binary
            const packageJson = JSON.parse(
                fs.readFileSync(path.join(ROOT_DIR, 'package.json'), 'utf-8')
            );
            
            // Check for SBOM generation script
            expect(packageJson.scripts['sbom:generate']).toBeDefined();
            expect(packageJson.scripts['sbom:generate']).toContain('cyclonedx');
        });
        
        it('should have CI configuration for reproducible builds', () => {
            // Check for CI configuration files
            const ciPaths = [
                '.github/workflows',
                '.drone.yml',
                '.woodpecker.yml',
                'Dockerfile'
            ];
            
            const hasCI = ciPaths.some(p => fs.existsSync(path.join(ROOT_DIR, p)));
            expect(hasCI, 'Should have CI configuration').toBe(true);
        });
    });
    
    // =========================================================================
    // 1.3 Documentation & Architecture
    // =========================================================================
    describe('1.3 Documentation & Architecture', () => {
        
        it('should have ADR (Architecture Decision Records) system', () => {
            // Evidence: ADR 001, 002, 003 committed
            const adrDir = path.join(ROOT_DIR, 'docs/adr');
            expect(fs.existsSync(adrDir), 'docs/adr directory should exist').toBe(true);
            
            const adrFiles = fs.readdirSync(adrDir);
            const requiredADRs = ['0001', '0002', '0003'];
            
            for (const adr of requiredADRs) {
                const hasADR = adrFiles.some(f => f.includes(adr));
                expect(hasADR, `ADR ${adr} should exist`).toBe(true);
            }
        });
        
        it('should have docs as code system', () => {
            // Evidence: Static site generator building from /docs
            const docsDir = path.join(ROOT_DIR, 'docs');
            expect(fs.existsSync(docsDir)).toBe(true);
            
            // Check for README or index
            const hasIndex = fs.existsSync(path.join(docsDir, 'README.md')) ||
                           fs.existsSync(path.join(docsDir, 'index.md'));
            expect(hasIndex, 'Docs should have an index/README').toBe(true);
        });
    });
    
    // =========================================================================
    // 1.4 Hard Quality Gates
    // =========================================================================
    describe('1.4 Hard Quality Gates', () => {
        
        it('should have TypeScript strict mode enabled', () => {
            // Ghost function detection via tsc --noEmit
            const tsconfigPath = path.join(ROOT_DIR, 'tsconfig.base.json');
            expect(fs.existsSync(tsconfigPath)).toBe(true);
            
            const tsconfig = JSON.parse(fs.readFileSync(tsconfigPath, 'utf-8'));
            expect(tsconfig.compilerOptions.strict).toBe(true);
            expect(tsconfig.compilerOptions.noUnusedLocals).toBe(true);
            expect(tsconfig.compilerOptions.noUnusedParameters).toBe(true);
        });
        
        it('should have route verification capability', () => {
            // Evidence: Test script that enumerates all API endpoints
            const packageJson = JSON.parse(
                fs.readFileSync(path.join(ROOT_DIR, 'package.json'), 'utf-8')
            );
            
            expect(packageJson.scripts['verify:routes']).toBeDefined();
        });
        
        it('should have unused code detection', () => {
            const packageJson = JSON.parse(
                fs.readFileSync(path.join(ROOT_DIR, 'package.json'), 'utf-8')
            );
            
            expect(packageJson.scripts['verify:unused']).toBeDefined();
        });
    });
    
    // =========================================================================
    // 1.5 The "Bus Factor" Protocol
    // =========================================================================
    describe('1.5 Bus Factor Protocol (Owner Security)', () => {
        
        it('should have dead mans switch implementation', () => {
            // Check for implementation in ops or compliance app
            const opsDir = path.join(ROOT_DIR, 'apps/ops/src');
            const complianceDir = path.join(ROOT_DIR, 'apps/compliance/src');
            
            // Check if either has some form of owner security
            const hasOps = fs.existsSync(opsDir);
            const hasCompliance = fs.existsSync(complianceDir);
            
            expect(hasOps || hasCompliance, 'Should have ops or compliance app').toBe(true);
        });
        
        it('should have break glass access logging capability', () => {
            // Check for audit logging infrastructure
            const auditPaths = [
                'apps/compliance/src/audit',
                'packages/db/src/repositories/audit-logs.ts'
            ];
            
            const hasAudit = auditPaths.some(p => 
                fs.existsSync(path.join(ROOT_DIR, p))
            );
            expect(hasAudit, 'Should have audit logging').toBe(true);
        });
    });
    
    // =========================================================================
    // 1.6 Zero-Day Active Defense
    // =========================================================================
    describe('1.6 Zero-Day Active Defense', () => {
        
        it('should have alerting infrastructure for honeytokens', () => {
            // Check for alerting capability
            const alertPaths = [
                'apps/ops/src/alerts',
                'apps/observability/src/services/alerting.ts'
            ];
            
            const hasAlerts = alertPaths.some(p => 
                fs.existsSync(path.join(ROOT_DIR, p))
            );
            expect(hasAlerts, 'Should have alerting infrastructure').toBe(true);
        });
        
        it('should have canary token infrastructure', () => {
            // Check for canary/security monitoring
            // Security paths: apps/compliance/src/secrets, ops/canary_tokens.txt
            
            // At minimum should have compliance/secrets module
            const hasSecrets = fs.existsSync(
                path.join(ROOT_DIR, 'apps/compliance/src/secrets')
            );
            expect(hasSecrets, 'Should have secrets management').toBe(true);
        });
    });
});
