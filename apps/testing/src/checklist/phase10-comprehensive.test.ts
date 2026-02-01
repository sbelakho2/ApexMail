/**
 * Phase 10: Operations & SLOs - Comprehensive Tests
 * 
 * Tests based on APEXMAIL_IMPLEMENTATION_CHECKLIST.md
 * Goal: Transparent, high-trust operations with public SLOs.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

// Test utilities
const ROOT_DIR = path.resolve(__dirname, '../../../..');

function fileExists(relativePath: string): boolean {
    return fs.existsSync(path.join(ROOT_DIR, relativePath));
}

function directoryExists(relativePath: string): boolean {
    const fullPath = path.join(ROOT_DIR, relativePath);
    return fs.existsSync(fullPath) && fs.statSync(fullPath).isDirectory();
}

describe('Phase 10: Operations & SLOs (Comprehensive)', () => {
    beforeAll(() => {
        console.log('🧪 Starting Phase 10 Operations & SLOs test suite...');
    });

    afterAll(() => {
        console.log('✅ Phase 10 test suite completed');
    });

    describe('10.0 Operations Infrastructure', () => {
        it('should have ops application', () => {
            expect(directoryExists('apps/ops')).toBe(true);
        });
        
        it('should have ops entry point', () => {
            expect(fileExists('apps/ops/src/index.ts')).toBe(true);
        });
        
        it('should have ops routes', () => {
            expect(fileExists('apps/ops/src/routes.ts')).toBe(true);
        });
        
        it('should have ops types', () => {
            expect(fileExists('apps/ops/src/types.ts')).toBe(true);
        });
    });

    describe('10.1 Public SLOs', () => {
        describe('10.1.1 SLO Management', () => {
            // Evidence Required: /slo page showing live graphs vs targets
            
            it('should have SLO module', () => {
                expect(directoryExists('apps/ops/src/slo')).toBe(true);
            });
        });
        
        describe('10.1.2 Health Checks', () => {
            it('should have health module', () => {
                expect(directoryExists('apps/ops/src/health')).toBe(true);
            });
        });
        
        describe('10.1.3 Status Page', () => {
            // Evidence Required: Status page accessible without login
            
            it('should have status module', () => {
                expect(directoryExists('apps/ops/src/status')).toBe(true);
            });
        });
        
        describe('10.1.4 Trust Center', () => {
            // Evidence Required: /trust page showing uptime and security posture
            
            it('should have trust module', () => {
                expect(directoryExists('apps/ops/src/trust')).toBe(true);
            });
        });
    });

    describe('10.2 Incident Management', () => {
        it('should have incidents module', () => {
            expect(directoryExists('apps/ops/src/incidents')).toBe(true);
        });
    });

    describe('10.3 Metrics & Monitoring', () => {
        it('should have metrics module', () => {
            expect(directoryExists('apps/ops/src/metrics')).toBe(true);
        });
    });

    describe('10.4 Alerting', () => {
        it('should have alerts module', () => {
            expect(directoryExists('apps/ops/src/alerts')).toBe(true);
        });
    });

    describe('10.5 Tracing', () => {
        it('should have tracing module', () => {
            expect(directoryExists('apps/ops/src/tracing')).toBe(true);
        });
    });

    describe('Critical Success Factors for Phase 10', () => {
        describe('CSF: Operational Excellence', () => {
            it('should have all core operational modules', () => {
                expect(directoryExists('apps/ops/src/slo')).toBe(true);
                expect(directoryExists('apps/ops/src/health')).toBe(true);
                expect(directoryExists('apps/ops/src/status')).toBe(true);
                expect(directoryExists('apps/ops/src/trust')).toBe(true);
            });
        });
    });
});
