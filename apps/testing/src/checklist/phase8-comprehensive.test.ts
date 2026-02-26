/**
 * Phase 8: AI Training Suite - Architecture Tests
 *
 * Current architecture uses Python training pipelines under apps/ai/training.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

// Test utilities
const ROOT_DIR = path.resolve(__dirname, '../../../..');

function fileExists(relativePath: string): boolean {
    return fs.existsSync(path.join(ROOT_DIR, relativePath));
}

function readFile(relativePath: string): string {
    const fullPath = path.join(ROOT_DIR, relativePath);
    if (!fs.existsSync(fullPath)) {
        throw new Error(`File not found: ${relativePath}`);
    }
    return fs.readFileSync(fullPath, 'utf-8');
}

function directoryExists(relativePath: string): boolean {
    const fullPath = path.join(ROOT_DIR, relativePath);
    return fs.existsSync(fullPath) && fs.statSync(fullPath).isDirectory();
}

describe('Phase 8: AI Training Suite (Current Architecture)', () => {
    beforeAll(() => {
        console.log('🧪 Starting Phase 8 AI Intelligence test suite...');
    });

    afterAll(() => {
        console.log('✅ Phase 8 test suite completed');
    });

    describe('8.0 AI Training Infrastructure', () => {
        it('should have AI application directory', () => {
            expect(directoryExists('apps/ai')).toBe(true);
        });

        it('should have training workspace', () => {
            expect(directoryExists('apps/ai/training')).toBe(true);
        });
    });

    describe('8.1 Training Pipeline', () => {
        it('should have training configuration', () => {
            expect(fileExists('apps/ai/training/config.yaml')).toBe(true);
        });

        it('should have pipeline entrypoint', () => {
            expect(fileExists('apps/ai/training/pipeline.sh')).toBe(true);
        });

        it('should have training script', () => {
            expect(fileExists('apps/ai/training/train.py')).toBe(true);
        });

        it('should have validation script', () => {
            expect(fileExists('apps/ai/training/validate_pipeline.py')).toBe(true);
        });
    });

    describe('8.2 Dataset Tooling', () => {
        it('should support dataset generation', () => {
            expect(fileExists('apps/ai/training/generate_dataset.py')).toBe(true);
        });

        it('should include prompt templates', () => {
            expect(fileExists('apps/ai/training/prompts_v2.py')).toBe(true);
        });
    });
});
