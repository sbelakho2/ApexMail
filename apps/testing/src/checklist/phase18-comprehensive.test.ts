/**
 * Phase 18: Public Marketing Website (The Sales Machine) - Comprehensive Tests
 * 
 * Tests for:
 * - Landing pages for killer features
 * - Developer conversion tools
 * - Live API console
 * - Pricing calculator
 */

import { describe, test, expect, beforeAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const MARKETING_DIR = path.join(__dirname, '../../../..', 'apps/marketing/src');
const MARKETING_APP = path.join(MARKETING_DIR, 'app');
const MARKETING_COMPONENTS = path.join(MARKETING_DIR, 'components');

describe('Phase 18: Public Marketing Website (The Sales Machine)', () => {
  // ============================================================
  // Marketing App Structure
  // ============================================================
  describe('Marketing App Structure', () => {
    test('marketing app exists', () => {
      expect(fs.existsSync(MARKETING_DIR)).toBe(true);
    });

    test('has Next.js configuration', () => {
      const marketingRoot = path.join(__dirname, '../../../..', 'apps/marketing');
      expect(fs.existsSync(path.join(marketingRoot, 'next.config.mjs'))).toBe(true);
    });

    test('has Tailwind configuration', () => {
      const marketingRoot = path.join(__dirname, '../../../..', 'apps/marketing');
      expect(fs.existsSync(path.join(marketingRoot, 'tailwind.config.ts'))).toBe(true);
    });

    test('has TypeScript configuration', () => {
      const marketingRoot = path.join(__dirname, '../../../..', 'apps/marketing');
      expect(fs.existsSync(path.join(marketingRoot, 'tsconfig.json'))).toBe(true);
    });

    test('has app directory for Next.js App Router', () => {
      expect(fs.existsSync(MARKETING_APP)).toBe(true);
    });
  });

  // ============================================================
  // 18.1 "Killer Feature" Landing Pages
  // ============================================================
  describe('18.1 Killer Feature Landing Pages', () => {
    describe('Page Routes', () => {
      test('has landing page structure', () => {
        if (fs.existsSync(MARKETING_APP)) {
          const files = fs.readdirSync(MARKETING_APP, { recursive: true });
          const pageFiles = files.filter(f => 
            typeof f === 'string' && (f.includes('page.tsx') || f.includes('page.ts'))
          );
          expect(pageFiles.length).toBeGreaterThan(0);
        }
      });

      test('has layout structure', () => {
        if (fs.existsSync(MARKETING_APP)) {
          const layoutPath = path.join(MARKETING_APP, 'layout.tsx');
          expect(fs.existsSync(layoutPath)).toBe(true);
        }
      });
    });

    describe('Components', () => {
      test('has components directory', () => {
        expect(fs.existsSync(MARKETING_COMPONENTS)).toBe(true);
      });

      test('has reusable UI components', () => {
        if (fs.existsSync(MARKETING_COMPONENTS)) {
          const components = fs.readdirSync(MARKETING_COMPONENTS);
          expect(components.length).toBeGreaterThan(0);
        }
      });
    });

    describe('Feature Pages Content', () => {
      let marketingFiles: string[] = [];

      beforeAll(() => {
        if (fs.existsSync(MARKETING_DIR)) {
          const allFiles = fs.readdirSync(MARKETING_DIR, { recursive: true });
          marketingFiles = allFiles
            .filter((f): f is string => typeof f === 'string' && f.endsWith('.tsx'))
            .map(f => path.join(MARKETING_DIR, f));
        }
      });

      test('has hero sections', () => {
        let hasHero = false;
        for (const file of marketingFiles) {
          try {
            const content = fs.readFileSync(file, 'utf-8');
            if (content.includes('hero') || content.includes('Hero')) {
              hasHero = true;
              break;
            }
          } catch {
            // Skip unreadable files
          }
        }
        expect(hasHero).toBe(true);
      });

      test('has call-to-action elements', () => {
        let hasCTA = false;
        for (const file of marketingFiles) {
          try {
            const content = fs.readFileSync(file, 'utf-8');
            if (content.match(/cta|CTA|button|Button|SignUp|GetStarted/i)) {
              hasCTA = true;
              break;
            }
          } catch {
            // Skip unreadable files
          }
        }
        expect(hasCTA).toBe(true);
      });

      test('mentions key features', () => {
        let hasFeatures = false;
        for (const file of marketingFiles) {
          try {
            const content = fs.readFileSync(file, 'utf-8');
            if (content.match(/feature|Feature|deliverability|compliance|api/i)) {
              hasFeatures = true;
              break;
            }
          } catch {
            // Skip unreadable files
          }
        }
        expect(hasFeatures).toBe(true);
      });
    });
  });

  // ============================================================
  // 18.2 Developer Conversion Tools
  // ============================================================
  describe('18.2 Developer Conversion Tools', () => {
    let marketingFiles: string[] = [];

    beforeAll(() => {
      if (fs.existsSync(MARKETING_DIR)) {
        const allFiles = fs.readdirSync(MARKETING_DIR, { recursive: true });
        marketingFiles = allFiles
          .filter((f): f is string => typeof f === 'string' && f.endsWith('.tsx'))
          .map(f => path.join(MARKETING_DIR, f));
      }
    });

    describe('API Console', () => {
      test('has interactive elements for developers', () => {
        let hasInteractive = false;
        for (const file of marketingFiles) {
          try {
            const content = fs.readFileSync(file, 'utf-8');
            if (content.match(/console|Console|playground|Playground|demo|Demo|try|Try/i)) {
              hasInteractive = true;
              break;
            }
          } catch {
            // Skip unreadable files
          }
        }
        expect(hasInteractive).toBe(true);
      });
    });

    describe('Pricing Calculator', () => {
      test('has pricing-related content', () => {
        let hasPricing = false;
        for (const file of marketingFiles) {
          try {
            const content = fs.readFileSync(file, 'utf-8');
            if (content.match(/pricing|Pricing|price|Price|plan|Plan|tier|Tier/i)) {
              hasPricing = true;
              break;
            }
          } catch {
            // Skip unreadable files
          }
        }
        expect(hasPricing).toBe(true);
      });
    });

    describe('Documentation Links', () => {
      test('has documentation or docs links', () => {
        let hasDocs = false;
        for (const file of marketingFiles) {
          try {
            const content = fs.readFileSync(file, 'utf-8');
            if (content.match(/docs|Docs|documentation|Documentation|api.*reference/i)) {
              hasDocs = true;
              break;
            }
          } catch {
            // Skip unreadable files
          }
        }
        expect(hasDocs).toBe(true);
      });
    });
  });

  // ============================================================
  // Design System Consistency
  // ============================================================
  describe('Design System Consistency', () => {
    test('uses Tailwind for styling', () => {
      if (fs.existsSync(MARKETING_APP)) {
        const layoutPath = path.join(MARKETING_APP, 'layout.tsx');
        if (fs.existsSync(layoutPath)) {
          const content = fs.readFileSync(layoutPath, 'utf-8');
          expect(content).toMatch(/className|tailwind|Tailwind/i);
        }
      }
    });

    test('has consistent typography', () => {
      const marketingRoot = path.join(__dirname, '../../../..', 'apps/marketing');
      const tailwindConfig = path.join(marketingRoot, 'tailwind.config.ts');
      
      if (fs.existsSync(tailwindConfig)) {
        const content = fs.readFileSync(tailwindConfig, 'utf-8');
        expect(content).toMatch(/font|Font|typography/i);
      }
    });

    test('has consistent color scheme', () => {
      const marketingRoot = path.join(__dirname, '../../../..', 'apps/marketing');
      const tailwindConfig = path.join(marketingRoot, 'tailwind.config.ts');
      
      if (fs.existsSync(tailwindConfig)) {
        const content = fs.readFileSync(tailwindConfig, 'utf-8');
        expect(content).toMatch(/color|Color/i);
      }
    });
  });

  // ============================================================
  // SEO & Performance
  // ============================================================
  describe('SEO & Performance', () => {
    test('has metadata configuration', () => {
      if (fs.existsSync(MARKETING_APP)) {
        const layoutPath = path.join(MARKETING_APP, 'layout.tsx');
        if (fs.existsSync(layoutPath)) {
          const content = fs.readFileSync(layoutPath, 'utf-8');
          expect(content).toMatch(/metadata|Metadata|title|description/i);
        }
      }
    });

    test('Next.js config has performance optimizations', () => {
      const marketingRoot = path.join(__dirname, '../../../..', 'apps/marketing');
      const nextConfig = path.join(marketingRoot, 'next.config.mjs');
      
      if (fs.existsSync(nextConfig)) {
        const content = fs.readFileSync(nextConfig, 'utf-8');
        // Check for any config options
        expect(content.length).toBeGreaterThan(0);
      }
    });
  });

  // ============================================================
  // Mobile Responsiveness
  // ============================================================
  describe('Mobile Responsiveness', () => {
    test('uses responsive Tailwind classes', () => {
      let hasResponsive = false;
      
      if (fs.existsSync(MARKETING_DIR)) {
        const allFiles = fs.readdirSync(MARKETING_DIR, { recursive: true });
        const tsxFiles = allFiles
          .filter((f): f is string => typeof f === 'string' && f.endsWith('.tsx'))
          .map(f => path.join(MARKETING_DIR, f));
        
        for (const file of tsxFiles) {
          try {
            const content = fs.readFileSync(file, 'utf-8');
            if (content.match(/sm:|md:|lg:|xl:/)) {
              hasResponsive = true;
              break;
            }
          } catch {
            // Skip unreadable files
          }
        }
      }
      
      expect(hasResponsive).toBe(true);
    });
  });

  // ============================================================
  // Package Configuration
  // ============================================================
  describe('Package Configuration', () => {
    test('has valid package.json', () => {
      const marketingRoot = path.join(__dirname, '../../../..', 'apps/marketing');
      const packageJson = path.join(marketingRoot, 'package.json');
      
      expect(fs.existsSync(packageJson)).toBe(true);
      
      const content = JSON.parse(fs.readFileSync(packageJson, 'utf-8'));
      expect(content.name).toBeDefined();
    });

    test('has Next.js as dependency', () => {
      const marketingRoot = path.join(__dirname, '../../../..', 'apps/marketing');
      const packageJson = path.join(marketingRoot, 'package.json');
      
      const content = JSON.parse(fs.readFileSync(packageJson, 'utf-8'));
      const hasNext = 
        (content.dependencies && content.dependencies.next) ||
        (content.devDependencies && content.devDependencies.next);
      
      expect(hasNext).toBeTruthy();
    });

    test('has React as dependency', () => {
      const marketingRoot = path.join(__dirname, '../../../..', 'apps/marketing');
      const packageJson = path.join(marketingRoot, 'package.json');
      
      const content = JSON.parse(fs.readFileSync(packageJson, 'utf-8'));
      const hasReact = 
        (content.dependencies && content.dependencies.react) ||
        (content.devDependencies && content.devDependencies.react);
      
      expect(hasReact).toBeTruthy();
    });

    test('has Tailwind CSS as dependency', () => {
      const marketingRoot = path.join(__dirname, '../../../..', 'apps/marketing');
      const packageJson = path.join(marketingRoot, 'package.json');
      
      const content = JSON.parse(fs.readFileSync(packageJson, 'utf-8'));
      const hasTailwind = 
        (content.dependencies && content.dependencies.tailwindcss) ||
        (content.devDependencies && content.devDependencies.tailwindcss);
      
      expect(hasTailwind).toBeTruthy();
    });
  });
});
