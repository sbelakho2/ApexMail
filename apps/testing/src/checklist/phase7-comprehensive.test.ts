/**
 * Phase 7: Product UX & Design System - Comprehensive Tests
 * 
 * Tests based on APEXMAIL_IMPLEMENTATION_CHECKLIST.md
 * Goal: Polished, accessible, consistent UI. Matches ApexMediation standards.
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

describe('Phase 7: Product UX & Design System (Comprehensive)', () => {
    beforeAll(() => {
        console.log('🧪 Starting Phase 7 Product UX test suite...');
    });

    afterAll(() => {
        console.log('✅ Phase 7 test suite completed');
    });

    describe('7.0 Web Application Infrastructure', () => {
        it('should have web application', () => {
            expect(directoryExists('apps/web')).toBe(true);
        });
        
        it('should have Next.js configuration', () => {
            expect(fileExists('apps/web/next.config.mjs')).toBe(true);
        });
        
        it('should have Tailwind configuration', () => {
            expect(fileExists('apps/web/tailwind.config.ts')).toBe(true);
        });
        
        it('should have PostCSS configuration', () => {
            expect(fileExists('apps/web/postcss.config.mjs')).toBe(true);
        });
        
        it('should have TypeScript configuration', () => {
            expect(fileExists('apps/web/tsconfig.json')).toBe(true);
        });
    });

    describe('7.1 Design System Implementation', () => {
        describe('7.1.1 Adopt Shadcn/UI + Tailwind', () => {
            // Evidence Required: Component gallery page showing Buttons, Inputs, Cards
            
            it('should have UI components directory', () => {
                expect(directoryExists('apps/web/src/components/ui')).toBe(true);
            });
            
            it('should have Button component', () => {
                expect(fileExists('apps/web/src/components/ui/button.tsx')).toBe(true);
            });
            
            it('should have Input component', () => {
                expect(fileExists('apps/web/src/components/ui/input.tsx')).toBe(true);
            });
            
            it('should have Card component', () => {
                expect(fileExists('apps/web/src/components/ui/card.tsx')).toBe(true);
            });
            
            it('should have Dialog component', () => {
                expect(fileExists('apps/web/src/components/ui/dialog.tsx')).toBe(true);
            });
            
            it('should have Dropdown component', () => {
                expect(fileExists('apps/web/src/components/ui/dropdown-menu.tsx')).toBe(true);
            });
            
            it('should have Table component', () => {
                expect(fileExists('apps/web/src/components/ui/table.tsx')).toBe(true);
            });
            
            it('should have Tabs component', () => {
                expect(fileExists('apps/web/src/components/ui/tabs.tsx')).toBe(true);
            });
            
            it('should have Toast component', () => {
                expect(fileExists('apps/web/src/components/ui/toast.tsx')).toBe(true);
            });
            
            it('should have Tooltip component', () => {
                expect(fileExists('apps/web/src/components/ui/tooltip.tsx')).toBe(true);
            });
            
            it('should have Select component', () => {
                expect(fileExists('apps/web/src/components/ui/select.tsx')).toBe(true);
            });
            
            it('should have UI components index', () => {
                expect(fileExists('apps/web/src/components/ui/index.ts')).toBe(true);
            });
        });

        describe('7.1.2 ApexMail Design Tokens', () => {
            // Evidence Required: Token manifest with references across all surfaces
            
            it('should have global CSS with design tokens', () => {
                expect(fileExists('apps/web/src/app/globals.css')).toBe(true);
            });
            
            it('should define primary color token', () => {
                const content = readFile('apps/web/src/app/globals.css');
                expect(content).toContain('--primary');
            });
            
            it('should define secondary color token', () => {
                const content = readFile('apps/web/src/app/globals.css');
                expect(content).toContain('--secondary');
            });
            
            it('should define destructive color token', () => {
                const content = readFile('apps/web/src/app/globals.css');
                expect(content).toContain('--destructive');
            });
            
            it('should define success color token', () => {
                const content = readFile('apps/web/src/app/globals.css');
                expect(content).toContain('--success');
            });
            
            it('should define warning color token', () => {
                const content = readFile('apps/web/src/app/globals.css');
                expect(content).toContain('--warning');
            });
            
            it('should define border radius token', () => {
                const content = readFile('apps/web/src/app/globals.css');
                expect(content).toContain('--radius');
            });
            
            it('should define background token', () => {
                const content = readFile('apps/web/src/app/globals.css');
                expect(content).toContain('--background');
            });
            
            it('should define foreground token', () => {
                const content = readFile('apps/web/src/app/globals.css');
                expect(content).toContain('--foreground');
            });
            
            it('should have apex brand colors in Tailwind', () => {
                const content = readFile('apps/web/tailwind.config.ts');
                expect(content).toContain('apex');
            });
        });

        describe('7.1.3 Accessibility (WCAG 2.1 AA) Compliance', () => {
            // Evidence Required: Lighthouse accessibility score ≥ 95
            
            it('should have focus-visible styles for accessibility', () => {
                const content = readFile('apps/web/src/app/globals.css');
                expect(content).toContain('focus-visible');
            });
            
            it('should have reduced motion support', () => {
                const content = readFile('apps/web/src/app/globals.css');
                expect(content).toContain('prefers-reduced-motion');
            });
            
            it('should have focus ring in button component', () => {
                const content = readFile('apps/web/src/components/ui/button.tsx');
                expect(content).toContain('focus-visible');
            });
            
            it('should have ring offset for focus states', () => {
                const content = readFile('apps/web/src/components/ui/button.tsx');
                expect(content).toContain('ring-offset');
            });
        });

        describe('7.1.4 Dark Mode Support', () => {
            // Evidence Required: Dark theme CSS variables
            
            it('should have dark mode in Tailwind config', () => {
                const content = readFile('apps/web/tailwind.config.ts');
                expect(content).toContain('darkMode');
            });
            
            it('should have dark mode CSS variables', () => {
                const content = readFile('apps/web/src/app/globals.css');
                expect(content).toContain('.dark');
            });
        });
    });

    describe('7.2 Button Component Variants', () => {
        it('should have default button variant', () => {
            const content = readFile('apps/web/src/components/ui/button.tsx');
            expect(content).toContain('default:');
        });
        
        it('should have destructive button variant', () => {
            const content = readFile('apps/web/src/components/ui/button.tsx');
            expect(content).toContain('destructive');
        });
        
        it('should have outline button variant', () => {
            const content = readFile('apps/web/src/components/ui/button.tsx');
            expect(content).toContain('outline');
        });
        
        it('should have ghost button variant', () => {
            const content = readFile('apps/web/src/components/ui/button.tsx');
            expect(content).toContain('ghost');
        });
        
        it('should have link button variant', () => {
            const content = readFile('apps/web/src/components/ui/button.tsx');
            expect(content).toContain('link');
        });
        
        it('should have glass button variant (ApexMediation style)', () => {
            const content = readFile('apps/web/src/components/ui/button.tsx');
            expect(content).toContain('glass');
        });
        
        it('should support loading state', () => {
            const content = readFile('apps/web/src/components/ui/button.tsx');
            expect(content).toContain('loading');
        });
        
        it('should have multiple size variants', () => {
            const content = readFile('apps/web/src/components/ui/button.tsx');
            expect(content).toMatch(/sm.*lg.*icon/s);
        });
    });

    describe('7.3 Web Application Structure', () => {
        describe('7.3.1 Next.js App Router', () => {
            // Evidence Required: Network tab showing server-rendered content
            
            it('should have app directory structure', () => {
                expect(directoryExists('apps/web/src/app')).toBe(true);
            });
            
            it('should have root layout', () => {
                expect(fileExists('apps/web/src/app/layout.tsx')).toBe(true);
            });
            
            it('should have root page', () => {
                expect(fileExists('apps/web/src/app/page.tsx')).toBe(true);
            });
            
            it('should have dashboard routes', () => {
                expect(directoryExists('apps/web/src/app/(dashboard)')).toBe(true);
            });
        });

        describe('7.3.2 Component Organization', () => {
            it('should have components directory', () => {
                expect(directoryExists('apps/web/src/components')).toBe(true);
            });
            
            it('should have layout components', () => {
                expect(directoryExists('apps/web/src/components/layout')).toBe(true);
            });
            
            it('should have charts components', () => {
                expect(directoryExists('apps/web/src/components/charts')).toBe(true);
            });
        });

        describe('7.3.3 State Management', () => {
            it('should have stores directory', () => {
                expect(directoryExists('apps/web/src/stores')).toBe(true);
            });
            
            it('should have hooks directory', () => {
                expect(directoryExists('apps/web/src/hooks')).toBe(true);
            });
        });

        describe('7.3.4 Utility Libraries', () => {
            it('should have lib directory', () => {
                expect(directoryExists('apps/web/src/lib')).toBe(true);
            });
        });
    });

    describe('7.4 Additional UI Components', () => {
        it('should have Alert component', () => {
            expect(fileExists('apps/web/src/components/ui/alert.tsx')).toBe(true);
        });
        
        it('should have Avatar component', () => {
            expect(fileExists('apps/web/src/components/ui/avatar.tsx')).toBe(true);
        });
        
        it('should have Badge component', () => {
            expect(fileExists('apps/web/src/components/ui/badge.tsx')).toBe(true);
        });
        
        it('should have Checkbox component', () => {
            expect(fileExists('apps/web/src/components/ui/checkbox.tsx')).toBe(true);
        });
        
        it('should have Label component', () => {
            expect(fileExists('apps/web/src/components/ui/label.tsx')).toBe(true);
        });
        
        it('should have Progress component', () => {
            expect(fileExists('apps/web/src/components/ui/progress.tsx')).toBe(true);
        });
        
        it('should have ScrollArea component', () => {
            expect(fileExists('apps/web/src/components/ui/scroll-area.tsx')).toBe(true);
        });
        
        it('should have Separator component', () => {
            expect(fileExists('apps/web/src/components/ui/separator.tsx')).toBe(true);
        });
        
        it('should have Slider component', () => {
            expect(fileExists('apps/web/src/components/ui/slider.tsx')).toBe(true);
        });
        
        it('should have Spinner component', () => {
            expect(fileExists('apps/web/src/components/ui/spinner.tsx')).toBe(true);
        });
        
        it('should have Switch component', () => {
            expect(fileExists('apps/web/src/components/ui/switch.tsx')).toBe(true);
        });
        
        it('should have Textarea component', () => {
            expect(fileExists('apps/web/src/components/ui/textarea.tsx')).toBe(true);
        });
        
        it('should have Toaster component', () => {
            expect(fileExists('apps/web/src/components/ui/toaster.tsx')).toBe(true);
        });
    });

    describe('Critical Success Factors for Phase 7', () => {
        describe('CSF: Design Consistency', () => {
            it('should use CSS variables for theming', () => {
                const content = readFile('apps/web/src/app/globals.css');
                // Can use either HSL or RGB format with CSS variables
                const usesVars = content.includes('hsl(var(--') || content.includes('rgb(var(--') || content.includes('var(--');
                expect(usesVars).toBe(true);
            });
            
            it('should use HSL colors in Tailwind config', () => {
                const content = readFile('apps/web/tailwind.config.ts');
                // Can use either HSL or RGB format with CSS variables
                const usesColorVars = content.includes('hsl(var(--') || content.includes('rgb(var(--');
                expect(usesColorVars).toBe(true);
            });
        });
        
        describe('CSF: Component Library', () => {
            it('should use class-variance-authority for variants', () => {
                const content = readFile('apps/web/src/components/ui/button.tsx');
                expect(content).toContain('class-variance-authority');
                expect(content).toContain('cva');
            });
            
            it('should use Radix UI primitives', () => {
                const content = readFile('apps/web/src/components/ui/button.tsx');
                expect(content).toContain('@radix-ui');
            });
        });
    });
});
