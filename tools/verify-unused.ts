/**
 * Unused Code Verifier
 * Finds unused exports and imports in the codebase
 */

import { execSync } from 'child_process';
import { existsSync } from 'fs';
import { join } from 'path';

function verifyUnused() {
  console.log('🔍 Checking for unused code...\n');

  try {
    // Check if eslint-plugin-unused-imports is configured
    const eslintConfig = join(process.cwd(), '.eslintrc.json');
    if (!existsSync(eslintConfig)) {
      console.log('⚠️  .eslintrc.json not found');
      console.log('   Creating basic config...\n');
      createEslintConfig();
    }

    // Run eslint with unused-imports plugin
    console.log('Running ESLint with unused-imports check...\n');
    
    const result = execSync('pnpm lint 2>&1', {
      encoding: 'utf-8',
      maxBuffer: 10 * 1024 * 1024,
    });

    console.log(result);

    // Parse results
    const unusedMatches = result.match(/unused-imports/g) || [];
    const unusedCount = unusedMatches.length;

    if (unusedCount > 0) {
      console.log(`\n⚠️  Found ${unusedCount} unused imports/exports`);
      console.log('   Run "pnpm lint --fix" to auto-fix');
      process.exit(1);
    } else {
      console.log('\n✅ No unused code found!');
    }
  } catch (error) {
    if (error instanceof Error && 'stdout' in error) {
      const stdout = (error as any).stdout?.toString() || '';
      if (stdout.includes('unused-imports')) {
        const unusedMatches = stdout.match(/unused-imports/g) || [];
        console.log(`\n⚠️  Found ${unusedMatches.length} unused imports/exports`);
        console.log('   Run "pnpm lint --fix" to auto-fix');
        process.exit(1);
      }
    }
    console.error('❌ Error running unused check:', error);
    process.exit(1);
  }
}

function createEslintConfig() {
  const fs = require('fs');
  const config = {
    root: true,
    parser: '@typescript-eslint/parser',
    plugins: ['@typescript-eslint', 'unused-imports'],
    extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended'],
    rules: {
      'unused-imports/no-unused-imports': 'error',
      'unused-imports/no-unused-vars': [
        'warn',
        {
          vars: 'all',
          varsIgnorePattern: '^_',
          args: 'after-used',
          argsIgnorePattern: '^_',
        },
      ],
    },
  };

  fs.writeFileSync('.eslintrc.json', JSON.stringify(config, null, 2));
  console.log('✓ Created .eslintrc.json');
}

if (require.main === module) {
  verifyUnused();
}

export { verifyUnused };
