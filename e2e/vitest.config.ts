import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/repo/**/*.spec.ts', 'tests/api/**/*.spec.ts', 'tests/services/**/*.spec.ts'],
    hookTimeout: 60_000,
    testTimeout: 60_000,
    reporters: ['verbose'],
    sequence: {
      hooks: 'stack',
    },
  },
});
