import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    pool: 'forks',
    teardownTimeout: 10_000,
    testTimeout: 30_000,
    hookTimeout: 15_000,
  },
});
