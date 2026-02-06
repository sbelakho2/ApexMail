import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        // Use child processes instead of worker threads.
        // Pino-pretty transports spawn worker_threads.Worker instances
        // that keep vitest's thread-pool workers alive after tests finish.
        // With 'forks', child processes can be SIGKILL'd on timeout.
        pool: 'forks',

        // Force exit after teardown even if open handles remain
        teardownTimeout: 10_000,

        // Default per-test timeout (individual tests can override)
        testTimeout: 60_000,

        // Hook timeout for beforeAll/afterAll
        hookTimeout: 30_000,
    },
});
