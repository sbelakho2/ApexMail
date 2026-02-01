/**
 * @apexmail/testing - Test Setup
 * 
 * Global setup for all unit and integration tests.
 */

import { beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';

// Mock environment variables
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/apexmail_test';
process.env.REDIS_URL = 'redis://localhost:6379/1';
process.env.JWT_SECRET = 'test-jwt-secret-for-testing-only';

// Global mocks
vi.mock('ioredis', () => ({
    default: vi.fn().mockImplementation(() => ({
        get: vi.fn().mockResolvedValue(null),
        set: vi.fn().mockResolvedValue('OK'),
        del: vi.fn().mockResolvedValue(1),
        expire: vi.fn().mockResolvedValue(1),
        incr: vi.fn().mockResolvedValue(1),
        decr: vi.fn().mockResolvedValue(0),
        hget: vi.fn().mockResolvedValue(null),
        hset: vi.fn().mockResolvedValue(1),
        hdel: vi.fn().mockResolvedValue(1),
        hgetall: vi.fn().mockResolvedValue({}),
        lpush: vi.fn().mockResolvedValue(1),
        rpush: vi.fn().mockResolvedValue(1),
        lpop: vi.fn().mockResolvedValue(null),
        rpop: vi.fn().mockResolvedValue(null),
        lrange: vi.fn().mockResolvedValue([]),
        sadd: vi.fn().mockResolvedValue(1),
        srem: vi.fn().mockResolvedValue(1),
        smembers: vi.fn().mockResolvedValue([]),
        sismember: vi.fn().mockResolvedValue(0),
        zadd: vi.fn().mockResolvedValue(1),
        zrem: vi.fn().mockResolvedValue(1),
        zrange: vi.fn().mockResolvedValue([]),
        zrangebyscore: vi.fn().mockResolvedValue([]),
        zscore: vi.fn().mockResolvedValue(null),
        publish: vi.fn().mockResolvedValue(1),
        subscribe: vi.fn().mockResolvedValue(undefined),
        unsubscribe: vi.fn().mockResolvedValue(undefined),
        on: vi.fn(),
        disconnect: vi.fn(),
        quit: vi.fn().mockResolvedValue('OK'),
    })),
}));

// Setup before all tests
beforeAll(async () => {
    console.log('🧪 Starting test suite...');
});

// Cleanup after all tests
afterAll(async () => {
    console.log('✅ Test suite completed');
});

// Reset mocks before each test
beforeEach(() => {
    vi.clearAllMocks();
});

// Additional cleanup after each test
afterEach(() => {
    vi.restoreAllMocks();
});

// Custom matchers
expect.extend({
    toBeWithinRange(received: number, floor: number, ceiling: number) {
        const pass = received >= floor && received <= ceiling;
        if (pass) {
            return {
                message: () =>
                    `expected ${received} not to be within range ${floor} - ${ceiling}`,
                pass: true,
            };
        } else {
            return {
                message: () =>
                    `expected ${received} to be within range ${floor} - ${ceiling}`,
                pass: false,
            };
        }
    },
    
    toContainObject(received: unknown[], expected: Record<string, unknown>) {
        const pass = received.some((item) =>
            Object.entries(expected).every(
                ([key, value]) => (item as Record<string, unknown>)[key] === value
            )
        );
        if (pass) {
            return {
                message: () =>
                    `expected array not to contain object ${JSON.stringify(expected)}`,
                pass: true,
            };
        } else {
            return {
                message: () =>
                    `expected array to contain object ${JSON.stringify(expected)}`,
                pass: false,
            };
        }
    },
});

// Extend Vitest types
declare module 'vitest' {
    interface Assertion<T> {
        toBeWithinRange(floor: number, ceiling: number): this;
        toContainObject(expected: Record<string, unknown>): this;
    }
}
