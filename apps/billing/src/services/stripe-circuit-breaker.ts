export type CircuitState = 'closed' | 'open' | 'half_open';

export interface CircuitBreakerConfig {
    failureThreshold: number;
    resetTimeoutMs: number;
    slowCallThresholdMs: number;
    slowCallRateThreshold: number;
}

interface CircuitBreakerState {
    state: CircuitState;
    failureCount: number;
    successCount: number;
    slowCallCount: number;
    totalCalls: number;
    lastFailureTime: number | null;
    lastStateChange: number;
}

const DEFAULT_CIRCUIT_CONFIG: CircuitBreakerConfig = {
    failureThreshold: 5,
    resetTimeoutMs: 30000,
    slowCallThresholdMs: 10000,
    slowCallRateThreshold: 80,
};

export class StripeCircuitBreaker {
    private state: CircuitBreakerState = {
        state: 'closed',
        failureCount: 0,
        successCount: 0,
        slowCallCount: 0,
        totalCalls: 0,
        lastFailureTime: null,
        lastStateChange: Date.now(),
    };

    constructor(private readonly config: CircuitBreakerConfig = DEFAULT_CIRCUIT_CONFIG) {}

    async execute<T>(fn: () => Promise<T>): Promise<T> {
        if (this.state.state === 'open') {
            const timeSinceLastFailure = Date.now() - (this.state.lastFailureTime ?? 0);
            if (timeSinceLastFailure >= this.config.resetTimeoutMs) {
                this.transitionTo('half_open');
            } else {
                throw new Error(
                    `Stripe API circuit breaker is OPEN. ` +
                    `Retry after ${Math.ceil((this.config.resetTimeoutMs - timeSinceLastFailure) / 1000)}s`
                );
            }
        }

        const startTime = Date.now();
        try {
            const result = await fn();
            this.recordSuccess(Date.now() - startTime);
            return result;
        } catch (error) {
            this.recordFailure();
            throw error;
        }
    }

    getState(): CircuitState {
        return this.state.state;
    }

    getStats(): CircuitBreakerState & { config: CircuitBreakerConfig } {
        return { ...this.state, config: this.config };
    }

    private recordSuccess(durationMs: number): void {
        this.state.totalCalls++;
        this.state.successCount++;

        if (durationMs > this.config.slowCallThresholdMs) {
            this.state.slowCallCount++;
        }

        if (this.state.state === 'half_open') {
            this.transitionTo('closed');
        }

        if (this.state.state === 'closed' && this.state.totalCalls >= 10) {
            const slowCallRate = (this.state.slowCallCount / this.state.totalCalls) * 100;
            if (slowCallRate >= this.config.slowCallRateThreshold) {
                this.transitionTo('open');
            }
        }
    }

    private recordFailure(): void {
        this.state.failureCount++;
        this.state.totalCalls++;
        this.state.lastFailureTime = Date.now();

        if (this.state.state === 'half_open' || this.state.failureCount >= this.config.failureThreshold) {
            this.transitionTo('open');
        }
    }

    private transitionTo(newState: CircuitState): void {
        this.state.state = newState;
        this.state.lastStateChange = Date.now();

        if (newState === 'closed') {
            this.state.failureCount = 0;
            this.state.successCount = 0;
            this.state.slowCallCount = 0;
            this.state.totalCalls = 0;
        }
    }
}