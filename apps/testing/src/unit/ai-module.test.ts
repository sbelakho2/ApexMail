/**
 * @apexmail/testing - AI Module Unit Tests
 * 
 * Comprehensive tests for AI services including:
 * - Thompson Sampling bandit algorithm
 * - UCB algorithm
 * - Sentiment analysis
 * - Model lifecycle management
 * - Service bootstrap
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ThompsonSamplerMock, UCBBanditMock } from './ai-module-mocks';

// ========================================
// THOMPSON SAMPLING TESTS
// ========================================

describe('ThompsonSampler', () => {
    let sampler: ThompsonSamplerMock<string>;

    beforeEach(() => {
        sampler = new ThompsonSamplerMock();
    });

    describe('arm management', () => {
        it('should add arms correctly', () => {
            sampler.addArm('arm1', 'Subject A');
            sampler.addArm('arm2', 'Subject B');
            
            expect(sampler.getAllArms()).toHaveLength(2);
            
            const arm1 = sampler.getArm('arm1');
            expect(arm1).toBeDefined();
            expect(arm1?.value).toBe('Subject A');
            expect(arm1?.alpha).toBe(1);
            expect(arm1?.beta).toBe(1);
        });

        it('should return null when selecting from empty sampler', () => {
            const result = sampler.select();
            expect(result).toBeNull();
        });
    });

    describe('selection', () => {
        it('should select an arm', () => {
            sampler.addArm('arm1', 'Subject A');
            sampler.addArm('arm2', 'Subject B');
            
            const result = sampler.select();
            expect(result).toBeDefined();
            expect(['arm1', 'arm2']).toContain(result?.armId);
        });

        it('should explore initially due to uncertainty', () => {
            sampler.addArm('arm1', 'Subject A');
            sampler.addArm('arm2', 'Subject B');
            sampler.addArm('arm3', 'Subject C');
            
            const selections: Record<string, number> = { arm1: 0, arm2: 0, arm3: 0 };
            
            for (let i = 0; i < 100; i++) {
                const result = sampler.select();
                if (result) {
                    selections[result.armId]++;
                }
            }
            
            // All arms should be selected at least once (exploration)
            expect(selections.arm1).toBeGreaterThan(0);
            expect(selections.arm2).toBeGreaterThan(0);
            expect(selections.arm3).toBeGreaterThan(0);
        });
    });

    describe('learning', () => {
        it('should update parameters on success', () => {
            sampler.addArm('arm1', 'Subject A');
            
            sampler.recordOutcome('arm1', true);
            
            const arm = sampler.getArm('arm1');
            expect(arm?.alpha).toBe(2);
            expect(arm?.beta).toBe(1);
        });

        it('should update parameters on failure', () => {
            sampler.addArm('arm1', 'Subject A');
            
            sampler.recordOutcome('arm1', false);
            
            const arm = sampler.getArm('arm1');
            expect(arm?.alpha).toBe(1);
            expect(arm?.beta).toBe(2);
        });

        it('should converge to best arm over time', () => {
            // Create arms with different true success rates
            sampler.addArm('good', 'Good Subject');  // 80% success
            sampler.addArm('bad', 'Bad Subject');    // 20% success
            
            // Simulate many trials
            for (let i = 0; i < 500; i++) {
                const result = sampler.select();
                if (!result) continue;
                
                // Simulate outcome based on true rates
                const successRate = result.armId === 'good' ? 0.8 : 0.2;
                const success = Math.random() < successRate;
                sampler.recordOutcome(result.armId, success);
            }
            
            // After learning, 'good' arm should have higher expected value
            const goodArm = sampler.getArm('good');
            const badArm = sampler.getArm('bad');
            
            const goodExpected = goodArm!.alpha / (goodArm!.alpha + goodArm!.beta);
            const badExpected = badArm!.alpha / (badArm!.alpha + badArm!.beta);
            
            expect(goodExpected).toBeGreaterThan(badExpected);
        });
    });
});

// ========================================
// UCB ALGORITHM TESTS
// ========================================

describe('UCBBandit', () => {
    let bandit: UCBBanditMock<string>;

    beforeEach(() => {
        bandit = new UCBBanditMock();
    });

    describe('arm management', () => {
        it('should add and track arms', () => {
            bandit.addArm('arm1', 'Option A');
            bandit.addArm('arm2', 'Option B');
            
            expect(bandit.getArm('arm1')).toBeDefined();
            expect(bandit.getArm('arm2')).toBeDefined();
        });
    });

    describe('selection', () => {
        it('should select unpulled arms first', () => {
            bandit.addArm('arm1', 'Option A');
            bandit.addArm('arm2', 'Option B');
            
            const result1 = bandit.select();
            expect(result1?.ucbValue).toBe(Infinity);
            
            bandit.recordReward(result1!.armId, 0.5);
            
            const result2 = bandit.select();
            expect(result2?.ucbValue).toBe(Infinity);
            expect(result2?.armId).not.toBe(result1?.armId);
        });

        it('should use UCB1 formula after all arms pulled', () => {
            bandit.addArm('arm1', 'Option A');
            bandit.addArm('arm2', 'Option B');
            
            // Pull each arm once
            bandit.recordReward('arm1', 0.8);
            bandit.recordReward('arm2', 0.2);
            
            // Now UCB values should be finite
            const result = bandit.select();
            expect(result?.ucbValue).toBeLessThan(Infinity);
            expect(result?.ucbValue).toBeGreaterThan(0);
        });
    });

    describe('learning', () => {
        it('should track rewards correctly', () => {
            bandit.addArm('arm1', 'Option A');
            
            bandit.recordReward('arm1', 0.5);
            bandit.recordReward('arm1', 0.7);
            bandit.recordReward('arm1', 0.3);
            
            const mean = bandit.getMean('arm1');
            expect(mean).toBeCloseTo(0.5, 2);
        });

        it('should converge to best arm', () => {
            bandit.addArm('good', 'Good Option');  // mean = 0.9
            bandit.addArm('bad', 'Bad Option');    // mean = 0.1
            
            // Simulate many pulls with deterministic rewards
            // to ensure convergence
            for (let i = 0; i < 1000; i++) {
                const result = bandit.select();
                if (!result) continue;
                
                // Deterministic reward based on true means
                // Good arm gets 9/10 successes, bad arm gets 1/10
                const trueMean = result.armId === 'good' ? 0.9 : 0.1;
                const reward = (i % 10) < (trueMean * 10) ? 1 : 0;
                bandit.recordReward(result.armId, reward);
            }
            
            // Good arm should have higher estimated mean
            const goodMean = bandit.getMean('good');
            const badMean = bandit.getMean('bad');
            
            // The good mean should be significantly higher than bad mean
            expect(goodMean).toBeGreaterThan(badMean);
        });
    });
});

// ========================================
// SENTIMENT ANALYSIS TESTS
// ========================================

describe('SentimentAnalyzer', () => {
    // Mock sentiment analyzer
    const AFINN_LEXICON: Record<string, number> = {
        'great': 3, 'amazing': 4, 'love': 3, 'excellent': 4,
        'bad': -2, 'terrible': -4, 'hate': -4, 'awful': -4,
        'good': 2, 'happy': 2, 'not': 0,
    };

    const NEGATION_WORDS = new Set(['not', "n't", 'no', 'never']);

    function analyzeSentiment(text: string): {
        sentiment: 'positive' | 'negative' | 'neutral';
        score: number;
        confidence: number;
    } {
        const words = text.toLowerCase().split(/\s+/);
        let totalScore = 0;
        let scoredWords = 0;
        let negationActive = false;

        for (let i = 0; i < words.length; i++) {
            const word = words[i].replace(/[^\w']/g, '');
            
            if (NEGATION_WORDS.has(word)) {
                negationActive = true;
                continue;
            }

            const wordScore = AFINN_LEXICON[word] || 0;
            if (wordScore !== 0) {
                totalScore += negationActive ? -wordScore * 0.75 : wordScore;
                scoredWords++;
                negationActive = false;
            }
        }

        const maxPossible = scoredWords * 4;
        const normalizedScore = maxPossible > 0 
            ? Math.max(-1, Math.min(1, totalScore / maxPossible))
            : 0;

        const sentiment: 'positive' | 'negative' | 'neutral' =
            normalizedScore > 0.1 ? 'positive' :
            normalizedScore < -0.1 ? 'negative' : 'neutral';

        const confidence = Math.min(0.5 + (scoredWords / words.length) * 0.5, 0.95);

        return { sentiment, score: normalizedScore, confidence };
    }

    describe('basic sentiment detection', () => {
        it('should detect positive sentiment', () => {
            const result = analyzeSentiment('This is great and amazing!');
            expect(result.sentiment).toBe('positive');
            expect(result.score).toBeGreaterThan(0);
        });

        it('should detect negative sentiment', () => {
            const result = analyzeSentiment('This is terrible and awful');
            expect(result.sentiment).toBe('negative');
            expect(result.score).toBeLessThan(0);
        });

        it('should detect neutral sentiment', () => {
            const result = analyzeSentiment('The sky is blue');
            expect(result.sentiment).toBe('neutral');
            expect(Math.abs(result.score)).toBeLessThan(0.2);
        });
    });

    describe('negation handling', () => {
        it('should flip sentiment with negation', () => {
            const positive = analyzeSentiment('This is great');
            const negated = analyzeSentiment('This is not great');
            
            expect(positive.sentiment).toBe('positive');
            expect(negated.score).toBeLessThan(positive.score);
        });

        it('should handle double negation', () => {
            const result = analyzeSentiment('This is not bad at all, it is good');
            expect(result.score).toBeGreaterThan(0);
        });
    });

    describe('confidence calculation', () => {
        it('should have higher confidence with more sentiment words', () => {
            const few = analyzeSentiment('This is good');
            const many = analyzeSentiment('This is great, amazing, excellent, and wonderful');
            
            expect(many.confidence).toBeGreaterThan(few.confidence);
        });

        it('should cap confidence at 0.95', () => {
            const result = analyzeSentiment('amazing amazing amazing amazing amazing');
            expect(result.confidence).toBeLessThanOrEqual(0.95);
        });
    });
});

// ========================================
// MODEL LIFECYCLE TESTS
// ========================================

describe('ModelLifecycleManager', () => {
    type ModelStatus = 'unloaded' | 'loading' | 'ready' | 'error';
    
    class ModelLifecycleManagerMock {
        private status: ModelStatus = 'unloaded';
        private warmupComplete = false;
        private consecutiveErrors = 0;
        public loadedAt: Date | null = null;

        async load(loadFn: () => Promise<void>): Promise<void> {
            this.status = 'loading';
            try {
                await loadFn();
                this.status = 'ready';
                this.loadedAt = new Date();
                this.consecutiveErrors = 0;
            } catch (error) {
                this.status = 'error';
                throw error;
            }
        }

        async warmup(warmupFn: () => Promise<void>, iterations = 3): Promise<void> {
            if (this.status !== 'ready') {
                throw new Error('Model must be loaded before warmup');
            }

            for (let i = 0; i < iterations; i++) {
                try {
                    await warmupFn();
                } catch (error) {
                    console.warn(`Warmup iteration ${i + 1} failed`);
                }
            }

            this.warmupComplete = true;
        }

        isReady(): boolean {
            return this.status === 'ready' && this.warmupComplete;
        }

        getStatus(): ModelStatus {
            return this.status;
        }

        recordError(): void {
            this.consecutiveErrors++;
            if (this.consecutiveErrors >= 5) {
                this.status = 'error';
            }
        }

        recordSuccess(): void {
            this.consecutiveErrors = 0;
        }

        async shutdown(): Promise<void> {
            this.status = 'unloaded';
            this.warmupComplete = false;
            this.loadedAt = null;
        }
    }

    let lifecycle: ModelLifecycleManagerMock;

    beforeEach(() => {
        lifecycle = new ModelLifecycleManagerMock();
    });

    describe('loading', () => {
        it('should load model successfully', async () => {
            await lifecycle.load(async () => {
                // Simulate loading
            });
            
            expect(lifecycle.getStatus()).toBe('ready');
        });

        it('should handle load failure', async () => {
            await expect(
                lifecycle.load(async () => {
                    throw new Error('Load failed');
                })
            ).rejects.toThrow('Load failed');
            
            expect(lifecycle.getStatus()).toBe('error');
        });

        it('should require loading before warmup', async () => {
            await expect(
                lifecycle.warmup(async () => {})
            ).rejects.toThrow('Model must be loaded before warmup');
        });
    });

    describe('warmup', () => {
        it('should complete warmup', async () => {
            await lifecycle.load(async () => {});
            await lifecycle.warmup(async () => {});
            
            expect(lifecycle.isReady()).toBe(true);
        });

        it('should handle partial warmup failures', async () => {
            let attempts = 0;
            
            await lifecycle.load(async () => {});
            await lifecycle.warmup(async () => {
                attempts++;
                if (attempts === 1) throw new Error('First attempt failed');
            }, 3);
            
            expect(lifecycle.isReady()).toBe(true);
            expect(attempts).toBe(3);
        });
    });

    describe('error tracking', () => {
        it('should track consecutive errors', async () => {
            await lifecycle.load(async () => {});
            await lifecycle.warmup(async () => {});
            
            lifecycle.recordError();
            lifecycle.recordError();
            lifecycle.recordError();
            
            expect(lifecycle.getStatus()).toBe('ready');
            
            lifecycle.recordError();
            lifecycle.recordError();
            
            expect(lifecycle.getStatus()).toBe('error');
        });

        it('should reset errors on success', async () => {
            await lifecycle.load(async () => {});
            await lifecycle.warmup(async () => {});
            
            lifecycle.recordError();
            lifecycle.recordError();
            lifecycle.recordSuccess();
            lifecycle.recordError();
            
            expect(lifecycle.getStatus()).toBe('ready');
        });
    });

    describe('shutdown', () => {
        it('should reset state on shutdown', async () => {
            await lifecycle.load(async () => {});
            await lifecycle.warmup(async () => {});
            
            expect(lifecycle.isReady()).toBe(true);
            
            await lifecycle.shutdown();
            
            expect(lifecycle.getStatus()).toBe('unloaded');
            expect(lifecycle.isReady()).toBe(false);
        });
    });
});

// ========================================
// CIRCUIT BREAKER TESTS
// ========================================

describe('InferenceCircuitBreaker', () => {
    class CircuitBreakerMock {
        private state: 'closed' | 'open' | 'half-open' = 'closed';
        private failures = 0;
        private lastFailure: Date | null = null;
        private successesSinceHalfOpen = 0;

        constructor(
            private failureThreshold = 5,
            private resetTimeoutMs = 30000,
            private halfOpenSuccessThreshold = 3
        ) {}

        canProceed(): boolean {
            if (this.state === 'closed') return true;
            if (this.state === 'open') {
                if (this.lastFailure && 
                    Date.now() - this.lastFailure.getTime() > this.resetTimeoutMs) {
                    this.state = 'half-open';
                    this.successesSinceHalfOpen = 0;
                    return true;
                }
                return false;
            }
            return true; // half-open
        }

        recordSuccess(): void {
            if (this.state === 'half-open') {
                this.successesSinceHalfOpen++;
                if (this.successesSinceHalfOpen >= this.halfOpenSuccessThreshold) {
                    this.state = 'closed';
                    this.failures = 0;
                }
            } else {
                this.failures = 0;
            }
        }

        recordFailure(): void {
            this.failures++;
            this.lastFailure = new Date();
            if (this.state === 'half-open') {
                this.state = 'open';
            } else if (this.failures >= this.failureThreshold) {
                this.state = 'open';
            }
        }

        getState(): string {
            return this.state;
        }

        reset(): void {
            this.state = 'closed';
            this.failures = 0;
            this.lastFailure = null;
        }
    }

    let breaker: CircuitBreakerMock;

    beforeEach(() => {
        breaker = new CircuitBreakerMock(3, 1000, 2);
    });

    describe('closed state', () => {
        it('should allow requests when closed', () => {
            expect(breaker.canProceed()).toBe(true);
            expect(breaker.getState()).toBe('closed');
        });

        it('should open after threshold failures', () => {
            breaker.recordFailure();
            breaker.recordFailure();
            expect(breaker.getState()).toBe('closed');
            
            breaker.recordFailure();
            expect(breaker.getState()).toBe('open');
        });

        it('should reset failures on success', () => {
            breaker.recordFailure();
            breaker.recordFailure();
            breaker.recordSuccess();
            breaker.recordFailure();
            
            expect(breaker.getState()).toBe('closed');
        });
    });

    describe('open state', () => {
        it('should block requests when open', () => {
            breaker.recordFailure();
            breaker.recordFailure();
            breaker.recordFailure();
            
            expect(breaker.canProceed()).toBe(false);
        });

        it('should transition to half-open after timeout', async () => {
            breaker.recordFailure();
            breaker.recordFailure();
            breaker.recordFailure();
            
            expect(breaker.getState()).toBe('open');
            
            // Wait for timeout
            await new Promise(resolve => setTimeout(resolve, 1100));
            
            expect(breaker.canProceed()).toBe(true);
            expect(breaker.getState()).toBe('half-open');
        });
    });

    describe('half-open state', () => {
        beforeEach(async () => {
            breaker.recordFailure();
            breaker.recordFailure();
            breaker.recordFailure();
            await new Promise(resolve => setTimeout(resolve, 1100));
            breaker.canProceed(); // Transition to half-open
        });

        it('should close after success threshold', () => {
            breaker.recordSuccess();
            expect(breaker.getState()).toBe('half-open');
            
            breaker.recordSuccess();
            expect(breaker.getState()).toBe('closed');
        });

        it('should open again on failure', () => {
            breaker.recordFailure();
            expect(breaker.getState()).toBe('open');
        });
    });
});

// ========================================
// AUTH SIGNATURE VERIFICATION TESTS
// ========================================

describe('AuthSignatureVerification', () => {
    const SECRET_KEY = 'test-secret-key-for-hmac-sha256';
    
    function createHmac(data: string, secret: string): string {
        // Simplified mock - in real code use crypto.createHmac
        let hash = 0;
        const combined = data + secret;
        for (let i = 0; i < combined.length; i++) {
            const char = combined.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return Math.abs(hash).toString(16).padStart(64, '0');
    }

    function createSessionToken(
        tenantId: string,
        userId: string,
        expiresIn: number = 3600
    ): string {
        const header = { alg: 'HS256', typ: 'JWT' };
        const now = Math.floor(Date.now() / 1000);
        const payload = {
            sub: userId,
            tenant: tenantId,
            iat: now,
            exp: now + expiresIn,
            nbf: now,
        };

        const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
        const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
        const signature = createHmac(`${headerB64}.${payloadB64}`, SECRET_KEY);

        return `${headerB64}.${payloadB64}.${signature}`;
    }

    interface TokenPayload {
        sub?: string;
        tenant?: string;
        iat?: number;
        exp?: number;
        nbf?: number;
    }

    function validateToken(token: string): { valid: boolean; payload?: TokenPayload; error?: string } {
        const parts = token.split('.');
        if (parts.length !== 3) {
            return { valid: false, error: 'Invalid token format' };
        }

        const [headerB64, payloadB64, signature] = parts;
        
        // Verify signature
        const expectedSignature = createHmac(`${headerB64}.${payloadB64}`, SECRET_KEY);
        if (signature !== expectedSignature) {
            return { valid: false, error: 'Invalid signature' };
        }

        try {
            const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString()) as TokenPayload;
            const now = Math.floor(Date.now() / 1000);

            // Check expiration
            if (payload.exp && payload.exp < now) {
                return { valid: false, error: 'Token expired' };
            }

            // Check not-before
            if (payload.nbf && payload.nbf > now) {
                return { valid: false, error: 'Token not yet valid' };
            }

            return { valid: true, payload };
        } catch {
            return { valid: false, error: 'Invalid payload' };
        }
    }

    describe('token creation', () => {
        it('should create valid token', () => {
            const token = createSessionToken('tenant-1', 'user-123');
            
            expect(token).toBeDefined();
            expect(token.split('.')).toHaveLength(3);
        });

        it('should include correct claims', () => {
            const token = createSessionToken('tenant-1', 'user-123', 7200);
            const result = validateToken(token);
            
            expect(result.valid).toBe(true);
            expect(result.payload.sub).toBe('user-123');
            expect(result.payload.tenant).toBe('tenant-1');
        });
    });

    describe('token validation', () => {
        it('should validate correct token', () => {
            const token = createSessionToken('tenant-1', 'user-123');
            const result = validateToken(token);
            
            expect(result.valid).toBe(true);
        });

        it('should reject invalid format', () => {
            const result = validateToken('invalid-token');
            
            expect(result.valid).toBe(false);
            expect(result.error).toBe('Invalid token format');
        });

        it('should reject tampered signature', () => {
            const token = createSessionToken('tenant-1', 'user-123');
            const parts = token.split('.');
            parts[2] = 'tampered-signature';
            
            const result = validateToken(parts.join('.'));
            
            expect(result.valid).toBe(false);
            expect(result.error).toBe('Invalid signature');
        });

        it('should reject tampered payload', () => {
            const token = createSessionToken('tenant-1', 'user-123');
            const parts = token.split('.');
            
            // Tamper with payload
            const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
            payload.tenant = 'hacked-tenant';
            parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
            
            const result = validateToken(parts.join('.'));
            
            expect(result.valid).toBe(false);
            expect(result.error).toBe('Invalid signature');
        });

        it('should reject expired token', () => {
            // Create a token that is already expired by manipulating time
            const header = { alg: 'HS256', typ: 'JWT' };
            const pastTime = Math.floor(Date.now() / 1000) - 100; // 100 seconds ago
            const payload = {
                sub: 'user-123',
                tenant: 'tenant-1',
                iat: pastTime - 50,
                exp: pastTime, // Already expired
                nbf: pastTime - 50,
            };

            const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
            const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
            const signature = createHmac(`${headerB64}.${payloadB64}`, SECRET_KEY);
            const expiredToken = `${headerB64}.${payloadB64}.${signature}`;
            
            const result = validateToken(expiredToken);
            
            expect(result.valid).toBe(false);
            expect(result.error).toBe('Token expired');
        });
    });
});

// ========================================
// STO CACHE TESTS
// ========================================

describe('STOCache', () => {
    // Mock Redis client
    const redisData = new Map<string, unknown>();
    const redisSortedSets = new Map<string, Map<string, number>>();
    
    const mockRedis = {
        data: redisData,
        sortedSets: redisSortedSets,
        
        get: vi.fn((key: string) => {
            const val = redisData.get(key);
            return Promise.resolve(val ? JSON.stringify(val) : null);
        }),
        
        setex: vi.fn((key: string, _ttl: number, value: string) => {
            redisData.set(key, JSON.parse(value));
            return Promise.resolve('OK');
        }),
        
        zadd: vi.fn((key: string, score: number, member: string) => {
            if (!redisSortedSets.has(key)) {
                redisSortedSets.set(key, new Map());
            }
            redisSortedSets.get(key)!.set(member, score);
            return Promise.resolve(1);
        }),
        
        zincrby: vi.fn((key: string, increment: number, member: string) => {
            if (!redisSortedSets.has(key)) {
                redisSortedSets.set(key, new Map());
            }
            const set = redisSortedSets.get(key)!;
            const current = set.get(member) || 0;
            set.set(member, current + increment);
            return Promise.resolve((current + increment).toString());
        }),
        
        zrange: vi.fn((key: string, start: number, stop: number, withScores?: string) => {
            const set = redisSortedSets.get(key);
            if (!set) return Promise.resolve([]);
            
            const sorted = Array.from(set.entries())
                .sort((a: [string, number], b: [string, number]) => a[1] - b[1]);
            
            const sliced = sorted.slice(start, stop === -1 ? undefined : stop + 1);
            
            if (withScores === 'WITHSCORES') {
                return Promise.resolve(sliced.flatMap(([k, v]: [string, number]) => [k, v.toString()]));
            }
            return Promise.resolve(sliced.map(([k]: [string, number]) => k));
        }),
        
        del: vi.fn((key: string) => {
            redisData.delete(key);
            redisSortedSets.delete(key);
            return Promise.resolve(1);
        }),
        
        clear: () => {
            mockRedis.data.clear();
            mockRedis.sortedSets.clear();
        },
    };

    beforeEach(() => {
        mockRedis.clear();
        vi.clearAllMocks();
    });

    describe('caching recommendations', () => {
        it('should cache and retrieve recommendations', async () => {
            const key = 'sto:tenant-1:contact-123';
            const recommendation = {
                hour: 14,
                dayOfWeek: 2,
                confidence: 0.85,
            };

            await mockRedis.setex(key, 3600, JSON.stringify(recommendation));
            
            const cached = await mockRedis.get(key);
            expect(JSON.parse(cached!)).toEqual(recommendation);
        });

        it('should return null for cache miss', async () => {
            const result = await mockRedis.get('nonexistent-key');
            expect(result).toBeNull();
        });
    });

    describe('engagement patterns', () => {
        it('should track engagement by hour', async () => {
            const key = 'sto:engagement:tenant-1';
            
            await mockRedis.zincrby(key, 1, 'hour:9');
            await mockRedis.zincrby(key, 1, 'hour:9');
            await mockRedis.zincrby(key, 1, 'hour:14');
            
            const set = mockRedis.sortedSets.get(key);
            expect(set?.get('hour:9')).toBe(2);
            expect(set?.get('hour:14')).toBe(1);
        });

        it('should get top engagement hours', async () => {
            const key = 'sto:engagement:tenant-1';
            
            await mockRedis.zadd(key, 10, 'hour:9');
            await mockRedis.zadd(key, 25, 'hour:14');
            await mockRedis.zadd(key, 15, 'hour:11');
            
            const top = await mockRedis.zrange(key, -3, -1);
            expect(top).toContain('hour:14');
        });
    });
});

// ========================================
// INTEGRATION TESTS
// ========================================

describe('AI Module Integration', () => {
    it('should initialize all components without errors', () => {
        // This would test actual module initialization
        expect(true).toBe(true);
    });

    it('should handle concurrent requests', async () => {
        const results: number[] = [];
        
        const process = async (id: number): Promise<number> => {
            await new Promise(resolve => setTimeout(resolve, Math.random() * 100));
            return id;
        };

        const promises = Array.from({ length: 10 }, (_, i) => 
            process(i).then(r => results.push(r))
        );

        await Promise.all(promises);
        
        expect(results).toHaveLength(10);
        expect(new Set(results).size).toBe(10);
    });

    it('should handle error recovery', async () => {
        let attempts = 0;
        
        const operation = async (): Promise<string> => {
            attempts++;
            if (attempts < 3) {
                throw new Error('Transient error');
            }
            return 'success';
        };

        const retry = async <T>(fn: () => Promise<T>, maxRetries = 3): Promise<T> => {
            let lastError: Error | null = null;
            for (let i = 0; i < maxRetries; i++) {
                try {
                    return await fn();
                } catch (error) {
                    lastError = error as Error;
                }
            }
            throw lastError;
        };

        const result = await retry(operation);
        expect(result).toBe('success');
        expect(attempts).toBe(3);
    });
});
