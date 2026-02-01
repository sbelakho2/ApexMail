/**
 * @apexmail/testing - Chaos Experiments
 * 
 * Defines chaos experiments for resilience testing.
 */

import { ExperimentSpec, Assertion } from './runner.js';

export type ExperimentType =
    | 'network-latency'
    | 'network-partition'
    | 'network-packet-loss'
    | 'cpu-stress'
    | 'memory-stress'
    | 'disk-io-stress'
    | 'service-kill'
    | 'dns-failure'
    | 'http-error'
    | 'database-failure'
    | 'cache-failure'
    | 'queue-failure';

export interface ExperimentResult {
    id: string;
    name: string;
    type: ExperimentType;
    status: 'passed' | 'failed' | 'skipped';
    duration: number;
    assertions: Array<Assertion & { actual: number; passed: boolean }>;
    metrics: Record<string, number>;
    recoveryTime?: number;
    timestamp: Date;
    error?: string;
}

export abstract class ChaosExperiment {
    readonly id: string;
    readonly name: string;
    readonly description: string;
    readonly spec: ExperimentSpec;

    constructor(id: string, name: string, description: string, spec: ExperimentSpec) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.spec = spec;
    }

    abstract inject(): Promise<void>;
    abstract recover(): Promise<void>;
}

/**
 * Network Latency Experiment
 * Injects artificial latency into network requests
 */
export class NetworkLatencyExperiment extends ChaosExperiment {
    private originalProxy: string | undefined;

    constructor(target: string, latencyMs: number) {
        super(
            `network-latency-${target}`,
            `Network Latency - ${target}`,
            `Injects ${latencyMs}ms latency to ${target} service`,
            {
                type: 'network-latency',
                target,
                parameters: { latencyMs },
                assertions: [
                    {
                        metric: 'latency_p99',
                        operator: 'lt',
                        value: 5000,
                        description: 'P99 latency should remain under 5s',
                    },
                    {
                        metric: 'error_rate',
                        operator: 'lt',
                        value: 0.05,
                        description: 'Error rate should stay below 5%',
                    },
                ],
                rollbackOnFailure: true,
            }
        );
    }

    async inject(): Promise<void> {
        const { target, parameters } = this.spec;
        const { latencyMs } = parameters as { latencyMs: number };

        // Using tc (traffic control) for network latency
        // In containerized environment, use tc directly
        // For local testing, we use a proxy approach
        
        console.log(`Injecting ${latencyMs}ms latency to ${target}`);
        
        // Store original state for rollback
        this.originalProxy = process.env.HTTP_PROXY;
        
        // Set up delay proxy (simulated - real implementation would use tc or toxiproxy)
        process.env.CHAOS_LATENCY = String(latencyMs);
        process.env.CHAOS_TARGET = target;
    }

    async recover(): Promise<void> {
        console.log(`Removing latency injection from ${this.spec.target}`);
        
        // Restore original state
        if (this.originalProxy !== undefined) {
            process.env.HTTP_PROXY = this.originalProxy;
        }
        
        delete process.env.CHAOS_LATENCY;
        delete process.env.CHAOS_TARGET;
    }
}

/**
 * Network Partition Experiment
 * Simulates network partitions between services
 */
export class NetworkPartitionExperiment extends ChaosExperiment {
    constructor(service1: string, service2: string) {
        super(
            `network-partition-${service1}-${service2}`,
            `Network Partition - ${service1} <-> ${service2}`,
            `Simulates network partition between ${service1} and ${service2}`,
            {
                type: 'network-partition',
                target: service1,
                parameters: { service1, service2 },
                assertions: [
                    {
                        metric: 'availability',
                        operator: 'gte',
                        value: 0.95,
                        description: 'Service availability should remain above 95%',
                    },
                    {
                        metric: 'circuit_breaker_opens',
                        operator: 'gte',
                        value: 1,
                        description: 'Circuit breaker should activate',
                    },
                ],
                rollbackOnFailure: true,
            }
        );
    }

    async inject(): Promise<void> {
        const { service1, service2 } = this.spec.parameters as { service1: string; service2: string };
        
        console.log(`Creating network partition between ${service1} and ${service2}`);
        
        // Using iptables for network partition (simulated)
        // Real implementation would use: iptables -A OUTPUT -d <service2_ip> -j DROP
        process.env.CHAOS_PARTITION = `${service1}:${service2}`;
    }

    async recover(): Promise<void> {
        console.log(`Removing network partition`);
        delete process.env.CHAOS_PARTITION;
    }
}

/**
 * Packet Loss Experiment
 * Introduces packet loss in network traffic
 */
export class PacketLossExperiment extends ChaosExperiment {
    constructor(target: string, lossPercentage: number) {
        super(
            `packet-loss-${target}`,
            `Packet Loss - ${target}`,
            `Introduces ${lossPercentage}% packet loss to ${target}`,
            {
                type: 'network-packet-loss',
                target,
                parameters: { lossPercentage },
                assertions: [
                    {
                        metric: 'retry_count',
                        operator: 'gt',
                        value: 0,
                        description: 'Retry mechanism should activate',
                    },
                    {
                        metric: 'success_rate',
                        operator: 'gte',
                        value: 0.90,
                        description: 'Success rate should remain above 90% with retries',
                    },
                ],
                rollbackOnFailure: true,
            }
        );
    }

    async inject(): Promise<void> {
        const { target, parameters } = this.spec;
        const { lossPercentage } = parameters as { lossPercentage: number };
        
        console.log(`Injecting ${lossPercentage}% packet loss to ${target}`);
        process.env.CHAOS_PACKET_LOSS = String(lossPercentage);
        process.env.CHAOS_TARGET = target;
    }

    async recover(): Promise<void> {
        console.log(`Removing packet loss from ${this.spec.target}`);
        delete process.env.CHAOS_PACKET_LOSS;
        delete process.env.CHAOS_TARGET;
    }
}

/**
 * CPU Stress Experiment
 * Simulates high CPU load on target service
 */
export class CPUStressExperiment extends ChaosExperiment {
    private stressProcess: NodeJS.Timeout | null = null;

    constructor(target: string, loadPercentage: number) {
        super(
            `cpu-stress-${target}`,
            `CPU Stress - ${target}`,
            `Applies ${loadPercentage}% CPU stress to ${target}`,
            {
                type: 'cpu-stress',
                target,
                parameters: { loadPercentage },
                assertions: [
                    {
                        metric: 'latency_p50',
                        operator: 'lt',
                        value: 2000,
                        description: 'P50 latency should remain under 2s under CPU stress',
                    },
                    {
                        metric: 'throughput',
                        operator: 'gte',
                        value: 50,
                        description: 'Throughput should remain above 50% baseline',
                    },
                ],
                rollbackOnFailure: true,
            }
        );
    }

    async inject(): Promise<void> {
        const { loadPercentage } = this.spec.parameters as { loadPercentage: number };
        
        console.log(`Applying ${loadPercentage}% CPU stress to ${this.spec.target}`);
        
        // Simulated CPU stress - real implementation would use stress-ng
        // stress-ng --cpu 4 --cpu-load ${loadPercentage} --timeout ${duration}s
        
        const workers = Math.ceil(loadPercentage / 25);
        const startStress = () => {
            const arr = new Array(1000000).fill(0);
            arr.sort(() => Math.random() - 0.5);
        };
        
        this.stressProcess = setInterval(() => {
            for (let i = 0; i < workers; i++) {
                startStress();
            }
        }, 100);
    }

    async recover(): Promise<void> {
        console.log(`Removing CPU stress from ${this.spec.target}`);
        
        if (this.stressProcess) {
            clearInterval(this.stressProcess);
            this.stressProcess = null;
        }
    }
}

/**
 * Memory Stress Experiment
 * Simulates memory pressure on target service
 */
export class MemoryStressExperiment extends ChaosExperiment {
    private allocatedMemory: Buffer[] = [];

    constructor(target: string, memoryMB: number) {
        super(
            `memory-stress-${target}`,
            `Memory Stress - ${target}`,
            `Allocates ${memoryMB}MB of memory for ${target}`,
            {
                type: 'memory-stress',
                target,
                parameters: { memoryMB },
                assertions: [
                    {
                        metric: 'oom_events',
                        operator: 'eq',
                        value: 0,
                        description: 'No OOM events should occur',
                    },
                    {
                        metric: 'gc_pause_time',
                        operator: 'lt',
                        value: 1000,
                        description: 'GC pause time should remain under 1s',
                    },
                ],
                rollbackOnFailure: true,
            }
        );
    }

    async inject(): Promise<void> {
        const { memoryMB } = this.spec.parameters as { memoryMB: number };
        
        console.log(`Allocating ${memoryMB}MB of memory for ${this.spec.target}`);
        
        // Allocate memory in chunks
        const chunkSize = 10 * 1024 * 1024; // 10MB chunks
        const chunks = Math.ceil((memoryMB * 1024 * 1024) / chunkSize);
        
        for (let i = 0; i < chunks; i++) {
            const buffer = Buffer.alloc(chunkSize);
            buffer.fill(Math.random() * 255);
            this.allocatedMemory.push(buffer);
        }
    }

    async recover(): Promise<void> {
        console.log(`Releasing allocated memory for ${this.spec.target}`);
        this.allocatedMemory = [];
        global.gc?.(); // Force garbage collection if available
    }
}

/**
 * Service Kill Experiment
 * Simulates service crash/restart
 */
export class ServiceKillExperiment extends ChaosExperiment {
    constructor(target: string) {
        super(
            `service-kill-${target}`,
            `Service Kill - ${target}`,
            `Kills and restarts the ${target} service`,
            {
                type: 'service-kill',
                target,
                parameters: {},
                assertions: [
                    {
                        metric: 'recovery_time',
                        operator: 'lt',
                        value: 30000,
                        description: 'Service should recover within 30 seconds',
                    },
                    {
                        metric: 'data_loss',
                        operator: 'eq',
                        value: 0,
                        description: 'No data loss should occur',
                    },
                ],
                rollbackOnFailure: true,
            }
        );
    }

    async inject(): Promise<void> {
        console.log(`Killing service: ${this.spec.target}`);
        
        // Real implementation would use:
        // docker kill <container_id>
        // or: kubectl delete pod <pod_name>
        
        process.env.CHAOS_KILLED_SERVICE = this.spec.target;
    }

    async recover(): Promise<void> {
        console.log(`Restarting service: ${this.spec.target}`);
        
        // Real implementation would use:
        // docker start <container_id>
        // or: kubectl rollout restart deployment/<deployment_name>
        
        delete process.env.CHAOS_KILLED_SERVICE;
    }
}

/**
 * DNS Failure Experiment
 * Simulates DNS resolution failures
 */
export class DNSFailureExperiment extends ChaosExperiment {
    constructor(target: string) {
        super(
            `dns-failure-${target}`,
            `DNS Failure - ${target}`,
            `Simulates DNS resolution failure for ${target}`,
            {
                type: 'dns-failure',
                target,
                parameters: {},
                assertions: [
                    {
                        metric: 'fallback_activations',
                        operator: 'gte',
                        value: 1,
                        description: 'Fallback mechanism should activate',
                    },
                    {
                        metric: 'cached_responses',
                        operator: 'gt',
                        value: 0,
                        description: 'DNS cache should serve cached entries',
                    },
                ],
                rollbackOnFailure: true,
            }
        );
    }

    async inject(): Promise<void> {
        console.log(`Simulating DNS failure for: ${this.spec.target}`);
        
        // Real implementation would modify /etc/hosts or use dnsmasq
        process.env.CHAOS_DNS_FAILURE = this.spec.target;
    }

    async recover(): Promise<void> {
        console.log(`Restoring DNS for: ${this.spec.target}`);
        delete process.env.CHAOS_DNS_FAILURE;
    }
}

/**
 * HTTP Error Injection Experiment
 * Injects HTTP errors into responses
 */
export class HTTPErrorExperiment extends ChaosExperiment {
    constructor(target: string, errorCode: number, percentage: number) {
        super(
            `http-error-${target}-${errorCode}`,
            `HTTP ${errorCode} - ${target}`,
            `Injects ${errorCode} errors for ${percentage}% of requests to ${target}`,
            {
                type: 'http-error',
                target,
                parameters: { errorCode, percentage },
                assertions: [
                    {
                        metric: 'retry_success_rate',
                        operator: 'gte',
                        value: 0.95,
                        description: 'Retry mechanism should achieve 95% success rate',
                    },
                    {
                        metric: 'user_impact',
                        operator: 'lt',
                        value: 0.01,
                        description: 'User-visible errors should be under 1%',
                    },
                ],
                rollbackOnFailure: true,
            }
        );
    }

    async inject(): Promise<void> {
        const { errorCode, percentage } = this.spec.parameters as { errorCode: number; percentage: number };
        
        console.log(`Injecting ${errorCode} errors for ${percentage}% of requests to ${this.spec.target}`);
        
        process.env.CHAOS_HTTP_ERROR = String(errorCode);
        process.env.CHAOS_HTTP_ERROR_RATE = String(percentage / 100);
        process.env.CHAOS_TARGET = this.spec.target;
    }

    async recover(): Promise<void> {
        console.log(`Removing HTTP error injection from ${this.spec.target}`);
        delete process.env.CHAOS_HTTP_ERROR;
        delete process.env.CHAOS_HTTP_ERROR_RATE;
        delete process.env.CHAOS_TARGET;
    }
}

/**
 * Database Failure Experiment
 * Simulates database connection failures
 */
export class DatabaseFailureExperiment extends ChaosExperiment {
    constructor(connectionPool: string) {
        super(
            `database-failure-${connectionPool}`,
            `Database Failure - ${connectionPool}`,
            `Simulates database connection failure for ${connectionPool}`,
            {
                type: 'database-failure',
                target: connectionPool,
                parameters: {},
                assertions: [
                    {
                        metric: 'read_replica_failover',
                        operator: 'gte',
                        value: 1,
                        description: 'Read replica failover should activate',
                    },
                    {
                        metric: 'connection_recovery_time',
                        operator: 'lt',
                        value: 10000,
                        description: 'Connection should recover within 10 seconds',
                    },
                ],
                rollbackOnFailure: true,
            }
        );
    }

    async inject(): Promise<void> {
        console.log(`Simulating database failure for: ${this.spec.target}`);
        
        // Real implementation would pause/stop database container
        // or block connections via iptables
        process.env.CHAOS_DB_FAILURE = this.spec.target;
    }

    async recover(): Promise<void> {
        console.log(`Restoring database connection: ${this.spec.target}`);
        delete process.env.CHAOS_DB_FAILURE;
    }
}

/**
 * Cache Failure Experiment
 * Simulates Redis/cache failures
 */
export class CacheFailureExperiment extends ChaosExperiment {
    constructor(cacheCluster: string) {
        super(
            `cache-failure-${cacheCluster}`,
            `Cache Failure - ${cacheCluster}`,
            `Simulates cache cluster failure for ${cacheCluster}`,
            {
                type: 'cache-failure',
                target: cacheCluster,
                parameters: {},
                assertions: [
                    {
                        metric: 'cache_bypass_latency',
                        operator: 'lt',
                        value: 3000,
                        description: 'Bypass latency should be under 3 seconds',
                    },
                    {
                        metric: 'database_load_increase',
                        operator: 'lt',
                        value: 3,
                        description: 'Database load should not increase more than 3x',
                    },
                ],
                rollbackOnFailure: true,
            }
        );
    }

    async inject(): Promise<void> {
        console.log(`Simulating cache failure for: ${this.spec.target}`);
        process.env.CHAOS_CACHE_FAILURE = this.spec.target;
    }

    async recover(): Promise<void> {
        console.log(`Restoring cache: ${this.spec.target}`);
        delete process.env.CHAOS_CACHE_FAILURE;
    }
}

/**
 * Queue Failure Experiment
 * Simulates message queue failures
 */
export class QueueFailureExperiment extends ChaosExperiment {
    constructor(queueName: string) {
        super(
            `queue-failure-${queueName}`,
            `Queue Failure - ${queueName}`,
            `Simulates message queue failure for ${queueName}`,
            {
                type: 'queue-failure',
                target: queueName,
                parameters: {},
                assertions: [
                    {
                        metric: 'message_loss',
                        operator: 'eq',
                        value: 0,
                        description: 'No messages should be lost',
                    },
                    {
                        metric: 'dlq_usage',
                        operator: 'gte',
                        value: 0,
                        description: 'Dead letter queue should capture failed messages',
                    },
                ],
                rollbackOnFailure: true,
            }
        );
    }

    async inject(): Promise<void> {
        console.log(`Simulating queue failure for: ${this.spec.target}`);
        process.env.CHAOS_QUEUE_FAILURE = this.spec.target;
    }

    async recover(): Promise<void> {
        console.log(`Restoring queue: ${this.spec.target}`);
        delete process.env.CHAOS_QUEUE_FAILURE;
    }
}

/**
 * Creates a standard set of chaos experiments for ApexMail
 */
export function createStandardExperiments(): ChaosExperiment[] {
    return [
        // Network experiments
        new NetworkLatencyExperiment('api', 500),
        new NetworkLatencyExperiment('api', 2000),
        new NetworkPartitionExperiment('web', 'api'),
        new PacketLossExperiment('api', 10),
        
        // Resource experiments
        new CPUStressExperiment('api', 80),
        new MemoryStressExperiment('worker', 512),
        
        // Service experiments
        new ServiceKillExperiment('worker'),
        new ServiceKillExperiment('api'),
        
        // Infrastructure experiments
        new DNSFailureExperiment('api.internal'),
        new HTTPErrorExperiment('api', 500, 20),
        new HTTPErrorExperiment('api', 503, 30),
        
        // Data layer experiments
        new DatabaseFailureExperiment('primary'),
        new CacheFailureExperiment('redis-cluster'),
        new QueueFailureExperiment('email-queue'),
    ];
}
