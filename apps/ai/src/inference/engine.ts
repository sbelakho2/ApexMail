/**
 * @apexmail/ai — llama.cpp Server Inference Engine
 *
 * Talks to a local llama-server (llama.cpp) sidecar over its
 * OpenAI-compatible /v1/chat/completions endpoint.
 *
 * Why llama-server instead of ONNX Runtime:
 *  - Zero native Node.js module headaches
 *  - Hot-reloadable model (just restart the sidecar)
 *  - Streaming out of the box
 *  - Trivially swappable to a hosted model (GPT-4o, etc.)
 *  - CPU-optimised SIMD kernels (AVX2/AVX512/NEON) via llama.cpp
 *
 * The engine keeps the same public API surface as the old ONNX engine
 * so all callers (unified.ts, routes.ts, bootstrap.ts) keep working.
 */

import { EventEmitter } from 'events';
import type {
    InferenceConfig,
    InferenceResult,
    EmbeddingResult,
    TokenizeResult,
    ModelInfo,
    ModelStatus,
    ModelMetrics,
} from '../types.js';

// ════════════════════════════════════════════════════════════════
// CONFIG
// ════════════════════════════════════════════════════════════════

const DEFAULT_CONFIG: InferenceConfig = {
    modelPath: './models/qwen3-8b-q4_k_m.gguf',
    modelName: 'qwen3-8b-apexmail',
    maxTokens: 768,
    temperature: 0.0,          // greedy — matches training config
    topP: 0.95,
    topK: 50,
    repetitionPenalty: 1.15,   // matches inference config
    stopSequences: ['<|im_end|>', '<|endoftext|>'],
    useGPU: false,
    numThreads: 4,
    contextLength: 8192,
};

/** llama-server connection settings (override via env vars) */
interface LlamaServerConfig {
    /** Base URL of the llama-server process */
    baseUrl: string;
    /** Request timeout in ms */
    timeoutMs: number;
    /** Retry count for transient failures */
    maxRetries: number;
    /** Back-off base in ms between retries */
    retryBackoffMs: number;
}

function getLlamaServerConfig(): LlamaServerConfig {
    return {
        baseUrl: process.env.LLAMA_SERVER_URL ?? 'http://127.0.0.1:8081',
        timeoutMs: Number(process.env.LLAMA_TIMEOUT_MS ?? 30_000),
        maxRetries: Number(process.env.LLAMA_MAX_RETRIES ?? 2),
        retryBackoffMs: Number(process.env.LLAMA_RETRY_BACKOFF_MS ?? 500),
    };
}

// ════════════════════════════════════════════════════════════════
// OPENAI-COMPAT TYPES (subset that llama-server exposes)
// ════════════════════════════════════════════════════════════════

interface OAIMessage {
    role: 'system' | 'user' | 'assistant';
    content: string;
}

interface OAIChatRequest {
    model: string;
    messages: OAIMessage[];
    max_tokens?: number;
    temperature?: number;
    top_p?: number;
    top_k?: number;
    repeat_penalty?: number;
    stop?: string[];
    stream?: boolean;
}

interface OAIChatChoice {
    index: number;
    message: OAIMessage;
    finish_reason: 'stop' | 'length';
}

interface OAIUsage {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
}

interface OAIChatResponse {
    id: string;
    object: string;
    created: number;
    model: string;
    choices: OAIChatChoice[];
    usage: OAIUsage;
}

interface OAIEmbeddingRequest {
    model: string;
    input: string | string[];
}

interface OAIEmbeddingObject {
    index: number;
    embedding: number[];
}

interface OAIEmbeddingResponse {
    object: string;
    data: OAIEmbeddingObject[];
    model: string;
    usage: { prompt_tokens: number; total_tokens: number };
}

// llama-server /health response
interface LlamaHealthResponse {
    status: 'ok' | 'loading model' | 'error' | 'no slot available';
}

// ════════════════════════════════════════════════════════════════
// SIMPLE TOKENIZER (kept for token counting / tokenize() compat)
// ════════════════════════════════════════════════════════════════

class SimpleTokenizer {
    private vocab: Map<string, number> = new Map();
    private reverseVocab: Map<number, string> = new Map();
    private specialTokens: Map<string, number>;
    private sortedSpecialTokens: Array<[string, number]>;

    constructor() {
        this.specialTokens = new Map([
            ['<|im_start|>', 151644],
            ['<|im_end|>', 151645],
            ['<|endoftext|>', 151643],
            ['<|pad|>', 151646],
        ]);
        this.sortedSpecialTokens = [...this.specialTokens.entries()]
            .sort((a, b) => b[0].length - a[0].length);
        this.initializeVocab();
    }

    private initializeVocab(): void {
        for (const [token, id] of this.sortedSpecialTokens) {
            this.vocab.set(token, id);
            this.reverseVocab.set(id, token);
        }
        const basicChars =
            'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?\'"' +
            '-:;()[]{}@#$%^&*+=<>/\\|`~\n\t';
        let id = 100;
        for (const char of basicChars) {
            if (!this.vocab.has(char)) {
                this.vocab.set(char, id);
                this.reverseVocab.set(id, char);
                id++;
            }
        }
    }

    encode(text: string): number[] {
        const tokens: number[] = [];
        let i = 0;
        while (i < text.length) {
            let matched = false;
            for (const [token, tid] of this.sortedSpecialTokens) {
                if (text.startsWith(token, i)) {
                    tokens.push(tid);
                    i += token.length;
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                tokens.push(this.vocab.get(text[i]) ?? 0);
                i++;
            }
        }
        return tokens;
    }

    decode(tokens: number[]): string {
        return tokens.map((id) => this.reverseVocab.get(id) ?? '').join('');
    }
}

// ════════════════════════════════════════════════════════════════
// INFERENCE ENGINE (llama-server HTTP client)
// ════════════════════════════════════════════════════════════════

/**
 * Drop-in replacement for the old ONNX InferenceEngine.
 *
 * Instead of loading an ONNX model in-process, this talks to a
 * llama-server sidecar over HTTP.  The public API surface is identical
 * so all callers keep working without changes.
 */
export class InferenceEngine extends EventEmitter {
    private tokenizer: SimpleTokenizer;
    private config: InferenceConfig;
    private serverConfig: LlamaServerConfig;
    private metrics: ModelMetrics;
    private status: ModelStatus = 'unloaded';
    private loadedAt: Date | null = null;
    private loadingPromise: Promise<void> | null = null;

    constructor(config?: Partial<InferenceConfig>) {
        super();
        this.config = { ...DEFAULT_CONFIG, ...config };
        this.serverConfig = getLlamaServerConfig();
        this.tokenizer = new SimpleTokenizer();
        this.metrics = {
            requestCount: 0,
            avgLatencyMs: 0,
            errorRate: 0,
            tokensProcessed: 0,
        };
    }

    // ── Model lifecycle ───────────────────────────────────────

    /**
     * "Loading" the model means verifying llama-server is reachable
     * and the model is ready to accept requests.
     */
    async loadModel(_modelPath?: string): Promise<void> {
        if (this.loadingPromise) return this.loadingPromise;
        if (this.status === 'ready') return;

        this.loadingPromise = this._waitForServer();
        try {
            await this.loadingPromise;
        } finally {
            this.loadingPromise = null;
        }
    }

    private async _waitForServer(): Promise<void> {
        this.status = 'loading';
        this.emit('status', this.status);
        const { baseUrl, timeoutMs } = this.serverConfig;

        const deadline = Date.now() + timeoutMs;
        let lastError: string | undefined;

        while (Date.now() < deadline) {
            try {
                const res = await fetch(`${baseUrl}/health`, {
                    signal: AbortSignal.timeout(3000),
                });
                if (res.ok) {
                    const body = (await res.json()) as LlamaHealthResponse;
                    if (body.status === 'ok') {
                        this.status = 'ready';
                        this.loadedAt = new Date();
                        this.emit('status', this.status);
                        this.emit('loaded', this.getModelInfo());
                        console.log(
                            `✅ [AI] llama-server ready at ${baseUrl} ` +
                            `(model: ${this.config.modelName})`,
                        );
                        return;
                    }
                    lastError = `server status: ${body.status}`;
                } else {
                    lastError = `HTTP ${res.status}`;
                }
            } catch (err) {
                lastError = String(err);
            }
            // wait 500 ms before retry
            await new Promise((r) => setTimeout(r, 500));
        }

        this.status = 'error';
        this.emit('status', this.status);
        this.emit('error', new Error(`llama-server not ready: ${lastError}`));
        throw new Error(
            `llama-server at ${baseUrl} not ready after ${timeoutMs}ms: ${lastError}`,
        );
    }

    async unloadModel(): Promise<void> {
        // nothing to release — the sidecar owns the model
        this.status = 'unloaded';
        this.loadedAt = null;
        this.emit('status', this.status);
    }

    // ── Core inference ────────────────────────────────────────

    /**
     * Generate text from a raw prompt string.
     * Wraps the prompt in a single user message and calls chat().
     */
    async generate(
        prompt: string,
        options?: Partial<InferenceConfig>,
    ): Promise<InferenceResult> {
        return this.chat(
            [{ role: 'user', content: prompt }],
            options,
        );
    }

    /**
     * Chat completion via llama-server's /v1/chat/completions.
     */
    async chat(
        messages: Array<{ role: string; content: string }>,
        options?: Partial<InferenceConfig>,
    ): Promise<InferenceResult> {
        const startTime = Date.now();
        const cfg = { ...this.config, ...options };

        if (this.status !== 'ready') {
            await this.loadModel();
        }

        const body: OAIChatRequest = {
            model: cfg.modelName,
            messages: messages.map((m) => ({
                role: m.role as OAIMessage['role'],
                content: m.content,
            })),
            max_tokens: cfg.maxTokens,
            temperature: cfg.temperature,
            top_p: cfg.topP,
            top_k: cfg.topK,
            repeat_penalty: cfg.repetitionPenalty,
            stop: cfg.stopSequences,
            stream: false,
        };

        const data = await this.fetchWithRetry<OAIChatResponse>(
            '/v1/chat/completions',
            body,
        );

        const choice = data.choices[0];
        const usage = data.usage;
        const latencyMs = Date.now() - startTime;

        this.updateMetrics(latencyMs, usage.total_tokens, false);

        return {
            text: choice?.message?.content ?? '',
            tokens: usage.total_tokens,
            promptTokens: usage.prompt_tokens,
            completionTokens: usage.completion_tokens,
            latencyMs,
            model: data.model || cfg.modelName,
            finishReason: (choice?.finish_reason as 'stop' | 'length') ?? 'stop',
        };
    }

    /**
     * Generate embeddings via /v1/embeddings (if llama-server was
     * started with --embedding).  Falls back to synthetic embeddings
     * if the endpoint is not available.
     */
    async embed(text: string): Promise<EmbeddingResult> {
        const startTime = Date.now();

        if (this.status !== 'ready') {
            await this.loadModel();
        }

        try {
            const data = await this.fetchWithRetry<OAIEmbeddingResponse>(
                '/v1/embeddings',
                { model: this.config.modelName, input: text } as OAIEmbeddingRequest,
            );

            const vec = data.data[0]?.embedding ?? [];
            const latencyMs = Date.now() - startTime;
            this.updateMetrics(latencyMs, data.usage?.prompt_tokens ?? 0, false);

            return {
                embedding: vec,
                dimensions: vec.length,
                model: data.model || this.config.modelName,
                latencyMs,
            };
        } catch {
            // Embedding endpoint not enabled — fall back to hash-based mock
            const tokens = this.tokenizer.encode(text);
            const dimensions = 384;
            const embedding = this.generateMockEmbedding(tokens, dimensions);
            const latencyMs = Date.now() - startTime;
            return { embedding, dimensions, model: this.config.modelName, latencyMs };
        }
    }

    async embedBatch(texts: string[]): Promise<EmbeddingResult[]> {
        return Promise.all(texts.map((t) => this.embed(t)));
    }

    // ── Tokenizer utilities ───────────────────────────────────

    tokenize(text: string): TokenizeResult {
        const tokens = this.tokenizer.encode(text);
        return { tokens, tokenCount: tokens.length };
    }

    cosineSimilarity(a: number[], b: number[]): number {
        if (a.length !== b.length) {
            throw new Error('Embeddings must have the same dimensions');
        }
        let dot = 0, normA = 0, normB = 0;
        for (let i = 0; i < a.length; i++) {
            dot += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }
        const denom = Math.sqrt(normA) * Math.sqrt(normB);
        return denom === 0 ? 0 : dot / denom;
    }

    // ── Info & config ─────────────────────────────────────────

    getModelInfo(): ModelInfo {
        return {
            name: this.config.modelName,
            version: '1.0.0',
            type: 'llm',
            size: 4_500_000_000, // ~4.5 GB Q4_K_M
            loadedAt: this.loadedAt ?? undefined,
            status: this.status,
            metrics: this.metrics,
        };
    }

    getConfig(): InferenceConfig {
        return { ...this.config };
    }

    setConfig(config: Partial<InferenceConfig>): void {
        this.config = { ...this.config, ...config };
    }

    /** Expose server URL for health-check routes */
    getServerUrl(): string {
        return this.serverConfig.baseUrl;
    }

    // ════════════════════════════════════════════════════════════
    // PRIVATE
    // ════════════════════════════════════════════════════════════

    /**
     * POST JSON to llama-server with retries on transient errors.
     */
    private async fetchWithRetry<T>(path: string, body: unknown): Promise<T> {
        const { baseUrl, timeoutMs, maxRetries, retryBackoffMs } = this.serverConfig;
        const url = `${baseUrl}${path}`;

        let lastError: Error | undefined;

        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                const res = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body),
                    signal: AbortSignal.timeout(timeoutMs),
                });

                if (!res.ok) {
                    const text = await res.text().catch(() => '');
                    throw new Error(`llama-server ${res.status}: ${text}`);
                }

                return (await res.json()) as T;
            } catch (err) {
                lastError = err instanceof Error ? err : new Error(String(err));

                // Don't retry on 4xx client errors
                if (lastError.message.includes('400') || lastError.message.includes('422')) {
                    throw lastError;
                }

                if (attempt < maxRetries) {
                    await new Promise((r) =>
                        setTimeout(r, retryBackoffMs * (attempt + 1)),
                    );
                }
            }
        }

        this.updateMetrics(0, 0, true);
        throw lastError ?? new Error('llama-server request failed');
    }

    private generateMockEmbedding(tokens: number[], dimensions: number): number[] {
        const embedding = new Array(dimensions).fill(0);
        for (let i = 0; i < dimensions; i++) {
            let sum = 0;
            for (let j = 0; j < tokens.length; j++) {
                sum += Math.sin(tokens[j] * (i + 1) * 0.01) * Math.cos(j * 0.1);
            }
            embedding[i] = sum / tokens.length;
        }
        const norm = Math.sqrt(embedding.reduce((s, v) => s + v * v, 0));
        return norm === 0 ? embedding : embedding.map((v) => v / norm);
    }

    private updateMetrics(latencyMs: number, tokens: number, isError: boolean): void {
        this.metrics.requestCount++;
        this.metrics.tokensProcessed += tokens;
        this.metrics.lastUsed = new Date();

        this.metrics.avgLatencyMs =
            (this.metrics.avgLatencyMs * (this.metrics.requestCount - 1) + latencyMs) /
            this.metrics.requestCount;

        if (isError) {
            this.metrics.errorRate =
                (this.metrics.errorRate * (this.metrics.requestCount - 1) + 1) /
                this.metrics.requestCount;
        } else {
            this.metrics.errorRate =
                (this.metrics.errorRate * (this.metrics.requestCount - 1)) /
                this.metrics.requestCount;
        }
    }
}

export { SimpleTokenizer, DEFAULT_CONFIG };
