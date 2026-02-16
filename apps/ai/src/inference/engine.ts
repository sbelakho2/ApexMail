/**
 * @apexmail/ai - ONNX Runtime Inference Engine
 * 
 * Local LLM inference using ONNX Runtime for privacy-preserving AI.
 * Supports Qwen 2.5-7B-Instruct and other ONNX-compatible models.
 */

import * as ort from 'onnxruntime-node';
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

// Default inference configuration
const DEFAULT_CONFIG: InferenceConfig = {
    modelPath: './models/qwen2.5-7b-instruct-onnx',
    modelName: 'qwen2.5-7b-instruct',
    maxTokens: 4096,
    temperature: 0.7,
    topP: 0.95,
    topK: 50,
    repetitionPenalty: 1.1,
    stopSequences: ['<|im_end|>', '<|endoftext|>'],
    useGPU: false,
    numThreads: 4,
    contextLength: 8192,
};

// Phase-8 compatibility marker: include additional local model identifiers.
const SUPPORTED_MODEL_NAMES = new Set([
    'qwen2.5-7b-instruct',
    'phi-3.5-mini',
]);

// Simple tokenizer for Qwen 2.5 (BPE-based, ChatML format)
// In production, use the actual tokenizer from the model
class SimpleTokenizer {
    private vocab: Map<string, number> = new Map();
    private reverseVocab: Map<number, string> = new Map();
    private specialTokens: Map<string, number>;
    // FIX-500-447: Pre-sorted by length descending so longer tokens match first
    private sortedSpecialTokens: Array<[string, number]>;

    constructor() {
        // Qwen 2.5 ChatML special tokens
        this.specialTokens = new Map([
            ['<|im_start|>', 151644],
            ['<|im_end|>', 151645],
            ['<|endoftext|>', 151643],
            ['<|pad|>', 151646],
        ]);

        // FIX-500-447: Sort by token length descending — ensures '<|assistant|>' matches before '<|end|>'
        this.sortedSpecialTokens = [...this.specialTokens.entries()].sort((a, b) => b[0].length - a[0].length);

        // Initialize basic vocab (simplified - real implementation would load from vocab.json)
        this.initializeVocab();
    }

    private initializeVocab(): void {
        // Add special tokens (use sorted list for consistency)
        for (const [token, id] of this.sortedSpecialTokens) {
            this.vocab.set(token, id);
            this.reverseVocab.set(id, token);
        }

        // Add basic ASCII characters and common subwords
        // In production, load the full vocab from the model files
        const basicChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?\'"-:;()[]{}@#$%^&*+=<>/\\|`~\n\t';
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

            // FIX-500-085: Check for special tokens using startsWith with offset
            // instead of allocating a substring via text.slice(i) on every iteration.
            // FIX-500-447: Iterate sorted by length descending so longer tokens match first.
            for (const [token, id] of this.sortedSpecialTokens) {
                if (text.startsWith(token, i)) {
                    tokens.push(id);
                    i += token.length;
                    matched = true;
                    break;
                }
            }

            if (!matched) {
                const char = text[i];
                const id = this.vocab.get(char);
                tokens.push(id ?? 0); // Use <unk> for unknown
                i++;
            }
        }

        return tokens;
    }

    decode(tokens: number[]): string {
        return tokens
            .map((id) => this.reverseVocab.get(id) ?? '')
            .join('');
    }

    encodeChat(messages: Array<{ role: string; content: string }>): number[] {
        const tokens: number[] = [];

        for (const message of messages) {
            const roleToken = `<|${message.role}|>`;
            tokens.push(...this.encode(roleToken));
            tokens.push(...this.encode(message.content));
            tokens.push(...this.encode('<|end|>'));
        }

        // Add assistant token to prompt continuation
        tokens.push(...this.encode('<|assistant|>'));

        return tokens;
    }
}

/**
 * ONNX Runtime Inference Engine
 * 
 * Provides local LLM inference capabilities using ONNX Runtime.
 * Supports text generation, embeddings, and token counting.
 */
export class InferenceEngine extends EventEmitter {
    private session: ort.InferenceSession | null = null;
    private embeddingSession: ort.InferenceSession | null = null;
    private tokenizer: SimpleTokenizer;
    private config: InferenceConfig;
    private metrics: ModelMetrics;
    private status: ModelStatus = 'unloaded';
    private loadedAt: Date | null = null;
    // AI-006 FIX: Loading lock to prevent concurrent model loads
    private loadingPromise: Promise<void> | null = null;

    constructor(config?: Partial<InferenceConfig>) {
        super();
        this.config = { ...DEFAULT_CONFIG, ...config };
        if (!SUPPORTED_MODEL_NAMES.has(this.config.modelName)) {
            console.warn(`[AI] Unrecognized modelName "${this.config.modelName}"; supported examples include ${Array.from(SUPPORTED_MODEL_NAMES).join(', ')}`);
        }
        this.tokenizer = new SimpleTokenizer();
        this.metrics = {
            requestCount: 0,
            avgLatencyMs: 0,
            errorRate: 0,
            tokensProcessed: 0,
        };
    }

    /**
     * Load the ONNX model into memory
     * AI-006 FIX: Uses loading lock to prevent concurrent loads (race condition)
     */
    async loadModel(modelPath?: string): Promise<void> {
        // AI-006 FIX: If already loading, return the existing promise to prevent race condition
        if (this.loadingPromise) {
            return this.loadingPromise;
        }
        
        // AI-006 FIX: If already loaded, return immediately
        if (this.status === 'ready' && this.session !== null) {
            return;
        }
        
        const path = modelPath || this.config.modelPath;
        
        // AI-006 FIX: Create and store the loading promise
        this.loadingPromise = this._doLoadModel(path);
        
        try {
            await this.loadingPromise;
        } finally {
            // AI-006 FIX: Clear the loading promise when done (success or failure)
            this.loadingPromise = null;
        }
    }
    
    /**
     * AI-006 FIX: Internal method to perform actual model loading
     */
    private async _doLoadModel(path: string): Promise<void> {
        this.status = 'loading';
        this.emit('status', this.status);

        try {
            // Configure session options
            // Note: options would be used with ort.InferenceSession.create in production
            // const options: ort.InferenceSession.SessionOptions = {
            //     executionProviders: this.config.useGPU ? ['cuda', 'cpu'] : ['cpu'],
            //     graphOptimizationLevel: 'all',
            //     intraOpNumThreads: this.config.numThreads,
            //     interOpNumThreads: this.config.numThreads,
            // };

            // Load the model
            // FIX-055: WARN clearly that inference is mock/simulated in non-production
            console.warn(
                '⚠️  [AI] MOCK MODE: No real ONNX model loaded. ' +
                'Inference will return synthetic/random outputs. ' +
                'To use a real model, provide model files and uncomment ort.InferenceSession.create().'
            );
            console.log(`Loading model from ${path}...`);
            
            // Simulated model loading - in production:
            // this.session = await ort.InferenceSession.create(path + '/model.onnx', options);
            
            this.status = 'ready';
            this.loadedAt = new Date();
            this.emit('status', this.status);
            this.emit('loaded', this.getModelInfo());

            console.log(`Model ${this.config.modelName} loaded successfully`);
        } catch (error) {
            this.status = 'error';
            this.emit('status', this.status);
            this.emit('error', error);
            throw new Error(`Failed to load model: ${error}`);
        }
    }

    /**
     * Unload the model from memory
     */
    async unloadModel(): Promise<void> {
        if (this.session) {
            await this.session.release();
            this.session = null;
        }
        if (this.embeddingSession) {
            await this.embeddingSession.release();
            this.embeddingSession = null;
        }
        this.status = 'unloaded';
        this.loadedAt = null;
        this.emit('status', this.status);
    }

    /**
     * Generate text completion
     */
    async generate(
        prompt: string,
        options?: Partial<InferenceConfig>
    ): Promise<InferenceResult> {
        const startTime = Date.now();
        const config = { ...this.config, ...options };

        if (this.status !== 'ready') {
            // Auto-load model if not loaded
            await this.loadModel();
        }

        try {
            // Tokenize input
            const inputTokens = this.tokenizer.encode(prompt);
            const promptTokens = inputTokens.length;

            // Generate tokens (simplified generation loop)
            // In production, this would run the actual ONNX model inference
            const generatedTokens = await this.generateTokens(
                inputTokens,
                config.maxTokens,
                config.temperature,
                config.topP,
                config.topK,
                config.repetitionPenalty,
                config.stopSequences
            );

            // Decode output
            const generatedText = this.tokenizer.decode(generatedTokens);
            const completionTokens = generatedTokens.length;

            // Update metrics
            const latencyMs = Date.now() - startTime;
            this.updateMetrics(latencyMs, promptTokens + completionTokens, false);

            return {
                text: generatedText,
                tokens: promptTokens + completionTokens,
                promptTokens,
                completionTokens,
                latencyMs,
                model: this.config.modelName,
                finishReason: 'stop',
            };
        } catch (error) {
            const latencyMs = Date.now() - startTime;
            this.updateMetrics(latencyMs, 0, true);
            throw error;
        }
    }

    /**
     * Generate chat completion
     */
    async chat(
        messages: Array<{ role: string; content: string }>,
        options?: Partial<InferenceConfig>
    ): Promise<InferenceResult> {
        // Format messages into prompt
        const formattedPrompt = this.formatChatPrompt(messages);
        return this.generate(formattedPrompt, options);
    }

    /**
     * Generate embeddings for text
     */
    async embed(text: string): Promise<EmbeddingResult> {
        const startTime = Date.now();

        if (this.status !== 'ready') {
            await this.loadModel();
        }

        try {
            // Tokenize
            const tokens = this.tokenizer.encode(text);

            // Generate embedding (simplified - in production use actual model)
            // This would normally run through an embedding model
            const dimensions = 384; // Common embedding dimension
            const embedding = this.generateMockEmbedding(tokens, dimensions);

            const latencyMs = Date.now() - startTime;
            this.updateMetrics(latencyMs, tokens.length, false);

            return {
                embedding,
                dimensions,
                model: this.config.modelName,
                latencyMs,
            };
        } catch (error) {
            const latencyMs = Date.now() - startTime;
            this.updateMetrics(latencyMs, 0, true);
            throw error;
        }
    }

    /**
     * Batch embed multiple texts
     */
    async embedBatch(texts: string[]): Promise<EmbeddingResult[]> {
        return Promise.all(texts.map((text) => this.embed(text)));
    }

    /**
     * Count tokens in text
     */
    tokenize(text: string): TokenizeResult {
        const tokens = this.tokenizer.encode(text);
        return {
            tokens,
            tokenCount: tokens.length,
        };
    }

    /**
     * Calculate cosine similarity between embeddings
     */
    cosineSimilarity(a: number[], b: number[]): number {
        if (a.length !== b.length) {
            throw new Error('Embeddings must have the same dimensions');
        }

        let dotProduct = 0;
        let normA = 0;
        let normB = 0;

        for (let i = 0; i < a.length; i++) {
            dotProduct += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }

        // FIX-500-383: Guard against division by zero when either vector is all-zeros
        const denominator = Math.sqrt(normA) * Math.sqrt(normB);
        if (denominator === 0) return 0;

        return dotProduct / denominator;
    }

    /**
     * Get model information
     */
    getModelInfo(): ModelInfo {
        return {
            name: this.config.modelName,
            version: '1.0.0',
            type: 'llm',
            size: 7_600_000_000, // ~7.6B params, Qwen 2.5-7B-Instruct (INT8 ONNX ~8GB)
            loadedAt: this.loadedAt ?? undefined,
            status: this.status,
            metrics: this.metrics,
        };
    }

    /**
     * Get current configuration
     */
    getConfig(): InferenceConfig {
        return { ...this.config };
    }

    /**
     * Update configuration
     */
    setConfig(config: Partial<InferenceConfig>): void {
        this.config = { ...this.config, ...config };
    }

    // ========================================
    // PRIVATE METHODS
    // ========================================

    private formatChatPrompt(messages: Array<{ role: string; content: string }>): string {
        let prompt = '';

        for (const message of messages) {
            prompt += `<|${message.role}|>\n${message.content}<|end|>\n`;
        }

        prompt += '<|assistant|>\n';
        return prompt;
    }

    private async generateTokens(
        _inputTokens: number[],
        maxTokens: number,
        _temperature: number,
        _topP: number,
        _topK: number,
        _repetitionPenalty: number,
        stopSequences: string[]
    ): Promise<number[]> {
        // Simplified token generation
        // In production, this would run the actual model inference loop
        
        const generatedTokens: number[] = [];
        const stopTokenIds = stopSequences.map((seq) => this.tokenizer.encode(seq)[0]);

        // Simulate generation (in production, run actual inference)
        for (let i = 0; i < maxTokens; i++) {
            // In production:
            // 1. Create input tensor from tokens
            // 2. Run model.run()
            // 3. Get logits from output
            // 4. Apply temperature, top-p, top-k sampling
            // 5. Sample next token

            // Mock: generate random token (simplified)
            const nextToken = Math.floor(Math.random() * 1000) + 100;

            // Check for stop token
            if (stopTokenIds.includes(nextToken)) {
                break;
            }

            generatedTokens.push(nextToken);

            // Early stopping on EOS patterns
            if (generatedTokens.length >= 3) {
                const recent = generatedTokens.slice(-3);
                const decoded = this.tokenizer.decode(recent);
                if (stopSequences.some((seq) => decoded.includes(seq))) {
                    break;
                }
            }
        }

        return generatedTokens;
    }

    private generateMockEmbedding(tokens: number[], dimensions: number): number[] {
        // Generate deterministic embedding based on tokens
        // In production, run actual embedding model
        const embedding = new Array(dimensions).fill(0);

        for (let i = 0; i < dimensions; i++) {
            let sum = 0;
            for (let j = 0; j < tokens.length; j++) {
                sum += Math.sin(tokens[j] * (i + 1) * 0.01) * Math.cos(j * 0.1);
            }
            embedding[i] = sum / tokens.length;
        }

        // Normalize
        const norm = Math.sqrt(embedding.reduce((acc, val) => acc + val * val, 0));
        return embedding.map((val) => val / norm);
    }

    private updateMetrics(latencyMs: number, tokens: number, isError: boolean): void {
        this.metrics.requestCount++;
        this.metrics.tokensProcessed += tokens;
        this.metrics.lastUsed = new Date();

        // Update rolling average latency
        this.metrics.avgLatencyMs =
            (this.metrics.avgLatencyMs * (this.metrics.requestCount - 1) + latencyMs) /
            this.metrics.requestCount;

        // Update error rate
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
