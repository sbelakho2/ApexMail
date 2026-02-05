/**
 * @apexmail/ai - Embeddings Service
 * 
 * Text embedding generation and similarity search for semantic operations.
 * Uses sentence-transformers style models via ONNX Runtime.
 */

import { InferenceEngine } from './engine.js';
import type { EmbeddingResult } from '../types.js';

/**
 * Embedding configuration
 */
export interface EmbeddingConfig {
    modelPath: string;
    modelName: string;
    dimensions: number;
    maxLength: number;
    normalize: boolean;
    poolingStrategy: 'mean' | 'cls' | 'max';
}

/**
 * Vector store entry
 */
export interface VectorEntry {
    id: string;
    vector: number[];
    metadata: Record<string, unknown>;
    text?: string;
}

/**
 * Search result
 */
export interface SearchResult {
    id: string;
    score: number;
    metadata: Record<string, unknown>;
    text?: string;
}

// Default embedding configuration
const DEFAULT_EMBEDDING_CONFIG: EmbeddingConfig = {
    modelPath: './models/all-MiniLM-L6-v2-onnx',
    modelName: 'all-MiniLM-L6-v2',
    dimensions: 384,
    maxLength: 512,
    normalize: true,
    poolingStrategy: 'mean',
};

/**
 * AI-004 FIX: Maximum vector store size for LRU eviction
 */
const DEFAULT_MAX_VECTOR_STORE_SIZE = 10000;

/**
 * Embeddings Service
 * 
 * Provides text embedding generation and vector similarity operations.
 * Includes an in-memory vector store for simple semantic search.
 * AI-004 FIX: Now includes LRU eviction when max size is exceeded.
 */
export class EmbeddingsService {
    private engine: InferenceEngine;
    private config: EmbeddingConfig;
    private vectorStore: Map<string, VectorEntry> = new Map();
    private accessOrder: Map<string, number> = new Map(); // AI-004: Track access order for LRU
    private accessCounter: number = 0; // AI-004: Monotonic counter for LRU ordering
    private maxVectorStoreSize: number;
    private initialized: boolean = false;

    constructor(config?: Partial<EmbeddingConfig>, maxStoreSize?: number) {
        this.config = { ...DEFAULT_EMBEDDING_CONFIG, ...config };
        this.maxVectorStoreSize = maxStoreSize ?? DEFAULT_MAX_VECTOR_STORE_SIZE;
        this.engine = new InferenceEngine({
            modelPath: this.config.modelPath,
            modelName: this.config.modelName,
        });
    }

    /**
     * Initialize the embeddings service
     */
    async initialize(): Promise<void> {
        if (this.initialized) return;

        await this.engine.loadModel();
        this.initialized = true;
    }

    /**
     * Generate embedding for text
     */
    async embed(text: string): Promise<EmbeddingResult> {
        if (!this.initialized) {
            await this.initialize();
        }

        // Truncate text if necessary
        const truncatedText = this.truncateText(text);

        // Generate embedding
        const result = await this.engine.embed(truncatedText);

        // Optionally normalize
        if (this.config.normalize) {
            result.embedding = this.normalize(result.embedding);
        }

        return result;
    }

    /**
     * Generate embeddings for multiple texts
     */
    async embedBatch(texts: string[]): Promise<EmbeddingResult[]> {
        if (!this.initialized) {
            await this.initialize();
        }

        const truncatedTexts = texts.map((t) => this.truncateText(t));
        const results = await this.engine.embedBatch(truncatedTexts);

        if (this.config.normalize) {
            return results.map((r) => ({
                ...r,
                embedding: this.normalize(r.embedding),
            }));
        }

        return results;
    }

    /**
     * Add vector to store
     * AI-004 FIX: Includes LRU eviction when store exceeds max size
     */
    async addVector(
        id: string,
        text: string,
        metadata: Record<string, unknown> = {}
    ): Promise<void> {
        const result = await this.embed(text);
        
        // AI-004 FIX: Evict LRU entries if at capacity (before adding new entry)
        if (!this.vectorStore.has(id) && this.vectorStore.size >= this.maxVectorStoreSize) {
            this.evictLRU();
        }
        
        this.vectorStore.set(id, {
            id,
            vector: result.embedding,
            metadata,
            text,
        });
        
        // AI-004: Update access order
        this.accessOrder.set(id, ++this.accessCounter);
    }

    /**
     * Add multiple vectors to store
     * AI-004 FIX: Includes LRU eviction when store exceeds max size
     */
    async addVectors(
        entries: Array<{ id: string; text: string; metadata?: Record<string, unknown> }>
    ): Promise<void> {
        const texts = entries.map((e) => e.text);
        const embeddings = await this.embedBatch(texts);

        for (let i = 0; i < entries.length; i++) {
            // AI-004 FIX: Evict LRU entries if at capacity
            if (!this.vectorStore.has(entries[i].id) && this.vectorStore.size >= this.maxVectorStoreSize) {
                this.evictLRU();
            }
            
            this.vectorStore.set(entries[i].id, {
                id: entries[i].id,
                vector: embeddings[i].embedding,
                metadata: entries[i].metadata || {},
                text: entries[i].text,
            });
            
            // AI-004: Update access order
            this.accessOrder.set(entries[i].id, ++this.accessCounter);
        }
    }

    /**
     * Remove vector from store
     * AI-004 FIX: Also removes from access order tracking
     */
    removeVector(id: string): boolean {
        this.accessOrder.delete(id);
        return this.vectorStore.delete(id);
    }

    /**
     * Search for similar vectors
     */
    async search(
        query: string,
        topK: number = 10,
        threshold: number = 0.0
    ): Promise<SearchResult[]> {
        const queryEmbedding = await this.embed(query);

        const results: SearchResult[] = [];

        for (const entry of this.vectorStore.values()) {
            const score = this.cosineSimilarity(queryEmbedding.embedding, entry.vector);

            if (score >= threshold) {
                results.push({
                    id: entry.id,
                    score,
                    metadata: entry.metadata,
                    text: entry.text,
                });
            }
        }

        // Sort by score descending
        results.sort((a, b) => b.score - a.score);

        // Return top K
        return results.slice(0, topK);
    }

    /**
     * Search by vector directly
     */
    searchByVector(
        vector: number[],
        topK: number = 10,
        threshold: number = 0.0
    ): SearchResult[] {
        const results: SearchResult[] = [];

        for (const entry of this.vectorStore.values()) {
            const score = this.cosineSimilarity(vector, entry.vector);

            if (score >= threshold) {
                results.push({
                    id: entry.id,
                    score,
                    metadata: entry.metadata,
                    text: entry.text,
                });
            }
        }

        results.sort((a, b) => b.score - a.score);
        return results.slice(0, topK);
    }

    /**
     * Get vector by ID
     * AI-004 FIX: Updates access order for LRU tracking
     */
    getVector(id: string): VectorEntry | undefined {
        const entry = this.vectorStore.get(id);
        if (entry) {
            // AI-004: Update access order on read
            this.accessOrder.set(id, ++this.accessCounter);
        }
        return entry;
    }

    /**
     * AI-004 FIX: Evict least recently used entry from vector store
     */
    private evictLRU(): void {
        if (this.vectorStore.size === 0) return;
        
        let lruId: string | null = null;
        let lruOrder = Infinity;
        
        for (const [id, order] of this.accessOrder) {
            if (order < lruOrder && this.vectorStore.has(id)) {
                lruOrder = order;
                lruId = id;
            }
        }
        
        if (lruId) {
            this.vectorStore.delete(lruId);
            this.accessOrder.delete(lruId);
        }
    }

    /**
     * Check if vector exists
     */
    hasVector(id: string): boolean {
        return this.vectorStore.has(id);
    }

    /**
     * Get all vectors
     */
    getAllVectors(): VectorEntry[] {
        return Array.from(this.vectorStore.values());
    }

    /**
     * Get vector count
     */
    getVectorCount(): number {
        return this.vectorStore.size;
    }

    /**
     * Clear all vectors
     * AI-004 FIX: Also clears access order tracking
     */
    clearVectors(): void {
        this.vectorStore.clear();
        this.accessOrder.clear();
        this.accessCounter = 0;
    }

    /**
     * Calculate cosine similarity between two vectors
     */
    cosineSimilarity(a: number[], b: number[]): number {
        return this.engine.cosineSimilarity(a, b);
    }

    /**
     * Calculate euclidean distance between two vectors
     */
    euclideanDistance(a: number[], b: number[]): number {
        if (a.length !== b.length) {
            throw new Error('Vectors must have the same dimensions');
        }

        let sum = 0;
        for (let i = 0; i < a.length; i++) {
            const diff = a[i] - b[i];
            sum += diff * diff;
        }
        return Math.sqrt(sum);
    }

    /**
     * Calculate dot product between two vectors
     */
    dotProduct(a: number[], b: number[]): number {
        if (a.length !== b.length) {
            throw new Error('Vectors must have the same dimensions');
        }

        let sum = 0;
        for (let i = 0; i < a.length; i++) {
            sum += a[i] * b[i];
        }
        return sum;
    }

    /**
     * Normalize a vector to unit length
     */
    normalize(vector: number[]): number[] {
        const norm = Math.sqrt(vector.reduce((acc, val) => acc + val * val, 0));
        if (norm === 0) return vector;
        return vector.map((val) => val / norm);
    }

    /**
     * Get configuration
     */
    getConfig(): EmbeddingConfig {
        return { ...this.config };
    }

    /**
     * Export store to JSON
     */
    exportStore(): string {
        const entries = Array.from(this.vectorStore.entries());
        return JSON.stringify(entries);
    }

    /**
     * Import store from JSON
     */
    importStore(json: string): void {
        const entries: Array<[string, VectorEntry]> = JSON.parse(json);
        this.vectorStore = new Map(entries);
    }

    /**
     * Get store statistics
     */
    getStats(): {
        count: number;
        dimensions: number;
        memoryBytes: number;
    } {
        const count = this.vectorStore.size;
        const memoryBytes = count * this.config.dimensions * 8; // 8 bytes per float64

        return {
            count,
            dimensions: this.config.dimensions,
            memoryBytes,
        };
    }

    // ========================================
    // PRIVATE METHODS
    // ========================================

    private truncateText(text: string): string {
        // Simple truncation by character count (approximation)
        // In production, truncate by token count
        const approxCharsPerToken = 4;
        const maxChars = this.config.maxLength * approxCharsPerToken;

        if (text.length <= maxChars) {
            return text;
        }

        return text.slice(0, maxChars);
    }
}

/**
 * Create a semantic text chunker for long documents
 */
export class TextChunker {
    private chunkSize: number;
    private chunkOverlap: number;
    private separators: string[];

    constructor(options?: {
        chunkSize?: number;
        chunkOverlap?: number;
        separators?: string[];
    }) {
        this.chunkSize = options?.chunkSize ?? 500;
        this.chunkOverlap = options?.chunkOverlap ?? 50;
        this.separators = options?.separators ?? ['\n\n', '\n', '. ', ' ', ''];
    }

    /**
     * Split text into chunks
     */
    split(text: string): string[] {
        return this.splitText(text, this.separators);
    }

    private splitText(text: string, separators: string[]): string[] {
        const separator = separators[0];
        const remainingSeparators = separators.slice(1);

        // Split by the first separator
        let splits: string[];
        if (separator === '') {
            // Character-level split
            splits = text.split('');
        } else {
            splits = text.split(separator);
        }

        // Merge small chunks
        const chunks: string[] = [];
        let currentChunk = '';

        for (const split of splits) {
            const potentialChunk = currentChunk
                ? currentChunk + separator + split
                : split;

            if (potentialChunk.length <= this.chunkSize) {
                currentChunk = potentialChunk;
            } else {
                if (currentChunk) {
                    chunks.push(currentChunk);
                }

                // If the split itself is too large, recursively split it
                if (split.length > this.chunkSize && remainingSeparators.length > 0) {
                    const subChunks = this.splitText(split, remainingSeparators);
                    chunks.push(...subChunks.slice(0, -1));
                    currentChunk = subChunks[subChunks.length - 1] || '';
                } else {
                    currentChunk = split;
                }
            }
        }

        if (currentChunk) {
            chunks.push(currentChunk);
        }

        // Add overlapping context
        return this.addOverlap(chunks);
    }

    private addOverlap(chunks: string[]): string[] {
        if (chunks.length <= 1 || this.chunkOverlap === 0) {
            return chunks;
        }

        const overlappedChunks: string[] = [];

        for (let i = 0; i < chunks.length; i++) {
            let chunk = chunks[i];

            // Add overlap from previous chunk
            if (i > 0) {
                const prevChunk = chunks[i - 1];
                const overlapText = prevChunk.slice(-this.chunkOverlap);
                chunk = overlapText + chunk;
            }

            overlappedChunks.push(chunk);
        }

        return overlappedChunks;
    }
}

export { DEFAULT_EMBEDDING_CONFIG };
