/**
 * @apexmail/ai - Inference Module Exports
 */

export {
    InferenceEngine,
    SimpleTokenizer,
    DEFAULT_CONFIG,
} from './engine.js';

export {
    EmbeddingsService,
    TextChunker,
    DEFAULT_EMBEDDING_CONFIG,
    type EmbeddingConfig,
    type VectorEntry,
    type SearchResult,
} from './embeddings.js';

export {
    ModelLifecycleManager,
    InferenceCircuitBreaker,
    InferenceQueue,
    type ModelHealth,
    type LifecycleConfig,
} from './lifecycle.js';
