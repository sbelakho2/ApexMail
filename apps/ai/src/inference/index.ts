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

/**
 * FIX-500-099: Shared InferenceEngine instances keyed by config hash.
 * Instead of creating a new InferenceEngine in every service class
 * (routes, ChatbotAssistant, ContentGenerator, etc.), call
 * getSharedEngine() to reuse the same instance for equivalent configs.
 */
import { InferenceEngine } from './engine.js';
import type { InferenceConfig } from '../types.js';

const sharedEngines = new Map<string, InferenceEngine>();

function configKey(config?: Partial<InferenceConfig>): string {
    if (!config) return '__default__';
    // Only key on fields that actually affect model behaviour
    const { modelPath, modelName, temperature } = config;
    return `${modelPath ?? 'default'}|${modelName ?? 'default'}|${temperature ?? 'default'}`;
}

export function getSharedEngine(config?: Partial<InferenceConfig>): InferenceEngine {
    const key = configKey(config);
    let engine = sharedEngines.get(key);
    if (!engine) {
        engine = new InferenceEngine(config);
        sharedEngines.set(key, engine);
    }
    return engine;
}
