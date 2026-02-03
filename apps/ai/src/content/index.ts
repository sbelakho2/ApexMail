/**
 * @apexmail/ai - Content Module Exports
 */

export {
    ContentGenerator,
    DEFAULT_CONTENT_CONFIG,
    SUBJECT_PATTERNS,
    CTA_PATTERNS,
    type ContentGeneratorConfig,
} from './generator.js';
export {
    SentimentAnalyzer,
    NaiveBayesSentiment,
    sentimentAnalyzer,
} from './sentiment.js';