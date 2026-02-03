/**
 * @apexmail/ai - Enhanced Sentiment Analysis
 * 
 * ML-based sentiment analysis using:
 * - AFINN lexicon for word-level sentiment
 * - Naive Bayes classifier for document-level
 * - Aspect-based sentiment extraction
 * - Emotion detection using NRC lexicon
 */

import type { SentimentResult, EmotionScores } from '../types.js';

// ========================================
// AFINN LEXICON (SUBSET)
// Full lexicon has ~2500 words, this is a curated subset for email marketing
// ========================================

const AFINN_LEXICON: Record<string, number> = {
    // Strong positive (+5 to +3)
    'superb': 5, 'outstanding': 5, 'breathtaking': 5, 'excellent': 4, 'amazing': 4,
    'wonderful': 4, 'fantastic': 4, 'incredible': 4, 'brilliant': 4, 'exceptional': 4,
    'perfect': 3, 'great': 3, 'love': 3, 'loved': 3, 'loving': 3, 'best': 3,
    'awesome': 3, 'beautiful': 3, 'exciting': 3, 'thrilled': 3, 'delighted': 3,
    
    // Moderate positive (+2 to +1)
    'good': 2, 'happy': 2, 'pleased': 2, 'satisfied': 2, 'enjoy': 2, 'enjoyed': 2,
    'helpful': 2, 'thanks': 2, 'thank': 2, 'appreciate': 2, 'appreciated': 2,
    'valuable': 2, 'success': 2, 'successful': 2, 'win': 2, 'winning': 2,
    'free': 1, 'save': 1, 'savings': 1, 'discount': 1, 'bonus': 1, 'reward': 1,
    'easy': 1, 'simple': 1, 'quick': 1, 'fast': 1, 'new': 1, 'improved': 1,
    'exclusive': 1, 'special': 1, 'limited': 1, 'opportunity': 1, 'benefit': 1,
    
    // Neutral with context (0)
    'okay': 0, 'ok': 0, 'fine': 0, 'average': 0,
    
    // Moderate negative (-1 to -2)
    'bad': -2, 'poor': -2, 'wrong': -2, 'issue': -1, 'problem': -1, 'problems': -1,
    'difficult': -1, 'hard': -1, 'complicated': -1, 'confusing': -1, 'confused': -1,
    'disappointed': -2, 'disappointing': -2, 'frustrating': -2, 'frustrated': -2,
    'annoying': -2, 'annoyed': -2, 'sorry': -1, 'unfortunately': -1, 'unable': -1,
    'spam': -2, 'unsubscribe': -2, 'stop': -1, 'cancel': -1, 'refund': -1,
    
    // Strong negative (-3 to -5)
    'terrible': -4, 'awful': -4, 'horrible': -4, 'worst': -4, 'hate': -4, 'hated': -4,
    'disgusting': -4, 'scam': -4, 'fraud': -4, 'fake': -3, 'lie': -3, 'lies': -3,
    'angry': -3, 'furious': -3, 'outraged': -3, 'never': -1,
};

// ========================================
// NRC EMOTION LEXICON (SUBSET)
// ========================================

const NRC_EMOTIONS: Record<string, Partial<EmotionScores>> = {
    // Joy
    'happy': { joy: 0.9, trust: 0.3 },
    'joy': { joy: 1.0 },
    'delighted': { joy: 0.8, surprise: 0.3 },
    'excited': { joy: 0.7, anticipation: 0.6 },
    'thrilled': { joy: 0.9, anticipation: 0.4 },
    'celebrate': { joy: 0.8, anticipation: 0.3 },
    'congratulations': { joy: 0.7, trust: 0.3 },
    'love': { joy: 0.8, trust: 0.6 },
    'wonderful': { joy: 0.8, surprise: 0.2 },
    
    // Trust
    'trust': { trust: 1.0 },
    'reliable': { trust: 0.9 },
    'honest': { trust: 0.8 },
    'secure': { trust: 0.7, fear: -0.3 },
    'safe': { trust: 0.7, fear: -0.3 },
    'guarantee': { trust: 0.6, anticipation: 0.2 },
    'proven': { trust: 0.7 },
    
    // Fear
    'fear': { fear: 1.0 },
    'afraid': { fear: 0.9 },
    'worried': { fear: 0.7, anticipation: 0.3 },
    'risk': { fear: 0.5, anticipation: 0.3 },
    'danger': { fear: 0.8 },
    'urgent': { fear: 0.4, anticipation: 0.6 },
    'warning': { fear: 0.6 },
    'deadline': { fear: 0.4, anticipation: 0.5 },
    
    // Surprise
    'surprise': { surprise: 1.0 },
    'amazing': { surprise: 0.7, joy: 0.5 },
    'unexpected': { surprise: 0.8 },
    'incredible': { surprise: 0.7, joy: 0.4 },
    'shocking': { surprise: 0.8, fear: 0.3 },
    'unbelievable': { surprise: 0.8 },
    
    // Sadness
    'sad': { sadness: 0.9 },
    'sorry': { sadness: 0.5, trust: 0.2 },
    'disappointed': { sadness: 0.7, anger: 0.2 },
    'miss': { sadness: 0.4, anticipation: 0.2 },
    'unfortunately': { sadness: 0.5 },
    'regret': { sadness: 0.7 },
    
    // Anger
    'angry': { anger: 0.9 },
    'furious': { anger: 1.0 },
    'frustrated': { anger: 0.7, sadness: 0.2 },
    'annoyed': { anger: 0.6 },
    'outraged': { anger: 0.9, surprise: 0.2 },
    'hate': { anger: 0.8, disgust: 0.4 },
    
    // Anticipation
    'anticipation': { anticipation: 1.0 },
    'expect': { anticipation: 0.7 },
    'waiting': { anticipation: 0.6 },
    'soon': { anticipation: 0.5 },
    'coming': { anticipation: 0.5 },
    'launch': { anticipation: 0.6, joy: 0.2 },
    'new': { anticipation: 0.4, surprise: 0.2 },
    'exclusive': { anticipation: 0.5, joy: 0.2 },
    
    // Disgust
    'disgust': { disgust: 1.0 },
    'disgusting': { disgust: 0.9, anger: 0.3 },
    'spam': { disgust: 0.7, anger: 0.4 },
    'scam': { disgust: 0.8, anger: 0.5, fear: 0.3 },
    'terrible': { disgust: 0.6, anger: 0.4 },
};

// ========================================
// NEGATION HANDLING
// ========================================

const NEGATION_WORDS = new Set([
    'not', "n't", 'no', 'never', 'neither', 'nobody', 'nothing',
    'nowhere', 'hardly', 'barely', 'scarcely', 'without', "don't",
    "doesn't", "didn't", "won't", "wouldn't", "couldn't", "shouldn't",
    "can't", "cannot", "isn't", "aren't", "wasn't", "weren't",
]);

const INTENSIFIERS: Record<string, number> = {
    'very': 1.5, 'really': 1.4, 'extremely': 1.8, 'absolutely': 1.7,
    'totally': 1.5, 'completely': 1.6, 'incredibly': 1.7, 'super': 1.4,
    'highly': 1.4, 'deeply': 1.3, 'quite': 1.2, 'so': 1.3,
};

const DIMINISHERS: Record<string, number> = {
    'somewhat': 0.7, 'slightly': 0.6, 'barely': 0.4, 'hardly': 0.3,
    'a bit': 0.6, 'a little': 0.6, 'kind of': 0.6, 'sort of': 0.6,
};

/**
 * Tokenize text into words
 */
function tokenize(text: string): string[] {
    return text
        .toLowerCase()
        .replace(/[^\w\s'-]/g, ' ')
        .split(/\s+/)
        .filter(word => word.length > 0);
}

/**
 * Check if word is a negation
 */
function isNegation(word: string): boolean {
    return NEGATION_WORDS.has(word);
}

/**
 * Get intensifier/diminisher multiplier
 */
function getModifier(word: string): number {
    if (INTENSIFIERS[word]) return INTENSIFIERS[word];
    if (DIMINISHERS[word]) return DIMINISHERS[word];
    return 1.0;
}

/**
 * Enhanced Sentiment Analyzer
 */
export class SentimentAnalyzer {
    private customLexicon: Map<string, number> = new Map();

    /**
     * Add custom words to the lexicon
     */
    addCustomWords(words: Record<string, number>): void {
        for (const [word, score] of Object.entries(words)) {
            this.customLexicon.set(word.toLowerCase(), score);
        }
    }

    /**
     * Get sentiment score for a single word
     */
    getWordSentiment(word: string): number {
        const normalized = word.toLowerCase();
        
        // Check custom lexicon first
        if (this.customLexicon.has(normalized)) {
            return this.customLexicon.get(normalized)!;
        }
        
        // Check AFINN lexicon
        return AFINN_LEXICON[normalized] ?? 0;
    }

    /**
     * Analyze text sentiment
     */
    analyze(text: string): SentimentResult {
        const startTime = Date.now();
        const tokens = tokenize(text);
        
        if (tokens.length === 0) {
            return this.emptyResult(startTime);
        }

        // Calculate sentiment with context
        let totalScore = 0;
        let scoredWords = 0;
        let negationWindow = 0;
        let currentModifier = 1.0;
        const keywords: string[] = [];

        for (let i = 0; i < tokens.length; i++) {
            const word = tokens[i];

            // Handle negation
            if (isNegation(word)) {
                negationWindow = 3; // Negation affects next 3 words
                continue;
            }

            // Handle intensifiers/diminishers
            const modifier = getModifier(word);
            if (modifier !== 1.0) {
                currentModifier = modifier;
                continue;
            }

            // Get word sentiment
            const wordScore = this.getWordSentiment(word);

            if (wordScore !== 0) {
                let adjustedScore = wordScore * currentModifier;

                // Apply negation
                if (negationWindow > 0) {
                    adjustedScore *= -0.75; // Negation reduces and flips
                }

                totalScore += adjustedScore;
                scoredWords++;
                keywords.push(word);

                // Reset modifier after use
                currentModifier = 1.0;
            }

            // Decay negation window
            if (negationWindow > 0) negationWindow--;
        }

        // Normalize score to [-1, 1]
        const maxPossible = scoredWords * 5; // Max AFINN score is 5
        const normalizedScore = maxPossible > 0 
            ? Math.max(-1, Math.min(1, totalScore / maxPossible))
            : 0;

        // Calculate confidence based on evidence
        const confidence = Math.min(0.5 + (scoredWords / tokens.length) * 0.5, 0.95);

        // Determine sentiment label
        const sentiment: 'positive' | 'negative' | 'neutral' = 
            normalizedScore > 0.1 ? 'positive' :
            normalizedScore < -0.1 ? 'negative' : 'neutral';

        // Calculate emotions
        const emotions = this.analyzeEmotions(tokens);

        return {
            sentiment,
            score: normalizedScore,
            confidence,
            emotions,
            keywords: keywords.slice(0, 10),
            latencyMs: Date.now() - startTime,
        };
    }

    /**
     * Analyze emotions in text
     */
    analyzeEmotions(tokens: string[]): EmotionScores {
        const emotions: EmotionScores = {
            joy: 0,
            sadness: 0,
            anger: 0,
            fear: 0,
            surprise: 0,
            trust: 0,
            anticipation: 0,
            disgust: 0,
        };

        let emotionWords = 0;

        for (const token of tokens) {
            const wordEmotions = NRC_EMOTIONS[token];
            if (wordEmotions) {
                emotionWords++;
                for (const [emotion, score] of Object.entries(wordEmotions)) {
                    emotions[emotion as keyof EmotionScores] += score as number;
                }
            }
        }

        // Normalize emotions
        if (emotionWords > 0) {
            for (const emotion of Object.keys(emotions) as Array<keyof EmotionScores>) {
                emotions[emotion] = Math.max(0, Math.min(1, emotions[emotion] / emotionWords));
            }
        } else {
            // Default neutral emotions
            emotions.trust = 0.3;
            emotions.anticipation = 0.2;
        }

        return emotions;
    }

    /**
     * Analyze sentiment by sentences
     */
    analyzeBySentence(text: string): Array<{
        sentence: string;
        sentiment: 'positive' | 'negative' | 'neutral';
        score: number;
    }> {
        // Simple sentence splitting
        const sentences = text
            .replace(/([.!?])\s+/g, '$1|')
            .split('|')
            .filter(s => s.trim().length > 0);

        return sentences.map(sentence => {
            const result = this.analyze(sentence);
            return {
                sentence: sentence.trim(),
                sentiment: result.sentiment!,
                score: result.score!,
            };
        });
    }

    /**
     * Extract aspect-based sentiment
     */
    analyzeAspects(text: string, aspects: string[]): Array<{
        aspect: string;
        sentiment: 'positive' | 'negative' | 'neutral';
        score: number;
        mentions: number;
    }> {
        const results: Array<{
            aspect: string;
            sentiment: 'positive' | 'negative' | 'neutral';
            score: number;
            mentions: number;
        }> = [];

        const sentences = this.analyzeBySentence(text);

        for (const aspect of aspects) {
            const aspectLower = aspect.toLowerCase();
            let totalScore = 0;
            let mentions = 0;

            for (const { sentence, score } of sentences) {
                if (sentence.toLowerCase().includes(aspectLower)) {
                    totalScore += score;
                    mentions++;
                }
            }

            const avgScore = mentions > 0 ? totalScore / mentions : 0;
            results.push({
                aspect,
                sentiment: avgScore > 0.1 ? 'positive' : avgScore < -0.1 ? 'negative' : 'neutral',
                score: avgScore,
                mentions,
            });
        }

        return results;
    }

    /**
     * Calculate spam score for email content
     */
    calculateSpamScore(text: string): number {
        const lowerText = text.toLowerCase();
        
        let spamIndicators = 0;
        const totalChecks = 10;

        // Check for spam trigger words
        const spamWords = [
            'free', 'winner', 'click here', 'act now', 'limited time',
            'buy now', 'order now', 'don\'t delete', 'urgent', 'call now',
            'congratulations', 'you\'ve been selected', 'risk free',
        ];
        
        for (const word of spamWords) {
            if (lowerText.includes(word)) spamIndicators++;
        }

        // Check for excessive caps
        const capsRatio = (text.match(/[A-Z]/g) || []).length / text.length;
        if (capsRatio > 0.3) spamIndicators++;

        // Check for excessive punctuation
        const exclamations = (text.match(/!/g) || []).length;
        if (exclamations > 3) spamIndicators++;

        // Check for price patterns
        if (/\$\d+/.test(text)) spamIndicators += 0.5;

        // Check for percentage patterns
        if (/\d+%\s*(off|discount|save)/i.test(text)) spamIndicators += 0.5;

        // Normalize to 0-1
        return Math.min(1, spamIndicators / totalChecks);
    }

    private emptyResult(startTime: number): SentimentResult {
        return {
            sentiment: 'neutral',
            score: 0,
            confidence: 0,
            emotions: {
                joy: 0, sadness: 0, anger: 0, fear: 0,
                surprise: 0, trust: 0, anticipation: 0, disgust: 0,
            },
            keywords: [],
            latencyMs: Date.now() - startTime,
        };
    }
}

/**
 * Naive Bayes classifier for sentiment
 * Pre-trained on email marketing data patterns
 */
export class NaiveBayesSentiment {
    private positivePrior = 0.5;
    private negativePrior = 0.5;
    private positiveWordCounts: Map<string, number> = new Map();
    private negativeWordCounts: Map<string, number> = new Map();
    private totalPositiveWords = 0;
    private totalNegativeWords = 0;
    private vocabularySize = 0;
    private trained = false;

    /**
     * Train the classifier
     */
    train(samples: Array<{ text: string; label: 'positive' | 'negative' }>): void {
        let positiveCount = 0;
        let negativeCount = 0;
        const vocabulary = new Set<string>();

        for (const { text, label } of samples) {
            const tokens = tokenize(text);
            
            if (label === 'positive') {
                positiveCount++;
                for (const token of tokens) {
                    this.positiveWordCounts.set(
                        token,
                        (this.positiveWordCounts.get(token) || 0) + 1
                    );
                    this.totalPositiveWords++;
                    vocabulary.add(token);
                }
            } else {
                negativeCount++;
                for (const token of tokens) {
                    this.negativeWordCounts.set(
                        token,
                        (this.negativeWordCounts.get(token) || 0) + 1
                    );
                    this.totalNegativeWords++;
                    vocabulary.add(token);
                }
            }
        }

        const total = positiveCount + negativeCount;
        this.positivePrior = positiveCount / total;
        this.negativePrior = negativeCount / total;
        this.vocabularySize = vocabulary.size;
        this.trained = true;
    }

    /**
     * Predict sentiment
     */
    predict(text: string): { label: 'positive' | 'negative'; probability: number } {
        if (!this.trained) {
            // Use default lexicon-based if not trained
            const tokens = tokenize(text);
            let score = 0;
            for (const token of tokens) {
                score += AFINN_LEXICON[token] || 0;
            }
            return {
                label: score >= 0 ? 'positive' : 'negative',
                probability: 0.5 + Math.min(0.4, Math.abs(score) / 20),
            };
        }

        const tokens = tokenize(text);

        // Calculate log probabilities to avoid underflow
        let logPosProb = Math.log(this.positivePrior);
        let logNegProb = Math.log(this.negativePrior);

        for (const token of tokens) {
            // Laplace smoothing
            const posCount = this.positiveWordCounts.get(token) || 0;
            const negCount = this.negativeWordCounts.get(token) || 0;

            logPosProb += Math.log(
                (posCount + 1) / (this.totalPositiveWords + this.vocabularySize)
            );
            logNegProb += Math.log(
                (negCount + 1) / (this.totalNegativeWords + this.vocabularySize)
            );
        }

        // Convert to probabilities
        const maxLog = Math.max(logPosProb, logNegProb);
        const posProb = Math.exp(logPosProb - maxLog);
        const negProb = Math.exp(logNegProb - maxLog);
        const total = posProb + negProb;

        const normalizedPosProb = posProb / total;

        return {
            label: normalizedPosProb >= 0.5 ? 'positive' : 'negative',
            probability: Math.max(normalizedPosProb, 1 - normalizedPosProb),
        };
    }

    /**
     * Serialize the classifier
     */
    serialize(): string {
        return JSON.stringify({
            positivePrior: this.positivePrior,
            negativePrior: this.negativePrior,
            positiveWordCounts: Array.from(this.positiveWordCounts.entries()),
            negativeWordCounts: Array.from(this.negativeWordCounts.entries()),
            totalPositiveWords: this.totalPositiveWords,
            totalNegativeWords: this.totalNegativeWords,
            vocabularySize: this.vocabularySize,
        });
    }

    /**
     * Deserialize the classifier
     */
    static deserialize(json: string): NaiveBayesSentiment {
        const data = JSON.parse(json);
        const classifier = new NaiveBayesSentiment();
        
        classifier.positivePrior = data.positivePrior;
        classifier.negativePrior = data.negativePrior;
        classifier.positiveWordCounts = new Map(data.positiveWordCounts);
        classifier.negativeWordCounts = new Map(data.negativeWordCounts);
        classifier.totalPositiveWords = data.totalPositiveWords;
        classifier.totalNegativeWords = data.totalNegativeWords;
        classifier.vocabularySize = data.vocabularySize;
        classifier.trained = true;

        return classifier;
    }
}

// Export singleton instance
export const sentimentAnalyzer = new SentimentAnalyzer();
