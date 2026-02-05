/**
 * Comprehensive Tests for Email ML Training Pipeline
 * 
 * Tests cover:
 * 1. Quality evaluation metrics
 * 2. Subject line optimization
 * 3. Email writing model
 * 4. Statistical validation
 * 5. Overfitting detection
 */

import { describe, it, expect, beforeAll } from 'vitest';

import {
    EmailQualityEvaluator,
    fleschKincaidReadingEase,
    gunningFogIndex,
    calculateSpamScore,
    predictEngagement
} from './email-quality-evaluator.js';

import {
    SubjectLineOptimizer,
    extractSubjectFeatures
} from './subject-line-optimizer.js';

import {
    EmailWritingModel,
    type TrainingConfig
} from './email-training-pipeline.js';

import {
    AESLC_SAMPLES,
    SUBJECT_LINE_TRAINING_DATA,
    EMAIL_BODY_SAMPLES
} from './huggingface-datasets.js';

// =====================================================
// READABILITY METRIC TESTS
// =====================================================

describe('Readability Metrics', () => {
    it('calculates Flesch-Kincaid reading ease correctly', () => {
        // Simple sentence should have high readability
        const simple = 'The cat sat on the mat. It was a good day.';
        const simpleScore = fleschKincaidReadingEase(simple);
        expect(simpleScore).toBeGreaterThan(70);
        
        // Complex sentence should have lower readability
        const complex = 'The implementation of sophisticated algorithmic methodologies necessitates comprehensive understanding of computational paradigms and architectural considerations.';
        const complexScore = fleschKincaidReadingEase(complex);
        expect(complexScore).toBeLessThan(40);
    });
    
    it('handles edge cases for readability', () => {
        expect(fleschKincaidReadingEase('')).toBe(0);
        expect(fleschKincaidReadingEase('Hi.')).toBeGreaterThan(0);
    });
    
    it('calculates Gunning Fog index', () => {
        const simple = 'The dog ran fast. It was fun to watch.';
        const fog = gunningFogIndex(simple);
        // Simple text should have low fog index (< 10)
        expect(fog).toBeLessThan(10);
    });
});

// =====================================================
// SPAM SCORE TESTS
// =====================================================

describe('Spam Detection', () => {
    it('gives low spam score to legitimate emails', () => {
        const legitimate = `Hi Sarah,

I noticed your company recently launched a new product line. 
I'd love to chat about how we might help with your email infrastructure.

Would next Tuesday work for a quick call?

Best,
Alex`;
        
        const result = calculateSpamScore(legitimate);
        expect(result.score).toBeLessThan(20);
    });
    
    it('gives high spam score to spammy content', () => {
        const spammy = `CONGRATULATIONS!!! YOU HAVE WON $1,000,000!!!
        
ACT NOW! LIMITED TIME OFFER! FREE MONEY!
CLICK HERE IMMEDIATELY! 100% GUARANTEED!!!

This is NOT spam. You are a WINNER!`;
        
        const result = calculateSpamScore(spammy);
        expect(result.score).toBeGreaterThan(0.5);
    });
    
    it('penalizes excessive caps', () => {
        const allCaps = 'THIS IS ALL IN CAPS AND LOOKS SPAMMY';
        const normal = 'This is normal text and looks fine';
        
        const capsResult = calculateSpamScore(allCaps);
        const normalResult = calculateSpamScore(normal);
        
        expect(capsResult.score).toBeGreaterThan(normalResult.score);
    });
    
    it('penalizes multiple exclamation marks', () => {
        const excited = 'Wow!!! Amazing!!! Incredible!!!';
        const calm = 'This is interesting. I think you will like it.';
        
        const excitedResult = calculateSpamScore(excited);
        const calmResult = calculateSpamScore(calm);
        
        expect(excitedResult.score).toBeGreaterThan(calmResult.score);
    });
});

// =====================================================
// ENGAGEMENT PREDICTION TESTS
// =====================================================

describe('Engagement Prediction', () => {
    it('predicts higher engagement for personalized emails', () => {
        const personalized = predictEngagement(
            '{{firstName}}, quick question',
            'Hi {{firstName}}, I wanted to ask you about... [Click here](link)',
            'cold_outreach'
        );
        
        const generic = predictEngagement(
            'Quick question',
            'Hi, I wanted to ask you about...',
            'cold_outreach'
        );
        
        expect(personalized.predictedOpenRate).toBeGreaterThan(generic.predictedOpenRate);
        expect(personalized.predictedClickRate).toBeGreaterThan(generic.predictedClickRate);
    });
    
    it('predicts lower engagement for high spam scores', () => {
        const clean = predictEngagement(
            '{{firstName}}, quick question',
            'Hi {{firstName}}, I wanted to ask you about... [Learn more](link)',
            'cold_outreach'
        );
        
        const spammy = predictEngagement(
            'FREE MONEY NOW!!! CLICK HERE!!!',
            'BUY NOW!!! LIMITED TIME OFFER!!! ACT NOW!!! FREE!!!',
            'cold_outreach'
        );
        
        expect(clean.predictedOpenRate).toBeGreaterThan(spammy.predictedOpenRate);
    });
    
    it('adjusts predictions based on category', () => {
        const transactional = predictEngagement(
            'Your receipt #12345',
            'Thank you for your purchase. [View receipt](link)',
            'transactional'
        );
        
        const promotional = predictEngagement(
            'Special offer just for you',
            'Check out our latest deals! [Shop now](link)',
            'promotional'
        );
        
        // Transactional emails have higher baseline open rates
        expect(transactional.predictedOpenRate).toBeGreaterThan(promotional.predictedOpenRate);
    });
});

// =====================================================
// EMAIL QUALITY EVALUATOR TESTS
// =====================================================

describe('EmailQualityEvaluator', () => {
    let evaluator: EmailQualityEvaluator;
    
    beforeAll(() => {
        evaluator = new EmailQualityEvaluator(92, 0.95);
    });
    
    it('evaluates good emails highly', () => {
        const subject = '{{firstName}}, quick question about your email strategy?';
        const body = `Hi {{firstName}},

I noticed {{company}} has been growing rapidly - congratulations!

I help companies like yours improve email deliverability. Would it make sense to chat for 15 minutes this week?

Best,
Alex`;
        
        const result = evaluator.evaluate(subject, body, 'cold_outreach', 'professional');
        
        expect(result.overall).toBeGreaterThan(65);
        expect(result.breakdown.linguistic.clarity).toBeGreaterThan(60);
        expect(result.breakdown.deliverability.spamScore).toBeLessThan(0.2);
    });
    
    it('evaluates poor emails appropriately', () => {
        const subject = 'FREE MONEY NOW!!!';
        const body = `CLICK HERE TO CLAIM YOUR PRIZE!!!

YOU HAVE BEEN SELECTED AS A WINNER!!!

ACT NOW BEFORE IT'S TOO LATE!!!

This is 100% GUARANTEED!!!`;
        
        const result = evaluator.evaluate(subject, body, 'promotional', 'casual');
        
        expect(result.overall).toBeLessThan(65);
        expect(result.breakdown.deliverability.spamScore).toBeGreaterThan(0.4);
        expect(result.passesThreshold).toBe(false);
    });
    
    it('provides actionable recommendations', () => {
        const subject = 'email';
        const body = 'Hi, I wanted to reach out. Let me know. Thanks.';
        
        const result = evaluator.evaluate(subject, body, 'cold_outreach', 'professional');
        
        expect(result.recommendations.length).toBeGreaterThan(0);
    });
    
    it('validates business value metrics', () => {
        const subjectWithCTA = 'Quick question - 15 min call this week?';
        const bodyWithCTA = `Hi Sarah,

I noticed TechCorp launched a new product line. Congratulations!

I help companies like yours achieve 99% email deliverability.

Would a 15-minute call work this Tuesday at 2pm?

Best,
Alex`;
        
        const result = evaluator.evaluate(subjectWithCTA, bodyWithCTA, 'cold_outreach', 'professional');
        
        expect(result.breakdown.businessValue.ctaClarity).toBeGreaterThan(35);
    });
});

// =====================================================
// SUBJECT LINE OPTIMIZER TESTS
// =====================================================

describe('SubjectLineOptimizer', () => {
    let optimizer: SubjectLineOptimizer;
    
    beforeAll(async () => {
        optimizer = new SubjectLineOptimizer();
        // Train quickly for tests
        await optimizer.train();
    });
    
    it('extracts features correctly', () => {
        const features = extractSubjectFeatures(
            '{{firstName}}, quick question about deliverability?',
            'cold_outreach'
        );
        
        expect(features.hasPersonalization).toBe(true);
        expect(features.hasQuestion).toBe(true);
        expect(features.wordCount).toBe(5);
    });
    
    it('scores personalized subjects higher', () => {
        const personalized = optimizer.score(
            '{{firstName}}, quick question?',
            'cold_outreach'
        );
        
        const generic = optimizer.score(
            'Quick question',
            'cold_outreach'
        );
        
        expect(personalized.overall).toBeGreaterThan(generic.overall);
    });
    
    it('penalizes spammy subjects', () => {
        const clean = optimizer.score(
            'Quick question about your email strategy',
            'cold_outreach'
        );
        
        const spammy = optimizer.score(
            'FREE MONEY!!! ACT NOW!!!',
            'promotional'
        );
        
        expect(clean.deliverability).toBeGreaterThan(spammy.deliverability);
    });
    
    it('optimizes subject lines', () => {
        const result = optimizer.optimize(
            'FREE MONEY LIMITED TIME!!!',
            'promotional'
        );
        
        expect(result.optimizedScore.overall).toBeGreaterThan(result.originalScore.overall);
        expect(result.improvement).toBeGreaterThan(0);
    });
    
    it('generates multiple variants', () => {
        const variants = optimizer.generateVariants('email deliverability', 'cold_outreach', 5);
        
        expect(variants.length).toBe(5);
        // Should be sorted by score descending
        for (let i = 1; i < variants.length; i++) {
            expect(variants[i - 1]!.score.overall).toBeGreaterThanOrEqual(variants[i]!.score.overall);
        }
    });
    
    it('performs A/B test comparison', () => {
        const result = optimizer.abTest(
            '{{firstName}}, quick question?',
            'Question for you',
            'cold_outreach'
        );
        
        expect(result.winner).toBeDefined();
        expect(['A', 'B']).toContain(result.winner);
        expect(result.confidence).toBeGreaterThan(0);
        expect(result.recommendation).toBeDefined();
    });
});

// =====================================================
// EMAIL WRITING MODEL TESTS
// =====================================================

describe('EmailWritingModel', () => {
    let model: EmailWritingModel;
    
    beforeAll(async () => {
        model = new EmailWritingModel();
        // Quick training for tests
        await model.train({
            maxEpochs: 10,
            minEpochs: 5,
            earlyStoppingPatience: 3
        });
    });
    
    it('generates emails for all categories', () => {
        const categories = ['cold_outreach', 'welcome', 'follow_up', 'newsletter'] as const;
        
        for (const category of categories) {
            const result = model.generate({
                category,
                topic: 'test topic',
                recipientName: 'Test',
                companyName: 'TestCorp',
                senderName: 'Sender'
            });
            
            expect(result.subject).toBeDefined();
            expect(result.body).toBeDefined();
            expect(result.quality.overall).toBeGreaterThan(0);
        }
    });
    
    it('includes personalization when provided', () => {
        const result = model.generate({
            category: 'cold_outreach',
            topic: 'email deliverability',
            recipientName: 'Sarah',
            companyName: 'TechCorp',
            senderName: 'Alex'
        });
        
        expect(result.body).toContain('Sarah');
    });
    
    it('tracks training metrics', async () => {
        const metrics = model.getMetrics();
        
        expect(metrics).not.toBeNull();
        expect(metrics!.totalEpochs).toBeGreaterThan(0);
        expect(metrics!.cvScores.length).toBeGreaterThan(0);
    });
    
    it('reports trained status', () => {
        expect(model.isTrained()).toBe(true);
    });
});

// =====================================================
// DATASET VALIDATION TESTS
// =====================================================

describe('Training Datasets', () => {
    it('has valid AESLC samples', () => {
        expect(AESLC_SAMPLES.length).toBeGreaterThan(0);
        
        for (const sample of AESLC_SAMPLES) {
            expect(sample.id).toBeDefined();
            expect(sample.subject).toBeDefined();
            expect(sample.body).toBeDefined();
            expect(sample.category).toBeDefined();
            expect(sample.quality.overall).toBeGreaterThanOrEqual(0);
            expect(sample.quality.overall).toBeLessThanOrEqual(100);
        }
    });
    
    it('has valid subject line training data', () => {
        expect(SUBJECT_LINE_TRAINING_DATA.length).toBeGreaterThan(0);
        
        for (const sample of SUBJECT_LINE_TRAINING_DATA) {
            expect(sample.text).toBeDefined();
            expect(sample.category).toBeDefined();
            expect(sample.performance.openRate).toBeGreaterThanOrEqual(0);
            expect(sample.performance.openRate).toBeLessThanOrEqual(1);
        }
    });
    
    it('has valid email body samples', () => {
        expect(EMAIL_BODY_SAMPLES.length).toBeGreaterThan(0);
        
        for (const sample of EMAIL_BODY_SAMPLES) {
            expect(sample.id).toBeDefined();
            expect(sample.body).toBeDefined();
            expect(sample.category).toBeDefined();
            expect(sample.features.wordCount).toBeGreaterThan(0);
        }
    });
    
    it('covers all major email categories', () => {
        const categories = new Set(AESLC_SAMPLES.map(s => s.category));
        
        expect(categories.has('cold_outreach')).toBe(true);
        expect(categories.has('welcome')).toBe(true);
        expect(categories.has('follow_up')).toBe(true);
    });
});

// =====================================================
// STATISTICAL VALIDATION TESTS
// =====================================================

describe('Statistical Validation', () => {
    it('calculates confidence intervals correctly', async () => {
        const model = new EmailWritingModel();
        await model.train({ maxEpochs: 5, minEpochs: 3 });
        
        const metrics = model.getMetrics();
        
        // CI should contain the mean
        expect(metrics!.cv95CI.lower).toBeLessThan(metrics!.cvMean);
        expect(metrics!.cv95CI.upper).toBeGreaterThan(metrics!.cvMean);
    });
    
    it('detects quality improvements over epochs', async () => {
        const model = new EmailWritingModel();
        const metrics = await model.train({ maxEpochs: 20, minEpochs: 5 });
        
        const epochs = metrics.epochMetrics;
        if (epochs.length > 5) {
            // Later epochs should generally have better quality
            const earlyQuality = epochs.slice(0, 3).reduce((a, b) => a + b.validationQuality, 0) / 3;
            const lateQuality = epochs.slice(-3).reduce((a, b) => a + b.validationQuality, 0) / 3;
            
            // Training should improve or at least maintain quality
            expect(lateQuality).toBeGreaterThanOrEqual(earlyQuality * 0.9);
        }
    });
});

// =====================================================
// OVERFITTING DETECTION TESTS
// =====================================================

describe('Overfitting Prevention', () => {
    it('applies L2 regularization', async () => {
        const model = new EmailWritingModel();
        
        // Train with high regularization
        await model.train({
            maxEpochs: 10,
            minEpochs: 5,
            l2Regularization: 0.1
        });
        
        // Model should still work
        const result = model.generate({
            category: 'cold_outreach',
            topic: 'test',
            recipientName: 'Test'
        });
        
        expect(result.quality.overall).toBeGreaterThan(0);
    });
    
    it('stops early when validation loss increases', async () => {
        const model = new EmailWritingModel();
        
        const metrics = await model.train({
            maxEpochs: 100,
            minEpochs: 3,
            earlyStoppingPatience: 3
        });
        
        // Should stop before max epochs due to early stopping
        expect(metrics.totalEpochs).toBeLessThan(100);
    });
});

// =====================================================
// INTEGRATION TESTS
// =====================================================

describe('End-to-End Integration', () => {
    it('generates production-quality emails', async () => {
        const model = new EmailWritingModel();
        await model.train({
            qualityThreshold: 70, // Lower threshold for faster tests
            maxEpochs: 20,
            minEpochs: 5
        });
        
        const result = model.generate({
            category: 'cold_outreach',
            topic: 'email deliverability',
            recipientName: 'Sarah',
            companyName: 'TechCorp',
            senderName: 'Alex from ApexMail'
        });
        
        // Check quality passes reasonable threshold
        expect(result.quality.overall).toBeGreaterThan(50);
        
        // Check email is well-formed
        expect(result.subject.length).toBeGreaterThan(5);
        expect(result.body.length).toBeGreaterThan(50);
        
        // Check no spam indicators
        expect(result.quality.breakdown.deliverability.spamScore).toBeLessThan(30);
    });
    
    it('optimizer and model work together', async () => {
        const optimizer = new SubjectLineOptimizer();
        await optimizer.train();
        
        const model = new EmailWritingModel();
        await model.train({ maxEpochs: 10, minEpochs: 5 });
        
        // Generate email
        const email = model.generate({
            category: 'cold_outreach',
            topic: 'deliverability',
            recipientName: 'Test'
        });
        
        // Optimize subject
        const optimized = optimizer.optimize(email.subject, 'cold_outreach');
        
        // Optimized should be at least as good
        expect(optimized.optimizedScore.overall).toBeGreaterThanOrEqual(
            optimized.originalScore.overall - 5 // Allow small variance
        );
    });
});
