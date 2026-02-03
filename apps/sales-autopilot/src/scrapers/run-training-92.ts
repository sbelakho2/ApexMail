#!/usr/bin/env tsx
/**
 * Hunter Training Runner - Targets 92%+ Quality
 */

import { generateSyntheticTrainingData, trainUntilQualityThreshold } from './hunter-training.js';

async function main() {
    console.log('🚀 Starting Hunter Training - Target: 92%+\n');
    
    // Generate high-quality training data
    const samples = generateSyntheticTrainingData(500, true);
    console.log(`Generated ${samples.length} high-quality training samples\n`);
    
    // Run training
    const result = await trainUntilQualityThreshold(samples, 0.92, 25);
    
    console.log('\n========================================');
    console.log('         FINAL TRAINING RESULTS         ');
    console.log('========================================');
    console.log(`Overall Quality:     ${(result.metrics.overallQuality * 100).toFixed(2)}%`);
    console.log(`Extraction F1:       ${(result.metrics.extractionF1 * 100).toFixed(2)}%`);
    console.log(`Scoring Accuracy:    ${(result.metrics.scoringAccuracy * 100).toFixed(2)}%`);
    console.log(`Scoring AUC:         ${(result.metrics.scoringAUC * 100).toFixed(2)}%`);
    console.log(`Field Completeness:  ${(result.metrics.avgFieldCompleteness * 100).toFixed(2)}%`);
    console.log(`Avg Confidence:      ${(result.metrics.avgConfidence * 100).toFixed(2)}%`);
    console.log(`Statistically Robust: ${result.metrics.isStatisticallyRobust}`);
    console.log(`Iterations:          ${result.iterations}`);
    console.log(`Sample Size:         ${result.metrics.sampleSize}`);
    console.log('========================================\n');
    
    if (result.metrics.overallQuality >= 0.92) {
        console.log('🎉 SUCCESS! Achieved >92% quality!');
        console.log('✅ Model is ready for production use.');
    } else {
        console.log(`⚠️  Quality at ${(result.metrics.overallQuality * 100).toFixed(2)}% - below 92% target`);
        console.log('Consider: more data, longer training, or hyperparameter tuning.');
    }
}

main().catch(console.error);
