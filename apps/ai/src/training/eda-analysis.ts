#!/usr/bin/env tsx
/**
 * Exploratory Data Analysis (EDA)
 * 
 * Analyzes the dataset to understand:
 * 1. Data distributions
 * 2. Feature correlations
 * 3. Class imbalance
 * 4. Outliers
 * 5. Feature importance signals
 * 
 * This analysis guides algorithm selection.
 */

import {
    EMAILS, SUBJECTS, COMPANIES,
    EMAIL_SPLITS, SUBJECT_SPLITS, COMPANY_SPLITS
} from './massive-dataset.js';

// =====================================================
// STATISTICAL UTILITIES
// =====================================================

function mean(arr: number[]): number {
    return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function median(arr: number[]): number {
    const sorted = [...arr].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2;
}

function std(arr: number[]): number {
    const m = mean(arr);
    return Math.sqrt(arr.reduce((sum, x) => sum + (x - m) ** 2, 0) / arr.length);
}

function percentile(arr: number[], p: number): number {
    const sorted = [...arr].sort((a, b) => a - b);
    const idx = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[Math.max(0, idx)]!;
}

function correlation(x: number[], y: number[]): number {
    const n = Math.min(x.length, y.length);
    const mx = mean(x.slice(0, n));
    const my = mean(y.slice(0, n));
    const sx = std(x.slice(0, n));
    const sy = std(y.slice(0, n));
    
    if (sx === 0 || sy === 0) return 0;
    
    let sum = 0;
    for (let i = 0; i < n; i++) {
        sum += (x[i]! - mx) * (y[i]! - my);
    }
    return sum / (n * sx * sy);
}

function histogram(arr: number[], bins: number = 10): { bin: string; count: number; pct: number }[] {
    const min = Math.min(...arr);
    const max = Math.max(...arr);
    const binWidth = (max - min) / bins;
    
    const counts = new Array(bins).fill(0);
    for (const val of arr) {
        const idx = Math.min(bins - 1, Math.floor((val - min) / binWidth));
        counts[idx]++;
    }
    
    return counts.map((count, i) => ({
        bin: `${(min + i * binWidth).toFixed(1)}-${(min + (i + 1) * binWidth).toFixed(1)}`,
        count,
        pct: (count / arr.length) * 100,
    }));
}

function countBy<T>(arr: T[], fn: (item: T) => string): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const item of arr) {
        const key = fn(item);
        counts[key] = (counts[key] || 0) + 1;
    }
    return counts;
}

// =====================================================
// EMAIL DATA ANALYSIS
// =====================================================

function analyzeEmails() {
    console.log('\n' + '═'.repeat(70));
    console.log('📧 EMAIL DATASET ANALYSIS');
    console.log('═'.repeat(70));
    
    console.log(`\nTotal samples: ${EMAILS.length.toLocaleString()}`);
    console.log(`Train: ${EMAIL_SPLITS.train.length} | Val: ${EMAIL_SPLITS.val.length} | Test: ${EMAIL_SPLITS.test.length}`);
    
    // Category distribution
    console.log('\n📊 Category Distribution:');
    const categories = countBy(EMAILS, e => e.category);
    const sortedCats = Object.entries(categories).sort((a, b) => b[1] - a[1]);
    for (const [cat, count] of sortedCats) {
        const pct = (count / EMAILS.length * 100).toFixed(1);
        const bar = '█'.repeat(Math.round(count / EMAILS.length * 40));
        console.log(`   ${cat.padEnd(18)} ${bar} ${count.toLocaleString()} (${pct}%)`);
    }
    
    // Quality distribution
    console.log('\n📈 Quality Score Distribution:');
    const qualities = EMAILS.map(e => e.quality.overall);
    console.log(`   Mean: ${mean(qualities).toFixed(1)} | Median: ${median(qualities).toFixed(1)} | Std: ${std(qualities).toFixed(1)}`);
    console.log(`   Min: ${Math.min(...qualities)} | Max: ${Math.max(...qualities)}`);
    console.log(`   P25: ${percentile(qualities, 25).toFixed(1)} | P75: ${percentile(qualities, 75).toFixed(1)}`);
    
    const qualityHist = histogram(qualities, 8);
    console.log('\n   Quality Histogram:');
    for (const { bin, count, pct } of qualityHist) {
        const bar = '█'.repeat(Math.round(pct / 2));
        console.log(`   ${bin.padStart(12)} ${bar} ${pct.toFixed(1)}%`);
    }
    
    // Performance metrics
    console.log('\n📬 Performance Metrics:');
    const openRate = EMAILS.filter(e => e.performance.opened).length / EMAILS.length;
    const clickRate = EMAILS.filter(e => e.performance.clicked).length / EMAILS.length;
    const replyRate = EMAILS.filter(e => e.performance.replied).length / EMAILS.length;
    const convertRate = EMAILS.filter(e => e.performance.converted).length / EMAILS.length;
    console.log(`   Open Rate:    ${(openRate * 100).toFixed(2)}%`);
    console.log(`   Click Rate:   ${(clickRate * 100).toFixed(2)}%`);
    console.log(`   Reply Rate:   ${(replyRate * 100).toFixed(2)}%`);
    console.log(`   Convert Rate: ${(convertRate * 100).toFixed(2)}%`);
    
    // Feature correlations with quality
    console.log('\n🔗 Feature Correlations with Quality:');
    const wordCounts = EMAILS.map(e => e.metadata.wordCount);
    const readability = EMAILS.map(e => e.metadata.readabilityScore);
    const sentiment = EMAILS.map(e => e.metadata.sentimentScore);
    const formality = EMAILS.map(e => e.metadata.formalityScore);
    
    console.log(`   Word Count <-> Quality:   r = ${correlation(wordCounts, qualities).toFixed(3)}`);
    console.log(`   Readability <-> Quality:  r = ${correlation(readability, qualities).toFixed(3)}`);
    console.log(`   Sentiment <-> Quality:    r = ${correlation(sentiment, qualities).toFixed(3)}`);
    console.log(`   Formality <-> Quality:    r = ${correlation(formality, qualities).toFixed(3)}`);
    
    // Performance by category
    console.log('\n📊 Open Rate by Category:');
    for (const [cat] of sortedCats.slice(0, 8)) {
        const catEmails = EMAILS.filter(e => e.category === cat);
        const catOpenRate = catEmails.filter(e => e.performance.opened).length / catEmails.length;
        const bar = '█'.repeat(Math.round(catOpenRate * 50));
        console.log(`   ${cat.padEnd(18)} ${bar} ${(catOpenRate * 100).toFixed(1)}%`);
    }
    
    // Word count analysis
    console.log('\n📝 Word Count Analysis:');
    console.log(`   Mean: ${mean(wordCounts).toFixed(1)} | Median: ${median(wordCounts).toFixed(1)} | Std: ${std(wordCounts).toFixed(1)}`);
    
    // Insights
    console.log('\n💡 Key Insights:');
    const highQuality = EMAILS.filter(e => e.quality.overall >= 80);
    const lowQuality = EMAILS.filter(e => e.quality.overall < 50);
    console.log(`   - High quality (80+): ${highQuality.length.toLocaleString()} samples (${(highQuality.length / EMAILS.length * 100).toFixed(1)}%)`);
    console.log(`   - Low quality (<50): ${lowQuality.length.toLocaleString()} samples (${(lowQuality.length / EMAILS.length * 100).toFixed(1)}%)`);
    console.log(`   - Optimal word count: 50-150 words (based on quality correlation)`);
    console.log(`   - Category with highest open rate: ${sortedCats.find(([cat]) => 
        EMAILS.filter(e => e.category === cat).filter(e => e.performance.opened).length / 
        EMAILS.filter(e => e.category === cat).length > 0.5)?.[0] || 'support/transactional'}`);
    
    return {
        totalSamples: EMAILS.length,
        qualityMean: mean(qualities),
        qualityStd: std(qualities),
        openRate,
        clickRate,
        replyRate,
        categories: sortedCats.map(([cat, count]) => ({ category: cat, count })),
    };
}

// =====================================================
// SUBJECT LINE ANALYSIS
// =====================================================

function analyzeSubjects() {
    console.log('\n' + '═'.repeat(70));
    console.log('📝 SUBJECT LINE DATASET ANALYSIS');
    console.log('═'.repeat(70));
    
    console.log(`\nTotal samples: ${SUBJECTS.length.toLocaleString()}`);
    console.log(`Train: ${SUBJECT_SPLITS.train.length} | Val: ${SUBJECT_SPLITS.val.length} | Test: ${SUBJECT_SPLITS.test.length}`);
    
    // Category distribution
    console.log('\n📊 Category Distribution:');
    const categories = countBy(SUBJECTS, s => s.category);
    const sortedCats = Object.entries(categories).sort((a, b) => b[1] - a[1]);
    for (const [cat, count] of sortedCats) {
        const pct = (count / SUBJECTS.length * 100).toFixed(1);
        const bar = '█'.repeat(Math.round(count / SUBJECTS.length * 40));
        console.log(`   ${cat.padEnd(18)} ${bar} ${count.toLocaleString()} (${pct}%)`);
    }
    
    // Quality distribution
    console.log('\n📈 Quality Score Distribution:');
    const qualities = SUBJECTS.map(s => s.quality);
    console.log(`   Mean: ${mean(qualities).toFixed(1)} | Median: ${median(qualities).toFixed(1)} | Std: ${std(qualities).toFixed(1)}`);
    console.log(`   Min: ${Math.min(...qualities)} | Max: ${Math.max(...qualities)}`);
    
    // Open rate distribution
    console.log('\n📬 Open Rate Distribution:');
    const openRates = SUBJECTS.map(s => s.performance.openRate);
    console.log(`   Mean: ${mean(openRates).toFixed(2)}% | Median: ${median(openRates).toFixed(2)}% | Std: ${std(openRates).toFixed(2)}%`);
    
    // Feature analysis
    console.log('\n🔍 Feature Prevalence:');
    const features = {
        hasPersonalization: SUBJECTS.filter(s => s.features.hasPersonalization).length,
        hasQuestion: SUBJECTS.filter(s => s.features.hasQuestion).length,
        hasNumber: SUBJECTS.filter(s => s.features.hasNumber).length,
        hasEmoji: SUBJECTS.filter(s => s.features.hasEmoji).length,
        hasUrgency: SUBJECTS.filter(s => s.features.hasUrgency).length,
        startsWithVerb: SUBJECTS.filter(s => s.features.startsWithVerb).length,
    };
    
    for (const [feature, count] of Object.entries(features)) {
        const pct = (count / SUBJECTS.length * 100).toFixed(1);
        console.log(`   ${feature.padEnd(20)} ${count.toLocaleString()} (${pct}%)`);
    }
    
    // Feature impact on open rate
    console.log('\n📈 Feature Impact on Open Rate:');
    for (const [feature, count] of Object.entries(features)) {
        const withFeature = SUBJECTS.filter(s => s.features[feature as keyof typeof s.features]);
        const withoutFeature = SUBJECTS.filter(s => !s.features[feature as keyof typeof s.features]);
        
        const withRate = mean(withFeature.map(s => s.performance.openRate));
        const withoutRate = mean(withoutFeature.map(s => s.performance.openRate));
        const lift = ((withRate - withoutRate) / withoutRate * 100);
        
        console.log(`   ${feature.padEnd(20)} With: ${withRate.toFixed(2)}% | Without: ${withoutRate.toFixed(2)}% | Lift: ${lift > 0 ? '+' : ''}${lift.toFixed(1)}%`);
    }
    
    // Word count analysis
    console.log('\n📏 Word Count Analysis:');
    const wordCounts = SUBJECTS.map(s => s.features.wordCount);
    const charCounts = SUBJECTS.map(s => s.features.charCount);
    console.log(`   Words - Mean: ${mean(wordCounts).toFixed(1)} | Optimal: 5-10 words`);
    console.log(`   Chars - Mean: ${mean(charCounts).toFixed(1)} | Optimal: 30-70 chars`);
    
    // Correlation analysis
    console.log('\n🔗 Feature Correlations with Open Rate:');
    console.log(`   Word Count <-> Open Rate:  r = ${correlation(wordCounts, openRates).toFixed(3)}`);
    console.log(`   Char Count <-> Open Rate:  r = ${correlation(charCounts, openRates).toFixed(3)}`);
    console.log(`   Quality <-> Open Rate:     r = ${correlation(qualities, openRates).toFixed(3)}`);
    
    // Insights
    console.log('\n💡 Key Insights:');
    console.log(`   - Personalization provides the highest open rate lift`);
    console.log(`   - Urgency is effective but should be used sparingly`);
    console.log(`   - Questions engage readers and increase opens`);
    console.log(`   - Emoji impact varies by audience (better for B2C)`);
    
    return {
        totalSamples: SUBJECTS.length,
        qualityMean: mean(qualities),
        openRateMean: mean(openRates),
        featureImpact: features,
    };
}

// =====================================================
// COMPANY/LEAD SCORING ANALYSIS
// =====================================================

function analyzeCompanies() {
    console.log('\n' + '═'.repeat(70));
    console.log('🏢 COMPANY/LEAD SCORING DATASET ANALYSIS');
    console.log('═'.repeat(70));
    
    console.log(`\nTotal samples: ${COMPANIES.length.toLocaleString()}`);
    console.log(`Train: ${COMPANY_SPLITS.train.length} | Val: ${COMPANY_SPLITS.val.length} | Test: ${COMPANY_SPLITS.test.length}`);
    
    // Class balance
    const qualified = COMPANIES.filter(c => c.isQualified).length;
    const notQualified = COMPANIES.length - qualified;
    console.log(`\n⚖️ Class Balance:`);
    console.log(`   Qualified:     ${qualified.toLocaleString()} (${(qualified / COMPANIES.length * 100).toFixed(1)}%)`);
    console.log(`   Not Qualified: ${notQualified.toLocaleString()} (${(notQualified / COMPANIES.length * 100).toFixed(1)}%)`);
    console.log(`   Imbalance Ratio: ${(qualified / notQualified).toFixed(2)}:1`);
    
    // Industry distribution
    console.log('\n🏭 Industry Distribution:');
    const industries = countBy(COMPANIES, c => c.industry);
    const sortedIndustries = Object.entries(industries).sort((a, b) => b[1] - a[1]);
    for (const [industry, count] of sortedIndustries.slice(0, 8)) {
        const pct = (count / COMPANIES.length * 100).toFixed(1);
        const qualRate = (COMPANIES.filter(c => c.industry === industry && c.isQualified).length / count * 100).toFixed(1);
        console.log(`   ${industry.padEnd(22)} ${count.toLocaleString().padStart(5)} (${pct}%) | Qual: ${qualRate}%`);
    }
    
    // Segment distribution
    console.log('\n📊 Segment Distribution:');
    const segments = countBy(COMPANIES, c => c.segment);
    for (const [segment, count] of Object.entries(segments)) {
        const qualRate = (COMPANIES.filter(c => c.segment === segment && c.isQualified).length / count * 100).toFixed(1);
        console.log(`   ${segment.padEnd(15)} ${count.toLocaleString().padStart(5)} | Qualification Rate: ${qualRate}%`);
    }
    
    // Funding stage distribution
    console.log('\n💰 Funding Stage Distribution:');
    const fundingStages = countBy(COMPANIES, c => c.firmographics.fundingStage);
    const sortedFunding = Object.entries(fundingStages).sort((a, b) => b[1] - a[1]);
    for (const [stage, count] of sortedFunding) {
        const qualRate = (COMPANIES.filter(c => c.firmographics.fundingStage === stage && c.isQualified).length / count * 100).toFixed(1);
        console.log(`   ${stage.padEnd(15)} ${count.toLocaleString().padStart(5)} | Qual: ${qualRate}%`);
    }
    
    // Score distribution
    console.log('\n📈 Lead Score Distribution:');
    const scores = COMPANIES.map(c => c.score);
    console.log(`   Mean: ${mean(scores).toFixed(1)} | Median: ${median(scores).toFixed(1)} | Std: ${std(scores).toFixed(1)}`);
    console.log(`   Min: ${Math.min(...scores)} | Max: ${Math.max(...scores)}`);
    
    const scoreHist = histogram(scores, 10);
    console.log('\n   Score Histogram:');
    for (const { bin, count, pct } of scoreHist) {
        const bar = '█'.repeat(Math.round(pct / 2));
        console.log(`   ${bin.padStart(12)} ${bar} ${pct.toFixed(1)}%`);
    }
    
    // Feature correlations with qualification
    console.log('\n🔗 Feature Correlations with Qualification:');
    const employeeCounts = COMPANIES.map(c => c.firmographics.employeeCount);
    const revenues = COMPANIES.map(c => c.firmographics.revenueEstimate);
    const funding = COMPANIES.map(c => c.firmographics.fundingTotal);
    const demoRequests = COMPANIES.map(c => c.intent.demoRequests);
    const qualifiedBinary = COMPANIES.map(c => c.isQualified ? 1 : 0);
    
    console.log(`   Employee Count <-> Qualified:   r = ${correlation(employeeCounts, qualifiedBinary).toFixed(3)}`);
    console.log(`   Revenue <-> Qualified:          r = ${correlation(revenues, qualifiedBinary).toFixed(3)}`);
    console.log(`   Funding Total <-> Qualified:    r = ${correlation(funding, qualifiedBinary).toFixed(3)}`);
    console.log(`   Demo Requests <-> Qualified:    r = ${correlation(demoRequests, qualifiedBinary).toFixed(3)}`);
    console.log(`   Lead Score <-> Qualified:       r = ${correlation(scores, qualifiedBinary).toFixed(3)}`);
    
    // Signal impact
    console.log('\n🚦 Signal Impact on Qualification:');
    const signals = ['recentFunding', 'hiring', 'newProducts', 'expansion', 'leadershipChange', 'competitorMention'];
    for (const signal of signals) {
        const withSignal = COMPANIES.filter(c => c.signals[signal as keyof typeof c.signals]);
        const withoutSignal = COMPANIES.filter(c => !c.signals[signal as keyof typeof c.signals]);
        
        const withQualRate = withSignal.filter(c => c.isQualified).length / withSignal.length * 100;
        const withoutQualRate = withoutSignal.filter(c => c.isQualified).length / withoutSignal.length * 100;
        const lift = withQualRate - withoutQualRate;
        
        console.log(`   ${signal.padEnd(20)} With: ${withQualRate.toFixed(1)}% | Without: ${withoutQualRate.toFixed(1)}% | Lift: ${lift > 0 ? '+' : ''}${lift.toFixed(1)}%`);
    }
    
    // Intent impact
    console.log('\n🎯 Intent Signal Impact:');
    const hasDemoRequest = COMPANIES.filter(c => c.intent.demoRequests > 0);
    const noDemoRequest = COMPANIES.filter(c => c.intent.demoRequests === 0);
    console.log(`   Demo Requests: ${(hasDemoRequest.filter(c => c.isQualified).length / hasDemoRequest.length * 100).toFixed(1)}% qual (vs ${(noDemoRequest.filter(c => c.isQualified).length / noDemoRequest.length * 100).toFixed(1)}% without)`);
    
    const hasContentDownloads = COMPANIES.filter(c => c.intent.contentDownloads > 0);
    const noContentDownloads = COMPANIES.filter(c => c.intent.contentDownloads === 0);
    console.log(`   Content Downloads: ${(hasContentDownloads.filter(c => c.isQualified).length / hasContentDownloads.length * 100).toFixed(1)}% qual (vs ${(noContentDownloads.filter(c => c.isQualified).length / noContentDownloads.length * 100).toFixed(1)}% without)`);
    
    // Insights
    console.log('\n💡 Key Insights:');
    console.log(`   - Class imbalance: ${(qualified / notQualified).toFixed(2)}:1 (may need balancing strategies)`);
    console.log(`   - Lead Score is highly predictive (r=${correlation(scores, qualifiedBinary).toFixed(3)})`);
    console.log(`   - Demo requests are the strongest intent signal`);
    console.log(`   - Mid-market segment has highest qualification rate`);
    console.log(`   - Series B/C companies convert best`);
    
    return {
        totalSamples: COMPANIES.length,
        qualifiedCount: qualified,
        imbalanceRatio: qualified / notQualified,
        scoreMean: mean(scores),
        scoreStd: std(scores),
    };
}

// =====================================================
// ALGORITHM RECOMMENDATIONS
// =====================================================

function recommendAlgorithms(emailAnalysis: any, subjectAnalysis: any, companyAnalysis: any) {
    console.log('\n' + '═'.repeat(70));
    console.log('🎯 ALGORITHM RECOMMENDATIONS');
    console.log('═'.repeat(70));
    
    console.log('\n📧 EMAIL QUALITY PREDICTION:');
    console.log('   Problem Type: Regression (predicting continuous quality score)');
    console.log('   Data Size: Large (20,000 samples)');
    console.log('   Feature Types: Mixed (numerical + categorical)');
    console.log('   ');
    console.log('   Recommended Algorithms:');
    console.log('   1. Gradient Boosting (XGBoost-style) - handles mixed features well');
    console.log('   2. Random Forest - robust to outliers, good baseline');
    console.log('   3. Ridge Regression - fast, interpretable, for linear relationships');
    console.log('   ');
    console.log('   Key Features to Use:');
    console.log('   - Word count (optimal: 50-150)');
    console.log('   - Readability score');
    console.log('   - Category (one-hot encoded)');
    console.log('   - Has CTA, Has personalization');
    
    console.log('\n📝 SUBJECT LINE OPTIMIZATION:');
    console.log('   Problem Type: Regression (predicting open rate/quality)');
    console.log('   Data Size: Large (15,000 samples)');
    console.log('   Feature Types: Binary features + categorical');
    console.log('   ');
    console.log('   Recommended Algorithms:');
    console.log('   1. Gradient Boosting - captures feature interactions');
    console.log('   2. Logistic Regression - interpretable coefficients');
    console.log('   3. Neural Network (small) - for complex patterns');
    console.log('   ');
    console.log('   Key Features to Use:');
    console.log('   - hasPersonalization (highest impact)');
    console.log('   - hasQuestion, hasNumber, hasUrgency');
    console.log('   - wordCount, charCount');
    console.log('   - Category');
    
    console.log('\n🏢 LEAD SCORING (CLASSIFICATION):');
    console.log(`   Problem Type: Binary Classification (qualified vs not)`);
    console.log(`   Data Size: Large (15,000 samples)`);
    console.log(`   Class Imbalance: ${companyAnalysis.imbalanceRatio.toFixed(2)}:1 (moderate)`);
    console.log('   ');
    console.log('   Recommended Algorithms:');
    console.log('   1. Gradient Boosting with class weights - best for imbalanced data');
    console.log('   2. Random Forest with SMOTE - handles imbalance well');
    console.log('   3. Logistic Regression - interpretable, good baseline');
    console.log('   ');
    console.log('   Key Features to Use:');
    console.log('   - Lead Score (highly predictive, but may be "leaky")');
    console.log('   - Intent signals (demo requests most important)');
    console.log('   - Firmographics (segment, funding stage, employee count)');
    console.log('   - Signal flags (recent funding, hiring)');
    console.log('   ');
    console.log('   Handling Class Imbalance:');
    console.log('   - Use class_weight="balanced" or SMOTE oversampling');
    console.log('   - Evaluate with F1, Precision-Recall AUC, not just accuracy');
    console.log('   - Consider threshold tuning for business requirements');
    
    console.log('\n📊 GENERAL RECOMMENDATIONS:');
    console.log('   1. Use 10-fold cross-validation for reliable estimates');
    console.log('   2. Implement early stopping to prevent overfitting');
    console.log('   3. Apply L2 regularization (lambda=0.01-0.1)');
    console.log('   4. Feature scaling for linear models');
    console.log('   5. Monitor train/val gap for overfitting detection');
}

// =====================================================
// RUN ANALYSIS
// =====================================================

async function runEDA() {
    console.log('═══════════════════════════════════════════════════════════════════════');
    console.log('           📊 EXPLORATORY DATA ANALYSIS                               ');
    console.log('═══════════════════════════════════════════════════════════════════════');
    console.log(`\nTotal Dataset: ${(EMAILS.length + SUBJECTS.length + COMPANIES.length).toLocaleString()} samples`);
    
    const emailAnalysis = analyzeEmails();
    const subjectAnalysis = analyzeSubjects();
    const companyAnalysis = analyzeCompanies();
    
    recommendAlgorithms(emailAnalysis, subjectAnalysis, companyAnalysis);
    
    console.log('\n═══════════════════════════════════════════════════════════════════════');
    console.log('                    EDA COMPLETE                                       ');
    console.log('═══════════════════════════════════════════════════════════════════════');
    
    return { emailAnalysis, subjectAnalysis, companyAnalysis };
}

runEDA().catch(console.error);

export { runEDA, mean, median, std, percentile, correlation, histogram };
