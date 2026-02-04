/**
 * Statistical Validation Framework
 * 
 * Rigorous statistical methods for validating ML models:
 * - K-Fold Cross Validation
 * - Bootstrap Confidence Intervals
 * - Stratified Sampling
 * - Hypothesis Testing
 * - Model Calibration
 * - Feature Importance Analysis
 * 
 * Targets: 92%+ quality with 95% confidence
 */

// =====================================================
// STATISTICAL INTERFACES
// =====================================================

export interface ConfidenceInterval {
    lower: number;
    upper: number;
    confidence: number;
    pointEstimate: number;
}

export interface CrossValidationResult {
    folds: number;
    scores: number[];
    mean: number;
    std: number;
    confidenceInterval: ConfidenceInterval;
    worstFold: number;
    bestFold: number;
}

export interface BootstrapResult {
    samples: number;
    mean: number;
    std: number;
    confidenceInterval: ConfidenceInterval;
    distribution: number[];
}

export interface CalibrationCurve {
    bins: number;
    predictedProbabilities: number[];
    actualFractions: number[];
    expectedCalibrationError: number;
    maxCalibrationError: number;
}

export interface HypothesisTestResult {
    testName: string;
    statistic: number;
    pValue: number;
    isSignificant: boolean;
    effectSize: number;
    interpretation: string;
}

export interface FeatureImportance {
    feature: string;
    importance: number;
    permutationImportance: number;
    shap: number;
}

export interface ModelValidationReport {
    modelName: string;
    timestamp: Date;
    crossValidation: CrossValidationResult;
    bootstrapMetrics: {
        accuracy: BootstrapResult;
        precision: BootstrapResult;
        recall: BootstrapResult;
        f1: BootstrapResult;
        auc: BootstrapResult;
    };
    calibration: CalibrationCurve;
    hypothesisTests: HypothesisTestResult[];
    featureImportances: FeatureImportance[];
    overallQuality: number;
    passesThreshold: boolean;
    recommendations: string[];
}

// =====================================================
// STATISTICAL UTILITIES
// =====================================================

/**
 * Calculate mean of array
 */
export function mean(arr: number[]): number {
    if (arr.length === 0) return 0;
    return arr.reduce((a, b) => a + b, 0) / arr.length;
}

/**
 * Calculate standard deviation
 */
export function std(arr: number[], ddof: number = 0): number {
    if (arr.length <= ddof) return 0;
    const m = mean(arr);
    const variance = arr.reduce((sum, x) => sum + (x - m) ** 2, 0) / (arr.length - ddof);
    return Math.sqrt(variance);
}

/**
 * Calculate percentile
 */
export function percentile(arr: number[], p: number): number {
    if (arr.length === 0) return 0;
    const sorted = [...arr].sort((a, b) => a - b);
    const idx = (p / 100) * (sorted.length - 1);
    const lower = Math.floor(idx);
    const upper = Math.ceil(idx);
    const lowerVal = sorted[lower] as number;
    const upperVal = sorted[upper] as number;
    if (lower === upper) return lowerVal;
    return lowerVal + (upperVal - lowerVal) * (idx - lower);
}

/**
 * Random sampling with replacement (bootstrap)
 */
export function bootstrapSample<T>(arr: T[], size?: number): T[] {
    const n = size !== undefined ? size : arr.length;
    const sample: T[] = [];
    for (let i = 0; i < n; i++) {
        const idx = Math.floor(Math.random() * arr.length);
        sample.push(arr[idx] as T);
    }
    return sample;
}

/**
 * Stratified train-test split
 */
export function stratifiedSplit<T>(
    data: T[],
    labels: boolean[],
    testSize: number = 0.2,
    seed?: number
): { train: T[]; test: T[]; trainLabels: boolean[]; testLabels: boolean[] } {
    // Use seed for reproducibility
    let seedVal = seed !== undefined ? seed : Date.now();
    const rng = () => {
        seedVal = (seedVal * 1103515245 + 12345) % 2147483648;
        return seedVal / 2147483648;
    };
    
    // Separate by class
    const positives: { item: T; idx: number }[] = [];
    const negatives: { item: T; idx: number }[] = [];
    
    for (let idx = 0; idx < labels.length; idx++) {
        const item = data[idx];
        const label = labels[idx];
        if (item !== undefined && label !== undefined) {
            if (label) {
                positives.push({ item, idx });
            } else {
                negatives.push({ item, idx });
            }
        }
    }
    
    // Shuffle each class (type-safe version)
    const shuffleTyped = <X extends object>(arr: X[]): X[] => {
        const shuffled = [...arr];
        for (let i = shuffled.length - 1; i > 0; i--) {
            const j = Math.floor(rng() * (i + 1));
            const temp = shuffled[i] as X;
            shuffled[i] = shuffled[j] as X;
            shuffled[j] = temp;
        }
        return shuffled;
    };
    
    const shuffledPos = shuffleTyped(positives);
    const shuffledNeg = shuffleTyped(negatives);
    
    // Calculate split points
    const posTestCount = Math.round(shuffledPos.length * testSize);
    const negTestCount = Math.round(shuffledNeg.length * testSize);
    
    // Split - these maintain the same type as input
    const testPos = shuffledPos.slice(0, posTestCount);
    const trainPos = shuffledPos.slice(posTestCount);
    const testNeg = shuffledNeg.slice(0, negTestCount);
    const trainNeg = shuffledNeg.slice(negTestCount);
    
    // Combine and shuffle
    const trainCombined = shuffleTyped([...trainPos, ...trainNeg]);
    const testCombined = shuffleTyped([...testPos, ...testNeg]);
    
    return {
        train: trainCombined.map(x => x.item),
        test: testCombined.map(x => x.item),
        trainLabels: trainCombined.map(x => (labels[x.idx] ?? false) as boolean),
        testLabels: testCombined.map(x => (labels[x.idx] ?? false) as boolean),
    };
}

// =====================================================
// K-FOLD CROSS VALIDATION
// =====================================================

export interface KFoldOptions {
    k: number;
    stratified: boolean;
    shuffle: boolean;
    seed?: number;
}

/**
 * Create K stratified folds
 */
export function createKFolds<T>(
    data: T[],
    labels: boolean[],
    options: KFoldOptions
): { trainIdx: number[]; testIdx: number[] }[] {
    const { k, stratified, shuffle, seed } = options;
    
    // Indices for positive and negative samples
    let posIndices: number[] = [];
    let negIndices: number[] = [];
    
    labels.forEach((label, idx) => {
        if (label) posIndices.push(idx);
        else negIndices.push(idx);
    });
    
    // Shuffle if requested
    if (shuffle) {
        const rng = seed !== undefined ? mulberry32(seed) : Math.random;
        posIndices = shuffleArray(posIndices, rng);
        negIndices = shuffleArray(negIndices, rng);
    }
    
    // Create folds
    const folds: { trainIdx: number[]; testIdx: number[] }[] = [];
    
    if (stratified) {
        // Distribute positive and negative samples evenly across folds
        const posFolds = splitIntoFolds(posIndices, k);
        const negFolds = splitIntoFolds(negIndices, k);
        
        for (let i = 0; i < k; i++) {
            const posFold = posFolds[i] ?? [];
            const negFold = negFolds[i] ?? [];
            const testIdx = [...posFold, ...negFold];
            const trainIdx: number[] = [];
            for (let j = 0; j < k; j++) {
                if (j !== i) {
                    trainIdx.push(...(posFolds[j] ?? []), ...(negFolds[j] ?? []));
                }
            }
            folds.push({ trainIdx, testIdx });
        }
    } else {
        // Simple k-fold
        const allIndices = shuffle 
            ? shuffleArray([...Array(data.length).keys()], seed !== undefined ? mulberry32(seed) : Math.random)
            : [...Array(data.length).keys()];
        const splits = splitIntoFolds(allIndices, k);
        
        for (let i = 0; i < k; i++) {
            const testIdx = splits[i] ?? [];
            const trainIdx = splits.filter((_, j) => j !== i).flat();
            folds.push({ trainIdx, testIdx });
        }
    }
    
    return folds;
}

function splitIntoFolds(indices: number[], k: number): number[][] {
    const folds: number[][] = Array.from({ length: k }, () => []);
    indices.forEach((idx, i) => {
        const foldArr = folds[i % k];
        if (foldArr) foldArr.push(idx);
    });
    return folds;
}

function shuffleArray<T>(arr: T[], rng: () => number): T[] {
    const result = [...arr];
    for (let i = result.length - 1; i > 0; i--) {
        const j = Math.floor(rng() * (i + 1));
        const temp = result[i] as T;
        result[i] = result[j] as T;
        result[j] = temp;
    }
    return result;
}

function mulberry32(seed: number): () => number {
    return function() {
        seed = (seed + 0x6D2B79F5) | 0;
        let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

/**
 * Run k-fold cross validation with a scoring function
 */
export function kFoldCrossValidation(
    scores: number[],
    confidence: number = 0.95
): CrossValidationResult {
    const k = scores.length;
    const m = mean(scores);
    const s = std(scores, 1); // Use Bessel's correction
    
    // t-distribution critical value approximation for 95% CI
    const tCrit = confidence === 0.95 ? 2.0 : 2.576; // Approximate for k-1 df
    const marginOfError = tCrit * (s / Math.sqrt(k));
    
    return {
        folds: k,
        scores,
        mean: m,
        std: s,
        confidenceInterval: {
            lower: m - marginOfError,
            upper: m + marginOfError,
            confidence,
            pointEstimate: m,
        },
        worstFold: Math.min(...scores),
        bestFold: Math.max(...scores),
    };
}

// =====================================================
// BOOTSTRAP CONFIDENCE INTERVALS
// =====================================================

export interface BootstrapOptions {
    samples: number;
    confidence: number;
    method: 'percentile' | 'bca' | 'basic';
}

/**
 * Bootstrap confidence interval estimation
 */
export function bootstrapConfidenceInterval(
    data: number[],
    statistic: (sample: number[]) => number,
    options: BootstrapOptions = { samples: 1000, confidence: 0.95, method: 'percentile' }
): BootstrapResult {
    const { samples, confidence, method } = options;
    const bootstrapStats: number[] = [];
    
    for (let i = 0; i < samples; i++) {
        const sample = bootstrapSample(data);
        bootstrapStats.push(statistic(sample));
    }
    
    const alpha = 1 - confidence;
    const sortedStats = [...bootstrapStats].sort((a, b) => a - b);
    
    let lower: number, upper: number;
    
    if (method === 'percentile') {
        lower = percentile(sortedStats, (alpha / 2) * 100);
        upper = percentile(sortedStats, (1 - alpha / 2) * 100);
    } else if (method === 'basic') {
        const observed = statistic(data);
        lower = 2 * observed - percentile(sortedStats, (1 - alpha / 2) * 100);
        upper = 2 * observed - percentile(sortedStats, (alpha / 2) * 100);
    } else {
        // BCa method - simplified implementation
        lower = percentile(sortedStats, (alpha / 2) * 100);
        upper = percentile(sortedStats, (1 - alpha / 2) * 100);
    }
    
    return {
        samples,
        mean: mean(bootstrapStats),
        std: std(bootstrapStats),
        confidenceInterval: {
            lower,
            upper,
            confidence,
            pointEstimate: statistic(data),
        },
        distribution: sortedStats,
    };
}

// =====================================================
// CLASSIFICATION METRICS
// =====================================================

export interface BinaryPrediction {
    actual: boolean;
    predicted: boolean;
    probability: number;
}

export interface ConfusionMatrix {
    truePositives: number;
    trueNegatives: number;
    falsePositives: number;
    falseNegatives: number;
}

export function computeConfusionMatrix(predictions: BinaryPrediction[]): ConfusionMatrix {
    let tp = 0, tn = 0, fp = 0, fn = 0;
    
    for (const pred of predictions) {
        if (pred.actual && pred.predicted) tp++;
        else if (!pred.actual && !pred.predicted) tn++;
        else if (!pred.actual && pred.predicted) fp++;
        else fn++;
    }
    
    return { truePositives: tp, trueNegatives: tn, falsePositives: fp, falseNegatives: fn };
}

export function accuracy(cm: ConfusionMatrix): number {
    const total = cm.truePositives + cm.trueNegatives + cm.falsePositives + cm.falseNegatives;
    return total === 0 ? 0 : (cm.truePositives + cm.trueNegatives) / total;
}

export function precision(cm: ConfusionMatrix): number {
    const denom = cm.truePositives + cm.falsePositives;
    return denom === 0 ? 0 : cm.truePositives / denom;
}

export function recall(cm: ConfusionMatrix): number {
    const denom = cm.truePositives + cm.falseNegatives;
    return denom === 0 ? 0 : cm.truePositives / denom;
}

export function f1Score(cm: ConfusionMatrix): number {
    const p = precision(cm);
    const r = recall(cm);
    return p + r === 0 ? 0 : 2 * (p * r) / (p + r);
}

export function specificity(cm: ConfusionMatrix): number {
    const denom = cm.trueNegatives + cm.falsePositives;
    return denom === 0 ? 0 : cm.trueNegatives / denom;
}

/**
 * Calculate AUC-ROC using trapezoidal rule
 */
export function aucRoc(predictions: BinaryPrediction[]): number {
    // Sort by probability descending
    const sorted = [...predictions].sort((a, b) => b.probability - a.probability);
    
    const totalPositives = sorted.filter(p => p.actual).length;
    const totalNegatives = sorted.length - totalPositives;
    
    if (totalPositives === 0 || totalNegatives === 0) return 0.5;
    
    let auc = 0;
    let tpCount = 0;
    let fpCount = 0;
    let prevTpRate = 0;
    let prevFpRate = 0;
    
    for (const pred of sorted) {
        if (pred.actual) {
            tpCount++;
        } else {
            fpCount++;
        }
        
        const tpRate = tpCount / totalPositives;
        const fpRate = fpCount / totalNegatives;
        
        // Trapezoidal rule
        auc += (fpRate - prevFpRate) * (tpRate + prevTpRate) / 2;
        
        prevTpRate = tpRate;
        prevFpRate = fpRate;
    }
    
    return auc;
}

// =====================================================
// MODEL CALIBRATION
// =====================================================

/**
 * Compute calibration curve (reliability diagram)
 */
export function computeCalibrationCurve(
    predictions: BinaryPrediction[],
    bins: number = 10
): CalibrationCurve {
    const binEdges = Array.from({ length: bins + 1 }, (_, i) => i / bins);
    const predictedProbs: number[] = [];
    const actualFractions: number[] = [];
    
    let totalEce = 0;
    let maxCe = 0;
    
    for (let i = 0; i < bins; i++) {
        const edgeI = binEdges[i] ?? 0;
        const edgeI1 = binEdges[i + 1] ?? 1;
        const binPreds = predictions.filter(
            p => p.probability >= edgeI && p.probability < edgeI1
        );
        
        if (binPreds.length > 0) {
            const avgProb = mean(binPreds.map(p => p.probability));
            const actualFrac = binPreds.filter(p => p.actual).length / binPreds.length;
            
            predictedProbs.push(avgProb);
            actualFractions.push(actualFrac);
            
            const binError = Math.abs(avgProb - actualFrac);
            totalEce += (binPreds.length / predictions.length) * binError;
            maxCe = Math.max(maxCe, binError);
        } else {
            predictedProbs.push((edgeI + edgeI1) / 2);
            actualFractions.push(0);
        }
    }
    
    return {
        bins,
        predictedProbabilities: predictedProbs,
        actualFractions,
        expectedCalibrationError: totalEce,
        maxCalibrationError: maxCe,
    };
}

// =====================================================
// HYPOTHESIS TESTING
// =====================================================

/**
 * One-sample t-test (is mean significantly different from threshold?)
 */
export function oneSampleTTest(
    data: number[],
    hypothesizedMean: number,
    alpha: number = 0.05
): HypothesisTestResult {
    const n = data.length;
    const m = mean(data);
    const s = std(data, 1);
    const se = s / Math.sqrt(n);
    const t = (m - hypothesizedMean) / se;
    
    // Approximate p-value (for large n, t ~ N(0,1))
    const pValue = 2 * (1 - normalCdf(Math.abs(t)));
    
    // Cohen's d effect size
    const effectSize = (m - hypothesizedMean) / s;
    
    return {
        testName: 'One-Sample t-Test',
        statistic: t,
        pValue,
        isSignificant: pValue < alpha,
        effectSize,
        interpretation: pValue < alpha 
            ? `Mean (${m.toFixed(4)}) is significantly different from ${hypothesizedMean}` 
            : `Cannot reject that mean equals ${hypothesizedMean}`,
    };
}

/**
 * Paired t-test (comparing two models)
 */
export function pairedTTest(
    data1: number[],
    data2: number[],
    alpha: number = 0.05
): HypothesisTestResult {
    if (data1.length !== data2.length) {
        throw new Error('Arrays must have same length');
    }
    
    const differences = data1.map((x, i) => x - (data2[i] ?? 0));
    const n = differences.length;
    const m = mean(differences);
    const s = std(differences, 1);
    const se = s / Math.sqrt(n);
    const t = m / se;
    
    const pValue = 2 * (1 - normalCdf(Math.abs(t)));
    const effectSize = m / s;
    
    return {
        testName: 'Paired t-Test',
        statistic: t,
        pValue,
        isSignificant: pValue < alpha,
        effectSize,
        interpretation: pValue < alpha 
            ? `Models are significantly different (mean diff: ${m.toFixed(4)})` 
            : 'No significant difference between models',
    };
}

/**
 * McNemar's test (for comparing classifiers on same test set)
 */
export function mcNemarTest(
    predictions1: boolean[],
    predictions2: boolean[],
    actuals: boolean[],
    alpha: number = 0.05
): HypothesisTestResult {
    // Count discordant pairs
    let b = 0; // Model 1 correct, Model 2 wrong
    let c = 0; // Model 1 wrong, Model 2 correct
    
    for (let i = 0; i < actuals.length; i++) {
        const m1Correct = predictions1[i] === actuals[i];
        const m2Correct = predictions2[i] === actuals[i];
        
        if (m1Correct && !m2Correct) b++;
        else if (!m1Correct && m2Correct) c++;
    }
    
    // McNemar's chi-squared statistic with continuity correction
    const chiSquared = b + c > 0 ? Math.pow(Math.abs(b - c) - 1, 2) / (b + c) : 0;
    
    // Chi-squared distribution with 1 df, approximate p-value
    const pValue = 1 - chiSquaredCdf(chiSquared, 1);
    
    return {
        testName: "McNemar's Test",
        statistic: chiSquared,
        pValue,
        isSignificant: pValue < alpha,
        effectSize: (b - c) / (b + c + 1),
        interpretation: pValue < alpha 
            ? `Classifiers have significantly different error rates (b=${b}, c=${c})` 
            : 'No significant difference in classifier performance',
    };
}

// Statistical distribution functions
function normalCdf(x: number): number {
    // Approximation using error function
    const a1 =  0.254829592;
    const a2 = -0.284496736;
    const a3 =  1.421413741;
    const a4 = -1.453152027;
    const a5 =  1.061405429;
    const p  =  0.3275911;
    
    const sign = x < 0 ? -1 : 1;
    x = Math.abs(x) / Math.sqrt(2);
    
    const t = 1.0 / (1.0 + p * x);
    const y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);
    
    return 0.5 * (1.0 + sign * y);
}

function chiSquaredCdf(x: number, k: number): number {
    // Approximation for chi-squared CDF
    if (x <= 0) return 0;
    return gammaIncomplete(k / 2, x / 2) / gamma(k / 2);
}

function gamma(x: number): number {
    // Lanczos approximation
    const g = 7;
    const c: number[] = [
        0.99999999999980993,
        676.5203681218851,
        -1259.1392167224028,
        771.32342877765313,
        -176.61502916214059,
        12.507343278686905,
        -0.13857109526572012,
        9.9843695780195716e-6,
        1.5056327351493116e-7,
    ];
    
    if (x < 0.5) {
        return Math.PI / (Math.sin(Math.PI * x) * gamma(1 - x));
    }
    
    x -= 1;
    let a: number = c[0] as number;
    for (let i = 1; i < g + 2; i++) {
        a += (c[i] as number) / (x + i);
    }
    
    const t = x + g + 0.5;
    return Math.sqrt(2 * Math.PI) * Math.pow(t, x + 0.5) * Math.exp(-t) * a;
}

function gammaIncomplete(a: number, x: number): number {
    // Series expansion for lower incomplete gamma
    if (x === 0) return 0;
    
    let sum = 0;
    let term = 1 / a;
    sum += term;
    
    for (let n = 1; n < 100; n++) {
        term *= x / (a + n);
        sum += term;
        if (Math.abs(term) < 1e-10) break;
    }
    
    return Math.pow(x, a) * Math.exp(-x) * sum;
}

// =====================================================
// FEATURE IMPORTANCE ANALYSIS
// =====================================================

/**
 * Compute permutation importance
 */
export function permutationImportance<T>(
    data: T[],
    labels: boolean[],
    getFeature: (item: T) => number,
    setFeature: (item: T, value: number) => T,
    scoreFunction: (data: T[], labels: boolean[]) => number,
    nRepeats: number = 5
): number {
    const baselineScore = scoreFunction(data, labels);
    const featureValues = data.map(getFeature);
    const importances: number[] = [];
    
    for (let r = 0; r < nRepeats; r++) {
        // Shuffle the feature values
        const shuffled = shuffleArray(featureValues, Math.random);
        const permutedData = data.map((item, idx) => setFeature(item, shuffled[idx] as number));
        const permutedScore = scoreFunction(permutedData, labels);
        importances.push(baselineScore - permutedScore);
    }
    
    return mean(importances);
}

// =====================================================
// VALIDATION REPORT GENERATOR
// =====================================================

/**
 * Generate comprehensive model validation report
 */
export function generateValidationReport(
    modelName: string,
    crossValScores: number[],
    predictions: BinaryPrediction[],
    qualityThreshold: number = 0.92
): ModelValidationReport {
    const cv = kFoldCrossValidation(crossValScores);
    const cm = computeConfusionMatrix(predictions);
    
    // Bootstrap metrics
    const accuracies = predictions.map((_pred, _idx, arr) => {
        const sample = bootstrapSample(arr);
        const sampleCm = computeConfusionMatrix(sample);
        return accuracy(sampleCm);
    });
    
    const f1Scores = predictions.map((_pred, _idx, arr) => {
        const sample = bootstrapSample(arr);
        const sampleCm = computeConfusionMatrix(sample);
        return f1Score(sampleCm);
    });
    
    const aucScores = predictions.map((_pred, _idx, arr) => {
        const sample = bootstrapSample(arr);
        return aucRoc(sample);
    });
    
    // Full bootstrap CI for key metrics
    const bootstrapAccuracy = bootstrapConfidenceInterval(
        accuracies,
        mean,
        { samples: 1000, confidence: 0.95, method: 'percentile' }
    );
    
    const bootstrapF1 = bootstrapConfidenceInterval(
        f1Scores,
        mean,
        { samples: 1000, confidence: 0.95, method: 'percentile' }
    );
    
    const bootstrapAuc = bootstrapConfidenceInterval(
        aucScores,
        mean,
        { samples: 1000, confidence: 0.95, method: 'percentile' }
    );
    
    // Calibration
    const calibration = computeCalibrationCurve(predictions);
    
    // Hypothesis tests
    const tTest = oneSampleTTest(crossValScores, qualityThreshold);
    
    // Overall quality (weighted average)
    const overallQuality = 
        0.3 * accuracy(cm) +
        0.3 * f1Score(cm) +
        0.3 * aucRoc(predictions) +
        0.1 * (1 - calibration.expectedCalibrationError);
    
    // Generate recommendations
    const recommendations: string[] = [];
    
    if (cv.std > 0.05) {
        recommendations.push('High variance across folds - consider more training data');
    }
    if (recall(cm) < 0.8) {
        recommendations.push('Low recall - adjust decision threshold or add more positive examples');
    }
    if (precision(cm) < 0.8) {
        recommendations.push('Low precision - consider feature engineering or more negative examples');
    }
    if (calibration.expectedCalibrationError > 0.1) {
        recommendations.push('Poor calibration - consider Platt scaling or isotonic regression');
    }
    if (overallQuality < qualityThreshold) {
        recommendations.push(`Quality ${(overallQuality * 100).toFixed(1)}% below ${(qualityThreshold * 100)}% threshold`);
    }
    
    return {
        modelName,
        timestamp: new Date(),
        crossValidation: cv,
        bootstrapMetrics: {
            accuracy: bootstrapAccuracy,
            precision: bootstrapConfidenceInterval(
                predictions.map((_pred, _idx, arr) => {
                    const sample = bootstrapSample(arr);
                    return precision(computeConfusionMatrix(sample));
                }),
                mean,
                { samples: 500, confidence: 0.95, method: 'percentile' }
            ),
            recall: bootstrapConfidenceInterval(
                predictions.map((_pred, _idx, arr) => {
                    const sample = bootstrapSample(arr);
                    return recall(computeConfusionMatrix(sample));
                }),
                mean,
                { samples: 500, confidence: 0.95, method: 'percentile' }
            ),
            f1: bootstrapF1,
            auc: bootstrapAuc,
        },
        calibration,
        hypothesisTests: [tTest],
        featureImportances: [], // To be filled by model-specific analysis
        overallQuality,
        passesThreshold: overallQuality >= qualityThreshold && cv.confidenceInterval.lower >= qualityThreshold,
        recommendations,
    };
}

// =====================================================
// REPORT PRINTER
// =====================================================

export function printValidationReport(report: ModelValidationReport): void {
    /* eslint-disable no-console */
    console.log('\n' + '═'.repeat(70));
    console.log(`    MODEL VALIDATION REPORT: ${report.modelName}`);
    console.log(`    Generated: ${report.timestamp.toISOString()}`);
    console.log('═'.repeat(70));
    
    console.log('\n📊 CROSS-VALIDATION RESULTS');
    console.log('─'.repeat(50));
    console.log(`  Folds: ${report.crossValidation.folds}`);
    console.log(`  Mean Score: ${(report.crossValidation.mean * 100).toFixed(2)}%`);
    console.log(`  Std Dev: ${(report.crossValidation.std * 100).toFixed(2)}%`);
    console.log(`  95% CI: [${(report.crossValidation.confidenceInterval.lower * 100).toFixed(2)}%, ${(report.crossValidation.confidenceInterval.upper * 100).toFixed(2)}%]`);
    console.log(`  Best Fold: ${(report.crossValidation.bestFold * 100).toFixed(2)}%`);
    console.log(`  Worst Fold: ${(report.crossValidation.worstFold * 100).toFixed(2)}%`);
    
    console.log('\n📈 BOOTSTRAP METRICS (95% CI)');
    console.log('─'.repeat(50));
    console.log(`  Accuracy:  ${(report.bootstrapMetrics.accuracy.mean * 100).toFixed(2)}% [${(report.bootstrapMetrics.accuracy.confidenceInterval.lower * 100).toFixed(2)}%, ${(report.bootstrapMetrics.accuracy.confidenceInterval.upper * 100).toFixed(2)}%]`);
    console.log(`  Precision: ${(report.bootstrapMetrics.precision.mean * 100).toFixed(2)}% [${(report.bootstrapMetrics.precision.confidenceInterval.lower * 100).toFixed(2)}%, ${(report.bootstrapMetrics.precision.confidenceInterval.upper * 100).toFixed(2)}%]`);
    console.log(`  Recall:    ${(report.bootstrapMetrics.recall.mean * 100).toFixed(2)}% [${(report.bootstrapMetrics.recall.confidenceInterval.lower * 100).toFixed(2)}%, ${(report.bootstrapMetrics.recall.confidenceInterval.upper * 100).toFixed(2)}%]`);
    console.log(`  F1 Score:  ${(report.bootstrapMetrics.f1.mean * 100).toFixed(2)}% [${(report.bootstrapMetrics.f1.confidenceInterval.lower * 100).toFixed(2)}%, ${(report.bootstrapMetrics.f1.confidenceInterval.upper * 100).toFixed(2)}%]`);
    console.log(`  AUC-ROC:   ${(report.bootstrapMetrics.auc.mean * 100).toFixed(2)}% [${(report.bootstrapMetrics.auc.confidenceInterval.lower * 100).toFixed(2)}%, ${(report.bootstrapMetrics.auc.confidenceInterval.upper * 100).toFixed(2)}%]`);
    
    console.log('\n📉 MODEL CALIBRATION');
    console.log('─'.repeat(50));
    console.log(`  Expected Calibration Error: ${(report.calibration.expectedCalibrationError * 100).toFixed(2)}%`);
    console.log(`  Max Calibration Error: ${(report.calibration.maxCalibrationError * 100).toFixed(2)}%`);
    
    console.log('\n🔬 HYPOTHESIS TESTS');
    console.log('─'.repeat(50));
    for (const test of report.hypothesisTests) {
        console.log(`  ${test.testName}:`);
        console.log(`    Statistic: ${test.statistic.toFixed(4)}`);
        console.log(`    p-value: ${test.pValue.toFixed(6)}`);
        console.log(`    Effect Size: ${test.effectSize.toFixed(4)}`);
        console.log(`    ${test.isSignificant ? '✅' : '❌'} ${test.interpretation}`);
    }
    
    console.log('\n⭐ OVERALL ASSESSMENT');
    console.log('─'.repeat(50));
    console.log(`  Overall Quality: ${(report.overallQuality * 100).toFixed(2)}%`);
    console.log(`  Passes Threshold: ${report.passesThreshold ? '✅ YES' : '❌ NO'}`);
    
    if (report.recommendations.length > 0) {
        console.log('\n💡 RECOMMENDATIONS');
        console.log('─'.repeat(50));
        report.recommendations.forEach((rec, i) => {
            console.log(`  ${i + 1}. ${rec}`);
        });
    }
    
    console.log('\n' + '═'.repeat(70));
    /* eslint-enable no-console */
}

// =====================================================
// QUALITY GATE CHECK
// =====================================================

export interface QualityGateResult {
    passed: boolean;
    overallScore: number;
    checks: {
        name: string;
        passed: boolean;
        actual: number;
        threshold: number;
        message: string;
    }[];
}

export function runQualityGate(
    report: ModelValidationReport,
    thresholds: {
        minAccuracy: number;
        minF1: number;
        minAuc: number;
        maxCalibrationError: number;
        minCvLowerBound: number;
    } = {
        minAccuracy: 0.90,
        minF1: 0.88,
        minAuc: 0.92,
        maxCalibrationError: 0.10,
        minCvLowerBound: 0.88,
    }
): QualityGateResult {
    const checks = [
        {
            name: 'Accuracy',
            actual: report.bootstrapMetrics.accuracy.mean,
            threshold: thresholds.minAccuracy,
            passed: report.bootstrapMetrics.accuracy.confidenceInterval.lower >= thresholds.minAccuracy,
        },
        {
            name: 'F1 Score',
            actual: report.bootstrapMetrics.f1.mean,
            threshold: thresholds.minF1,
            passed: report.bootstrapMetrics.f1.confidenceInterval.lower >= thresholds.minF1,
        },
        {
            name: 'AUC-ROC',
            actual: report.bootstrapMetrics.auc.mean,
            threshold: thresholds.minAuc,
            passed: report.bootstrapMetrics.auc.confidenceInterval.lower >= thresholds.minAuc,
        },
        {
            name: 'Calibration',
            actual: report.calibration.expectedCalibrationError,
            threshold: thresholds.maxCalibrationError,
            passed: report.calibration.expectedCalibrationError <= thresholds.maxCalibrationError,
        },
        {
            name: 'CV Lower Bound',
            actual: report.crossValidation.confidenceInterval.lower,
            threshold: thresholds.minCvLowerBound,
            passed: report.crossValidation.confidenceInterval.lower >= thresholds.minCvLowerBound,
        },
    ].map(c => ({
        ...c,
        message: c.passed 
            ? `✅ ${c.name}: ${(c.actual * 100).toFixed(1)}% >= ${(c.threshold * 100).toFixed(1)}%`
            : `❌ ${c.name}: ${(c.actual * 100).toFixed(1)}% < ${(c.threshold * 100).toFixed(1)}%`,
    }));
    
    return {
        passed: checks.every(c => c.passed),
        overallScore: report.overallQuality,
        checks,
    };
}
