/**
 * Statistical Validation Framework (Clean Version)
 * 
 * Rigorous statistical methods for validating ML models:
 * - K-Fold Cross Validation
 * - Bootstrap Confidence Intervals
 * - Hypothesis Testing
 * - Quality Gates
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

export interface QualityMetrics {
    accuracy: number;
    precision: number;
    recall: number;
    f1Score: number;
    aucRoc: number;
    calibrationError: number;
}

export interface QualityGateConfig {
    minAccuracy: number;
    minPrecision: number;
    minRecall: number;
    minF1: number;
    minAuc: number;
    maxCalibrationError: number;
    minSampleSize: number;
    confidenceLevel: number;
}

export interface QualityGateResult {
    passed: boolean;
    metrics: QualityMetrics;
    thresholds: QualityGateConfig;
    violations: string[];
    confidence: ConfidenceInterval;
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
 * Calculate percentile using linear interpolation
 */
export function percentile(arr: number[], p: number): number {
    if (arr.length === 0) return 0;
    const sorted = [...arr].sort((a, b) => a - b);
    const idx = (p / 100) * (sorted.length - 1);
    const lower = Math.floor(idx);
    const upper = Math.ceil(idx);
    
    if (lower === upper || lower >= sorted.length - 1) {
        return sorted[lower] ?? 0;
    }
    
    const lowerVal = sorted[lower] ?? 0;
    const upperVal = sorted[upper] ?? 0;
    return lowerVal + (upperVal - lowerVal) * (idx - lower);
}

/**
 * Random sampling with replacement (bootstrap)
 */
export function bootstrapSample(arr: number[], size?: number): number[] {
    const n = size ?? arr.length;
    const sample: number[] = [];
    for (let i = 0; i < n; i++) {
        const idx = Math.floor(Math.random() * arr.length);
        const val = arr[idx];
        if (val !== undefined) sample.push(val);
    }
    return sample;
}

/**
 * Seeded random number generator (Mulberry32)
 */
function mulberry32(seed: number): () => number {
    return function() {
        seed = (seed + 0x6D2B79F5) | 0;
        let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

/**
 * Shuffle array in place with optional seeded RNG
 */
function shuffleArray<T>(arr: T[], rng: () => number = Math.random): T[] {
    const result = [...arr];
    for (let i = result.length - 1; i > 0; i--) {
        const j = Math.floor(rng() * (i + 1));
        // Swap elements safely
        const temp = result[i];
        const swapVal = result[j];
        if (temp !== undefined && swapVal !== undefined) {
            result[i] = swapVal;
            result[j] = temp;
        }
    }
    return result;
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

export interface FoldIndices {
    trainIdx: number[];
    testIdx: number[];
}

/**
 * Create K stratified folds for cross-validation
 */
export function createKFolds(
    labels: boolean[],
    options: KFoldOptions
): FoldIndices[] {
    const { k, stratified, shuffle, seed } = options;
    const rng = seed !== undefined ? mulberry32(seed) : Math.random;
    
    // Separate by class
    const posIndices: number[] = [];
    const negIndices: number[] = [];
    
    labels.forEach((label, idx) => {
        if (label) posIndices.push(idx);
        else negIndices.push(idx);
    });
    
    // Shuffle if requested
    const shuffledPos = shuffle ? shuffleArray(posIndices, rng) : posIndices;
    const shuffledNeg = shuffle ? shuffleArray(negIndices, rng) : negIndices;
    
    const folds: FoldIndices[] = [];
    
    if (stratified) {
        // Distribute positive and negative samples evenly across folds
        const posFolds = splitIntoFolds(shuffledPos, k);
        const negFolds = splitIntoFolds(shuffledNeg, k);
        
        for (let i = 0; i < k; i++) {
            const testIdx = [...(posFolds[i] ?? []), ...(negFolds[i] ?? [])];
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
            ? shuffleArray([...Array(labels.length).keys()], rng)
            : [...Array(labels.length).keys()];
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
        const fold = folds[i % k];
        if (fold) fold.push(idx);
    });
    return folds;
}

/**
 * Run k-fold cross validation with scores
 */
export function kFoldCrossValidation(
    scores: number[],
    confidence: number = 0.95
): CrossValidationResult {
    const k = scores.length;
    const m = mean(scores);
    const s = std(scores, 1); // Use Bessel's correction
    
    // t-distribution critical value approximation
    const tCrit = confidence === 0.95 ? 2.0 : 2.576;
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
    method: 'percentile' | 'basic';
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
    } else {
        // Basic method
        const observed = statistic(data);
        lower = 2 * observed - percentile(sortedStats, (1 - alpha / 2) * 100);
        upper = 2 * observed - percentile(sortedStats, (alpha / 2) * 100);
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
        distribution: bootstrapStats,
    };
}

// =====================================================
// MODEL EVALUATION METRICS
// =====================================================

export interface BinaryPrediction {
    actual: boolean;
    predicted: boolean;
    probability: number;
}

export interface ConfusionMatrix {
    tp: number;
    fp: number;
    tn: number;
    fn: number;
}

/**
 * Calculate confusion matrix from predictions
 */
export function confusionMatrix(predictions: BinaryPrediction[]): ConfusionMatrix {
    let tp = 0, fp = 0, tn = 0, fn = 0;
    
    for (const pred of predictions) {
        if (pred.actual && pred.predicted) tp++;
        else if (!pred.actual && pred.predicted) fp++;
        else if (!pred.actual && !pred.predicted) tn++;
        else fn++;
    }
    
    return { tp, fp, tn, fn };
}

/**
 * Calculate accuracy
 */
export function accuracy(cm: ConfusionMatrix): number {
    const total = cm.tp + cm.fp + cm.tn + cm.fn;
    return total === 0 ? 0 : (cm.tp + cm.tn) / total;
}

/**
 * Calculate precision
 */
export function precision(cm: ConfusionMatrix): number {
    const denom = cm.tp + cm.fp;
    return denom === 0 ? 0 : cm.tp / denom;
}

/**
 * Calculate recall
 */
export function recall(cm: ConfusionMatrix): number {
    const denom = cm.tp + cm.fn;
    return denom === 0 ? 0 : cm.tp / denom;
}

/**
 * Calculate F1 score
 */
export function f1Score(cm: ConfusionMatrix): number {
    const p = precision(cm);
    const r = recall(cm);
    return p + r === 0 ? 0 : 2 * (p * r) / (p + r);
}

/**
 * Calculate AUC-ROC using trapezoidal rule
 */
export function aucRoc(predictions: BinaryPrediction[]): number {
    if (predictions.length === 0) return 0;
    
    // Sort by probability descending
    const sorted = [...predictions].sort((a, b) => b.probability - a.probability);
    
    // Count positives and negatives
    const numPositive = sorted.filter(p => p.actual).length;
    const numNegative = sorted.length - numPositive;
    
    if (numPositive === 0 || numNegative === 0) return 0.5;
    
    // Calculate ROC points
    let tpCount = 0;
    let fpCount = 0;
    const points: { tpr: number; fpr: number }[] = [{ tpr: 0, fpr: 0 }];
    
    for (const pred of sorted) {
        if (pred.actual) tpCount++;
        else fpCount++;
        
        points.push({
            tpr: tpCount / numPositive,
            fpr: fpCount / numNegative,
        });
    }
    
    // Calculate AUC using trapezoidal rule
    let auc = 0;
    for (let i = 1; i < points.length; i++) {
        const p1 = points[i - 1];
        const p2 = points[i];
        if (p1 && p2) {
            auc += (p2.fpr - p1.fpr) * (p1.tpr + p2.tpr) / 2;
        }
    }
    
    return auc;
}

// =====================================================
// CALIBRATION ANALYSIS
// =====================================================

/**
 * Calculate calibration curve
 */
export function calibrationCurve(
    predictions: BinaryPrediction[],
    bins: number = 10
): CalibrationCurve {
    const binEdges = Array.from({ length: bins + 1 }, (_, i) => i / bins);
    const predictedProbs: number[] = [];
    const actualFracs: number[] = [];
    const binCounts: number[] = [];
    
    for (let i = 0; i < bins; i++) {
        const lower = binEdges[i];
        const upper = binEdges[i + 1];
        
        if (lower === undefined || upper === undefined) continue;
        
        const binPreds = predictions.filter(
            p => p.probability >= lower && (i === bins - 1 ? p.probability <= upper : p.probability < upper)
        );
        
        if (binPreds.length > 0) {
            const avgPredicted = mean(binPreds.map(p => p.probability));
            const actualPositive = binPreds.filter(p => p.actual).length / binPreds.length;
            predictedProbs.push(avgPredicted);
            actualFracs.push(actualPositive);
            binCounts.push(binPreds.length);
        } else {
            predictedProbs.push((lower + upper) / 2);
            actualFracs.push(0);
            binCounts.push(0);
        }
    }
    
    // Calculate ECE (Expected Calibration Error)
    const totalSamples = predictions.length;
    let ece = 0;
    let mce = 0;
    
    for (let i = 0; i < bins; i++) {
        const count = binCounts[i] ?? 0;
        const predicted = predictedProbs[i] ?? 0;
        const actual = actualFracs[i] ?? 0;
        const calibrationError = Math.abs(predicted - actual);
        
        ece += (count / totalSamples) * calibrationError;
        mce = Math.max(mce, calibrationError);
    }
    
    return {
        bins,
        predictedProbabilities: predictedProbs,
        actualFractions: actualFracs,
        expectedCalibrationError: ece,
        maxCalibrationError: mce,
    };
}

// =====================================================
// HYPOTHESIS TESTING
// =====================================================

/**
 * Two-sample t-test for model comparison
 */
export function tTest(sample1: number[], sample2: number[]): HypothesisTestResult {
    const n1 = sample1.length;
    const n2 = sample2.length;
    const mean1 = mean(sample1);
    const mean2 = mean(sample2);
    const var1 = std(sample1, 1) ** 2;
    const var2 = std(sample2, 1) ** 2;
    
    // Welch's t-test
    const se = Math.sqrt(var1 / n1 + var2 / n2);
    const tStat = se === 0 ? 0 : (mean1 - mean2) / se;
    
    // Approximate p-value using normal distribution for large df
    const pValue = 2 * (1 - normalCdf(Math.abs(tStat)));
    
    // Cohen's d effect size
    const pooledStd = Math.sqrt(((n1 - 1) * var1 + (n2 - 1) * var2) / (n1 + n2 - 2));
    const effectSize = pooledStd === 0 ? 0 : (mean1 - mean2) / pooledStd;
    
    const isSignificant = pValue < 0.05;
    
    return {
        testName: 'Welch\'s t-test',
        statistic: tStat,
        pValue,
        isSignificant,
        effectSize,
        interpretation: isSignificant
            ? `Significant difference (p=${pValue.toFixed(4)}, d=${effectSize.toFixed(2)})`
            : `No significant difference (p=${pValue.toFixed(4)})`,
    };
}

/**
 * Normal CDF approximation (Abramowitz and Stegun)
 */
function normalCdf(x: number): number {
    const a1 = 0.254829592;
    const a2 = -0.284496736;
    const a3 = 1.421413741;
    const a4 = -1.453152027;
    const a5 = 1.061405429;
    const p = 0.3275911;
    
    const sign = x < 0 ? -1 : 1;
    x = Math.abs(x) / Math.sqrt(2);
    
    const t = 1 / (1 + p * x);
    const y = 1 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);
    
    return 0.5 * (1 + sign * y);
}

// =====================================================
// QUALITY GATES
// =====================================================

const DEFAULT_QUALITY_GATE: QualityGateConfig = {
    minAccuracy: 0.88,
    minPrecision: 0.85,
    minRecall: 0.80,
    minF1: 0.85,
    minAuc: 0.90,
    maxCalibrationError: 0.10,
    minSampleSize: 100,
    confidenceLevel: 0.95,
};

/**
 * Run quality gate validation
 */
export function runQualityGate(
    predictions: BinaryPrediction[],
    config: Partial<QualityGateConfig> = {}
): QualityGateResult {
    const thresholds = { ...DEFAULT_QUALITY_GATE, ...config };
    const violations: string[] = [];
    const recommendations: string[] = [];
    
    // Check sample size
    if (predictions.length < thresholds.minSampleSize) {
        violations.push(`Sample size (${predictions.length}) below minimum (${thresholds.minSampleSize})`);
        recommendations.push('Collect more training/test data');
    }
    
    // Calculate metrics
    const cm = confusionMatrix(predictions);
    const acc = accuracy(cm);
    const prec = precision(cm);
    const rec = recall(cm);
    const f1 = f1Score(cm);
    const auc = aucRoc(predictions);
    const cal = calibrationCurve(predictions);
    
    const metrics: QualityMetrics = {
        accuracy: acc,
        precision: prec,
        recall: rec,
        f1Score: f1,
        aucRoc: auc,
        calibrationError: cal.expectedCalibrationError,
    };
    
    // Check thresholds
    if (acc < thresholds.minAccuracy) {
        violations.push(`Accuracy (${(acc * 100).toFixed(1)}%) below threshold (${(thresholds.minAccuracy * 100).toFixed(1)}%)`);
        recommendations.push('Improve feature engineering or model complexity');
    }
    
    if (prec < thresholds.minPrecision) {
        violations.push(`Precision (${(prec * 100).toFixed(1)}%) below threshold (${(thresholds.minPrecision * 100).toFixed(1)}%)`);
        recommendations.push('Increase prediction threshold or reduce false positives');
    }
    
    if (rec < thresholds.minRecall) {
        violations.push(`Recall (${(rec * 100).toFixed(1)}%) below threshold (${(thresholds.minRecall * 100).toFixed(1)}%)`);
        recommendations.push('Lower prediction threshold or improve positive class detection');
    }
    
    if (f1 < thresholds.minF1) {
        violations.push(`F1 Score (${(f1 * 100).toFixed(1)}%) below threshold (${(thresholds.minF1 * 100).toFixed(1)}%)`);
        recommendations.push('Balance precision and recall trade-off');
    }
    
    if (auc < thresholds.minAuc) {
        violations.push(`AUC-ROC (${(auc * 100).toFixed(1)}%) below threshold (${(thresholds.minAuc * 100).toFixed(1)}%)`);
        recommendations.push('Improve model discriminative ability');
    }
    
    if (cal.expectedCalibrationError > thresholds.maxCalibrationError) {
        violations.push(`Calibration error (${(cal.expectedCalibrationError * 100).toFixed(1)}%) above threshold (${(thresholds.maxCalibrationError * 100).toFixed(1)}%)`);
        recommendations.push('Apply probability calibration (Platt scaling or isotonic regression)');
    }
    
    // Calculate confidence interval for accuracy
    const accuracies = predictions.map(p => (p.actual === p.predicted) ? 1 : 0);
    const bootstrap = bootstrapConfidenceInterval(accuracies, mean, {
        samples: 1000,
        confidence: thresholds.confidenceLevel,
        method: 'percentile',
    });
    
    return {
        passed: violations.length === 0,
        metrics,
        thresholds,
        violations,
        confidence: bootstrap.confidenceInterval,
        recommendations,
    };
}

// =====================================================
// VALIDATION REPORT GENERATION
// =====================================================

export interface ValidationReport {
    modelName: string;
    timestamp: Date;
    datasetSize: number;
    positiveRate: number;
    crossValidation: CrossValidationResult | null;
    qualityGate: QualityGateResult;
    summary: string;
    passesAllChecks: boolean;
}

/**
 * Generate comprehensive validation report
 */
export function generateValidationReport(
    modelName: string,
    predictions: BinaryPrediction[],
    crossValScores?: number[],
    config?: Partial<QualityGateConfig>
): ValidationReport {
    const positiveCount = predictions.filter(p => p.actual).length;
    const positiveRate = predictions.length > 0 ? positiveCount / predictions.length : 0;
    
    // Run quality gate
    const qualityGate = runQualityGate(predictions, config);
    
    // Cross-validation results if available
    const crossValidation = crossValScores && crossValScores.length > 0
        ? kFoldCrossValidation(crossValScores)
        : null;
    
    // Check cross-validation stability
    let cvPasses = true;
    if (crossValidation) {
        // Check if worst fold is within acceptable range
        if (crossValidation.worstFold < 0.80) {
            cvPasses = false;
            qualityGate.violations.push(`Cross-validation worst fold (${(crossValidation.worstFold * 100).toFixed(1)}%) below 80%`);
            qualityGate.recommendations.push('Address model instability across data splits');
        }
        
        // Check if standard deviation is too high
        if (crossValidation.std > 0.05) {
            cvPasses = false;
            qualityGate.violations.push(`Cross-validation std (${(crossValidation.std * 100).toFixed(1)}%) above 5%`);
            qualityGate.recommendations.push('Reduce variance in model performance');
        }
    }
    
    const passesAllChecks = qualityGate.passed && cvPasses;
    
    // Generate summary
    const summaryParts: string[] = [
        `Model: ${modelName}`,
        `Dataset: ${predictions.length} samples (${(positiveRate * 100).toFixed(1)}% positive)`,
        `Accuracy: ${(qualityGate.metrics.accuracy * 100).toFixed(1)}%`,
        `F1 Score: ${(qualityGate.metrics.f1Score * 100).toFixed(1)}%`,
        `AUC-ROC: ${(qualityGate.metrics.aucRoc * 100).toFixed(1)}%`,
    ];
    
    if (crossValidation) {
        summaryParts.push(`CV Mean: ${(crossValidation.mean * 100).toFixed(1)}% ± ${(crossValidation.std * 100).toFixed(1)}%`);
    }
    
    summaryParts.push(passesAllChecks ? '✅ PASSES ALL QUALITY GATES' : '❌ FAILS QUALITY GATES');
    
    return {
        modelName,
        timestamp: new Date(),
        datasetSize: predictions.length,
        positiveRate,
        crossValidation,
        qualityGate,
        summary: summaryParts.join('\n'),
        passesAllChecks,
    };
}

// =====================================================
// EXPORTS FOR TRAINING PIPELINE
// =====================================================

export {
    DEFAULT_QUALITY_GATE,
    normalCdf,
};
