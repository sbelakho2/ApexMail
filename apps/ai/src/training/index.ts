/**
 * Master Training Runner
 * 
 * Orchestrates all email ML training:
 * 1. Email Writing Model
 * 2. Subject Line Optimizer
 * 3. Lead Scoring (webscraping)
 * 
 * Runs iterative training loops until quality gates are met.
 */

import { runEmailWritingTraining, EmailWritingModel, type TrainingMetrics } from './email-training-pipeline.js';
import { runSubjectLineTraining, SubjectLineOptimizer } from './subject-line-optimizer.js';
import { runLeadScoringTraining, LeadScoringModel } from './lead-scoring-pipeline.js';
import { EmailQualityEvaluator } from './email-quality-evaluator.js';

// =====================================================
// MASTER TRAINING CONFIG
// =====================================================

export interface MasterTrainingConfig {
    // Quality gates
    emailWritingThreshold: number;     // Default: 92%
    subjectLineThreshold: number;      // Default: 90%
    leadScoringThreshold: number;      // Default: 88%
    
    // Training settings
    maxIterations: number;             // Default: 5
    continueOnFailure: boolean;        // Default: true
    
    // Output
    verbose: boolean;                  // Default: true
    saveModels: boolean;               // Default: true
}

const DEFAULT_MASTER_CONFIG: MasterTrainingConfig = {
    emailWritingThreshold: 92,
    subjectLineThreshold: 90,
    leadScoringThreshold: 88,
    maxIterations: 5,
    continueOnFailure: true,
    verbose: true,
    saveModels: true
};

// =====================================================
// TRAINING RESULTS
// =====================================================

export interface MasterTrainingResult {
    success: boolean;
    emailWriting: {
        trained: boolean;
        quality: number;
        passedThreshold: boolean;
        iterations: number;
        metrics?: TrainingMetrics;
    };
    subjectLine: {
        trained: boolean;
        quality: number;
        passedThreshold: boolean;
        iterations: number;
    };
    leadScoring: {
        trained: boolean;
        quality: number;
        passedThreshold: boolean;
        iterations: number;
    };
    totalTime: number;
    recommendations: string[];
}

// =====================================================
// MASTER TRAINING ORCHESTRATOR
// =====================================================

export class MasterTrainingOrchestrator {
    private config: MasterTrainingConfig;
    private emailModel: EmailWritingModel | null = null;
    private subjectOptimizer: SubjectLineOptimizer | null = null;
    private leadModel: LeadScoringModel | null = null;
    
    constructor(config: Partial<MasterTrainingConfig> = {}) {
        this.config = { ...DEFAULT_MASTER_CONFIG, ...config };
    }
    
    /**
     * Run all training pipelines
     */
    async runAll(): Promise<MasterTrainingResult> {
        const startTime = Date.now();
        
        console.log('\n' + '═'.repeat(70));
        console.log('🚀 APEXMAIL MASTER ML TRAINING SYSTEM');
        console.log('═'.repeat(70));
        console.log('\nTraining all email ML modules with real HuggingFace data');
        console.log('Quality gates enforced with statistical validation');
        console.log('Overfitting prevention through cross-validation');
        
        const result: MasterTrainingResult = {
            success: false,
            emailWriting: { trained: false, quality: 0, passedThreshold: false, iterations: 0 },
            subjectLine: { trained: false, quality: 0, passedThreshold: false, iterations: 0 },
            leadScoring: { trained: false, quality: 0, passedThreshold: false, iterations: 0 },
            totalTime: 0,
            recommendations: []
        };
        
        // ========================================
        // 1. TRAIN EMAIL WRITING MODEL
        // ========================================
        console.log('\n\n' + '─'.repeat(70));
        console.log('📝 PHASE 1: EMAIL WRITING MODEL');
        console.log('─'.repeat(70));
        
        try {
            for (let iteration = 1; iteration <= this.config.maxIterations; iteration++) {
                result.emailWriting.iterations = iteration;
                console.log(`\n🔄 Iteration ${iteration}/${this.config.maxIterations}`);
                
                this.emailModel = new EmailWritingModel();
                const metrics = await this.emailModel.train({
                    qualityThreshold: this.config.emailWritingThreshold,
                    maxEpochs: 50 + (iteration * 20), // Increase epochs each iteration
                    learningRate: 0.001 / iteration  // Decrease LR each iteration
                });
                
                result.emailWriting.quality = metrics.cvMean;
                result.emailWriting.metrics = metrics;
                result.emailWriting.trained = true;
                
                if (metrics.cv95CI.lower >= this.config.emailWritingThreshold) {
                    result.emailWriting.passedThreshold = true;
                    console.log(`\n✅ Email Writing Model PASSED quality gate at ${metrics.cvMean.toFixed(1)}%`);
                    break;
                } else if (iteration < this.config.maxIterations) {
                    console.log(`\n⚠️ Quality ${metrics.cvMean.toFixed(1)}% below threshold. Retrying...`);
                }
            }
            
            if (!result.emailWriting.passedThreshold) {
                result.recommendations.push(
                    'Email writing model needs more training data or hyperparameter tuning'
                );
            }
        } catch (error) {
            console.error('❌ Email Writing Training failed:', error);
            if (!this.config.continueOnFailure) throw error;
        }
        
        // ========================================
        // 2. TRAIN SUBJECT LINE OPTIMIZER
        // ========================================
        console.log('\n\n' + '─'.repeat(70));
        console.log('📧 PHASE 2: SUBJECT LINE OPTIMIZER');
        console.log('─'.repeat(70));
        
        try {
            for (let iteration = 1; iteration <= this.config.maxIterations; iteration++) {
                result.subjectLine.iterations = iteration;
                console.log(`\n🔄 Iteration ${iteration}/${this.config.maxIterations}`);
                
                this.subjectOptimizer = new SubjectLineOptimizer();
                await this.subjectOptimizer.train();
                
                // Evaluate on test set
                const testScore = await this.evaluateSubjectLineModel();
                result.subjectLine.quality = testScore;
                result.subjectLine.trained = true;
                
                if (testScore >= this.config.subjectLineThreshold) {
                    result.subjectLine.passedThreshold = true;
                    console.log(`\n✅ Subject Line Optimizer PASSED quality gate at ${testScore.toFixed(1)}%`);
                    break;
                } else if (iteration < this.config.maxIterations) {
                    console.log(`\n⚠️ Quality ${testScore.toFixed(1)}% below threshold. Retrying...`);
                }
            }
            
            if (!result.subjectLine.passedThreshold) {
                result.recommendations.push(
                    'Subject line optimizer needs additional A/B test data'
                );
            }
        } catch (error) {
            console.error('❌ Subject Line Training failed:', error);
            if (!this.config.continueOnFailure) throw error;
        }
        
        // ========================================
        // 3. TRAIN LEAD SCORING (WEBSCRAPING)
        // ========================================
        console.log('\n\n' + '─'.repeat(70));
        console.log('🎯 PHASE 3: LEAD SCORING MODEL (WEBSCRAPING)');
        console.log('─'.repeat(70));
        
        try {
            // Lead scoring uses existing infrastructure from hunter-training.ts
            // This phase validates and enhances it
            const leadScore = await this.trainLeadScoring();
            result.leadScoring = leadScore;
            
            if (!result.leadScoring.passedThreshold) {
                result.recommendations.push(
                    'Lead scoring model needs more diverse company data'
                );
            }
        } catch (error) {
            console.error('❌ Lead Scoring Training failed:', error);
            if (!this.config.continueOnFailure) throw error;
        }
        
        // ========================================
        // FINAL REPORT
        // ========================================
        result.totalTime = Date.now() - startTime;
        result.success = result.emailWriting.passedThreshold && 
                         result.subjectLine.passedThreshold && 
                         result.leadScoring.passedThreshold;
        
        this.printFinalReport(result);
        
        return result;
    }
    
    private async evaluateSubjectLineModel(): Promise<number> {
        if (!this.subjectOptimizer) return 0;
        
        // Test cases with known good/bad scores
        const testCases = [
            { subject: '{{firstName}}, quick question about your strategy?', category: 'cold_outreach' as const, expectedMin: 75 },
            { subject: 'Welcome aboard! 🎉', category: 'welcome' as const, expectedMin: 80 },
            { subject: '3 ways to boost your deliverability', category: 'nurture' as const, expectedMin: 70 },
            { subject: 'Re: Following up', category: 'follow_up' as const, expectedMin: 65 },
            { subject: 'FREE CASH NOW!!!', category: 'promotional' as const, expectedMax: 40 } // Bad example
        ];
        
        let passedTests = 0;
        for (const test of testCases) {
            const score = this.subjectOptimizer.score(test.subject, test.category);
            
            const passed = test.expectedMin 
                ? score.overall >= test.expectedMin 
                : score.overall <= test.expectedMax!;
            
            if (passed) passedTests++;
        }
        
        return (passedTests / testCases.length) * 100;
    }
    
    private async trainLeadScoring(): Promise<{
        trained: boolean;
        quality: number;
        passedThreshold: boolean;
        iterations: number;
    }> {
        // Use the real lead scoring model
        this.leadModel = new LeadScoringModel();
        const metrics = await this.leadModel.train({
            qualityThreshold: this.config.leadScoringThreshold,
            numTrees: 100,
            learningRate: 0.1
        });
        
        return {
            trained: true,
            quality: metrics.finalAccuracy,
            passedThreshold: metrics.passedThreshold,
            iterations: 1
        };
    }
    
    private printFinalReport(result: MasterTrainingResult): void {
        console.log('\n\n' + '═'.repeat(70));
        console.log('📋 MASTER TRAINING COMPLETE - FINAL REPORT');
        console.log('═'.repeat(70));
        
        console.log('\n📊 Model Quality Summary:');
        console.log('┌──────────────────────────┬──────────┬───────────┬──────────┐');
        console.log('│ Model                    │ Quality  │ Threshold │ Status   │');
        console.log('├──────────────────────────┼──────────┼───────────┼──────────┤');
        
        const ew = result.emailWriting;
        const ewStatus = ew.passedThreshold ? '✅ PASS' : '❌ FAIL';
        console.log(`│ Email Writing            │ ${ew.quality.toFixed(1).padStart(6)}%  │    ${this.config.emailWritingThreshold}%    │ ${ewStatus}   │`);
        
        const sl = result.subjectLine;
        const slStatus = sl.passedThreshold ? '✅ PASS' : '❌ FAIL';
        console.log(`│ Subject Line Optimizer   │ ${sl.quality.toFixed(1).padStart(6)}%  │    ${this.config.subjectLineThreshold}%    │ ${slStatus}   │`);
        
        const ls = result.leadScoring;
        const lsStatus = ls.passedThreshold ? '✅ PASS' : '❌ FAIL';
        console.log(`│ Lead Scoring (Webscrape) │ ${ls.quality.toFixed(1).padStart(6)}%  │    ${this.config.leadScoringThreshold}%    │ ${lsStatus}   │`);
        
        console.log('└──────────────────────────┴──────────┴───────────┴──────────┘');
        
        console.log(`\n⏱️ Total Training Time: ${(result.totalTime / 1000).toFixed(1)}s`);
        console.log(`📈 Training Iterations: Email=${ew.iterations}, Subject=${sl.iterations}, Lead=${ls.iterations}`);
        
        if (result.recommendations.length > 0) {
            console.log('\n💡 Recommendations for Improvement:');
            for (const rec of result.recommendations) {
                console.log(`   • ${rec}`);
            }
        }
        
        const overallStatus = result.success ? '✅ ALL QUALITY GATES PASSED' : '⚠️ SOME MODELS NEED IMPROVEMENT';
        console.log(`\n${overallStatus}`);
        console.log('═'.repeat(70));
    }
    
    /**
     * Get trained email model
     */
    getEmailModel(): EmailWritingModel | null {
        return this.emailModel;
    }
    
    /**
     * Get trained subject optimizer
     */
    getSubjectOptimizer(): SubjectLineOptimizer | null {
        return this.subjectOptimizer;
    }
}

// =====================================================
// MAIN ENTRY POINT
// =====================================================

/**
 * Run the complete ML training pipeline
 */
export async function runMasterTraining(
    config?: Partial<MasterTrainingConfig>
): Promise<MasterTrainingResult> {
    const orchestrator = new MasterTrainingOrchestrator(config);
    return orchestrator.runAll();
}

// =====================================================
// QUICK DEMO FUNCTION
// =====================================================

export async function demoEmailGeneration(): Promise<void> {
    console.log('\n' + '═'.repeat(70));
    console.log('📧 APEXMAIL EMAIL GENERATION DEMO');
    console.log('═'.repeat(70));
    
    // Quick train the model
    const model = new EmailWritingModel();
    await model.train({ maxEpochs: 30, minEpochs: 5 });
    
    // Generate sample emails
    const scenarios = [
        { category: 'cold_outreach' as const, topic: 'email deliverability', recipientName: 'Sarah', companyName: 'TechCorp' },
        { category: 'welcome' as const, topic: 'your new account', recipientName: 'Alex', companyName: 'ApexMail' },
        { category: 'follow_up' as const, topic: 'our meeting', recipientName: 'Jordan', companyName: 'Startup Inc' }
    ];
    
    for (const scenario of scenarios) {
        console.log(`\n${'─'.repeat(50)}`);
        console.log(`Category: ${scenario.category.toUpperCase()}`);
        console.log(`${'─'.repeat(50)}`);
        
        const result = model.generate({
            ...scenario,
            senderName: 'The ApexMail Team'
        });
        
        console.log(`\n📨 Subject: ${result.subject}`);
        console.log(`\n📝 Body:\n${result.body}`);
        console.log(`\n📊 Quality Score: ${result.quality.overall.toFixed(1)}%`);
        console.log(`   Passed Threshold: ${result.quality.passesThreshold ? '✅ Yes' : '❌ No'}`);
    }
}

// =====================================================
// CLI INTERFACE
// =====================================================

async function main() {
    const args = process.argv.slice(2);
    
    if (args.includes('--demo')) {
        await demoEmailGeneration();
    } else if (args.includes('--subject-only')) {
        await runSubjectLineTraining();
    } else if (args.includes('--email-only')) {
        await runEmailWritingTraining();
    } else if (args.includes('--lead-only')) {
        await runLeadScoringTraining();
    } else {
        await runMasterTraining();
    }
}

// Run if executed directly
if (typeof require !== 'undefined' && require.main === module) {
    main().catch(console.error);
}

export { EmailWritingModel, SubjectLineOptimizer, EmailQualityEvaluator, LeadScoringModel };
