//! AI service performance tests.

use std::time::Instant;

use ai_service::analytics::AnalyticsPredictor;
use ai_service::assistant::AiAssistant;
use ai_service::content::ContentOptimizer;
mod budget;

#[test]
fn test_prediction_throughput() {
    let iterations = 10_000;
    let predictor = AnalyticsPredictor::new();
    let subjects = [
        "Great deals inside — don't miss out!",
        "Your weekly newsletter",
        "Important account update",
        "🎉 Special offer just for you",
        "Quick reminder about your subscription",
    ];

    let start = Instant::now();
    for i in 0..iterations {
        let subject = subjects[i % subjects.len()];
        let hour = (i % 24) as u8;
        let day = (i % 7) as u8;
        let _ = predictor.predict_open_rate(subject, hour, day);
    }
    let elapsed = start.elapsed();

    println!(
        "Prediction throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < budget::from_secs(1),
        "10,000 predictions took {:?}, expected < 1s",
        elapsed
    );
}

#[test]
fn test_sentiment_analysis_throughput() {
    let iterations = 10_000;
    let assistant = AiAssistant::new();
    let texts = [
        "I love this product, it's amazing and wonderful!",
        "This is the worst experience ever, terrible service.",
        "The report is attached, please review it.",
        "Great news! We won the award for best support.",
        "I'm disappointed and angry about the refund delay.",
        "Thank you for the excellent help, you are awesome!",
    ];

    let start = Instant::now();
    for i in 0..iterations {
        let text = texts[i % texts.len()];
        let _ = assistant.analyze_sentiment(text);
    }
    let elapsed = start.elapsed();

    println!(
        "Sentiment analysis throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < budget::from_secs(1),
        "10,000 sentiment analyses took {:?}, expected < 1s",
        elapsed
    );
}

#[test]
fn test_subject_scoring_throughput() {
    let iterations = 10_000;
    let optimizer = ContentOptimizer::new();
    let subjects = [
        "🔥 Last chance: 50% off everything today only!",
        "Hi {{name}}, check out our new features",
        "Q4 results",
        "Don't miss this limited time offer — act now!",
        "Your monthly digest for December",
        "Introducing our redesigned dashboard experience",
    ];

    let start = Instant::now();
    for i in 0..iterations {
        let subject = subjects[i % subjects.len()];
        let _ = optimizer.score_subject_line(subject);
    }
    let elapsed = start.elapsed();

    println!(
        "Subject scoring throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < budget::from_secs(1),
        "10,000 subject scorings took {:?}, expected < 1s",
        elapsed
    );
}
