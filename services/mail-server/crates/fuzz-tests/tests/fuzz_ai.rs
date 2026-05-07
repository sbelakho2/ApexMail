//! Fuzz tests for AI service functions.

use ai_service::analytics::AnalyticsPredictor;
use ai_service::bandits::BanditOptimizer;
use ai_service::content::ContentOptimizer;
use fuzz_tests::*;
use rand::Rng;

#[test]
fn fuzz_open_rate_bounded() {
    // Any inputs must produce a rate in [0.0, 1.0].
    let predictor = AnalyticsPredictor::new();
    let mut rng = rand::rng();
    for _ in 0..5_000 {
        let subject = random_unicode(rng.random_range(0..200));
        let hour: u8 = rng.random_range(0..=23);
        let day: u8 = rng.random_range(0..=6);
        let rate = predictor.predict_open_rate(&subject, hour, day);
        assert!(
            (0.0..=1.0).contains(&rate),
            "Open rate {rate} out of bounds for subject len={}, hour={hour}, day={day}",
            subject.len()
        );
    }
}

#[test]
fn fuzz_click_rate_bounded() {
    // Any inputs must produce a rate in [0.0, 1.0].
    let predictor = AnalyticsPredictor::new();
    let mut rng = rand::rng();
    for _ in 0..5_000 {
        let cta = random_ascii(rng.random_range(0..100));
        let position: u32 = rng.random_range(0..1000);
        let rate = predictor.predict_click_rate(&cta, position);
        assert!(
            (0.0..=1.0).contains(&rate),
            "Click rate {rate} out of bounds for cta len={}, position={position}",
            cta.len()
        );
    }
}

#[test]
fn fuzz_sentiment_bounded() {
    // predict_unsubscribe_risk acts as our sentiment proxy — any inputs
    // must produce a value in [0.0, 1.0].
    let predictor = AnalyticsPredictor::new();
    for _ in 0..5_000 {
        let frequency = random_f64_range(0.0, 20.0);
        let engagement = random_f64_range(-1.0, 2.0); // intentionally out-of-range
        let risk = predictor.predict_unsubscribe_risk(frequency, engagement);
        assert!(
            (0.0..=1.0).contains(&risk),
            "Unsubscribe risk {risk} out of bounds for freq={frequency}, eng={engagement}"
        );
    }
}

#[test]
fn fuzz_subject_score_bounded() {
    // ContentOptimizer::score_subject_line must return 0-100.
    let optimizer = ContentOptimizer::new();
    let mut rng = rand::rng();
    for _ in 0..5_000 {
        let text = random_unicode(rng.random_range(0..300));
        let score = optimizer.score_subject_line(&text);
        assert!(
            score <= 100,
            "Subject score {score} exceeds 100 for text len={}",
            text.len()
        );
    }
    // Edge cases
    assert!(optimizer.score_subject_line("") <= 100);
    assert!(optimizer.score_subject_line(&"x".repeat(10_000)) <= 100);
}

#[tokio::test]
async fn fuzz_bandit_selection_valid() {
    // Selected arm must always exist in the registered arms.
    let optimizer = BanditOptimizer::new(0.1);
    let mut arm_ids: Vec<String> = Vec::with_capacity(10);
    for i in 0..10 {
        arm_ids.push(
            optimizer
                .add_arm(&format!("arm_{i}"))
                .await
                .expect("add_arm should not fail"),
        );
    }

    for _ in 0..1_000 {
        let selected = optimizer.select_arm().expect("should select an arm");
        assert!(
            arm_ids.contains(&selected),
            "Selected arm {selected} not in registered arms"
        );
    }

    // Record some rewards and keep selecting
    for id in &arm_ids {
        let _ = optimizer
            .record_reward(id, rand::rng().random_range(0.0..1.0))
            .await;
    }
    for _ in 0..1_000 {
        let selected = optimizer.select_arm().expect("should select an arm");
        assert!(arm_ids.contains(&selected));
    }
}
