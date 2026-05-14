//! Functional tests for ai-service:analytics, bandits, content, inference, STO.

use ai_service::analytics::AnalyticsPredictor;
use ai_service::bandits::BanditOptimizer;
use ai_service::content::ContentOptimizer;
use ai_service::sto::SendTimeOptimizer;

// ── Analytics ──────────────────────────────────────────────────

#[test]
fn open_rate_always_between_0_and_1() {
    let p = AnalyticsPredictor::new();
    for hour in 0..=23u8 {
        for day in 0..=6u8 {
            let rate = p.predict_open_rate("Check out our deal", hour, day);
            assert!(
                (0.0..=1.0).contains(&rate),
                "open_rate out of bounds: {} (h={}, d={})",
                rate,
                hour,
                day
            );
        }
    }
}

#[test]
fn click_rate_always_between_0_and_1() {
    let p = AnalyticsPredictor::new();
    for pos in 0..10u32 {
        let rate = p.predict_click_rate("Buy now free shipping", pos);
        assert!(
            (0.0..=1.0).contains(&rate),
            "click_rate out of bounds: {} at pos {}",
            rate,
            pos
        );
    }
}

#[test]
fn unsubscribe_risk_bounds() {
    let p = AnalyticsPredictor::new();
    // extremes
    let high = p.predict_unsubscribe_risk(10.0, 0.0);
    let low = p.predict_unsubscribe_risk(0.5, 1.0);
    assert!(
        (0.0..=1.0).contains(&high),
        "high risk {} out of bounds",
        high
    );
    assert!((0.0..=1.0).contains(&low), "low risk {} out of bounds", low);
    assert!(high > low, "high-freq/low-engagement should be riskier");
}

#[test]
fn open_rate_business_hours_boost() {
    let p = AnalyticsPredictor::new();
    let morning = p.predict_open_rate("Great deal inside", 10, 2);
    let midnight = p.predict_open_rate("Great deal inside", 2, 2);
    assert!(morning > midnight);
}

// ── Subject line scoring ───────────────────────────────────────

/// Optimal subject line length range used by the scoring heuristic.
const OPTIMAL_SUBJECT_MIN_CHARS: usize = 30;
/// Upper bound of the subject line length "sweet spot".
const OPTIMAL_SUBJECT_MAX_CHARS: usize = 60;
/// A subject line shorter than this is considered "very short" and scores lower.
const SHORT_SUBJECT_THRESHOLD: usize = OPTIMAL_SUBJECT_MIN_CHARS;
/// A subject line longer than this is considered "very long" and scores lower.
const LONG_SUBJECT_LENGTH: usize = 120;

#[test]
fn subject_line_scoring_length_heuristics() {
    let c = ContentOptimizer::new();
    // Optimal length (30-60 chars): test both ends of the sweet spot.
    let optimal_body = "x".repeat(OPTIMAL_SUBJECT_MIN_CHARS);
    let optimal = c.score_subject_line(&optimal_body);
    let optimal_upper_body = "x".repeat(OPTIMAL_SUBJECT_MAX_CHARS);
    let optimal_upper = c.score_subject_line(&optimal_upper_body);
    // Very short (below optimal threshold)
    let short_body = "x".repeat(SHORT_SUBJECT_THRESHOLD / 3);
    let short = c.score_subject_line(&short_body);
    // Very long (above optimal threshold)
    let long_body = "x".repeat(LONG_SUBJECT_LENGTH);
    let long = c.score_subject_line(&long_body);
    assert!(
        optimal > short,
        "optimal ({optimal}) should beat short ({short}): opt body len {} vs short body len {}",
        optimal_body.len(),
        short_body.len(),
    );
    assert!(
        optimal > long,
        "optimal ({optimal}) should beat long ({long}): opt body len {} vs long body len {}",
        optimal_body.len(),
        long_body.len(),
    );
    assert!(
        optimal_upper > long,
        "upper-optimal ({optimal_upper}) should beat long ({long}): upper body len {} vs long body len {}",
        optimal_upper_body.len(),
        long_body.len(),
    );
}

// ── Bandits ────────────────────────────────────────────────────

#[tokio::test]
async fn bandit_epsilon_0_always_exploits() {
    let b = BanditOptimizer::new(0.0);
    let id_a = b.add_arm("variant-a").await.unwrap();
    let id_b = b.add_arm("variant-b").await.unwrap();

    // Give arm A a much higher reward rate
    for _ in 0..50 {
        b.record_reward(&id_a, 1.0).await.unwrap();
    }
    for _ in 0..50 {
        b.record_reward(&id_b, 0.0).await.unwrap();
    }

    // epsilon=0 should always pick the best arm
    for _ in 0..20 {
        let choice = b.select_arm().unwrap();
        assert_eq!(choice, id_a, "epsilon=0 should always exploit best arm");
    }
}

#[tokio::test]
async fn bandit_epsilon_1_explores_both_arms() {
    let b = BanditOptimizer::new(1.0);
    let id_a = b.add_arm("variant-a").await.unwrap();
    let id_b = b.add_arm("variant-b").await.unwrap();
    // Record some rewards so arms are initialized
    b.record_reward(&id_a, 1.0).await.unwrap();
    b.record_reward(&id_b, 0.0).await.unwrap();

    let mut saw_a = false;
    let mut saw_b = false;
    for _ in 0..100 {
        let choice = b.select_arm().unwrap();
        if choice == id_a {
            saw_a = true;
        }
        if choice == id_b {
            saw_b = true;
        }
    }
    assert!(saw_a && saw_b, "epsilon=1 should eventually pick both arms");
}

#[tokio::test]
async fn bandit_record_reward_updates_stats() {
    let b = BanditOptimizer::new(0.1);
    let id = b.add_arm("cta-red").await.unwrap();
    b.record_reward(&id, 1.0).await.unwrap();
    b.record_reward(&id, 0.0).await.unwrap();
    b.record_reward(&id, 1.0).await.unwrap();

    let stats = b.get_stats();
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].impressions, 3);
    assert_eq!(stats[0].conversions, 2);
    let cr = stats[0].conversion_rate();
    assert!((cr - 2.0 / 3.0).abs() < 1e-9);
}

// ── K-means segmentation ───────────────────────────────────────

#[test]
fn segment_users_returns_k_clusters() {
    let p = AnalyticsPredictor::new();
    let scores: Vec<f64> = vec![0.1, 0.15, 0.2, 0.5, 0.55, 0.9, 0.92, 0.95];
    let k = 3;
    let assignments = p.segment_users(&scores, k).unwrap();
    assert_eq!(assignments.len(), scores.len());
    let unique_clusters: std::collections::HashSet<_> = assignments.into_iter().collect();
    assert!(unique_clusters.len() <= k, "should have at most k clusters");
    assert!(
        !unique_clusters.is_empty(),
        "should have at least 1 cluster"
    );
}

// ── STO ────────────────────────────────────────────────────────

#[test]
fn send_time_optimizer_returns_valid_hour_and_day() {
    let sto = SendTimeOptimizer::new();
    let data = vec![(9u8, 1u8, 0.5), (10, 2, 0.9), (10, 2, 0.8), (15, 4, 0.3)];
    let best = sto.find_optimal_time(&data).unwrap();
    assert!(best.hour <= 23, "hour {} out of range", best.hour);
    assert!(
        best.day_of_week <= 6,
        "day {} out of range",
        best.day_of_week
    );
}

// ── A/B test winner ────────────────────────────────────────────

#[test]
fn ab_test_winner_picks_highest_variant() {
    let c = ContentOptimizer::new();
    let variants = vec![
        ("variant-a".to_string(), 0.22),
        ("variant-b".to_string(), 0.35),
        ("variant-c".to_string(), 0.18),
    ];
    let (winner, val) = c.ab_test_winner(&variants).unwrap();
    assert_eq!(winner, "variant-b");
    assert!((val - 0.35).abs() < f64::EPSILON);
}

#[test]
fn ab_test_winner_empty_returns_none() {
    let c = ContentOptimizer::new();
    let empty: Vec<(String, f64)> = vec![];
    assert!(c.ab_test_winner(&empty).is_none());
}
