//! Thread-parallel tests — std::thread::spawn for true parallelism.

use std::sync::Arc;
use std::thread;

use apexmail_lib::create_hmac_signature;
use apexmail_lib::validation::is_valid_email;
use billing_service::config::PaygPricing;
use billing_service::invoices::calculate_vat;
use billing_service::plans::calculate_overage_cost;
use sales_autopilot::crm::CrmService;

const NUM_THREADS: usize = 8;

// ---------------------------------------------------------------------------
// 1. Parallel crypto — 8 threads doing HMAC
// ---------------------------------------------------------------------------

#[test]
fn test_parallel_crypto_threads() {
    let expected = create_hmac_signature(b"parallel-key", b"parallel-data");
    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|_| {
            let exp = expected.clone();
            thread::spawn(move || {
                for _ in 0..10_000 {
                    let sig = create_hmac_signature(b"parallel-key", b"parallel-data");
                    assert_eq!(sig, exp);
                }
            })
        })
        .collect();

    for (i, h) in handles.into_iter().enumerate() {
        h.join().unwrap_or_else(|_| {
            panic!(
                "crypto thread {} panicked — possible invariant violation",
                i
            )
        });
    }
}

// ---------------------------------------------------------------------------
// 2. Parallel validation — 8 threads validating emails
// ---------------------------------------------------------------------------

#[test]
fn test_parallel_validation_threads() {
    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|t| {
            thread::spawn(move || {
                for i in 0..10_000 {
                    let email = format!("t{t}-user{i}@example.com");
                    assert!(is_valid_email(&email), "expected valid: {email}");
                    assert!(!is_valid_email("not-an-email"));
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }
}

// ---------------------------------------------------------------------------
// 3. Parallel scoring — 8 threads scoring leads
// ---------------------------------------------------------------------------

#[test]
fn test_parallel_scoring_threads() {
    let crm = Arc::new(CrmService::new());

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|t| {
            let crm = Arc::clone(&crm);
            thread::spawn(move || {
                for i in 0..1_000 {
                    let email = format!("t{t}-lead{i}@test.com");
                    crm.create_lead(
                        "parallel".into(),
                        email,
                        format!("Lead {i}"),
                        "TestCo".into(),
                        "Dev".into(),
                        "parallel".into(),
                    );
                    let score = CrmService::score_lead((i % 100) as f64 / 100.0, 0.5, 0.5);
                    assert!(score <= 100);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }

    let all = crm.list_leads("parallel", None, None);
    assert_eq!(all.len(), NUM_THREADS * 1_000);
}

// ---------------------------------------------------------------------------
// 4. Parallel billing — 8 threads calculating costs
// ---------------------------------------------------------------------------

#[test]
fn test_parallel_billing_threads() {
    let pricing = Arc::new(PaygPricing::default());

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|_| {
            let p = Arc::clone(&pricing);
            thread::spawn(move || {
                for vol in 0..10_000u64 {
                    let (email_cost, api_cost, total) = p.calculate(vol * 10, vol * 100).expect(
                        "parallel billing load test should stay within supported PAYG bounds",
                    );
                    assert!(email_cost >= 0);
                    assert!(api_cost >= 0);
                    assert!(total >= 0);

                    let overage = calculate_overage_cost(vol as i64 * 10, 50_000);
                    assert!(overage >= 0);

                    let (vat_rate, vat_amt) = calculate_vat(10_000, "EE", None);
                    assert_eq!(vat_rate, 24);
                    assert!(vat_amt > 0);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }
}
