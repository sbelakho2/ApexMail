#![deny(unsafe_code)]
pub mod bot_detection;
pub mod campaign_autopilot;
pub mod churn_prediction;
pub mod clickhouse_engine;
pub mod compaction;
pub mod config;
pub mod email_hash;
pub mod engagement_trust;
pub mod inbox_placement;
pub mod ip_mask;
pub mod query_engine;
pub mod reconciliation;
pub mod reply_tracking;
pub mod send_time_optimizer;
pub mod subject_line_analyzer;
pub mod types;

pub use clickhouse_engine::ClickHouseEngine;
pub use query_engine::{QueryEngine, QueryError};

/// Test-only helpers shared by the crate's unit tests.
#[cfg(test)]
pub(crate) mod test_support {
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};

    /// Per-thread statement counter (optionally filtered by summary prefix).
    #[derive(Clone)]
    pub(crate) struct QueryCounter {
        inner: Arc<CounterState>,
    }

    #[derive(Default)]
    struct CounterState {
        count: AtomicUsize,
        summaries: Mutex<Vec<String>>,
        prefix: Option<&'static str>,
    }

    impl QueryCounter {
        pub(crate) fn reset(&self) {
            self.inner.count.store(0, Ordering::SeqCst);
            self.inner.summaries.lock().unwrap().clear();
        }

        pub(crate) fn get(&self) -> usize {
            self.inner.count.load(Ordering::SeqCst)
        }

        /// The summaries counted since the last reset (for failure messages).
        pub(crate) fn summaries(&self) -> Vec<String> {
            self.inner.summaries.lock().unwrap().clone()
        }
    }

    thread_local! {
        /// The counter (if any) that THIS thread's sqlx statements feed.
        static ACTIVE_COUNTER: RefCell<Option<Arc<CounterState>>> =
            const { RefCell::new(None) };
    }

    /// Counts `sqlx::query` statement events into the emitting thread's
    /// active counter, if it registered one.
    struct CountingLayer;

    fn statement_summary(event: &tracing::Event<'_>) -> Option<String> {
        struct Visitor<'a>(&'a mut Option<String>);
        impl tracing::field::Visit for Visitor<'_> {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "summary" {
                    *self.0 = Some(value.to_string());
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "summary" {
                    *self.0 = Some(format!("{value:?}"));
                }
            }
        }
        let mut summary = None;
        event.record(&mut Visitor(&mut summary));
        summary
    }

    impl<S> tracing_subscriber::Layer<S> for CountingLayer
    where
        S: tracing::Subscriber,
    {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if event.metadata().target() != "sqlx::query" {
                return;
            }
            let summary = statement_summary(event);
            ACTIVE_COUNTER.with(|slot| {
                if let Some(state) = slot.borrow().as_ref() {
                    let matches = match (state.prefix, summary.as_deref()) {
                        (None, _) => true,
                        (Some(prefix), Some(text)) => text
                            .trim_start()
                            .to_ascii_uppercase()
                            .starts_with(&prefix.to_ascii_uppercase()),
                        (Some(_), None) => false,
                    };
                    if matches {
                        state.count.fetch_add(1, Ordering::SeqCst);
                        if let Some(text) = summary {
                            state.summaries.lock().unwrap().push(text);
                        }
                    }
                }
            });
        }
    }

    fn register(prefix: Option<&'static str>) -> QueryCounter {
        use tracing_subscriber::layer::SubscriberExt;

        static INSTALL: OnceLock<()> = OnceLock::new();
        INSTALL.get_or_init(|| {
            let subscriber = tracing_subscriber::registry().with(CountingLayer);
            // A pre-existing global subscriber (none in this test binary)
            // would make this fail; the counter would then stay at zero,
            // which the tests treat as a failure.
            let _ = tracing::subscriber::set_global_default(subscriber);
        });
        tracing::callsite::rebuild_interest_cache();

        let counter = QueryCounter {
            inner: Arc::new(CounterState {
                prefix,
                ..CounterState::default()
            }),
        };
        ACTIVE_COUNTER.with(|slot| *slot.borrow_mut() = Some(counter.inner.clone()));
        counter
    }

    /// Count every sqlx statement executed on this thread.
    pub(crate) fn count_queries_on_this_thread() -> QueryCounter {
        register(None)
    }

    /// Count only sqlx statements whose summary starts with `prefix`
    /// (case-insensitive).
    pub(crate) fn count_statements_starting_with(prefix: &'static str) -> QueryCounter {
        register(Some(prefix))
    }
}
