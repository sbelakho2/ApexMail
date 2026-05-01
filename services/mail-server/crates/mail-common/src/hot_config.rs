//! Zero-downtime configuration hot-reload via `arc_swap`.
//!
//! ## Design
//!
//! Each security engine holds its configuration inside a [`HotConfig<T>`].
//! Normal reads (millions per second on production traffic) pay only the cost
//! of an atomic pointer load — no lock, no heap allocation. When an operator
//! pushes a new config (e.g., updated DDoS thresholds from a control-plane
//! API), a single `reload` call atomically swaps in the new value.
//!
//! All threads that loaded the old `Arc<T>` continue to use it safely until
//! they release their guard; the reload never blocks readers.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use mail_common::hot_config::HotConfig;
//!
//! let cfg = HotConfig::new(DdosConfig::default);
//!
//! // Fast read path — pays one atomic load://! let current = cfg.load;
//! println!("{}", current.block_threshold);
//!
//! // Hot-reload (e.g., from a filesystem watcher or gRPC call)://! cfg.reload(DdosConfig { block_threshold:200, ..DdosConfig::default });
//! ```

use arc_swap::ArcSwap;
use std::sync::Arc;

/// A thread-safe, hot-reloadable configuration holder.
/// Wraps `arc_swap::ArcSwap<T>` with a type-safe, ergonomic API and adds
/// optional reload logging via `tracing`.
pub struct HotConfig<T: Send + Sync + 'static> {
    inner: ArcSwap<T>,
}

impl<T> HotConfig<T>
where
    T: Send + Sync + 'static,
{
    /// Create a new `HotConfig` with an initial value.
    pub fn new(initial: T) -> Self {
        Self {
            inner: ArcSwap::new(Arc::new(initial)),
        }
    }

    /// Create a new `HotConfig` from an already-`Arc`-wrapped initial value.
    pub fn from_arc(initial: Arc<T>) -> Self {
        Self {
            inner: ArcSwap::new(initial),
        }
    }

    /// Load the current config.
    /// This is an **extremely fast** operation (a single atomic pointer load).
    /// The returned [`Arc<T>`] keeps the config value alive even if [`reload`]
    /// is called concurrently; callers should *not* hold the returned `Arc`
    /// across lengthy operations so that outdated configs can be freed.
    /// [`reload`]:Self::reload
    #[inline]
    pub fn load(&self) -> Arc<T> {
        self.inner.load_full()
    }

    /// Atomically swap in a new configuration value.
    /// All subsequent calls to [`load`] return the new value. Active readers
    /// holding a guard from a previous [`load`] continue using the old config
    /// safely until they drop their guard — there is no blocking or data race.
    /// [`load`]:Self::load
    pub fn reload(&self, new_config: T) {
        self.inner.store(Arc::new(new_config));
    }

    /// Atomically swap in a new configuration value from a pre-built `Arc`.
    /// Identical to [`reload`] but avoids an extra allocation when the caller
    /// already owns an `Arc<T>`.
    /// [`reload`]:Self::reload
    pub fn reload_arc(&self, new_config: Arc<T>) {
        self.inner.store(new_config);
    }

    /// Apply a function to the current config and store the result.
    /// Uses `arc_swap::ArcSwap::rcu` for a retry-loop that eliminates the
    /// TOCTOU race between `load()` and `store()`.
    pub fn update<F>(&self, f: F)
    where
        T: Clone,
        F: Fn(&T) -> T,
    {
        self.inner.rcu(|current| Arc::new(f(current)));
    }
}

impl<T> Default for HotConfig<T>
where
    T: Default + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new(T::default())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Logged variants
// ─────────────────────────────────────────────────────────────────────────────

/// Extension trait that adds a `reload_logged` method for engines that want
/// automatic tracing on every config swap.
pub trait HotConfigExt<T: Send + Sync + 'static> {
    /// Reload the config and emit a `tracing::info!` event with the type name.
    fn reload_logged(&self, new_config: T);
}

impl<T> HotConfigExt<T> for HotConfig<T>
where
    T: Send + Sync + 'static,
{
    fn reload_logged(&self, new_config: T) {
        self.reload(new_config);
        tracing::info!(
            config_type = std::any::type_name::<T>(),
            "Configuration hot-reloaded"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, PartialEq, Debug)]
    struct TestConfig {
        threshold: u32,
    }

    #[test]
    fn test_load_returns_initial_value() {
        let cfg = HotConfig::new(TestConfig { threshold: 100 });
        assert_eq!(cfg.load().threshold, 100);
    }

    #[test]
    fn test_reload_updates_value() {
        let cfg = HotConfig::new(TestConfig { threshold: 100 });
        cfg.reload(TestConfig { threshold: 200 });
        assert_eq!(cfg.load().threshold, 200);
    }

    #[test]
    fn test_old_arc_still_valid_after_reload() {
        let cfg = HotConfig::new(TestConfig { threshold: 100 });
        let old = cfg.load(); // holds ref to v1
        cfg.reload(TestConfig { threshold: 200 });
        // The old Arc still reads v1 safely
        assert_eq!(old.threshold, 100);
        // New loads return v2
        assert_eq!(cfg.load().threshold, 200);
    }

    #[test]
    fn test_update_applies_partial_change() {
        let cfg = HotConfig::new(TestConfig { threshold: 50 });
        cfg.update(|c| TestConfig {
            threshold: c.threshold + 10,
        });
        assert_eq!(cfg.load().threshold, 60);
    }

    #[test]
    fn test_default_creates_default_config() {
        #[derive(Default, PartialEq, Debug)]
        struct Cfg {
            x: u32,
        }
        let cfg: HotConfig<Cfg> = HotConfig::default();
        assert_eq!(cfg.load().x, 0);
    }
}
