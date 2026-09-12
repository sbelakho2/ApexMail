//! Listener supervision: an unexpected listener exit must never be just a
//! log line while the process keeps serving a lie.
//!
//! Every enabled SMTP listener is spawned into a [`ListenerSupervisor`]
//! (`tokio::task::JoinSet`). The binary selects on the JoinSet alongside the
//! shutdown signal:
//!
//! * a listener that exits — with `Ok`, `Err`, or a panic — flips the shared
//!   [`Readiness`] flag to false (`/ready` starts answering 503) and makes
//!   the process terminate with an error so the supervisor/orchestrator
//!   restarts the service;
//! * during an operator-initiated shutdown the tasks are stopped and joined
//!   with a grace period, and readiness is not consulted again.
//!
//! This replaces the previous `tokio::spawn(async move { if let Err(e) = … {
//! error!(…) } })` pattern, which logged a dead listener and left the MTA
//! process alive.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;

/// Shared readiness flag. `true` until a listener exits unexpectedly.
#[derive(Debug, Clone, Default)]
pub struct Readiness {
    flag: Arc<AtomicBool>,
}

impl Readiness {
    /// Ready initially — the flag exists before any listener binds.
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn is_ready(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Latches to `false`; only a process restart restores readiness.
    pub fn set_not_ready(&self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

/// Supervises the enabled listener tasks.
pub struct ListenerSupervisor {
    tasks: JoinSet<(&'static str, anyhow::Result<()>)>,
    readiness: Readiness,
}

impl ListenerSupervisor {
    pub fn new(readiness: Readiness) -> Self {
        Self {
            tasks: JoinSet::new(),
            readiness,
        }
    }

    /// Spawn one listener task under `name` (used in logs and errors).
    pub fn spawn<F>(&mut self, name: &'static str, future: F)
    where
        F: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        self.tasks.spawn(async move { (name, future.await) });
    }

    /// Wait for the next listener to exit.
    ///
    /// Any return from here before shutdown is by definition unexpected, so
    /// readiness is flipped false before the caller sees the result. A
    /// panicked task is surfaced as an `Err` with the join error text.
    pub async fn next_exit(&mut self) -> (&'static str, anyhow::Result<()>) {
        match self.tasks.join_next().await {
            Some(Ok((name, result))) => {
                self.readiness.set_not_ready();
                (name, result)
            }
            Some(Err(join_error)) => {
                self.readiness.set_not_ready();
                (
                    "<listener-task-panicked>",
                    Err(anyhow::anyhow!("listener task panicked: {join_error}")),
                )
            }
            None => {
                self.readiness.set_not_ready();
                (
                    "<no-listeners>",
                    Err(anyhow::anyhow!(
                        "listener supervisor has no running tasks while the service is live"
                    )),
                )
            }
        }
    }

    /// Abort every remaining task (failure path: the process is terminating).
    pub fn abort_all(&mut self) {
        self.tasks.abort_all();
    }

    /// Join every remaining task within `timeout` (graceful shutdown path).
    pub async fn join_all(mut self, timeout: Duration) -> Vec<(&'static str, anyhow::Result<()>)> {
        let mut results = Vec::new();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                self.tasks.abort_all();
                break;
            }
            match tokio::time::timeout(remaining, self.tasks.join_next()).await {
                Ok(Some(Ok((name, result)))) => results.push((name, result)),
                Ok(Some(Err(join_error))) => results.push((
                    "<listener-task-panicked>",
                    Err(anyhow::anyhow!("listener task panicked: {join_error}")),
                )),
                Ok(None) | Err(_) => {
                    self.tasks.abort_all();
                    break;
                }
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unexpected_listener_exit_flips_readiness() {
        let readiness = Readiness::new();
        assert!(readiness.is_ready());

        let mut supervisor = ListenerSupervisor::new(readiness.clone());
        supervisor.spawn("test-listener", async { Ok(()) });

        let (name, result) = supervisor.next_exit().await;
        assert_eq!(name, "test-listener");
        assert!(result.is_ok(), "the listener returned cleanly");
        assert!(
            !readiness.is_ready(),
            "an unexpected listener exit must flip readiness to false"
        );
    }

    #[tokio::test]
    async fn failed_listener_exit_flips_readiness_and_reports_error() {
        let readiness = Readiness::new();
        let mut supervisor = ListenerSupervisor::new(readiness.clone());
        supervisor.spawn("failing-listener", async { anyhow::bail!("bind failed") });

        let (name, result) = supervisor.next_exit().await;
        assert_eq!(name, "failing-listener");
        assert!(result.is_err());
        assert!(!readiness.is_ready());
    }

    #[tokio::test]
    async fn panicked_listener_flips_readiness() {
        let readiness = Readiness::new();
        let mut supervisor = ListenerSupervisor::new(readiness.clone());
        supervisor.spawn("panicking-listener", async {
            panic!("listener panicked");
        });

        let (name, result) = supervisor.next_exit().await;
        assert_eq!(name, "<listener-task-panicked>");
        assert!(result.is_err());
        assert!(!readiness.is_ready());
    }

    #[tokio::test]
    async fn graceful_join_stops_and_collects_listeners() {
        let readiness = Readiness::new();
        let mut supervisor = ListenerSupervisor::new(readiness.clone());
        supervisor.spawn("long-running", async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(())
        });

        // Give the task a chance to start, then join with a tiny grace.
        tokio::task::yield_now().await;
        let results = supervisor.join_all(Duration::from_millis(10)).await;
        assert!(results.is_empty(), "aborted task yields no result row");
        assert!(
            readiness.is_ready(),
            "graceful shutdown must not flip readiness"
        );
    }
}
