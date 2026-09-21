//! Governed offline training orchestration.
//!
//! The API does not pretend that a training request trained a model. It starts
//! a reviewed operator-provided runner, tracks the real child-process outcome,
//! and only reports completion after the runner exits successfully and writes
//! its evaluation artifact. Promotion remains a separate human-controlled
//! release decision.

use chrono::Utc;
use parking_lot::Mutex;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::process::Command;
use uuid::Uuid;

use crate::config::AiConfig;
use crate::types::{AiError, EvalMetrics, JobStatus, TrainingJob};

/// Cap on retained training-job records in the in-memory index. On insert,
/// the oldest TERMINAL jobs (completed/failed/cancelled — never running)
/// are evicted beyond this cap; the per-job snapshots under the checkpoint
/// path keep the full history.
const MAX_RETAINED_JOBS: usize = 500;

#[derive(Clone)]
pub struct TrainingManager {
    jobs: Arc<Mutex<HashMap<String, TrainingJob>>>,
    runner: Option<PathBuf>,
    working_dir: Option<PathBuf>,
    checkpoint_path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct RunnerMetrics {
    loss: Option<f64>,
    accuracy: Option<f64>,
    precision: Option<f64>,
    recall: Option<f64>,
    f1: Option<f64>,
}

impl TrainingManager {
    pub fn new(config: &AiConfig) -> Self {
        let runner = (!config.training_runner.trim().is_empty())
            .then(|| PathBuf::from(config.training_runner.trim()));
        let working_dir = (!config.training_working_dir.trim().is_empty())
            .then(|| PathBuf::from(config.training_working_dir.trim()));

        Self {
            jobs: Arc::new(Mutex::new(HashMap::new())),
            runner,
            working_dir,
            checkpoint_path: PathBuf::from(&config.checkpoint_path),
        }
    }

    /// Start a real, externally managed training run. `runner` is an absolute
    /// executable path from deployment configuration; user input is never
    /// interpreted as a shell command or a file path.
    pub async fn start_job(&self, model_id: &str, epochs: u32) -> Result<TrainingJob, AiError> {
        let runner = self.validated_runner()?;
        if model_id.trim().is_empty() || model_id.len() > 128 {
            return Err(AiError::InvalidInput("invalid model identifier".into()));
        }
        if !(1..=100).contains(&epochs) {
            return Err(AiError::InvalidInput(
                "epochs must be between 1 and 100".into(),
            ));
        }

        let mut job = TrainingJob::new(model_id, epochs);
        job.status = JobStatus::Queued;
        let job_id = job.id.clone();
        self.upsert_job(job.clone())?;

        let mut command = Command::new(&runner);
        command
            .arg("--job-id")
            .arg(&job_id)
            .arg("--model-id")
            .arg(model_id)
            .arg("--epochs")
            .arg(epochs.to_string())
            .arg("--artifact-dir")
            .arg(self.job_artifact_dir(&job_id));
        if let Some(working_dir) = &self.working_dir {
            command.current_dir(working_dir);
        }

        let child = command.spawn().map_err(|error| {
            let _ = self.fail_job(&job_id, format!("could not start training runner: {error}"));
            AiError::TrainingError(format!(
                "could not start configured training runner: {error}"
            ))
        })?;

        self.set_running(&job_id)?;
        let manager = self.clone();
        tokio::spawn(async move {
            manager.observe_child(job_id, child).await;
        });

        self.get_job(&job.id)
    }

    pub fn get_job(&self, job_id: &str) -> Result<TrainingJob, AiError> {
        self.jobs
            .lock()
            .get(job_id)
            .cloned()
            .ok_or_else(|| AiError::JobNotFound(job_id.to_string()))
    }

    pub fn list_jobs(&self) -> Vec<TrainingJob> {
        let mut jobs: Vec<_> = self.jobs.lock().values().cloned().collect();
        jobs.sort_by_key(|job| std::cmp::Reverse(job.started_at));
        jobs
    }

    /// Evaluate supplied predictions using real deterministic metrics. Offline
    /// runners write the same values to their artifact before a model can be
    /// reviewed for promotion.
    pub fn evaluate(&self, predictions: &[bool], labels: &[bool]) -> Result<EvalMetrics, AiError> {
        if predictions.len() != labels.len() || predictions.is_empty() {
            return Err(AiError::InvalidInput(
                "predictions and labels must be non-empty and the same length".into(),
            ));
        }
        let mut true_positive = 0usize;
        let mut true_negative = 0usize;
        let mut false_positive = 0usize;
        let mut false_negative = 0usize;

        for (prediction, label) in predictions.iter().zip(labels) {
            match (*prediction, *label) {
                (true, true) => true_positive += 1,
                (false, false) => true_negative += 1,
                (true, false) => false_positive += 1,
                (false, true) => false_negative += 1,
            }
        }

        let total = predictions.len() as f64;
        let precision_denominator = (true_positive + false_positive) as f64;
        let recall_denominator = (true_positive + false_negative) as f64;
        let precision = if precision_denominator == 0.0 {
            0.0
        } else {
            true_positive as f64 / precision_denominator
        };
        let recall = if recall_denominator == 0.0 {
            0.0
        } else {
            true_positive as f64 / recall_denominator
        };
        let f1 = if precision + recall == 0.0 {
            0.0
        } else {
            2.0 * precision * recall / (precision + recall)
        };

        Ok(EvalMetrics {
            accuracy: (true_positive + true_negative) as f64 / total,
            precision,
            recall,
            f1,
        })
    }

    fn validated_runner(&self) -> Result<PathBuf, AiError> {
        let runner = self.runner.clone().ok_or_else(|| {
            AiError::TrainingUnavailable(
                "AI_TRAINING_RUNNER is not configured; use the reviewed offline runner".into(),
            )
        })?;
        if !runner.is_absolute() || !runner.is_file() {
            return Err(AiError::TrainingUnavailable(
                "AI_TRAINING_RUNNER must be an existing absolute executable path".into(),
            ));
        }
        Ok(runner)
    }

    async fn observe_child(&self, job_id: String, mut child: tokio::process::Child) {
        let status = match child.wait().await {
            Ok(status) if status.success() => match self.load_runner_metrics(&job_id) {
                Ok(metrics) => self.complete_job(&job_id, metrics),
                Err(error) => self.fail_job(&job_id, error.to_string()),
            },
            Ok(status) => self.fail_job(
                &job_id,
                format!("training runner exited with status {status}"),
            ),
            Err(error) => self.fail_job(
                &job_id,
                format!("could not wait for training runner: {error}"),
            ),
        };
        if let Err(error) = status {
            tracing::error!(job_id = %job_id, %error, "failed to persist training job state");
        }
    }

    fn load_runner_metrics(&self, job_id: &str) -> Result<RunnerMetrics, AiError> {
        let path = self.job_artifact_dir(job_id).join("metrics.json");
        let bytes = std::fs::read(&path).map_err(|error| {
            AiError::TrainingError(format!(
                "runner completed without {}: {error}",
                path.display()
            ))
        })?;
        let metrics: RunnerMetrics = serde_json::from_slice(&bytes).map_err(|error| {
            AiError::TrainingError(format!("invalid runner metrics artifact: {error}"))
        })?;
        if metrics.loss.is_none()
            && metrics.accuracy.is_none()
            && metrics.precision.is_none()
            && metrics.recall.is_none()
            && metrics.f1.is_none()
        {
            return Err(AiError::TrainingError(
                "runner metrics artifact has no reported evaluation values".into(),
            ));
        }
        Ok(metrics)
    }

    fn set_running(&self, job_id: &str) -> Result<(), AiError> {
        self.update_job(job_id, |job| {
            job.status = JobStatus::Running;
            job.started_at = Utc::now();
        })
    }

    fn complete_job(&self, job_id: &str, metrics: RunnerMetrics) -> Result<(), AiError> {
        self.update_job(job_id, |job| {
            job.status = JobStatus::Completed;
            job.loss = metrics.loss;
            job.completed_at = Some(Utc::now());
            job.error = None;
        })
    }

    fn fail_job(&self, job_id: &str, error: String) -> Result<(), AiError> {
        self.update_job(job_id, |job| {
            job.status = JobStatus::Failed;
            job.completed_at = Some(Utc::now());
            job.error = Some(error);
        })
    }

    fn update_job<F>(&self, job_id: &str, update: F) -> Result<(), AiError>
    where
        F: FnOnce(&mut TrainingJob),
    {
        let job = {
            let mut jobs = self.jobs.lock();
            let job = jobs
                .get_mut(job_id)
                .ok_or_else(|| AiError::JobNotFound(job_id.to_string()))?;
            update(job);
            job.clone()
        };
        self.write_job_snapshot(&job)
    }

    fn upsert_job(&self, job: TrainingJob) -> Result<(), AiError> {
        {
            let mut jobs = self.jobs.lock();
            jobs.insert(job.id.clone(), job.clone());
            // Cap the live index: without an eviction the map grew without
            // bound for the process's lifetime (the old code never removed
            // finished jobs). Oldest terminal jobs go first; running jobs
            // are never dropped.
            if jobs.len() > MAX_RETAINED_JOBS {
                let mut terminal: Vec<(chrono::DateTime<Utc>, String)> = jobs
                    .values()
                    .filter(|j| {
                        matches!(
                            j.status,
                            JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled
                        )
                    })
                    .map(|j| (j.started_at, j.id.clone()))
                    .collect();
                terminal.sort();
                let excess = jobs.len() - MAX_RETAINED_JOBS;
                for (_, id) in terminal.into_iter().take(excess) {
                    jobs.remove(&id);
                }
            }
        }
        self.write_job_snapshot(&job)
    }

    fn job_artifact_dir(&self, job_id: &str) -> PathBuf {
        self.checkpoint_path.join("jobs").join(job_id)
    }

    fn write_job_snapshot(&self, job: &TrainingJob) -> Result<(), AiError> {
        let directory = self.job_artifact_dir(&job.id);
        std::fs::create_dir_all(&directory).map_err(|error| {
            AiError::CheckpointError(format!("could not create {}: {error}", directory.display()))
        })?;
        let payload = serde_json::to_vec_pretty(job).map_err(|error| {
            AiError::CheckpointError(format!("could not serialize job: {error}"))
        })?;
        atomic_write(&directory.join("job.json"), &payload)
    }
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<(), AiError> {
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    std::fs::write(&temporary, data).map_err(|error| {
        AiError::CheckpointError(format!("could not write {}: {error}", temporary.display()))
    })?;
    std::fs::rename(&temporary, path).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        AiError::CheckpointError(format!("could not publish {}: {error}", path.display()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_real_evaluation_metrics() {
        let manager = TrainingManager::new(&AiConfig::default());
        let metrics = manager
            .evaluate(&[true, true, false, false], &[true, false, true, false])
            .unwrap();

        assert_eq!(metrics.accuracy, 0.5);
        assert_eq!(metrics.precision, 0.5);
        assert_eq!(metrics.recall, 0.5);
        assert_eq!(metrics.f1, 0.5);
    }

    #[tokio::test]
    async fn refuses_unconfigured_training_runner() {
        let config = AiConfig::default();
        let manager = TrainingManager::new(&config);
        let result = manager.start_job("apexmail-assistant", 1).await;
        assert!(matches!(result, Err(AiError::TrainingUnavailable(_))));
    }

    #[test]
    fn job_index_is_capped_and_running_jobs_are_never_evicted() {
        // Regression: finished jobs were never removed from the in-memory
        // map, so it grew for the process's lifetime.
        let dir = std::env::temp_dir().join(format!("ai-train-{}", uuid::Uuid::new_v4())); // nosemgrep: rust.lang.security.temp-dir.temp-dir — test fixture under a unique pid/uuid path — no predictable-name temp collision
        std::fs::create_dir_all(&dir).unwrap();
        let config = AiConfig {
            checkpoint_path: dir.display().to_string(),
            ..AiConfig::default()
        };
        let manager = TrainingManager::new(&config);

        let mut job = TrainingJob::new("apexmail-assistant", 1);
        job.status = JobStatus::Running;
        let running_id = job.id.clone();
        manager.upsert_job(job).unwrap();

        let base = Utc::now() - chrono::Duration::hours(MAX_RETAINED_JOBS as i64 + 10);
        for i in 0..=MAX_RETAINED_JOBS {
            let mut finished = TrainingJob::new("apexmail-assistant", 1);
            finished.status = JobStatus::Completed;
            finished.started_at = base + chrono::Duration::seconds(i as i64);
            manager.upsert_job(finished).unwrap();
        }

        let listed = manager.list_jobs();
        assert!(
            listed.len() <= MAX_RETAINED_JOBS,
            "index must stay capped, got {}",
            listed.len()
        );
        assert!(
            manager.get_job(&running_id).is_ok(),
            "the running job must survive eviction"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── Governed runner lifecycle: hostile inputs, real child processes ──

    use std::time::Duration;

    /// A unique scratch checkpoint directory (removed by the guard on drop).
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                // nosemgrep: rust.lang.security.temp-dir.temp-dir — test fixture under a unique pid/uuid path — no predictable-name temp collision
                "ai-train-{label}-{}",
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn config(&self) -> AiConfig {
            AiConfig {
                checkpoint_path: self.0.display().to_string(),
                ..AiConfig::default()
            }
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    /// Write an executable POSIX-shell runner script and return its path.
    fn write_runner(label: &str, body: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("ai-runner-{label}-{}.sh", uuid::Uuid::new_v4())); // nosemgrep: rust.lang.security.temp-dir.temp-dir — test fixture under a unique pid/uuid path — no predictable-name temp collision
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// Poll until the job leaves the running state (the observer task updates
    /// it asynchronously after the child exits), or fail with the last state.
    async fn wait_for_terminal_state(manager: &TrainingManager, job_id: &str) -> TrainingJob {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let job = manager.get_job(job_id).expect("job present");
            if !matches!(job.status, JobStatus::Queued | JobStatus::Running) {
                return job;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "job {job_id} never reached a terminal state: {:?}",
                job.status
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn start_job_rejects_hostile_identifiers_and_epoch_bounds() {
        let scratch = ScratchDir::new("validation");
        let runner = write_runner("validation", "exit 0");
        let config = AiConfig {
            training_runner: runner.display().to_string(),
            ..scratch.config()
        };
        let manager = TrainingManager::new(&config);

        let oversized = "m".repeat(129);
        for bad_model_id in ["", "   ", oversized.as_str()] {
            let result = manager.start_job(bad_model_id, 1).await;
            assert!(
                matches!(result, Err(AiError::InvalidInput(_))),
                "model id {bad_model_id:?} must be rejected"
            );
        }
        for bad_epochs in [0, 101, 100_000] {
            let result = manager.start_job("apexmail-assistant", bad_epochs).await;
            assert!(
                matches!(result, Err(AiError::InvalidInput(_))),
                "epochs {bad_epochs} must be rejected"
            );
        }
        // A rejected request must not leave a job record behind.
        assert!(manager.list_jobs().is_empty(), "no job may be registered");
    }

    #[tokio::test]
    async fn runner_must_be_an_absolute_existing_file() {
        let scratch = ScratchDir::new("runner-path");
        for bad_runner in ["echo", "./runner.sh", "/nonexistent/ai-runner"] {
            let config = AiConfig {
                training_runner: bad_runner.into(),
                ..scratch.config()
            };
            let manager = TrainingManager::new(&config);
            let result = manager.start_job("apexmail-assistant", 1).await;
            assert!(
                matches!(result, Err(AiError::TrainingUnavailable(_))),
                "runner {bad_runner:?} must be unavailable, got {result:?}"
            );
            assert!(manager.list_jobs().is_empty());
        }
    }

    /// A runner that exits successfully WITHOUT writing its evaluation
    /// artifact must land the job in Failed — the API never pretends a
    /// training run completed.
    #[tokio::test]
    async fn runner_without_metrics_artifact_fails_the_job() {
        let scratch = ScratchDir::new("no-metrics");
        let runner = write_runner("no-metrics", "exit 0");
        let config = AiConfig {
            training_runner: runner.display().to_string(),
            training_working_dir: scratch.0.display().to_string(),
            ..scratch.config()
        };
        let manager = TrainingManager::new(&config);

        let job = manager.start_job("apexmail-assistant", 3).await.unwrap();
        assert_eq!(job.status, JobStatus::Running, "spawned job is running");
        assert_eq!(job.epochs, 3);

        let final_state = wait_for_terminal_state(&manager, &job.id).await;
        assert_eq!(final_state.status, JobStatus::Failed);
        let error = final_state.error.expect("failure reason recorded");
        assert!(
            error.contains("metrics.json"),
            "the missing artifact must be named: {error}"
        );
        assert!(final_state.completed_at.is_some());
        std::fs::remove_file(&runner).ok();
    }

    /// A runner that exits 0 and writes a real metrics artifact completes the
    /// job with the runner's own evaluation values.
    #[tokio::test]
    async fn runner_with_metrics_artifact_completes_the_job() {
        let scratch = ScratchDir::new("metrics");
        // Parse --artifact-dir and write the evaluation artifact there.
        let runner = write_runner(
            "metrics",
            r#"while [ $# -gt 0 ]; do
  if [ "$1" = "--artifact-dir" ]; then ART="$2"; fi
  shift
done
cat > "$ART/metrics.json" <<'JSON'
{"loss": 0.42, "accuracy": 0.91, "precision": 0.88, "recall": 0.9, "f1": 0.89}
JSON
exit 0"#,
        );
        let config = AiConfig {
            training_runner: runner.display().to_string(),
            ..scratch.config()
        };
        let manager = TrainingManager::new(&config);

        let job = manager.start_job("apexmail-assistant", 2).await.unwrap();
        let final_state = wait_for_terminal_state(&manager, &job.id).await;

        assert_eq!(final_state.status, JobStatus::Completed);
        assert_eq!(final_state.loss, Some(0.42));
        assert!(final_state.error.is_none());
        // The artifact keeps the full snapshot on disk.
        let snapshot =
            std::fs::read_to_string(scratch.0.join("jobs").join(&job.id).join("job.json"))
                .expect("snapshot persisted");
        assert!(snapshot.contains("\"loss\": 0.42"));
        assert!(snapshot.contains("\"status\""));
        std::fs::remove_file(&runner).ok();
    }

    /// A runner that exits nonzero fails the job with the exit status — the
    /// child outcome is tracked, never assumed.
    #[tokio::test]
    async fn failing_runner_exit_code_is_tracked() {
        let scratch = ScratchDir::new("failing");
        let runner = write_runner("failing", "echo boom >&2; exit 3");
        let config = AiConfig {
            training_runner: runner.display().to_string(),
            ..scratch.config()
        };
        let manager = TrainingManager::new(&config);

        let job = manager.start_job("apexmail-assistant", 1).await.unwrap();
        let final_state = wait_for_terminal_state(&manager, &job.id).await;
        assert_eq!(final_state.status, JobStatus::Failed);
        let error = final_state.error.expect("failure reason recorded");
        assert!(
            error.contains("exited with status") && error.contains("3"),
            "the real exit status must be reported: {error}"
        );
        std::fs::remove_file(&runner).ok();
    }

    /// An artifact with no reported evaluation values is not a completion:
    /// `{"loss": null, ...}` is treated as missing evidence.
    #[tokio::test]
    async fn metrics_artifact_without_any_values_fails_the_job() {
        let scratch = ScratchDir::new("empty-metrics");
        let runner = write_runner(
            "empty-metrics",
            r#"while [ $# -gt 0 ]; do
  if [ "$1" = "--artifact-dir" ]; then ART="$2"; fi
  shift
done
printf '{}\n' > "$ART/metrics.json"
exit 0"#,
        );
        let config = AiConfig {
            training_runner: runner.display().to_string(),
            ..scratch.config()
        };
        let manager = TrainingManager::new(&config);
        let job = manager.start_job("apexmail-assistant", 1).await.unwrap();
        let final_state = wait_for_terminal_state(&manager, &job.id).await;
        assert_eq!(final_state.status, JobStatus::Failed);
        assert!(final_state
            .error
            .expect("reason")
            .contains("no reported evaluation values"));
        std::fs::remove_file(&runner).ok();
    }

    /// A metrics artifact that is not JSON at all fails the job with the
    /// artifact error — never a silent completion.
    #[tokio::test]
    async fn metrics_artifact_with_invalid_json_fails_the_job() {
        let scratch = ScratchDir::new("bad-json-metrics");
        let runner = write_runner(
            "bad-json-metrics",
            r#"while [ $# -gt 0 ]; do
  if [ "$1" = "--artifact-dir" ]; then ART="$2"; fi
  shift
done
printf 'not json at all\n' > "$ART/metrics.json"
exit 0"#,
        );
        let config = AiConfig {
            training_runner: runner.display().to_string(),
            ..scratch.config()
        };
        let manager = TrainingManager::new(&config);
        let job = manager.start_job("apexmail-assistant", 1).await.unwrap();
        let final_state = wait_for_terminal_state(&manager, &job.id).await;
        assert_eq!(final_state.status, JobStatus::Failed);
        assert!(final_state
            .error
            .expect("reason")
            .contains("invalid runner metrics artifact"));
        std::fs::remove_file(&runner).ok();
    }

    /// An unwritable checkpoint directory surfaces as a CheckpointError on
    /// every state transition instead of losing job state silently.
    #[test]
    fn unwritable_job_directory_is_a_checkpoint_error() {
        let scratch = ScratchDir::new("readonly");
        let config = scratch.config();
        let manager = TrainingManager::new(&config);
        let mut job = TrainingJob::new("apexmail-assistant", 1);
        job.status = JobStatus::Completed;
        let directory = scratch.0.join("jobs").join(&job.id);
        std::fs::create_dir_all(&directory).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o555)).unwrap();

        let result = manager.upsert_job(job);
        assert!(
            matches!(result, Err(AiError::CheckpointError(ref e)) if e.contains("could not write")),
            "the temp-file write failure must be reported, got {result:?}"
        );
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A spawn failure (existing file, not executable) fails the job record
    /// and surfaces a TrainingError — it must not strand a Queued job.
    #[tokio::test]
    async fn unexecutable_runner_reports_spawn_failure_and_fails_the_job() {
        let scratch = ScratchDir::new("spawn-fail");
        let runner = scratch.0.join("not-executable.sh");
        std::fs::write(&runner, "#!/bin/sh\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o644)).unwrap();

        let config = AiConfig {
            training_runner: runner.display().to_string(),
            ..scratch.config()
        };
        let manager = TrainingManager::new(&config);

        let result = manager.start_job("apexmail-assistant", 1).await;
        assert!(matches!(result, Err(AiError::TrainingError(_))));
        // The job was registered, then marked failed with the spawn error.
        let listed = manager.list_jobs();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].status, JobStatus::Failed);
        assert!(listed[0]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("could not start training runner"));
    }

    #[test]
    fn evaluate_rejects_empty_and_mismatched_inputs() {
        let manager = TrainingManager::new(&AiConfig::default());
        let empty: Vec<bool> = Vec::new();
        assert!(matches!(
            manager.evaluate(&empty, &empty),
            Err(AiError::InvalidInput(_))
        ));
        assert!(matches!(
            manager.evaluate(&[true, false], &[true]),
            Err(AiError::InvalidInput(_))
        ));
    }

    /// Degenerate confusion matrices must degrade to zero metrics, never
    /// divide by zero or produce NaN.
    #[test]
    fn evaluate_with_no_positive_predictions_degrades_to_zero() {
        let manager = TrainingManager::new(&AiConfig::default());
        let metrics = manager
            .evaluate(&[false, false, false], &[false, false, false])
            .unwrap();
        assert_eq!(metrics.accuracy, 1.0);
        assert_eq!(metrics.precision, 0.0);
        assert_eq!(metrics.recall, 0.0);
        assert_eq!(metrics.f1, 0.0);
        assert!(!metrics.precision.is_nan());
        assert!(!metrics.f1.is_nan());
    }

    /// Snapshot persistence failures surface as CheckpointError instead of
    /// silently dropping job state.
    #[test]
    fn unwritable_checkpoint_dir_is_a_checkpoint_error() {
        // A FILE where the checkpoint directory must be created.
        let file = std::env::temp_dir().join(format!("ai-train-file-{}", uuid::Uuid::new_v4())); // nosemgrep: rust.lang.security.temp-dir.temp-dir — test fixture under a unique pid/uuid path — no predictable-name temp collision
        std::fs::write(&file, b"not a directory").unwrap();
        let config = AiConfig {
            checkpoint_path: file.display().to_string(),
            ..AiConfig::default()
        };
        let manager = TrainingManager::new(&config);
        let result = manager.upsert_job(TrainingJob::new("apexmail-assistant", 1));
        assert!(
            matches!(result, Err(AiError::CheckpointError(_))),
            "create_dir_all over a file must fail loudly, got {result:?}"
        );
        std::fs::remove_file(&file).ok();
    }

    /// A runner may report a subset of evaluation values (`loss: null`).
    /// Missing values stay None; the completion is still honest.
    #[tokio::test]
    async fn metrics_artifact_with_partial_values_completes() {
        let scratch = ScratchDir::new("partial-metrics");
        let runner = write_runner(
            "partial-metrics",
            r#"while [ $# -gt 0 ]; do
  if [ "$1" = "--artifact-dir" ]; then ART="$2"; fi
  shift
done
printf '{"loss": null, "accuracy": 0.5}\n' > "$ART/metrics.json"
exit 0"#,
        );
        let config = AiConfig {
            training_runner: runner.display().to_string(),
            ..scratch.config()
        };
        let manager = TrainingManager::new(&config);
        let job = manager.start_job("apexmail-assistant", 1).await.unwrap();
        let final_state = wait_for_terminal_state(&manager, &job.id).await;
        assert_eq!(final_state.status, JobStatus::Completed);
        assert_eq!(final_state.loss, None, "reported null stays None");
        assert!(final_state.error.is_none());
        std::fs::remove_file(&runner).ok();
    }

    #[test]
    fn atomic_write_publication_failure_is_reported_and_cleans_up() {
        let scratch = ScratchDir::new("publish");
        let config = scratch.config();
        let manager = TrainingManager::new(&config);
        // Pre-create the snapshot TARGET as a directory: the temp write
        // succeeds, the rename onto a directory fails, the temp file is
        // removed, and the error names the target.
        let mut job = TrainingJob::new("apexmail-assistant", 1);
        job.status = JobStatus::Completed;
        let target = scratch.0.join("jobs").join(&job.id).join("job.json");
        std::fs::create_dir_all(&target).unwrap();

        let result = manager.upsert_job(job);
        assert!(
            matches!(result, Err(AiError::CheckpointError(ref e)) if e.contains("could not publish")),
            "rename failure must be reported, got {result:?}"
        );
        // No *.tmp-* litter may survive a failed publish.
        let leftovers: Vec<_> = std::fs::read_dir(target.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "temp files must be cleaned up");
    }

    #[test]
    fn get_job_reports_unknown_ids() {
        let manager = TrainingManager::new(&AiConfig::default());
        let result = manager.get_job("no-such-job");
        assert!(matches!(result, Err(AiError::JobNotFound(id)) if id == "no-such-job"));
    }
}
