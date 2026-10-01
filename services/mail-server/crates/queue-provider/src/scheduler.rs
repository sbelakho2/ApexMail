//! Fair queue scheduler — prevents tenant starvation.

use std::collections::HashMap;
use uuid::Uuid;

use crate::types::Job;

/// Weighted fair scheduler that limits per-tenant share.
///
/// # Callers (F10-old — deliberately unwired)
///
/// NO production code constructs this scheduler. `queue-provider` itself is
/// only smoke-test-wired (smoke-tests exercises `queue_provider::types`
/// only) — no production poller dequeues from `queue_jobs`, so there is no
/// natural place to slot a fair-scheduling pass yet. The production email
/// path (`worker-processors/src/email/processor.rs`) polls `email_queue`
/// directly and runs no fair-scheduling pass of its own.
/// When a production owner adopts `PostgresQueueProvider::dequeue`, apply
/// `schedule(dequeued, batch_size)` to the dequeued batch before dispatch:
/// dispatch `outcome.selected` and release `outcome.deferred` back to
/// pending (mirroring the release-back in worker-processors' email
/// processor) — the API hands every non-selected job back so nothing is
/// silently discarded (audit finding 10).
pub struct FairQueueScheduler {
    /// Maximum share of total processing a single tenant can use (0.0-1.0)
    max_tenant_share: f64,
    /// Maximum tracked tenant count (bounded to prevent memory issues)
    max_tracked_tenants: usize,
}

/// Result of one scheduling pass (audit finding 10).
///
/// Every input job lands in EXACTLY one of the two vecs — the old
/// `Vec<Job>` return silently discarded jobs over the batch size, the
/// per-tenant cap, or the tracked-tenant bound, leaving a caller that
/// consumed the dequeued batch no way to release them back to pending.
#[derive(Debug, Clone, Default)]
pub struct ScheduleOutcome {
    /// Jobs that may be dispatched now.
    pub selected: Vec<Job>,
    /// Jobs NOT dispatched this pass (over the batch size, over their
    /// tenant's cap, or of an un-tracked tenant). The caller MUST release
    /// these back to pending (or otherwise account for them) — they were
    /// dequeued under a lease and must not vanish.
    pub deferred: Vec<Job>,
}

impl FairQueueScheduler {
    pub fn new(max_tenant_share: f64, max_tracked_tenants: usize) -> Self {
        Self {
            max_tenant_share: max_tenant_share.clamp(0.01, 1.0),
            max_tracked_tenants,
        }
    }

    /// Default scheduler with 30% max share per tenant.
    pub fn default_scheduler() -> Self {
        Self::new(0.30, 10_000)
    }

    /// Partition a batch of dequeued jobs under fair scheduling.
    ///
    /// Returns [`ScheduleOutcome`]: the jobs to process now (`selected`) and
    /// everything else (`deferred`) — jobs over the batch size, over their
    /// tenant's cap, or belonging to a tenant beyond the tracking bound.
    /// Nothing is dropped: `selected.len() + deferred.len() == jobs.len()`
    /// always holds, so the caller can release the deferred jobs back to
    /// pending (audit finding 10).
    pub fn schedule(&self, jobs: Vec<Job>, batch_size: usize) -> ScheduleOutcome {
        let mut outcome = ScheduleOutcome::default();
        if jobs.is_empty() {
            return outcome;
        }
        if batch_size == 0 {
            // Nothing can be dispatched this pass; every job is deferred so
            // the caller can release it back to pending.
            outcome.deferred = jobs;
            return outcome;
        }

        let max_per_tenant = ((batch_size as f64) * self.max_tenant_share).ceil() as usize;
        let max_per_tenant = max_per_tenant.max(1);

        let mut tenant_counts: HashMap<Uuid, usize> = HashMap::new();

        for job in jobs {
            // Batch full: the REST of the batch is deferred, not dropped.
            if outcome.selected.len() >= batch_size {
                outcome.deferred.push(job);
                continue;
            }

            // Bound tracked tenants: an un-trackable tenant cannot be
            // counted fairly, so its jobs defer instead of bypassing the
            // bound.
            if tenant_counts.len() >= self.max_tracked_tenants
                && !tenant_counts.contains_key(&job.tenant_id)
            {
                outcome.deferred.push(job);
                continue;
            }

            let count = tenant_counts.entry(job.tenant_id).or_insert(0);
            if *count < max_per_tenant {
                *count += 1;
                outcome.selected.push(job);
            } else {
                outcome.deferred.push(job);
            }
        }

        outcome
    }

    /// Calculate tenant distribution for monitoring.
    pub fn tenant_distribution(&self, jobs: &[Job]) -> HashMap<Uuid, usize> {
        let mut dist: HashMap<Uuid, usize> = HashMap::new();
        for job in jobs {
            *dist.entry(job.tenant_id).or_insert(0) += 1;
        }
        dist
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use chrono::Utc;

    fn make_job(tenant_id: Uuid) -> Job {
        Job {
            id: Uuid::new_v4(),
            tenant_id,
            queue: "test".to_string(),
            payload: serde_json::json!({}),
            status: JobStatus::Pending,
            attempts: 0,
            max_attempts: 3,
            priority: 0,
            scheduled_at: Utc::now(),
            started_at: None,
            completed_at: None,
            failed_at: None,
            error_message: None,
            visibility_timeout: 300,
            lease_token: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_fair_scheduling_limits_tenant() {
        let scheduler = FairQueueScheduler::new(0.30, 100);
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();

        let mut jobs = Vec::new();
        // 8 jobs from tenant A, 2 from tenant B
        for _ in 0..8 {
            jobs.push(make_job(tenant_a));
        }
        for _ in 0..2 {
            jobs.push(make_job(tenant_b));
        }

        let outcome = scheduler.schedule(jobs, 10);
        assert_eq!(
            outcome.selected.len() + outcome.deferred.len(),
            10,
            "every job is accounted for"
        );
        let dist = scheduler.tenant_distribution(&outcome.selected);

        // Tenant A should be capped at ~30% of 10 = 3
        assert!(*dist.get(&tenant_a).unwrap_or(&0) <= 3);
        // Tenant B should get all 2
        assert_eq!(*dist.get(&tenant_b).unwrap_or(&0), 2);
    }

    #[test]
    fn test_empty_jobs() {
        let scheduler = FairQueueScheduler::default_scheduler();
        let result = scheduler.schedule(vec![], 10);
        assert!(result.selected.is_empty());
        assert!(result.deferred.is_empty());
    }

    #[test]
    fn test_zero_batch_size() {
        let scheduler = FairQueueScheduler::default_scheduler();
        let result =
            scheduler.schedule(vec![make_job(Uuid::new_v4()), make_job(Uuid::new_v4())], 0);
        // Audit finding 10: nothing can dispatch on a zero batch, but the
        // jobs must be DEFERRED (release back to pending), never dropped.
        assert!(result.selected.is_empty());
        assert_eq!(result.deferred.len(), 2);
    }

    #[test]
    fn test_single_tenant_capped() {
        let scheduler = FairQueueScheduler::new(0.50, 100);
        let tenant = Uuid::new_v4();

        let jobs: Vec<Job> = (0..20).map(|_| make_job(tenant)).collect();
        let outcome = scheduler.schedule(jobs, 10);

        // Should be capped at 50% of 10 = 5
        assert!(outcome.selected.len() <= 5);
        // The capped remainder is deferred, not discarded.
        assert_eq!(outcome.selected.len() + outcome.deferred.len(), 20);
    }

    #[test]
    fn test_many_tenants_fair() {
        let scheduler = FairQueueScheduler::new(0.30, 100);

        let mut jobs = Vec::new();
        for _ in 0..5 {
            let tenant = Uuid::new_v4();
            for _ in 0..4 {
                jobs.push(make_job(tenant));
            }
        }

        let outcome = scheduler.schedule(jobs, 15);
        let dist = scheduler.tenant_distribution(&outcome.selected);

        // Each tenant should get at most 5 (30% of 15 = 4.5 → 5)
        for count in dist.values() {
            assert!(*count <= 5);
        }
        assert_eq!(outcome.selected.len() + outcome.deferred.len(), 20);
    }

    #[test]
    fn test_default_scheduler() {
        let scheduler = FairQueueScheduler::default_scheduler();
        assert!((scheduler.max_tenant_share - 0.30).abs() < f64::EPSILON);
        assert_eq!(scheduler.max_tracked_tenants, 10_000);
    }

    #[test]
    fn test_tenant_distribution() {
        let scheduler = FairQueueScheduler::default_scheduler();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();

        let jobs = vec![make_job(t1), make_job(t1), make_job(t2)];
        let dist = scheduler.tenant_distribution(&jobs);

        assert_eq!(*dist.get(&t1).unwrap(), 2);
        assert_eq!(*dist.get(&t2).unwrap(), 1);
    }

    #[test]
    fn test_max_share_clamped() {
        let s1 = FairQueueScheduler::new(0.001, 100);
        assert!((s1.max_tenant_share - 0.01).abs() < f64::EPSILON);

        let s2 = FairQueueScheduler::new(5.0, 100);
        assert!((s2.max_tenant_share - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_batch_size_respected() {
        let scheduler = FairQueueScheduler::new(1.0, 100); // no tenant limit
        let tenant = Uuid::new_v4();
        let jobs: Vec<Job> = (0..20).map(|_| make_job(tenant)).collect();
        let outcome = scheduler.schedule(jobs, 5);
        assert_eq!(outcome.selected.len(), 5);
        // The 15 jobs over the batch size are handed back, not dropped.
        assert_eq!(outcome.deferred.len(), 15);
    }

    // ── audit finding 10: nothing the scheduler touches may vanish ─────────

    /// Audit finding 10 regression: `schedule` consumes the dequeued batch,
    /// so jobs it used to drop (over the batch size or a per-tenant cap)
    /// were unrecoverable — dequeued under a lease, then silently lost.
    /// Every input job must land in EXACTLY one of selected/deferred, and
    /// the deferred vec must carry the over-cap jobs for release-back.
    #[test]
    fn schedule_accounts_for_every_job_in_selected_or_deferred() {
        let scheduler = FairQueueScheduler::new(0.30, 100);
        let busy = Uuid::new_v4();
        let other = Uuid::new_v4();
        let mut jobs: Vec<Job> = Vec::new();
        for _ in 0..12 {
            jobs.push(make_job(busy));
        }
        for _ in 0..3 {
            jobs.push(make_job(other));
        }

        let outcome = scheduler.schedule(jobs, 5);
        assert_eq!(
            outcome.selected.len() + outcome.deferred.len(),
            15,
            "selected + deferred must reconstruct the whole batch"
        );
        // The per-tenant cap is ceil(30% of 5) = 2 for EVERY tenant: 2 busy
        // + 2 other are selected, the rest defer.
        assert_eq!(
            outcome.selected.len(),
            4,
            "each tenant is capped at ceil(30% of the batch) = 2"
        );

        // The over-cap jobs are exactly what got deferred.
        let deferred = scheduler.tenant_distribution(&outcome.deferred);
        assert_eq!(
            *deferred.get(&busy).unwrap_or(&0),
            10,
            "busy tenant: 2 selected + 10 deferred"
        );
        assert_eq!(
            *deferred.get(&other).unwrap_or(&0),
            1,
            "other tenant: 2 selected + 1 deferred"
        );
        // No job may appear in both vecs: the deferred set carries only
        // jobs absent from the selected set (ids are unique per make_job).
        let selected_ids: std::collections::HashSet<_> =
            outcome.selected.iter().map(|job| job.id).collect();
        assert!(
            outcome
                .deferred
                .iter()
                .all(|job| !selected_ids.contains(&job.id)),
            "a job must not be both dispatched and deferred"
        );
    }
}
