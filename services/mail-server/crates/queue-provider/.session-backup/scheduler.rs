//! Fair queue scheduler — prevents tenant starvation.

use std::collections::HashMap;
use uuid::Uuid;

use crate::types::Job;

/// Weighted fair scheduler that limits per-tenant share.
pub struct FairQueueScheduler {
    /// Maximum share of total processing a single tenant can use (0.0-1.0)
    max_tenant_share: f64,
    /// Maximum tracked tenant count (bounded to prevent memory issues)
    max_tracked_tenants: usize,
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

    /// Filter a batch of dequeued jobs to enforce fair scheduling.
    /// Returns the jobs that should be processed, respecting tenant limits.
    pub fn schedule(&self, jobs: Vec<Job>, batch_size: usize) -> Vec<Job> {
        if jobs.is_empty() || batch_size == 0 {
            return vec![];
        }

        let max_per_tenant = ((batch_size as f64) * self.max_tenant_share).ceil() as usize;
        let max_per_tenant = max_per_tenant.max(1);

        let mut tenant_counts: HashMap<Uuid, usize> = HashMap::new();
        let mut selected = Vec::with_capacity(batch_size);

        for job in jobs {
            if selected.len() >= batch_size {
                break;
            }

            // Bound tracked tenants
            if tenant_counts.len() >= self.max_tracked_tenants
                && !tenant_counts.contains_key(&job.tenant_id)
            {
                continue;
            }

            let count = tenant_counts.entry(job.tenant_id).or_insert(0);
            if *count < max_per_tenant {
                *count += 1;
                selected.push(job);
            }
        }

        selected
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

        let selected = scheduler.schedule(jobs, 10);
        let dist = scheduler.tenant_distribution(&selected);

        // Tenant A should be capped at ~30% of 10 = 3
        assert!(*dist.get(&tenant_a).unwrap_or(&0) <= 3);
        // Tenant B should get all 2
        assert_eq!(*dist.get(&tenant_b).unwrap_or(&0), 2);
    }

    #[test]
    fn test_empty_jobs() {
        let scheduler = FairQueueScheduler::default_scheduler();
        let result = scheduler.schedule(vec![], 10);
        assert!(result.is_empty());
    }

    #[test]
    fn test_zero_batch_size() {
        let scheduler = FairQueueScheduler::default_scheduler();
        let result = scheduler.schedule(vec![make_job(Uuid::new_v4())], 0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_single_tenant_capped() {
        let scheduler = FairQueueScheduler::new(0.50, 100);
        let tenant = Uuid::new_v4();

        let jobs: Vec<Job> = (0..20).map(|_| make_job(tenant)).collect();
        let selected = scheduler.schedule(jobs, 10);

        // Should be capped at 50% of 10 = 5
        assert!(selected.len() <= 5);
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

        let selected = scheduler.schedule(jobs, 15);
        let dist = scheduler.tenant_distribution(&selected);

        // Each tenant should get at most 5 (30% of 15 = 4.5 → 5)
        for count in dist.values() {
            assert!(*count <= 5);
        }
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
        let selected = scheduler.schedule(jobs, 5);
        assert_eq!(selected.len(), 5);
    }
}
