//! Benchmark for rate limiter performance

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use std::collections::HashMap;
use std::time::Instant;

/// Simple token bucket for benchmarking
struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    #[inline]
    fn try_acquire(&mut self, tokens: f64) -> bool {
        self.refill();
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    #[inline]
    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed();
        let new_tokens = elapsed.as_secs_f64() * self.refill_rate;
        self.tokens = (self.tokens + new_tokens).min(self.max_tokens);
        self.last_refill = Instant::now();
    }
}

/// Sliding window rate limiter
struct SlidingWindow {
    counters: HashMap<String, (u64, Instant)>,
    window_ms: u64,
    limit: u64,
}

impl SlidingWindow {
    fn new(window_ms: u64, limit: u64) -> Self {
        Self {
            counters: HashMap::new(),
            window_ms,
            limit,
        }
    }

    #[inline]
    fn check(&mut self, key: &str) -> bool {
        let now = Instant::now();
        
        if let Some((count, start)) = self.counters.get_mut(key) {
            if start.elapsed().as_millis() as u64 > self.window_ms {
                *count = 1;
                *start = now;
                true
            } else if *count < self.limit {
                *count += 1;
                true
            } else {
                false
            }
        } else {
            self.counters.insert(key.to_string(), (1, now));
            true
        }
    }
}

fn bench_token_bucket(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_bucket");
    group.throughput(Throughput::Elements(1));

    group.bench_function("acquire_single", |b| {
        let mut bucket = TokenBucket::new(10000.0, 1000.0);
        b.iter(|| {
            bucket.tokens = 10000.0; // Reset for fair comparison
            black_box(bucket.try_acquire(1.0))
        })
    });

    group.bench_function("acquire_burst", |b| {
        b.iter(|| {
            let mut bucket = TokenBucket::new(100.0, 100.0);
            for _ in 0..100 {
                black_box(bucket.try_acquire(1.0));
            }
        })
    });

    group.finish();
}

fn bench_sliding_window(c: &mut Criterion) {
    let mut group = c.benchmark_group("sliding_window");
    group.throughput(Throughput::Elements(1));

    group.bench_function("check_single_key", |b| {
        let mut limiter = SlidingWindow::new(1000, 1000);
        b.iter(|| {
            black_box(limiter.check("192.168.1.1"))
        })
    });

    group.bench_function("check_many_keys", |b| {
        let mut limiter = SlidingWindow::new(1000, 100);
        let keys: Vec<String> = (0..1000)
            .map(|i| format!("192.168.{}.{}", i / 256, i % 256))
            .collect();
        let mut idx = 0;
        b.iter(|| {
            let result = limiter.check(&keys[idx % keys.len()]);
            idx += 1;
            black_box(result)
        })
    });

    group.finish();
}

fn bench_ip_hashing(c: &mut Criterion) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut group = c.benchmark_group("ip_hashing");
    
    group.bench_function("hash_ipv4_string", |b| {
        let ip = "192.168.1.100";
        b.iter(|| {
            let mut hasher = DefaultHasher::new();
            ip.hash(&mut hasher);
            black_box(hasher.finish())
        })
    });

    group.bench_function("shard_selection", |b| {
        let ip = "192.168.1.100";
        b.iter(|| {
            let mut hasher = DefaultHasher::new();
            ip.hash(&mut hasher);
            let hash = hasher.finish();
            black_box(hash % 16)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_token_bucket,
    bench_sliding_window,
    bench_ip_hashing,
);

criterion_main!(benches);
