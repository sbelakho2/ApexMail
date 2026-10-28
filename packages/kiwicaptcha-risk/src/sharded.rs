//! Sharded keyspace store (Plane 7): the horizontally scalable layout of
//! the risk state, spread over Redis Cluster slots so throughput scales
//! with the shard count. Byte-identical key derivation with the PHP
//! mirror `KiwiCaptcha\Risk\Storage\ShardedRedisRiskStateStore`, both
//! built on the sharded Lua family in this package's resources directory
//! (three canonical copies: `protocol/risk-v1/`, this package and the
//! PHP package, all byte-equal).
//!
//! # Key map (the family tag is the hash tag; one script, one slot)
//!
//!   identity state   `{kiwi:<ns>:<dim>:<hex2>}:risk:<dim>[:<epoch>]:<id>`
//!   per-dim marker   `{kiwi:<ns>:<dim>:<hex2>}:risk:dd:<event_id>`
//!   nonce dedupe     `{kiwi:<ns>:n:<hex2>}:risk:dedupe:<event_id>`
//!   scope aggregate  `{kiwi:<ns>:s:<id>:<shard>}:scope:<id>:<shard>`
//!   shard marker     `{kiwi:<ns>:s:<id>:<shard>}:dd:<event_id>`
//!   hysteresis state `{kiwi:<ns>}:risk:hyst`
//!   mode marker      `{kiwi:<ns>}:mode`
//!
//! `<dim>` names one of the seven sharded dimensions: src, net,
//! session, principal, asn, target and agent. `<hex2>` is the two hex
//! characters of the family identifier's first byte. `<shard>` is
//! `fnv1a32(event_id) mod 16`, or the caller's stable fallback hash for
//! an empty event id (the assessment's source pseudonym), so
//! dedupe-less writes disperse over the shards instead of funneling
//! onto one slot. Source and subnet
//! keep their ±1 epoch
//! boundary pseudonyms: each pseudonym carries its own family prefix, so
//! the boundary reads run as their own read-only invocations and the
//! caller sums the replies exactly per the risk-v1 sum3 contract.
//!
//! # Batching contract
//!
//! One assessment is one pipelined batch. The batch's invocations are
//! grouped by endpoint (the owner of each key's slot: the real cluster
//! node from `CLUSTER SLOTS`, or the slot-modulo stand-in server), every
//! group is fully written before any reply is read, and the read phase
//! then drains each group. The wall clock is therefore one round trip
//! per touched slot group, with the touched nodes processing in
//! parallel. Two batches exist per store instance: the assessment batch
//! above, and the merge batch that re-reads the 16 scope shards, issued
//! at most once per second.
//!
//! # Staleness contract of the merged aggregate
//!
//! The scope/global pressure lives in 16 shard counters and is merged on
//! read. A merge may lag the newest commit by at most one second: the
//! store refreshes its merged value at most once per
//! [`keyspace::MERGE_STALENESS`], and an assessment that arrives inside
//! the window reuses the last merged value for both the global pressure
//! signal and the level transition. Within one window the lag is bounded
//! by the window; across windows the next refresh absorbs every commit.
//!
//! # Atomicity boundaries (every transition and its boundary)
//!
//! | Surface | Key(s) | Boundary |
//! |---|---|---|
//! | identity dimension apply | one state hash + its marker | one Lua script, one slot; the marker is `SET NX` inside the script, so a partial-batch retry cannot double-count |
//! | scope shard increment | one shard hash + its marker | one Lua script, one slot, same marker rule |
//! | nonce dedupe verdict | one marker key | one `SET NX EX`; single-slot and atomic |
//! | level/cooldown transition | one hysteresis hash | one Lua script, one slot, run once per merge window inside the staleness refresh, never on the hot path |
//! | first-seen session tags | one record key each | one `SET NX EX` on the session family; the lifetime rides the write |
//! | target failure / spread | one hash + two HLLs | the canonical target script, one op on the target family slot; the assessment's read rides the batch, the failure write its second phase |
//! | outcome ledger register | one ledger key | one canonical script, `SET NX EX`, on the decision-id family |
//! | outcome confirm/correct | one ledger key | one canonical script; pending flips exactly once, corrections only after confirmation |
//! | marks and bucket trust | one key each | one canonical script per op |
//! | cross-dimension aggregation | client-side | reads of already-committed per-slot state; each dimension's own atomicity stays per-slot above |
//!
//! Single-use consume (the nonce marker, the ledger transitions, the
//! first-seen tags) stays single-slot on purpose: a wider batch would
//! widen the atomicity boundary without adding throughput, because these
//! transitions touch one key each.
//!
//! # Keyspace mode and the mixed-fleet rule
//!
//! A namespace carries exactly one layout, recorded in its mode marker
//! key `{kiwi:<ns>}:mode`. This store claims the marker (`SET NX`,
//! persistent) with the sharded value at construction and refuses a
//! legacy-marked namespace with
//! [`RiskStoreError::KeyspaceModeMismatch`]; it never falls back. The
//! legacy store keeps its construction lazy, so an operator wiring the
//! legacy layout should assert the marker through
//! [`keyspace::claim_keyspace_mode`] with [`KeyspaceMode::Legacy`] at
//! wiring time. The rule for a mixed fleet: pick the mode once per
//! namespace before any store serves traffic; drain the stores of the
//! other mode before switching, because the two layouts address disjoint
//! state families and a straggler would observe an empty keyspace.
//!
//! # Auxiliary surfaces
//!
//! The long-memory marks and the bucket trust records are single-key
//! scripts whose slot placement is irrelevant to throughput: they keep
//! the shared `{kiwi:<ns>}` tag in both modes and this store delegates
//! them to an embedded [`RedisRiskStateStore`] aimed at the node that
//! owns that tag. The surfaces the hot path touches (the first-seen
//! session tags, the outcome ledger, the target failure state) ride
//! their own family slots and are addressed through the same routed
//! dispatch as the assessment batch. The assessment path is where the
//! sharded layout lives.

use std::sync::atomic::{AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, MutexGuard};
use std::time::Duration;

use crate::event::RiskObservation;
use crate::keyspace::{
    claim_keyspace_mode, hysteresis_key, identity_marker_key, identity_state_key, KeyspaceMode,
    MergeGate, ShardedDimension,
};
use crate::namespace::NamespaceVersion;
use crate::redis::{map_redis_error, value_i64, ConnectionPool, RedisRiskStateStore};
use crate::signals::SignalVector;
use crate::store::{
    AssessV2Reply, Observed, OutcomeRegistration, RiskStateStore, RiskStoreError,
    SessionContextTagStore, SessionTlsTagStore, TargetState,
};
use ::redis as redis_crate;

/// The per-identity dimension script: one state hash read, leak, dedupe
/// gate, event apply and save, all inside one family slot.
pub const SHARDED_IDENTITY_LUA: &str = include_str!("../resources/sharded_identity.lua");

/// The scope aggregate shard script: the sharded counter read, leak,
/// dedupe gate, event apply and save for one shard, one slot.
pub const SHARDED_SCOPE_LUA: &str = include_str!("../resources/sharded_scope.lua");

/// The single-slot level/cooldown transition, fed with the merged
/// aggregate pressure.
pub const SHARDED_HYSTERESIS_LUA: &str = include_str!("../resources/sharded_hysteresis.lua");

/// The canonical outcome-ledger registration script (shared verbatim
/// with the legacy store): the pending ledger entry of one decision,
/// `SET NX EX`, exactly once.
pub const OUTCOME_REGISTER_LUA: &str = include_str!("../resources/outcome_register.lua");

/// The canonical outcome-ledger confirm script (shared verbatim with
/// the legacy store): pending -> L/A exactly once.
pub const OUTCOME_CONFIRM_LUA: &str = include_str!("../resources/outcome_confirm.lua");

/// The canonical outcome-ledger correction script (shared verbatim with
/// the legacy store): flip L <-> A after confirmation.
pub const OUTCOME_CORRECT_LUA: &str = include_str!("../resources/outcome_correct.lua");

/// The canonical target-dimension state script (shared verbatim with the
/// legacy store): the target's leaky failure counter plus its source/asn
/// spread HyperLogLogs, one op per call on the target family's own slot.
pub const TARGET_FAILURE_LUA: &str = include_str!("../resources/target_failure.lua");

/// The scope aggregate id the assessment path maintains: the
/// deployment-wide aggregate. Per-scope ids may be addressed through the
/// same shard key builders ([`crate::keyspace::scope_shard_key`]).
pub const GLOBAL_AGGREGATE_ID: &str = "global";

/// The number of leaked channels an identity script reply carries:
/// rf, rs, iss, bad, mal, rep, af, sw, trust.
const IDENTITY_CHANNELS: usize = 9;

/// The number of leaked channels a scope shard reply carries:
/// rf, rs, iss, bad, mal, rep, af.
const SCOPE_CHANNELS: usize = 7;

/// Knobs of a sharded keyspace store. Every field carries the contract
/// default the legacy store uses; TTLs obey the same positive and
/// bounded rule the legacy constructor enforces.
#[derive(Debug, Clone)]
pub struct ShardedOptions {
    /// The namespace key-version contract (the shared deployment
    /// derivation the legacy store uses).
    pub namespace_version: NamespaceVersion,
    /// Route by the real `CLUSTER SLOTS` topology when true; route by
    /// slot modulo the endpoint list when false (separate redis-server
    /// ports as slot stand-ins).
    pub cluster: bool,
    /// Lazy connections pooled per endpoint (>= 1).
    pub pool_size: usize,
    /// Source/subnet retention (seconds).
    pub state_ttl_secs: u64,
    /// Dedupe marker lifetime (seconds).
    pub dedupe_ttl_secs: u64,
    /// Global level hysteresis window (ms).
    pub hysteresis_ms: u64,
    /// Session state retention (seconds).
    pub session_ttl_secs: u64,
    /// Principal state retention (seconds).
    pub principal_ttl_secs: u64,
    /// Outcome ledger lifetime (seconds).
    pub outcome_ttl_secs: u64,
    /// Long-memory mark lifetime (seconds).
    pub mark_ttl_secs: u64,
    /// Target-dimension retention (seconds): the failure counter and the
    /// spread HyperLogLogs of one target.
    pub target_ttl_secs: u64,
    /// Raw saturations in the legacy argv order.
    pub saturations: [u32; 11],
    /// Connection establishment timeout per endpoint (ms).
    pub connection_timeout_ms: u64,
    /// Per-command read/write timeout (ms).
    pub command_timeout_ms: u64,
}

impl Default for ShardedOptions {
    fn default() -> Self {
        ShardedOptions {
            namespace_version: NamespaceVersion::Legacy,
            cluster: false,
            pool_size: 2,
            state_ttl_secs: 1800,
            dedupe_ttl_secs: 60,
            hysteresis_ms: 60_000,
            session_ttl_secs: 1800,
            principal_ttl_secs: 86_400,
            outcome_ttl_secs: crate::redis::DEFAULT_OUTCOME_TTL_SECS,
            mark_ttl_secs: crate::redis::DEFAULT_MARK_TTL_SECS,
            target_ttl_secs: 86_400,
            saturations: crate::redis::DEFAULT_SATURATIONS,
            connection_timeout_ms: RedisRiskStateStore::CONNECTION_TIMEOUT_MS,
            command_timeout_ms: RedisRiskStateStore::COMMAND_TIMEOUT_MS,
        }
    }
}

/// One routed endpoint: a client plus the same lazy pool the legacy
/// store uses, so eviction semantics stay identical.
struct Endpoint {
    client: redis_crate::Client,
    pool: ConnectionPool,
}

/// One unit of an assessment batch: an endpoint assignment plus the
/// packed command, and (for script calls) the script source that backs
/// the `NOSCRIPT` fallback.
struct BatchUnit {
    endpoint: usize,
    eval: redis_crate::Cmd,
    script: Option<&'static str>,
}

/// The cached merged scope aggregate: the latest known leaked sum of
/// every shard plus the instant the merge batch last ran. Assessments
/// write their own shard's post-apply sum back into the cache, so the
/// written shards stay current while the unwritten ones honor the
/// one-second merge window. Every slot is an independent atomic: the
/// hot path never takes an exclusive lock.
struct MergeCache {
    per_shard: [AtomicI64; 16],
    at_ms: AtomicU64,
    /// The highest merged pressure observed since the last refresh. The
    /// level ratchet runs once per staleness window; a short burst can
    /// peak and leak back below an entry threshold inside that window.
    /// Feeding the ratchet the window's peak keeps the documented
    /// emergency tripwire from missing the burst, at no extra Redis call.
    peak_gp: AtomicI64,
}

impl MergeCache {
    fn empty() -> MergeCache {
        MergeCache {
            per_shard: std::array::from_fn(|_| AtomicI64::new(0)),
            at_ms: AtomicU64::new(0),
            peak_gp: AtomicI64::new(0),
        }
    }

    /// The wall-clock millisecond the merge batch last ran (0 = never).
    fn merged_at_ms(&self) -> u64 {
        self.at_ms.load(Ordering::Acquire)
    }

    /// A point-in-time copy of the 16 shard sums (relaxed loads: each
    /// slot is an independent counter and the staleness window bounds
    /// any skew).
    fn snapshot(&self) -> [i64; 16] {
        std::array::from_fn(|i| self.per_shard[i].load(Ordering::Relaxed))
    }
}

/// Redis-backed [`RiskStateStore`] over the sharded keyspace. See the
/// module documentation for the key map, the batching contract, the
/// staleness contract and the atomicity boundaries.
pub struct ShardedRedisRiskStateStore {
    /// The encoded namespace inside every family tag (the derived value,
    /// never the raw configured discriminator).
    encoded_namespace: String,
    /// The raw configured deployment discriminator this store was built
    /// from.
    raw_namespace: String,
    options: ShardedOptions,
    /// The auxiliary single-key surfaces (ledger, marks, trust, first
    /// seen tags), aimed at the endpoint that owns the shared
    /// `{kiwi:<ns>}` tag.
    legacy: RedisRiskStateStore,
    endpoints: Vec<Endpoint>,
    /// The cluster topology as sorted slot ranges over endpoint indices;
    /// empty when routing is slot modulo the endpoint list.
    ranges: Vec<(u16, u16, usize)>,
    identity_script: Arc<redis_crate::Script>,
    scope_script: Arc<redis_crate::Script>,
    hysteresis_script: Arc<redis_crate::Script>,
    outcome_register_script: Arc<redis_crate::Script>,
    outcome_confirm_script: Arc<redis_crate::Script>,
    outcome_correct_script: Arc<redis_crate::Script>,
    target_script: Arc<redis_crate::Script>,
    merge: MergeCache,
    merge_gate: MergeGate,
    last_global_level: AtomicU8,
    last_cooldown_until_ms: AtomicU64,
}

impl ShardedRedisRiskStateStore {
    /// Builds a sharded store with the contract defaults and claims the
    /// namespace's keyspace mode marker. The URLs are the slot stand-in
    /// servers (stand-in routing: slot modulo the list).
    ///
    /// # Errors
    ///
    /// [`RiskStoreError::KeyspaceModeMismatch`] when the namespace is
    /// marked for the legacy layout; backend errors when the marker
    /// cannot be claimed.
    ///
    /// # Panics
    ///
    /// Panics on the same configuration bounds the legacy store enforces
    /// (empty or brace-carrying namespace, out-of-range TTLs, pool size
    /// 0) and when the endpoint list is empty.
    pub fn new(urls: &[String], namespace: &str) -> Result<Self, RiskStoreError> {
        Self::connect(urls, namespace, ShardedOptions::default())
    }

    /// Builds a sharded store with explicit options. See [`Self::new`]
    /// for the error and panic contract.
    pub fn connect(
        urls: &[String],
        namespace: &str,
        options: ShardedOptions,
    ) -> Result<Self, RiskStoreError> {
        assert!(
            !namespace.is_empty() && !namespace.contains(['{', '}']),
            "Risk namespace must be non-empty and free of braces"
        );
        assert!(
            !urls.is_empty(),
            "the sharded store needs at least one endpoint"
        );
        assert!(options.pool_size >= 1, "pool_size must be >= 1");
        for (knob, value) in [
            ("state_ttl_secs", options.state_ttl_secs),
            ("dedupe_ttl_secs", options.dedupe_ttl_secs),
            ("session_ttl_secs", options.session_ttl_secs),
            ("principal_ttl_secs", options.principal_ttl_secs),
            ("outcome_ttl_secs", options.outcome_ttl_secs),
            ("mark_ttl_secs", options.mark_ttl_secs),
            ("target_ttl_secs", options.target_ttl_secs),
        ] {
            assert!(
                (1..=crate::redis::MAX_TTL_SECS).contains(&value),
                "{knob} must be within 1..={} (got {value})",
                crate::redis::MAX_TTL_SECS,
            );
        }
        assert!(
            options.hysteresis_ms >= 1,
            "hysteresis_ms must be >= 1 (got {})",
            options.hysteresis_ms
        );
        assert!(
            options
                .saturations
                .iter()
                .all(|saturation| *saturation >= 1),
            "saturations must all be positive integers"
        );

        let encoded = crate::namespace::deployment_namespace(namespace, options.namespace_version);

        // Endpoints: the seed list, or the cluster topology resolved
        // from the first seed.
        let mut endpoints: Vec<Endpoint> = Vec::new();
        for url in urls {
            let client = redis_crate::Client::open(url.as_str())
                .map_err(|e| RiskStoreError::BackendUnavailable(e.to_string()))?;
            endpoints.push(Endpoint {
                pool: ConnectionPool::new(
                    options.pool_size,
                    options.connection_timeout_ms,
                    options.command_timeout_ms,
                ),
                client,
            });
        }
        let (endpoints, ranges) = if options.cluster {
            fetch_cluster_topology(&endpoints[0], &options)?
        } else {
            (endpoints, Vec::new())
        };
        let route = |key: &str| endpoint_for_slot(&ranges, endpoints.len(), slot_of(key));

        // The mode marker claim: construction refuses a namespace the
        // other layout already governs (no silent fallback).
        let marker_key = crate::keyspace::mode_marker_key(&encoded);
        let marker_endpoint = &endpoints[route(&marker_key)];
        {
            let mut guard = marker_endpoint.pool.acquire(&marker_endpoint.client)?;
            claim_keyspace_mode(
                guard.as_mut().ok_or_else(|| {
                    RiskStoreError::BackendUnavailable("connection vanished".to_string())
                })?,
                &encoded,
                KeyspaceMode::Sharded,
            )?;
        }

        // The auxiliary single-key surfaces ride an embedded legacy
        // store aimed at the endpoint owning the shared tag, carrying
        // this store's exact knobs.
        let shared_tag = format!("{{kiwi:{encoded}}}");
        let legacy_client = endpoints[route(&shared_tag)].client.clone();
        let legacy = RedisRiskStateStore::with_options(
            legacy_client,
            namespace,
            options.state_ttl_secs,
            options.dedupe_ttl_secs,
            options.hysteresis_ms,
            options.session_ttl_secs,
            options.principal_ttl_secs,
            options.outcome_ttl_secs,
            options.saturations,
        )
        .with_mark_ttl_secs(options.mark_ttl_secs)
        .with_io_timeouts(options.connection_timeout_ms, options.command_timeout_ms);

        Ok(ShardedRedisRiskStateStore {
            encoded_namespace: encoded,
            raw_namespace: namespace.to_string(),
            options,
            legacy,
            endpoints,
            ranges,
            identity_script: Arc::new(redis_crate::Script::new(SHARDED_IDENTITY_LUA)),
            scope_script: Arc::new(redis_crate::Script::new(SHARDED_SCOPE_LUA)),
            hysteresis_script: Arc::new(redis_crate::Script::new(SHARDED_HYSTERESIS_LUA)),
            outcome_register_script: Arc::new(redis_crate::Script::new(OUTCOME_REGISTER_LUA)),
            outcome_confirm_script: Arc::new(redis_crate::Script::new(OUTCOME_CONFIRM_LUA)),
            outcome_correct_script: Arc::new(redis_crate::Script::new(OUTCOME_CORRECT_LUA)),
            target_script: Arc::new(redis_crate::Script::new(TARGET_FAILURE_LUA)),
            merge: MergeCache::empty(),
            merge_gate: MergeGate::default(),
            last_global_level: AtomicU8::new(0),
            last_cooldown_until_ms: AtomicU64::new(0),
        })
    }

    /// The encoded deployment namespace inside the family tags (the
    /// derived value, never the raw configured discriminator).
    pub fn namespace(&self) -> &str {
        &self.encoded_namespace
    }

    /// The raw configured deployment discriminator this store was built
    /// from.
    pub fn raw_namespace(&self) -> &str {
        &self.raw_namespace
    }

    /// The number of routed endpoints (cluster nodes or stand-in
    /// servers).
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    /// The endpoint index that owns a key's cluster slot: the real
    /// topology range when the store routes by `CLUSTER SLOTS`, slot
    /// modulo the endpoint list otherwise (the stand-in rule).
    pub fn endpoint_for_key(&self, key: &str) -> usize {
        endpoint_for_slot(&self.ranges, self.endpoints.len(), slot_of(key))
    }

    /// The merged raw scope pressure, refreshing the merge first when
    /// the staleness window has passed. Diagnostic and test surface for
    /// the staleness contract; the assessment path uses the same cached
    /// value for the global pressure signal and the level transition.
    ///
    /// # Errors
    ///
    /// Backend errors when the merge batch cannot be served.
    pub fn merged_global_pressure(&self) -> Result<i64, RiskStoreError> {
        Ok(self.merged_snapshot()?.iter().sum())
    }

    /// The cached merge age, for tests of the staleness contract.
    #[doc(hidden)]
    pub fn merge_age(&self) -> Option<Duration> {
        let at = self.merge.merged_at_ms();
        if at == 0 {
            return None;
        }
        let now_ms = crate::keyspace::monotonic_ms().max(at);
        Some(Duration::from_millis(now_ms - at))
    }

    /// The last merged global pressure level (0..4) the assessment path
    /// decided on.
    pub fn last_global_level(&self) -> u8 {
        self.last_global_level.load(Ordering::Relaxed)
    }

    /// The cooldown deadline (epoch ms) of the most recent assessment.
    pub fn last_cooldown_until_ms(&self) -> u64 {
        self.last_cooldown_until_ms.load(Ordering::Relaxed)
    }

    /// The merged scope snapshot: refresh through the merge batch when
    /// the window has passed and this caller owns the refresh, else
    /// reuse the cache. The first assessment populates the cache no
    /// matter what, since an empty cache has no value to reuse.
    fn merged_snapshot(&self) -> Result<[i64; 16], RiskStoreError> {
        let cached_at = self.merge.merged_at_ms();
        if cached_at != 0 {
            let now_ms = crate::keyspace::monotonic_ms();
            let elapsed = now_ms.saturating_sub(cached_at);
            if u64::try_from(crate::keyspace::MERGE_STALENESS.as_millis())
                .map(|window| elapsed < window)
                .unwrap_or(true)
            {
                return Ok(self.merge.snapshot());
            }
        }
        if cached_at == 0 || self.merge_gate.start_refresh() {
            let per_shard = self.fetch_merged_gp()?;
            for (shard, sum) in per_shard.iter().enumerate() {
                self.merge.per_shard[shard].store(*sum, Ordering::Relaxed);
            }
            self.merge
                .at_ms
                .store(crate::keyspace::monotonic_ms(), Ordering::Release);
            return Ok(per_shard);
        }
        // Another thread owns this window's refresh and it is about to
        // publish this same instance's cache; reuse the last snapshot,
        // whose age the staleness window bounds.
        Ok(self.merge.snapshot())
    }

    /// Writes one shard's post-apply leaked sum back into the cache:
    /// the written shard is current, the unwritten ones keep honoring
    /// the merge window. A relaxed atomic store: each slot is an
    /// independent counter.
    fn record_shard_sum(&self, shard: u8, sum: i64) {
        self.merge.per_shard[usize::from(shard)].store(sum, Ordering::Relaxed);
        let window_sum: i64 = self.merge.snapshot().iter().sum();
        self.merge.peak_gp.fetch_max(window_sum, Ordering::Relaxed);
    }

    /// The merge batch: one read-only scope invocation per shard (every
    /// shard on its own slot, summed client-side in shard order), then
    /// the single-slot level/cooldown transition on the summed pressure.
    /// The level transition runs here — once per staleness window —
    /// instead of on every assessment: the hot path reuses the published
    /// level/cooldown, so the hysteresis hash is no longer a per-request
    /// single-slot write. Both steps stay bounded (16 reads + one
    /// transition, at most once per second).
    fn fetch_merged_gp(&self) -> Result<[i64; 16], RiskStoreError> {
        let ns = &self.encoded_namespace;
        let mut units = Vec::with_capacity(usize::from(crate::keyspace::SCOPE_SHARDS));
        for shard in 0..crate::keyspace::SCOPE_SHARDS {
            let key = crate::keyspace::scope_shard_key(ns, GLOBAL_AGGREGATE_ID, shard);
            let marker = crate::keyspace::scope_marker_key(ns, GLOBAL_AGGREGATE_ID, shard, "");
            units.push(BatchUnit {
                endpoint: self.endpoint_for_key(&key),
                eval: scope_evalsha(&self.scope_script, &key, &marker, 1, 0, 0, 1, ""),
                script: Some(SHARDED_SCOPE_LUA),
            });
        }
        let replies = self.dispatch(units)?;
        let mut per_shard = [0i64; 16];
        let mut merged_gp = 0i64;
        for (shard, reply) in replies.iter().enumerate() {
            per_shard[shard] = decode_channels(reply, SCOPE_CHANNELS, "scope shard")?
                .iter()
                .sum::<i64>();
            merged_gp += per_shard[shard];
        }
        // The level/cooldown ratchet on the merged pressure, then publish
        // for the hot path. The window's peak feeds the ratchet, then the
        // next window starts from the refreshed merged value.
        let peak_gp = self.merge.peak_gp.swap(merged_gp, Ordering::Relaxed);
        let hysteresis_gp = merged_gp.max(peak_gp);
        let hyst_key = hysteresis_key(ns);
        let mut hyst_eval = redis_crate::cmd("EVALSHA");
        hyst_eval
            .arg(self.hysteresis_script.get_hash())
            .arg(1)
            .arg(&hyst_key)
            .arg(hysteresis_gp)
            .arg(self.options.saturations[8])
            .arg(self.options.hysteresis_ms);
        let replies = self.dispatch(vec![BatchUnit {
            endpoint: self.endpoint_for_key(&hyst_key),
            eval: hyst_eval,
            script: Some(SHARDED_HYSTERESIS_LUA),
        }])?;
        let hyst = decode_channels(&replies[0], 2, "hysteresis transition")?;
        self.last_global_level
            .store(hyst[0].clamp(0, 4) as u8, Ordering::Relaxed);
        self.last_cooldown_until_ms
            .store(hyst[1].max(0) as u64, Ordering::Relaxed);
        Ok(per_shard)
    }

    /// The full sharded assessment: one pipelined batch of per-dimension
    /// scripts on their own slots and the nonce verdict, plus the
    /// consolidated single-key extras on their own families. Absent
    /// dimensions are never read (no zero-id round trips); the level
    /// transition rides the once-per-second merge refresh, not this path.
    fn run_assessment(
        &self,
        o: &RiskObservation,
        context_tag: Option<&str>,
        tls_tag: Option<&str>,
        registration: Option<&OutcomeRegistration>,
    ) -> Result<Assessment, RiskStoreError> {
        RedisRiskStateStore::validate_observation(o)?;
        let ns = &self.encoded_namespace;
        let session_hex = o
            .session_id
            .map(hex::encode)
            .unwrap_or_else(|| "0".repeat(32));
        let principal_hex = o
            .principal_id
            .map(hex::encode)
            .unwrap_or_else(|| "0".repeat(32));
        let session_present = o.session_id.is_some();
        let principal_present = o.principal_id.is_some();

        // The merged aggregate feeds the global pressure signal; the
        // level transition runs inside the merge refresh (at most once
        // per second) and the published level/cooldown is what this
        // assessment reports.
        let snapshot: [i64; 16] = self.merged_snapshot()?;
        // An empty event id (dedupe disabled) has no id bytes to spread;
        // the source pseudonym is the stable fallback so those writes do
        // not all funnel onto fnv1a32("")'s shard.
        let shard_fallback = o.source_id.as_bytes();
        let shard_of_event =
            |event_id: &str| crate::keyspace::scope_shard(event_id, shard_fallback);
        let snapshot_shard = usize::from(shard_of_event(&o.event_id));

        let mut units: Vec<BatchUnit> = Vec::with_capacity(12);
        // Identity units: source ±1 epoch, subnet ±1 epoch always; the
        // session and principal states only when the dimension is present
        // (an absent dimension is not read — no zero-id state hash).
        // Boundary and absent-dimension reads are read-only; the present
        // dimensions carry their own dedupe marker.
        let push_identity = |units: &mut Vec<BatchUnit>,
                             dimension: ShardedDimension,
                             epoch: i64,
                             hex_id: &str,
                             has_write: bool,
                             ttl: u64| {
            let state_key = identity_state_key(ns, dimension, Some(epoch), hex_id);
            units.push(BatchUnit {
                endpoint: self.endpoint_for_key(&state_key),
                eval: identity_evalsha(
                    &self.identity_script,
                    &state_key,
                    &identity_marker_key(ns, dimension, hex_id, &o.event_id),
                    o,
                    dimension,
                    has_write,
                    self.options.dedupe_ttl_secs,
                    ttl,
                ),
                script: Some(SHARDED_IDENTITY_LUA),
            });
        };
        push_identity(
            &mut units,
            ShardedDimension::Source,
            o.source_epoch.saturating_sub(1),
            &o.source_id_prev,
            false,
            self.options.state_ttl_secs,
        );
        push_identity(
            &mut units,
            ShardedDimension::Source,
            o.source_epoch,
            &o.source_id,
            true,
            self.options.state_ttl_secs,
        );
        push_identity(
            &mut units,
            ShardedDimension::Source,
            o.source_epoch.saturating_add(1),
            &o.source_id_next,
            false,
            self.options.state_ttl_secs,
        );
        push_identity(
            &mut units,
            ShardedDimension::Subnet,
            o.subnet_epoch.saturating_sub(1),
            &o.subnet_id_prev,
            false,
            self.options.state_ttl_secs,
        );
        push_identity(
            &mut units,
            ShardedDimension::Subnet,
            o.subnet_epoch,
            &o.subnet_id,
            true,
            self.options.state_ttl_secs,
        );
        push_identity(
            &mut units,
            ShardedDimension::Subnet,
            o.subnet_epoch.saturating_add(1),
            &o.subnet_id_next,
            false,
            self.options.state_ttl_secs,
        );
        if session_present {
            push_identity(
                &mut units,
                ShardedDimension::Session,
                0,
                &session_hex,
                true,
                self.options.session_ttl_secs,
            );
        }
        if principal_present {
            push_identity(
                &mut units,
                ShardedDimension::Principal,
                0,
                &principal_hex,
                true,
                self.options.principal_ttl_secs,
            );
        }

        // The event's scope shard: one of the 16 sharded counters,
        // chosen by fnv1a over the event id (or the source fallback).
        let shard = shard_of_event(&o.event_id);
        let shard_key = crate::keyspace::scope_shard_key(ns, GLOBAL_AGGREGATE_ID, shard);
        let shard_marker =
            crate::keyspace::scope_marker_key(ns, GLOBAL_AGGREGATE_ID, shard, &o.event_id);
        units.push(BatchUnit {
            endpoint: self.endpoint_for_key(&shard_key),
            eval: scope_evalsha(
                &self.scope_script,
                &shard_key,
                &shard_marker,
                o.event.as_u8(),
                o.scope,
                1,
                self.options.dedupe_ttl_secs,
                &o.event_id,
            ),
            script: Some(SHARDED_SCOPE_LUA),
        });

        // The nonce-family verdict: one SET NX EX, the assessment-level
        // duplicate semantics of the legacy dedupe key.
        let nonce_key = crate::keyspace::nonce_dedupe_key(ns, &o.event_id);
        let has_nonce = !o.event_id.is_empty();
        if has_nonce {
            let mut set = redis_crate::cmd("SET");
            set.arg(&nonce_key)
                .arg("1")
                .arg("NX")
                .arg("EX")
                .arg(self.options.dedupe_ttl_secs);
            units.push(BatchUnit {
                endpoint: self.endpoint_for_key(&nonce_key),
                eval: set,
                script: None,
            });
        }

        // The consolidated extras on the session/decision families: the
        // first-seen tag records (SET NX + GET on the session
        // pseudonym's own slot, one round trip — the GET resolves the
        // first-write race) and the optional ledger registration (its
        // own phase below). A tag that is not presented is not read at
        // all: assess_v2 reports '' for it.
        let ctx_key = crate::keyspace::session_tag_key(ns, "ctx", &session_hex);
        let tls_key = crate::keyspace::session_tag_key(ns, "tls", &session_hex);
        for (key, presented) in [(&ctx_key, context_tag), (&tls_key, tls_tag)] {
            if let Some(tag) = presented.filter(|tag| !tag.is_empty()) {
                let mut set = redis_crate::cmd("SET");
                set.arg(key.as_str())
                    .arg(tag)
                    .arg("NX")
                    .arg("EX")
                    .arg(self.options.session_ttl_secs);
                units.push(BatchUnit {
                    endpoint: self.endpoint_for_key(key),
                    eval: set,
                    script: None,
                });
                let mut get = redis_crate::cmd("GET");
                get.arg(key.as_str());
                units.push(BatchUnit {
                    endpoint: self.endpoint_for_key(key),
                    eval: get,
                    script: None,
                });
            }
        }

        // The target dimension (target-account protection): a read-only
        // invocation on the target family's own slot returns the
        // leak-decayed failure count and the two spread cardinalities
        // with the main batch's round trip. The failure write (an
        // AuthenticationFailure observation) runs as the batch's second
        // phase, once the nonce verdict is known — the canonical
        // target_failure.lua owns the same state the outcome bridge
        // writes, and the ledger score reacts to the returned counts.
        let target_id = registration.and_then(|reg| reg.target_id.as_deref());
        let target_id = target_id.filter(|id| !id.is_empty());
        if let Some(target) = target_id {
            // The read is keyed exactly like the fail op, so the slot
            // map never shifts between the assessment's read and the
            // outcome bridge's write; the marker key rides along
            // untouched.
            let mut keys =
                crate::keyspace::target_state_keys(ns, target, KeyspaceMode::Sharded).to_vec();
            keys.push(crate::keyspace::target_failure_marker_key(
                ns,
                target,
                "unused",
                KeyspaceMode::Sharded,
            ));
            units.push(BatchUnit {
                endpoint: self.endpoint_for_key(&keys[0]),
                eval: target_evalsha(
                    &self.target_script,
                    &keys,
                    "read",
                    "",
                    "",
                    self.options.target_ttl_secs,
                    "",
                    self.options.dedupe_ttl_secs,
                ),
                script: Some(TARGET_FAILURE_LUA),
            });
        }
        let replies = self.dispatch(units)?;
        let mut it = replies.into_iter();
        let mut assessment = Assessment::decode(
            &mut it,
            o,
            &snapshot,
            snapshot_shard,
            &self.options,
            has_nonce,
            context_tag,
            tls_tag,
        )?;
        // The target read's reply rides the main batch when a target is
        // addressed: {fails, spread_sources, spread_asns, first_ms,
        // last_ms} of the leak-decayed state.
        let mut target_state: Option<TargetCounts> = if target_id.is_some() {
            let reply = it
                .next()
                .ok_or_else(|| RiskStoreError::ScriptError("missing target reply".to_string()))?;
            let channels = decode_channels(&reply, 5, "target state")?;
            Some(TargetCounts {
                fails: channels[0].max(0) as u32,
                spread_sources: channels[1].max(0) as u32,
                spread_asns: channels[2].max(0) as u32,
            })
        } else {
            None
        };
        // The failure write: an AuthenticationFailure observation against
        // the target records one failure (leaky counter + spread PFADDs)
        // unless the event id is a duplicate — the same rule the
        // consolidated legacy script applies inside its atomic block.
        if let Some(target) = target_id {
            let records_failure = o.event.as_u8() == 11 && !assessment.is_duplicate;
            let (op, source_element, asn_element) = match registration {
                Some(reg) if records_failure => (
                    "fail",
                    reg.target_source_element.as_str(),
                    reg.target_asn_element.as_str(),
                ),
                _ => ("read", "", ""),
            };
            if records_failure {
                let mut keys =
                    crate::keyspace::target_state_keys(ns, target, KeyspaceMode::Sharded).to_vec();
                // The report event id rides the same per-report marker
                // target_failure.lua maintains, so a report delivered
                // through both the assessment and the outcome bridge
                // books one failure.
                keys.push(crate::keyspace::target_failure_marker_key(
                    ns,
                    target,
                    &o.event_id,
                    KeyspaceMode::Sharded,
                ));
                let mut eval = redis_crate::cmd("EVALSHA");
                eval.arg(self.target_script.get_hash())
                    .arg(4)
                    .arg(&keys[0])
                    .arg(&keys[1])
                    .arg(&keys[2])
                    .arg(&keys[3])
                    .arg(op)
                    .arg(source_element)
                    .arg(asn_element)
                    .arg(self.options.target_ttl_secs)
                    .arg(o.event_id.as_str())
                    .arg(self.options.dedupe_ttl_secs);
                let replies = self.dispatch(vec![BatchUnit {
                    endpoint: self.endpoint_for_key(&keys[0]),
                    eval,
                    script: Some(TARGET_FAILURE_LUA),
                }])?;
                let channels = decode_channels(&replies[0], 5, "target failure")?;
                target_state = Some(TargetCounts {
                    fails: channels[0].max(0) as u32,
                    spread_sources: channels[1].max(0) as u32,
                    spread_asns: channels[2].max(0) as u32,
                });
            }
        }
        if let Some(counts) = target_state {
            assessment.target_failures = counts.fails;
            assessment.target_spread_sources = counts.spread_sources;
            assessment.target_spread_asns = counts.spread_asns;
        }
        self.record_shard_sum(shard, assessment.shard_sum);
        assessment.global_level = self.last_global_level();
        assessment.cooldown_until_ms = self.last_cooldown_until_ms();
        if let Some(reg) = registration {
            // The ledger score is computed client-side from the decoded
            // vector and tags (the exact assess_v2 formula), so the
            // canonical registration script runs as the batch's second
            // phase on the decision-id key family. It is a SET NX on the
            // decision id: a retry of a batch whose first phase committed
            // stays idempotent.
            let ledger_key = crate::keyspace::outcome_ledger_key(ns, &reg.decision_id);
            let score = ledger_score(o, &assessment, context_tag, tls_tag, reg);
            let mut eval = redis_crate::cmd("EVALSHA");
            eval.arg(self.outcome_register_script.get_hash())
                .arg(1)
                .arg(&ledger_key)
                .arg(o.scope.to_string())
                .arg(reg.decision_hour.to_string())
                .arg(score.to_string())
                .arg(self.options.outcome_ttl_secs.to_string());
            let replies = self.dispatch(vec![BatchUnit {
                endpoint: self.endpoint_for_key(&ledger_key),
                eval,
                script: Some(OUTCOME_REGISTER_LUA),
            }])?;
            assessment.registration_status = matches!(
                replies.first(),
                Some(redis_crate::Value::Int(created)) if *created != 0
            ) || matches!(
                replies.first(),
                Some(redis_crate::Value::BulkString(b)) if b.as_slice() == b"1"
            );
        }

        Ok(assessment)
    }

    /// One canonical target_failure.lua op on the target family's own
    /// slot (the read the consolidated assessment reuses): op is one of
    /// `fail`, `clear`, `read`, with the source/asn spread elements
    /// PFADDed on the fail path.
    fn run_target_op(
        &self,
        op: &str,
        target_id: &str,
        source: &str,
        asn: &str,
        event_id: &str,
    ) -> Result<TargetState, RiskStoreError> {
        if !RedisRiskStateStore::valid_key_component(target_id) {
            return Err(RiskStoreError::InvalidIdentifier(format!(
                "target_id is not a safe Redis key component (got 0x{})",
                hex::encode(target_id)
            )));
        }
        if !event_id.is_empty() && !RedisRiskStateStore::valid_key_component(event_id) {
            return Err(RiskStoreError::InvalidIdentifier(
                "event_id is not a safe Redis key component".to_string(),
            ));
        }
        let mut keys = crate::keyspace::target_state_keys(
            &self.encoded_namespace,
            target_id,
            KeyspaceMode::Sharded,
        )
        .to_vec();
        keys.push(crate::keyspace::target_failure_marker_key(
            &self.encoded_namespace,
            target_id,
            if event_id.is_empty() {
                "unused"
            } else {
                event_id
            },
            KeyspaceMode::Sharded,
        ));
        let replies = self.dispatch(vec![BatchUnit {
            endpoint: self.endpoint_for_key(&keys[0]),
            eval: target_evalsha(
                &self.target_script,
                &keys,
                op,
                source,
                asn,
                self.options.target_ttl_secs,
                event_id,
                self.options.dedupe_ttl_secs,
            ),
            script: Some(TARGET_FAILURE_LUA),
        }])?;
        let channels = decode_channels(&replies[0], 5, "target state")?;
        Ok(TargetState {
            fails: channels[0].clamp(0, i64::from(u32::MAX)) as u32,
            spread_sources: channels[1].clamp(0, i64::from(u32::MAX)) as u32,
            spread_asns: channels[2].clamp(0, i64::from(u32::MAX)) as u32,
            first_ms: channels[3],
            last_ms: channels[4],
        })
    }

    /// Dispatches one pipelined batch: the units are grouped by
    /// endpoint, every group is written before any reply is read, and
    /// the read phase drains each group in submission order. Any failure
    /// evicts every endpoint's pool slot that took part, because a batch
    /// interrupted mid-read leaves unread replies on the socket; the
    /// committed slot groups stay covered by their dedupe markers, so a
    /// retry cannot double-count them.
    fn dispatch(&self, units: Vec<BatchUnit>) -> Result<Vec<redis_crate::Value>, RiskStoreError> {
        // Group the unit indices by endpoint across the whole batch: one
        // pool slot per endpoint per dispatch, in first-seen order, so
        // the send phase holds exactly one connection per endpoint (a
        // second slot on an already-held endpoint would self-deadlock a
        // single-threaded caller once the pool ran dry).
        let mut grouped: Vec<(usize, Vec<usize>)> = Vec::new();
        for (index, unit) in units.iter().enumerate() {
            match grouped
                .iter_mut()
                .find(|(endpoint, _)| *endpoint == unit.endpoint)
            {
                Some((_endpoint, indices)) => indices.push(index),
                None => grouped.push((unit.endpoint, vec![index])),
            }
        }

        let (mut replies, script_retries) = {
            let mut guards: Vec<MutexGuard<'_, Option<redis_crate::Connection>>> =
                Vec::with_capacity(grouped.len());
            let result = self.dispatch_phases(&units, &grouped, &mut guards);
            match result {
                Ok(parts) => parts,
                Err(e) => {
                    // A failed batch leaves unread replies on every
                    // connection that took part; evict all of them (the
                    // same poison rule the legacy pool applies per
                    // command).
                    for guard in guards.iter_mut() {
                        **guard = None;
                    }
                    return Err(e);
                }
            }
            // The guards drop at the end of this block, before the script
            // retries below: a retry acquires its own pool slot, and the
            // round-robin could otherwise land on a slot the batch still
            // holds.
        };
        for index in script_retries {
            let unit = &units[index];
            let endpoint = &self.endpoints[unit.endpoint];
            let script = unit.script.expect("retry units carry their script");
            replies[index] = endpoint.pool.with_connection(&endpoint.client, |conn| {
                use redis_crate::ConnectionLike;
                let mut load = redis_crate::cmd("SCRIPT");
                load.arg("LOAD").arg(script);
                conn.req_command(&load)?;
                conn.req_command(&unit.eval)
            })?;
        }
        Ok(replies)
    }

    /// The two batch phases: send every group, then drain every group.
    /// Returns the replies plus the unit indices whose script calls hit
    /// a NOSCRIPT miss (the caller retries them after the guards drop).
    fn dispatch_phases<'a>(
        &'a self,
        units: &[BatchUnit],
        groups: &[(usize, Vec<usize>)],
        guards: &mut Vec<MutexGuard<'a, Option<redis_crate::Connection>>>,
    ) -> Result<(Vec<redis_crate::Value>, Vec<usize>), RiskStoreError> {
        // Send phase: one pooled connection per group, every command
        // written before the first reply is read. The group's commands
        // are packed into ONE write (a command stream the server parses
        // exactly like sequential writes), so the client's syscall cost
        // is one send per touched slot group.
        for (endpoint, indices) in groups {
            let ep = &self.endpoints[*endpoint];
            let mut guard = ep.pool.acquire(&ep.client)?;
            let mut packed: Vec<u8> = Vec::new();
            for &index in indices {
                packed.extend_from_slice(&units[index].eval.get_packed_command());
            }
            guard
                .as_mut()
                .ok_or_else(|| {
                    RiskStoreError::BackendUnavailable("connection vanished".to_string())
                })
                .and_then(|conn| conn.send_packed_command(&packed).map_err(map_redis_error))?;
            guards.push(guard);
        }

        // Read phase: drain each group's replies in order. Server error
        // replies surface as `Value::ServerError` on this raw path. A
        // NOSCRIPT cache miss is retried only after the batch has been
        // fully drained: the reload's replies would otherwise read the
        // still-queued replies of the commands before it.
        let mut replies: Vec<redis_crate::Value> = vec![redis_crate::Value::Nil; units.len()];
        let mut script_retries: Vec<usize> = Vec::new();
        for (group_index, (_endpoint, indices)) in groups.iter().enumerate() {
            for &index in indices {
                let unit = &units[index];
                let guard = &mut guards[group_index];
                let value = guard
                    .as_mut()
                    .ok_or_else(|| {
                        RiskStoreError::BackendUnavailable("connection vanished".to_string())
                    })
                    .and_then(|conn| conn.recv_response().map_err(map_redis_error))?;
                if let redis_crate::Value::ServerError(server_error) = &value {
                    if server_error.code() == "NOSCRIPT" && unit.script.is_some() {
                        script_retries.push(index);
                        continue;
                    }
                    return Err(RiskStoreError::ScriptError(format!(
                        "redis reply error: {} {}",
                        server_error.code(),
                        server_error.details().unwrap_or("")
                    )));
                }
                replies[index] = value;
            }
        }
        Ok((replies, script_retries))
    }
}

/// Builds the identity dimension `EVALSHA` invocation. Argv order is the
/// sharded_identity.lua contract: event, scope, dimension, has_write,
/// dedupe ttl, event id, state ttl.
#[allow(clippy::too_many_arguments)]
fn identity_evalsha(
    script: &redis_crate::Script,
    state_key: &str,
    marker_key: &str,
    o: &RiskObservation,
    dimension: ShardedDimension,
    has_write: bool,
    dedupe_ttl_secs: u64,
    state_ttl_secs: u64,
) -> redis_crate::Cmd {
    let mut eval = redis_crate::cmd("EVALSHA");
    eval.arg(script.get_hash())
        .arg(2)
        .arg(state_key)
        .arg(marker_key)
        .arg(o.event.as_u8())
        .arg(o.scope)
        .arg(dimension.as_u8())
        .arg(u8::from(has_write))
        .arg(dedupe_ttl_secs)
        .arg(o.event_id.as_str())
        .arg(state_ttl_secs);
    eval
}

/// Builds the scope shard `EVALSHA` invocation. Argv order is the
/// sharded_scope.lua contract: event, scope, has_write, dedupe ttl,
/// event id. The merge pass uses event 1, scope 0, has_write 0.
#[allow(clippy::too_many_arguments)]
fn scope_evalsha(
    script: &redis_crate::Script,
    shard_key: &str,
    marker_key: &str,
    event: u8,
    scope: u32,
    has_write: u8,
    dedupe_ttl_secs: u64,
    event_id: &str,
) -> redis_crate::Cmd {
    let mut eval = redis_crate::cmd("EVALSHA");
    eval.arg(script.get_hash())
        .arg(2)
        .arg(shard_key)
        .arg(marker_key)
        .arg(event)
        .arg(scope)
        .arg(has_write)
        .arg(dedupe_ttl_secs)
        .arg(event_id);
    eval
}

/// The decoded target-dimension counts of one assessment: the
/// leak-decayed failure count plus the two separate spread
/// cardinalities (sources and ASNs, never summed).
#[derive(Debug, Clone, Copy, Default)]
struct TargetCounts {
    fails: u32,
    spread_sources: u32,
    spread_asns: u32,
}

/// Builds the target-dimension `EVALSHA` invocation (the
/// target_failure.lua contract): three family keys, then op, the two
/// spread elements and the state TTL.
//
// The arity is the script's own argv shape, one parameter per wire
// field, which keeps the call sites readable and the wire order visible;
// the same allowance the neighbouring sharded helpers carry.
#[allow(clippy::too_many_arguments)]
fn target_evalsha(
    script: &redis_crate::Script,
    keys: &[String],
    op: &str,
    source_element: &str,
    asn_element: &str,
    target_ttl_secs: u64,
    event_id: &str,
    dedupe_ttl_secs: u64,
) -> redis_crate::Cmd {
    let mut eval = redis_crate::cmd("EVALSHA");
    eval.arg(script.get_hash()).arg(keys.len());
    for key in keys {
        eval.arg(key);
    }
    eval.arg(op)
        .arg(source_element)
        .arg(asn_element)
        .arg(target_ttl_secs)
        .arg(event_id)
        .arg(dedupe_ttl_secs);
    eval
}

/// The assembled result of one sharded assessment.
struct Assessment {
    vector: SignalVector,
    global_level: u8,
    cooldown_until_ms: u64,
    is_duplicate: bool,
    existing_context_tag: Option<String>,
    existing_tls_tag: Option<String>,
    registration_status: bool,
    target_failures: u32,
    target_spread_sources: u32,
    target_spread_asns: u32,
    /// The post-apply leaked sum of the event's own scope shard, written
    /// back into the merge cache.
    shard_sum: i64,
}

impl Assessment {
    /// Decodes the batch replies in submission order and assembles the
    /// risk-v1 aggregation client-side: rotated-epoch pseudonyms of one
    /// dimension SUM (the replies carry the leaked channels), identity
    /// dimensions MAX, every channel normalizes with the saturation the
    /// legacy script divides by. The level/cooldown are the published
    /// values of the merge refresh (the transition no longer rides the
    /// assessment batch).
    #[allow(clippy::too_many_arguments)]
    fn decode(
        it: &mut std::vec::IntoIter<redis_crate::Value>,
        o: &RiskObservation,
        snapshot: &[i64],
        snapshot_shard: usize,
        options: &ShardedOptions,
        has_nonce: bool,
        context_tag: Option<&str>,
        tls_tag: Option<&str>,
    ) -> Result<Assessment, RiskStoreError> {
        let next_channels = |it: &mut std::vec::IntoIter<redis_crate::Value>,
                             width: usize,
                             what: &'static str|
         -> Result<Vec<i64>, RiskStoreError> {
            let reply = it
                .next()
                .ok_or_else(|| RiskStoreError::ScriptError(format!("missing {what} reply")))?;
            decode_channels(&reply, width, what)
        };
        let src_prev = next_channels(it, IDENTITY_CHANNELS, "source boundary")?;
        let src_cur = next_channels(it, IDENTITY_CHANNELS, "source state")?;
        let src_next = next_channels(it, IDENTITY_CHANNELS, "source boundary")?;
        let net_prev = next_channels(it, IDENTITY_CHANNELS, "subnet boundary")?;
        let net_cur = next_channels(it, IDENTITY_CHANNELS, "subnet state")?;
        let net_next = next_channels(it, IDENTITY_CHANNELS, "subnet boundary")?;
        // Absent dimensions were never read: their channels are zero.
        let zeros = vec![0i64; IDENTITY_CHANNELS];
        let sess = if o.session_id.is_some() {
            next_channels(it, IDENTITY_CHANNELS, "session state")?
        } else {
            zeros.clone()
        };
        let prin = if o.principal_id.is_some() {
            next_channels(it, IDENTITY_CHANNELS, "principal state")?
        } else {
            zeros
        };
        let shard_channels = next_channels(it, SCOPE_CHANNELS, "scope shard")?;
        let shard_sum: i64 = shard_channels.iter().sum();
        // The event's own shard contribution is exact: the fresh merged
        // pressure replaces the snapshot's stale entry for this shard
        // with the post-apply value the script just returned.
        let merged_gp = snapshot.iter().sum::<i64>()
            - snapshot.get(snapshot_shard).copied().unwrap_or(0)
            + shard_sum;
        let is_duplicate = if has_nonce {
            match it.next() {
                Some(redis_crate::Value::Nil) => true,
                Some(_) => false,
                None => {
                    return Err(RiskStoreError::ScriptError(
                        "missing nonce dedupe reply".to_string(),
                    ))
                }
            }
        } else {
            false
        };

        // First-seen tag records: the SET reply (when the tag was
        // presented) wins; its Nil miss falls back to the GET reply.
        let read_tag = |it: &mut std::vec::IntoIter<redis_crate::Value>,
                        presented: Option<&str>,
                        what: &'static str|
         -> Result<Option<String>, RiskStoreError> {
            let write_attempted = matches!(presented, Some(tag) if !tag.is_empty());
            if !write_attempted {
                // Nothing presented, nothing read (assess_v2 parity: the
                // existing value is reported as absent).
                return Ok(None);
            }
            let set_reply = it
                .next()
                .ok_or_else(|| RiskStoreError::ScriptError(format!("missing {what} reply")))?;
            if set_reply == redis_crate::Value::Okay {
                // Consume the trailing GET; the successful write already
                // carries the recorded value.
                let _ = it.next();
                return Ok(presented.map(str::to_string));
            }
            match it.next() {
                Some(redis_crate::Value::Nil) => Ok(None),
                Some(redis_crate::Value::BulkString(b)) => {
                    Ok(Some(String::from_utf8_lossy(&b).into_owned()))
                }
                Some(_) => Err(RiskStoreError::ScriptError(format!(
                    "risk script returned a non-string tag slot for {what}"
                ))),
                None => Err(RiskStoreError::ScriptError(format!("missing {what} reply"))),
            }
        };
        let existing_context_tag = read_tag(it, context_tag, "client-context tag")?;
        let existing_tls_tag = read_tag(it, tls_tag, "TLS tag")?;

        let sat = &options.saturations;
        let sum = |parts: &[&Vec<i64>], index: usize| -> i64 {
            parts.iter().map(|part| part[index]).sum()
        };
        let maxn = |values: &[i64]| -> i64 { values.iter().copied().max().unwrap_or(0) };
        let src = [&src_prev, &src_cur, &src_next];
        let net = [&net_prev, &net_cur, &net_next];
        let src_rf = sum(&src, 0);
        let src_rs = sum(&src, 1);
        let src_iss = sum(&src, 2);
        let src_bad = sum(&src, 3);
        let src_mal = sum(&src, 4);
        let src_rep = sum(&src, 5);
        let src_af = sum(&src, 6);
        let src_sw = sum(&src, 7);
        let src_trust = sum(&src, 8);
        let net_rf = sum(&net, 0);

        Ok(Assessment {
            vector: SignalVector {
                source_fast: normalize(maxn(&[src_rf, sess[0], 0]), sat[0]),
                source_slow: normalize(maxn(&[src_rs, sess[1], 0]), sat[1]),
                subnet_fast: normalize(net_rf, sat[0]),
                issue_debt: normalize(maxn(&[src_iss, sess[2], 0]), sat[2]),
                bad_proof: normalize(maxn(&[src_bad, sess[3], prin[3], 0]), sat[3]),
                malformed: normalize(maxn(&[src_mal, sess[4], prin[4], 0]), sat[4]),
                replay: normalize(maxn(&[src_rep, sess[5], 0]), sat[5]),
                action_failure: normalize(maxn(&[src_af, sess[6], prin[6], 0]), sat[6]),
                scope_switch: normalize(maxn(&[src_sw, sess[7], 0]), sat[7]),
                global_pressure: normalize(merged_gp, sat[8]),
                network_risk: o.network_risk,
                trust_credit: normalize(maxn(&[src_trust, sess[8], 0]), sat[9]),
                principal_credit: normalize(prin[8], sat[10]),
            },
            // The published merge-refresh values (the transition is no
            // longer run per assessment).
            global_level: 0,
            cooldown_until_ms: 0,
            is_duplicate,
            existing_context_tag,
            existing_tls_tag,
            registration_status: false,
            // The target dimension's decoded counts: the read-only
            // target_failure.lua invocation rides the main batch (its
            // own family slot) and a failure observation re-reads the
            // state after the atomic fail op.
            target_failures: 0,
            target_spread_sources: 0,
            target_spread_asns: 0,
            shard_sum,
        })
    }
}

/// The consolidated ledger score, computed from the decoded vector and
/// tags with the exact assess_v2.lua formula: base plus the weighted
/// signals (global pressure zeroed for the ledger when the feature flag
/// is off), clamped, then the weighted risk-v2 evidence factors added,
/// clamped again. The honeypot-derived event kinds 18..20 count as a
/// honeypot hit; a recorded first tag that differs from the presented
/// one counts as an inconsistency, an empty presented tag against a
/// recorded one included.
fn ledger_score(
    o: &RiskObservation,
    assessment: &Assessment,
    context_tag: Option<&str>,
    tls_tag: Option<&str>,
    registration: &OutcomeRegistration,
) -> u16 {
    use crate::score::{score as score_v1, weighted};

    let mut ledger_vector = assessment.vector;
    if !registration.global_pressure_enabled {
        ledger_vector.global_pressure = 0;
    }
    let mut risk = u32::from(score_v1(
        registration.base_risk,
        &ledger_vector,
        &registration.v1_weights,
    ));
    let honeypot: u16 = if registration.honeypot_hit || (18..=20).contains(&o.event.as_u8()) {
        1000
    } else {
        0
    };
    let presented_ctx = context_tag.unwrap_or("");
    let presented_tls = tls_tag.unwrap_or("");
    let session_inconsistency: u16 = match &assessment.existing_context_tag {
        Some(existing) if !existing.is_empty() && existing != presented_ctx => 1000,
        _ => 0,
    };
    let tls_inconsistency: u16 = match &assessment.existing_tls_tag {
        Some(existing) if !existing.is_empty() && existing != presented_tls => 1000,
        _ => 0,
    };
    risk += weighted(honeypot, registration.v2_weights.honeypot);
    risk += weighted(
        session_inconsistency,
        registration.v2_weights.session_inconsistency,
    );
    risk += weighted(tls_inconsistency, registration.v2_weights.tls);
    // Target-account pressure and spread: five failures or twenty
    // distinct sources saturate at 1000, matching the engine's target
    // helpers and the consolidated legacy script. The scored spread is
    // the wider of the two dimensions (never the sum: sources+asns
    // would double-count one campaign's growth).
    risk += weighted(
        crate::target_pressure_signal(assessment.target_failures),
        registration.v2_weights.target_failure_pressure,
    );
    risk += weighted(
        crate::target_spread_signal(
            assessment
                .target_spread_sources
                .max(assessment.target_spread_asns),
        ),
        registration.v2_weights.target_spread,
    );
    risk.min(1000) as u16
}

/// Decodes one script reply into exactly `width` integer channels, the
/// same fail-closed rule the legacy typed decode gives (an integer or a
/// parseable string per slot, everything else refused).
fn decode_channels(
    value: &redis_crate::Value,
    width: usize,
    what: &'static str,
) -> Result<Vec<i64>, RiskStoreError> {
    let elements = match value {
        redis_crate::Value::Array(elements) => elements,
        other => {
            return Err(RiskStoreError::ScriptError(format!(
                "risk script returned a non-array {what} reply: {other:?}"
            )))
        }
    };
    if elements.len() < width {
        return Err(RiskStoreError::ScriptError(format!(
            "risk script returned a short {what} reply ({} values)",
            elements.len()
        )));
    }
    elements[..width].iter().map(value_i64).collect()
}

/// The client-side normalize: `floor(v * 1000 / sat)` capped at 1000,
/// zero for a zero saturation, identical to the legacy Lua.
fn normalize(value: i64, saturation: u32) -> u16 {
    if saturation == 0 {
        return 0;
    }
    (value * 1000 / i64::from(saturation)).clamp(0, 1000) as u16
}

/// The outcomes plane's marks surface over the sharded store: the marks
/// keys are mode-insensitive (the shared `{kiwi:<ns>}` tag), the live
/// target-dimension state rides the target family's own slot through the
/// sharded dispatch. This is what lets the typed outcomes facade and the
/// marks stage serve a sharded deployment without an extra store.
impl crate::outcomes::OutcomeMarksStore for ShardedRedisRiskStateStore {
    fn mark_key(&self, dimension: &str, id: &str) -> Result<String, crate::RiskError> {
        self.legacy
            .mark_key(dimension, id)
            .map_err(|e| crate::RiskError::Store(e.to_string()))
    }

    fn write_mark(
        &self,
        dimension: &str,
        id: &str,
        kind: &str,
        now_ms: u64,
        event_id: &str,
    ) -> Result<i64, crate::RiskError> {
        self.legacy
            .write_mark(dimension, id, kind, now_ms, event_id)
            .map_err(|e| crate::RiskError::Store(e.to_string()))
    }

    fn read_mark(
        &self,
        dimension: &str,
        id: &str,
    ) -> Result<Option<crate::outcomes::MarkRecord>, crate::RiskError> {
        self.legacy
            .read_mark(dimension, id)
            .map_err(|e| crate::RiskError::Store(e.to_string()))
    }

    fn forget_marks(&self, dimension: &str, id: &str) -> Result<u32, crate::RiskError> {
        self.legacy
            .forget_marks(dimension, id)
            .map_err(|e| crate::RiskError::Store(e.to_string()))
    }

    fn read_target_state(
        &self,
        target_id: &str,
    ) -> Result<crate::store::TargetState, crate::RiskError> {
        RiskStateStore::read_target_state(self, target_id)
            .map_err(|e| crate::RiskError::Store(e.to_string()))
    }
}

/// The endpoint index owning a slot: the real topology range when
/// present, slot modulo the endpoint list otherwise (the stand-in rule).
fn endpoint_for_slot(ranges: &[(u16, u16, usize)], endpoint_count: usize, slot: u16) -> usize {
    if ranges.is_empty() {
        return usize::from(slot) % endpoint_count.max(1);
    }
    for (start, end, endpoint) in ranges {
        if slot >= *start && slot <= *end {
            return *endpoint;
        }
    }
    0
}

/// The cluster slot of a key (`CRC-16` of the hash tag, masked), through
/// the shared implementation.
fn slot_of(key: &str) -> u16 {
    crate::keyspace::slot_of(key)
}

/// The cluster topology: one endpoint per primary plus its slot ranges.
type ClusterTopology = (Vec<Endpoint>, Vec<(u16, u16, usize)>);

/// Resolves the real cluster topology from one seed node: the primary
/// endpoints of every slot range, plus the sorted range table. Replica
/// rows are ignored (assessments write; routing follows primaries).
fn fetch_cluster_topology(
    seed: &Endpoint,
    options: &ShardedOptions,
) -> Result<ClusterTopology, RiskStoreError> {
    let mut guard = seed.pool.acquire(&seed.client)?;
    let conn = guard
        .as_mut()
        .ok_or_else(|| RiskStoreError::BackendUnavailable("connection vanished".to_string()))?;
    let reply: redis_crate::Value = redis_crate::cmd("CLUSTER")
        .arg("SLOTS")
        .query(conn)
        .map_err(map_redis_error)?;
    let rows = match reply {
        redis_crate::Value::Array(rows) => rows,
        _ => {
            return Err(RiskStoreError::BackendUnavailable(
                "CLUSTER SLOTS did not return a topology array".to_string(),
            ))
        }
    };
    let mut hosts: Vec<String> = Vec::new();
    let mut ranges: Vec<(u16, u16, usize)> = Vec::new();
    for row in &rows {
        let cells = match row {
            redis_crate::Value::Array(cells) if cells.len() >= 3 => cells,
            _ => continue,
        };
        let Ok(start) = value_i64(&cells[0]) else {
            continue;
        };
        let Ok(end) = value_i64(&cells[1]) else {
            continue;
        };
        if !(0..=16383).contains(&start) || !(0..=16383).contains(&end) {
            continue;
        }
        let node = match &cells[2] {
            redis_crate::Value::Array(node) if node.len() >= 2 => node,
            _ => continue,
        };
        let host = match &node[0] {
            redis_crate::Value::BulkString(b) => String::from_utf8_lossy(b).into_owned(),
            _ => continue,
        };
        let Ok(port) = value_i64(&node[1]) else {
            continue;
        };
        if port <= 0 {
            continue;
        }
        let url = format!("redis://{host}:{port}/");
        let index = match hosts.iter().position(|existing| *existing == url) {
            Some(index) => index,
            None => {
                hosts.push(url);
                hosts.len() - 1
            }
        };
        ranges.push((start as u16, end as u16, index));
    }
    if ranges.is_empty() {
        return Err(RiskStoreError::BackendUnavailable(
            "CLUSTER SLOTS returned no usable slot ranges".to_string(),
        ));
    }
    ranges.sort();
    let mut endpoints = Vec::with_capacity(hosts.len());
    for url in &hosts {
        let client = redis_crate::Client::open(url.as_str())
            .map_err(|e| RiskStoreError::BackendUnavailable(e.to_string()))?;
        endpoints.push(Endpoint {
            pool: ConnectionPool::new(
                options.pool_size,
                options.connection_timeout_ms,
                options.command_timeout_ms,
            ),
            client,
        });
    }
    Ok((endpoints, ranges))
}

impl RiskStateStore for ShardedRedisRiskStateStore {
    fn observe(&self, o: &RiskObservation) -> Result<Observed, RiskStoreError> {
        let assessment = self.run_assessment(o, None, None, None)?;
        Ok(Observed {
            vector: assessment.vector,
            global_level: assessment.global_level,
            cooldown_until_ms: assessment.cooldown_until_ms,
            is_duplicate: assessment.is_duplicate,
        })
    }

    fn assess_v2(
        &self,
        o: &RiskObservation,
        context_tag: Option<&str>,
        tls_tag: Option<&str>,
        registration: Option<&OutcomeRegistration>,
    ) -> Result<Option<AssessV2Reply>, RiskStoreError> {
        let assessment = self.run_assessment(o, context_tag, tls_tag, registration)?;
        Ok(Some(AssessV2Reply {
            observed: Observed {
                vector: assessment.vector,
                global_level: assessment.global_level,
                cooldown_until_ms: assessment.cooldown_until_ms,
                is_duplicate: assessment.is_duplicate,
            },
            existing_context_tag: assessment.existing_context_tag,
            existing_tls_tag: assessment.existing_tls_tag,
            registration_status: assessment.registration_status,
            target_failures: assessment.target_failures,
            target_spread_sources: assessment.target_spread_sources,
            target_spread_asns: assessment.target_spread_asns,
        }))
    }

    fn register_outcome(
        &self,
        decision_id: &str,
        scope: u32,
        decision_hour: i64,
        score: u32,
    ) -> Result<bool, RiskStoreError> {
        // The decision-id key family (the same key the assessment path's
        // consolidated registration writes), so confirm/correct resolve
        // the same ledger in both modes. The identifier follows the same
        // key-safety rule as the classic store.
        if !RedisRiskStateStore::valid_key_component(decision_id) {
            return Err(RiskStoreError::InvalidIdentifier(
                "decision_id is not a safe Redis key component".to_string(),
            ));
        }
        let key = crate::keyspace::outcome_ledger_key(&self.encoded_namespace, decision_id);
        let mut eval = redis_crate::cmd("EVALSHA");
        eval.arg(self.outcome_register_script.get_hash())
            .arg(1)
            .arg(&key)
            .arg(scope.to_string())
            .arg(decision_hour.to_string())
            .arg(score.to_string())
            .arg(self.options.outcome_ttl_secs.to_string());
        let replies = self.dispatch(vec![BatchUnit {
            endpoint: self.endpoint_for_key(&key),
            eval,
            script: Some(OUTCOME_REGISTER_LUA),
        }])?;
        Ok(matches!(
            replies.first(),
            Some(redis_crate::Value::Int(created)) if *created != 0
        ) || matches!(
            replies.first(),
            Some(redis_crate::Value::BulkString(b)) if b.as_slice() == b"1"
        ))
    }

    fn confirm_outcome(&self, decision_id: &str, legitimate: bool) -> Result<u8, RiskStoreError> {
        if !RedisRiskStateStore::valid_key_component(decision_id) {
            return Err(RiskStoreError::InvalidIdentifier(
                "decision_id is not a safe Redis key component".to_string(),
            ));
        }
        let key = crate::keyspace::outcome_ledger_key(&self.encoded_namespace, decision_id);
        let mut eval = redis_crate::cmd("EVALSHA");
        eval.arg(self.outcome_confirm_script.get_hash())
            .arg(1)
            .arg(&key)
            .arg(if legitimate { "L" } else { "A" })
            .arg(self.options.outcome_ttl_secs.to_string());
        let replies = self.dispatch(vec![BatchUnit {
            endpoint: self.endpoint_for_key(&key),
            eval,
            script: Some(OUTCOME_CONFIRM_LUA),
        }])?;
        match replies.first() {
            Some(redis_crate::Value::Int(status)) => Ok(*status as u8),
            Some(redis_crate::Value::BulkString(b)) => std::str::from_utf8(b)
                .ok()
                .and_then(|s| s.parse::<u8>().ok())
                .ok_or_else(|| {
                    RiskStoreError::ScriptError(
                        "outcome confirm returned a non-integer".to_string(),
                    )
                }),
            _ => Err(RiskStoreError::ScriptError(
                "outcome confirm returned no status".to_string(),
            )),
        }
    }

    fn correct_outcome(&self, decision_id: &str, legitimate: bool) -> Result<bool, RiskStoreError> {
        if !RedisRiskStateStore::valid_key_component(decision_id) {
            return Err(RiskStoreError::InvalidIdentifier(
                "decision_id is not a safe Redis key component".to_string(),
            ));
        }
        let key = crate::keyspace::outcome_ledger_key(&self.encoded_namespace, decision_id);
        let mut eval = redis_crate::cmd("EVALSHA");
        eval.arg(self.outcome_correct_script.get_hash())
            .arg(1)
            .arg(&key)
            .arg(if legitimate { "L" } else { "A" })
            .arg(self.options.outcome_ttl_secs.to_string());
        let replies = self.dispatch(vec![BatchUnit {
            endpoint: self.endpoint_for_key(&key),
            eval,
            script: Some(OUTCOME_CORRECT_LUA),
        }])?;
        Ok(matches!(
            replies.first(),
            Some(redis_crate::Value::Int(applied)) if *applied != 0
        ) || matches!(
            replies.first(),
            Some(redis_crate::Value::BulkString(b)) if b.as_slice() == b"1"
        ))
    }

    fn last_global_level(&self) -> u8 {
        ShardedRedisRiskStateStore::last_global_level(self)
    }

    fn last_cooldown_until_ms(&self) -> u64 {
        ShardedRedisRiskStateStore::last_cooldown_until_ms(self)
    }

    /// The canonical target_failure.lua ops, routed to the target
    /// family's own slot (never the shared namespace tag): the
    /// outcome-bridge write path of target-account protection in the
    /// sharded layout.
    fn register_target_failure(
        &self,
        target_id: &str,
        source: &str,
        asn: &str,
    ) -> Result<TargetState, RiskStoreError> {
        self.run_target_op("fail", target_id, source, asn, "")
    }

    fn register_target_failure_once(
        &self,
        target_id: &str,
        source: &str,
        asn: &str,
        event_id: &str,
    ) -> Result<TargetState, RiskStoreError> {
        self.run_target_op("fail", target_id, source, asn, event_id)
    }

    fn clear_target_failures(&self, target_id: &str) -> Result<(), RiskStoreError> {
        self.run_target_op("clear", target_id, "", "", "")?;
        Ok(())
    }

    fn read_target_state(&self, target_id: &str) -> Result<TargetState, RiskStoreError> {
        self.run_target_op("read", target_id, "", "", "")
    }
}

/// The first-seen session tag surfaces write the session-family record
/// (`{kiwi:<ns>:session:<hex2>}:risk:ctx|tls:<hex>`): the same SET NX
/// semantics as the legacy store, on the session's own slot family
/// (the consolidated assessment path addresses the identical keys).
impl SessionContextTagStore for ShardedRedisRiskStateStore {
    fn session_first_context_tag(
        &self,
        session_id: &[u8; 16],
        tag: &str,
    ) -> Result<Option<String>, RiskStoreError> {
        let key = crate::keyspace::session_tag_key(
            &self.encoded_namespace,
            "ctx",
            &hex::encode(session_id),
        );
        self.session_first_tag_record(&key, tag)
    }
}

impl SessionTlsTagStore for ShardedRedisRiskStateStore {
    fn session_first_tls_tag(
        &self,
        session_id: &[u8; 16],
        tag: &str,
    ) -> Result<Option<String>, RiskStoreError> {
        let key = crate::keyspace::session_tag_key(
            &self.encoded_namespace,
            "tls",
            &hex::encode(session_id),
        );
        self.session_first_tag_record(&key, tag)
    }
}

impl ShardedRedisRiskStateStore {
    /// ONE atomic `SET key tag NX EX ttl`, falling back to GET on a lost
    /// first-write race (the legacy store's identical rule).
    fn session_first_tag_record(
        &self,
        key: &str,
        tag: &str,
    ) -> Result<Option<String>, RiskStoreError> {
        if tag.len() > 64 {
            return Err(RiskStoreError::InvalidIdentifier(format!(
                "session tag must be at most 64 bytes (got {})",
                tag.len()
            )));
        }
        let endpoint = &self.endpoints[self.endpoint_for_key(key)];
        let ttl: i64 = self.options.session_ttl_secs.try_into().unwrap_or(i64::MAX);
        endpoint.pool.with_connection(&endpoint.client, |conn| {
            use ::redis::Commands;
            let set: Option<String> = ::redis::cmd("SET")
                .arg(key)
                .arg(tag)
                .arg("NX")
                .arg("EX")
                .arg(ttl)
                .query(conn)?;
            if set.is_some() {
                return Ok(Some(tag.to_string()));
            }
            let stored: Option<String> = conn.get(key)?;
            Ok(stored)
        })
    }

    /// Writes one long-memory mark through the canonical marks script on
    /// the shared tag (the marks surface is mode-insensitive).
    ///
    /// # Errors
    ///
    /// The same contract the legacy store documents for
    /// [`RedisRiskStateStore::write_mark`].
    pub fn write_mark(
        &self,
        dimension: &str,
        id: &str,
        kind: &str,
        now_ms: u64,
        event_id: &str,
    ) -> Result<i64, RiskStoreError> {
        self.legacy
            .write_mark(dimension, id, kind, now_ms, event_id)
    }

    /// Reads one long-memory mark on the shared tag.
    ///
    /// # Errors
    ///
    /// The same contract the legacy store documents for
    /// [`RedisRiskStateStore::read_mark`].
    pub fn read_mark(
        &self,
        dimension: &str,
        id: &str,
    ) -> Result<Option<crate::outcomes::MarkRecord>, RiskStoreError> {
        self.legacy.read_mark(dimension, id)
    }

    /// The decayed bucket-local trust of one session and bucket.
    ///
    /// # Errors
    ///
    /// The same contract the legacy store documents for the trust
    /// surface.
    pub fn read_bucket_trust(&self, session_id: &str, bucket: &str) -> Result<u32, RiskStoreError> {
        self.legacy.read_bucket_trust(session_id, bucket)
    }

    /// Credits the session's bucket record through the canonical trust
    /// script on the shared tag.
    ///
    /// # Errors
    ///
    /// The same contract the legacy store documents for the trust
    /// surface.
    pub fn credit_bucket_trust(
        &self,
        session_id: &str,
        bucket: &str,
        delta: u32,
    ) -> Result<u32, RiskStoreError> {
        self.legacy.credit_bucket_trust(session_id, bucket, delta)
    }

    /// Decays the session's bucket record through the canonical trust
    /// script on the shared tag.
    ///
    /// # Errors
    ///
    /// The same contract the legacy store documents for the trust
    /// surface.
    pub fn decay_bucket_trust(
        &self,
        session_id: &str,
        bucket: &str,
        delta: u32,
    ) -> Result<u32, RiskStoreError> {
        self.legacy.decay_bucket_trust(session_id, bucket, delta)
    }

    /// Removes one long-memory mark (the erasure path of the outcomes
    /// plane) on the shared tag.
    ///
    /// # Errors
    ///
    /// The same contract the legacy store documents for
    /// [`RedisRiskStateStore::forget_marks`].
    pub fn forget_marks(&self, dimension: &str, id: &str) -> Result<u32, RiskStoreError> {
        self.legacy.forget_marks(dimension, id)
    }
}
