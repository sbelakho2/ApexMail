//! The sharded keyspace contract (Plane 7): shared key derivation, the
//! per-namespace keyspace mode and its marker, and the scope-aggregate
//! shard function. Byte-identical with the PHP mirror
//! `KiwiCaptcha\Risk\Storage\KeyspaceMode`, so both cores address the
//! same keys for the same inputs.
//!
//! Families (the hash tag is the family tag; every script touches exactly
//! one family slot):
//!
//!   identity state   `{kiwi:<ns>:<dim>:<hex2>}:risk:<dim>[:<epoch>]:<id>`
//!   per-dim marker   `{kiwi:<ns>:<dim>:<hex2>}:risk:dd:<event_id>`
//!   session tags     `{kiwi:<ns>:session:<hex2>}:risk:ctx|tls:<session>`
//!   nonce dedupe     `{kiwi:<ns>:n:<hex2>}:risk:dedupe:<event_id>`
//!   scope aggregate  `{kiwi:<ns>:s:<id>:<shard>}:scope:<id>:<shard>`
//!   shard marker     `{kiwi:<ns>:s:<id>:<shard>}:dd:<event_id>`
//!   outcome ledger   `{kiwi:<ns>:o:<hex2>}:outcome:<decision_id>`
//!   target state     `{kiwi:<ns>:target:<hex2>}:risk:tgt[:src|:asn]:<id>`
//!   mark dedupe      `mark:{kiwi:<ns>}:dd:<event_id>`
//!   hysteresis state `{kiwi:<ns>}:risk:hyst`
//!   mode marker      `{kiwi:<ns>}:mode`
//!
//! `<hex2>` is the two hex characters of the identifier's first byte, so
//! each dimension disperses over 256 slots. `<dim>` is one of the seven
//! sharded dimensions (src, net, session, principal, asn, target, agent).
//! `<shard>` is `fnv1a32(event_id) mod 16` (0..=15), or the caller's
//! stable fallback hash for an empty event id, so one event increments
//! exactly one scope shard while the 16 shards spread the aggregate
//! write load. The aggregate is merged on read with a staleness contract
//! of at most one second (the stores refresh their merge at most once
//! per second).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::redis::RedisRiskStateStore;
use crate::store::RiskStoreError;
use ::redis as redis_crate;

/// The keyspace layout of one namespace: [`KeyspaceMode::Legacy`] keeps
/// the single-tag `{kiwi:<ns>}` layout, [`KeyspaceMode::Sharded`] spreads
/// it over per-family slots. A namespace carries exactly one layout,
/// recorded in its mode marker key; the first constructed store claims
/// it, and a later store built in the other mode is refused instead of
/// silently addressing the wrong layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyspaceMode {
    /// The historical single-tag layout (the default store mode).
    Legacy,
    /// The horizontally scalable per-family layout; the recommended mode
    /// for new namespaces.
    Sharded,
}

impl KeyspaceMode {
    /// The canonical marker value stored in the mode marker key.
    pub fn as_marker(self) -> &'static str {
        match self {
            KeyspaceMode::Legacy => "legacy",
            KeyspaceMode::Sharded => "sharded",
        }
    }

    /// The mode of a canonical marker value, or `None` for an unknown
    /// value (never silently defaulted).
    pub fn from_marker(value: &str) -> Option<Self> {
        match value {
            "legacy" => Some(KeyspaceMode::Legacy),
            "sharded" => Some(KeyspaceMode::Sharded),
            _ => None,
        }
    }
}

/// The marker key that records a namespace's keyspace mode:
/// `{kiwi:<ns>}:mode`. The key persists (no expiry): it is configuration
/// metadata, and an expiring claim would let a second store re-claim the
/// namespace in the other layout.
pub fn mode_marker_key(encoded_namespace: &str) -> String {
    format!("{{kiwi:{encoded_namespace}}}:mode")
}

/// The hysteresis state key (single slot by design):
/// `{kiwi:<ns>}:risk:hyst`. The level/cooldown machine is a chained
/// transition over one hash, so it stays atomic even though the pressure
/// it summarizes lives in sharded counters.
pub fn hysteresis_key(encoded_namespace: &str) -> String {
    format!("{{kiwi:{encoded_namespace}}}:risk:hyst")
}

/// The identity dimension of a sharded keyspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardedDimension {
    Source = 1,
    Subnet = 2,
    Session = 3,
    Principal = 4,
    Asn = 5,
    Target = 6,
    Agent = 7,
}

impl ShardedDimension {
    /// The dimension name inside the family tag (`src`, `net`,
    /// `session`, `principal`, `asn`, `target`, `agent`).
    pub fn as_name(self) -> &'static str {
        match self {
            ShardedDimension::Source => "src",
            ShardedDimension::Subnet => "net",
            ShardedDimension::Session => "session",
            ShardedDimension::Principal => "principal",
            ShardedDimension::Asn => "asn",
            ShardedDimension::Target => "target",
            ShardedDimension::Agent => "agent",
        }
    }

    /// The Lua dimension argument (1..7).
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The two hex characters of the identifier's first byte: the family
/// prefix that disperses one dimension over 256 slots. Identifiers are
/// lowercase hex pseudonyms per the store's validation contract, so the
/// prefix is always ASCII and the byte slice is always even.
pub fn id_prefix(hex_id: &str) -> &str {
    &hex_id[..hex_id.len().min(2)]
}

/// FNV-1a 32-bit over the event id bytes: `hash = (hash ^ byte) * prime`
/// with offset `0x811c9dc5` and prime `0x01000193`.
pub fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// The scope shard an event id increments: `fnv1a32(event_id) mod 16`,
/// 0..=15. The empty event id (dedupe disabled) has no id bytes to hash,
/// so the caller's stable fallback (the assessment's source pseudonym)
/// is hashed instead: routing every dedupe-less write to the single
/// `fnv1a32("")` shard would put all of that traffic on one slot.
pub fn scope_shard(event_id: &str, fallback: &[u8]) -> u8 {
    let bytes: &[u8] = if event_id.is_empty() {
        fallback
    } else {
        event_id.as_bytes()
    };
    (fnv1a32(bytes) % 16) as u8
}

/// The identity state key of one pseudonym
/// (`{kiwi:<ns>:<dim>:<hex2>}:risk:<dim>[:<epoch>]:<id>`). Source/subnet
/// keys carry the epoch segment; session/principal keys do not.
pub fn identity_state_key(
    encoded_namespace: &str,
    dimension: ShardedDimension,
    epoch: Option<i64>,
    hex_id: &str,
) -> String {
    let tag = format!(
        "{{kiwi:{encoded_namespace}:{}:{}}}",
        dimension.as_name(),
        id_prefix(hex_id)
    );
    match epoch {
        Some(epoch) => format!("{tag}:risk:{}:{epoch}:{hex_id}", dimension.as_name()),
        None => format!("{tag}:risk:{}:{hex_id}", dimension.as_name()),
    }
}

/// The per-dimension dedupe marker of one event id, on the same slot as
/// the state hash that increments behind it:
/// `{kiwi:<ns>:<dim>:<hex2>}:risk:dd:<event_id>`.
pub fn identity_marker_key(
    encoded_namespace: &str,
    dimension: ShardedDimension,
    hex_id: &str,
    event_id: &str,
) -> String {
    format!(
        "{{kiwi:{encoded_namespace}:{}:{}}}:risk:dd:{event_id}",
        dimension.as_name(),
        id_prefix(hex_id)
    )
}

/// The nonce-family dedupe key of one event id
/// (`{kiwi:<ns>:n:<hex2>}:risk:dedupe:<event_id>`): a single
/// `SET NX EX` gives the assessment-level duplicate verdict.
pub fn nonce_dedupe_key(encoded_namespace: &str, event_id: &str) -> String {
    format!(
        "{{kiwi:{encoded_namespace}:n:{}}}:risk:dedupe:{event_id}",
        id_prefix(event_id)
    )
}

/// The session-family first-seen tag record (`ctx` or `tls`):
/// `{kiwi:<ns>:session:<hex2>}:risk:<kind>:<session_hex>`. The record
/// lives on the session pseudonym's own family slot instead of the
/// shared namespace tag, so first-seen writes disperse with the session
/// dimension.
pub fn session_tag_key(encoded_namespace: &str, kind: &str, session_hex: &str) -> String {
    format!(
        "{{kiwi:{encoded_namespace}:session:{}}}:risk:{kind}:{session_hex}",
        id_prefix(session_hex)
    )
}

/// The decision-id-family outcome ledger key:
/// `{kiwi:<ns>:o:<hex2>}:outcome:<decision_id>`. The ledger of one
/// decision lives on the decision id's own family slot instead of the
/// shared namespace tag, so registration writes disperse instead of
/// funneling through one slot.
pub fn outcome_ledger_key(encoded_namespace: &str, decision_id: &str) -> String {
    format!(
        "{{kiwi:{encoded_namespace}:o:{}}}:outcome:{decision_id}",
        id_prefix(decision_id)
    )
}

/// The event-id dedupe marker of one long-memory mark write, on the
/// same slot as the mark hash (`mark:{kiwi:<ns>}:dd:<event_id>`).
pub fn mark_dedupe_key(encoded_namespace: &str, event_id: &str) -> String {
    format!("mark:{{kiwi:{encoded_namespace}}}:dd:{event_id}")
}

/// The target-dimension state family of one target pseudonym
/// (`{kiwi:<ns>:target:<hex2>}`): the target's failure hash and its
/// source/asn spread HLLs live on the target id's own family slot
/// instead of the shared namespace tag, so a stuffing storm against one
/// target never hammers the primary that holds the rest of the risk
/// state.
pub fn target_state_tag(encoded_namespace: &str, hex_id: &str) -> String {
    format!(
        "{{kiwi:{encoded_namespace}:target:{}}}",
        id_prefix(hex_id)
    )
}

/// The three target-dimension state keys of one target pseudonym:
/// the failure hash plus the source/asn spread HLLs, all on the
/// target's own family slot (`{kiwi:<ns>:target:<hex2>}:risk:tgt...`).
pub fn target_state_keys(encoded_namespace: &str, hex_id: &str) -> [String; 3] {
    let tag = target_state_tag(encoded_namespace, hex_id);
    [
        format!("{tag}:risk:tgt:{hex_id}"),
        format!("{tag}:risk:tgt:src:{hex_id}"),
        format!("{tag}:risk:tgt:asn:{hex_id}"),
    ]
}

/// The scope aggregate shard hash of one aggregate id and shard:
/// `{kiwi:<ns>:s:<id>:<shard>}:scope:<id>:<shard>`. The assessment path
/// uses the aggregate id `global`; per-scope ids may be decimal strings.
pub fn scope_shard_key(encoded_namespace: &str, aggregate_id: &str, shard: u8) -> String {
    debug_assert!(shard <= 15, "scope shards are 0..=15");
    format!("{{kiwi:{encoded_namespace}:s:{aggregate_id}:{shard}}}:scope:{aggregate_id}:{shard}")
}

/// The per-shard dedupe marker of one event id, on the same slot as the
/// shard hash it guards:
/// `{kiwi:<ns>:s:<id>:<shard>}:dd:<event_id>`.
pub fn scope_marker_key(
    encoded_namespace: &str,
    aggregate_id: &str,
    shard: u8,
    event_id: &str,
) -> String {
    debug_assert!(shard <= 15, "scope shards are 0..=15");
    format!("{{kiwi:{encoded_namespace}:s:{aggregate_id}:{shard}}}:dd:{event_id}")
}

/// Reads and claims a namespace's keyspace mode marker. A missing marker
/// is claimed (`SET NX`, persistent) with `mode`; an existing marker of
/// any other mode is a refusal (no silent fallback). Returns the marker
/// mode that now governs the namespace on success.
///
/// # Errors
///
/// [`RiskStoreError::KeyspaceModeMismatch`] when the namespace is marked
/// for the other mode; backend errors when Redis cannot serve the check.
pub fn claim_keyspace_mode(
    conn: &mut redis_crate::Connection,
    encoded_namespace: &str,
    mode: KeyspaceMode,
) -> Result<KeyspaceMode, RiskStoreError> {
    use redis_crate::Commands;
    let key = mode_marker_key(encoded_namespace);
    let stored: Option<String> = conn.get(&key).map_err(map_mode_error)?;
    match stored.as_deref().and_then(KeyspaceMode::from_marker) {
        Some(existing) if existing != mode => {
            return Err(RiskStoreError::KeyspaceModeMismatch {
                namespace: encoded_namespace.to_string(),
                stored: existing.as_marker().to_string(),
                expected: mode.as_marker().to_string(),
            });
        }
        Some(existing) => return Ok(existing),
        None => {}
    }
    // The claim only lands when the marker is still absent (SET NX), so
    // two stores racing the first claim settle on exactly one winner.
    let claimed: Option<String> = redis_crate::cmd("SET")
        .arg(&key)
        .arg(mode.as_marker())
        .arg("NX")
        .query(conn)
        .map_err(map_mode_error)?;
    match claimed {
        Some(_) => Ok(mode),
        None => {
            let stored: Option<String> = conn.get(&key).map_err(map_mode_error)?;
            match stored.as_deref().and_then(KeyspaceMode::from_marker) {
                Some(existing) if existing != mode => Err(RiskStoreError::KeyspaceModeMismatch {
                    namespace: encoded_namespace.to_string(),
                    stored: existing.as_marker().to_string(),
                    expected: mode.as_marker().to_string(),
                }),
                Some(existing) => Ok(existing),
                None => Err(RiskStoreError::BackendUnavailable(
                    "the keyspace mode marker vanished mid-claim".to_string(),
                )),
            }
        }
    }
}

/// Maps a mode-marker backend failure to the store error taxonomy. A
/// connection-level failure stays a backend error; a server response
/// error is a script-level refusal.
fn map_mode_error(e: redis_crate::RedisError) -> RiskStoreError {
    match e.kind() {
        redis_crate::ErrorKind::ResponseError | redis_crate::ErrorKind::ExecAbortError => {
            RiskStoreError::ScriptError(e.to_string())
        }
        _ => RiskStoreError::BackendUnavailable(e.to_string()),
    }
}

/// The staleness contract of the merged scope aggregate: a store
/// refreshes its merged value at most once per this interval, so a
/// transition decided on the merged value may lag the newest commit by
/// up to this window. One second, per the Plane 7 contract.
pub const MERGE_STALENESS: Duration = Duration::from_millis(1000);

/// The number of scope aggregate shards (0..=15).
pub const SCOPE_SHARDS: u8 = 16;

/// Monotonic gate that lets a store refresh its merged aggregate at most
/// once per [`MERGE_STALENESS`]: the first caller inside a window wins
/// the refresh duty, concurrent callers reuse the last merged value
/// (their own batch's increment lands within the next window).
#[derive(Debug, Default)]
pub struct MergeGate {
    claimed_window: AtomicU64,
}

/// The process-start anchor of the monotonic millisecond clock the gate
/// uses (windows only need to be consistent within one process).
pub(crate) fn monotonic_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis().max(1) as u64
}

impl MergeGate {
    /// True when the caller owns the refresh for the staleness window
    /// containing `now_ms`: at most one caller per [`MERGE_STALENESS`].
    /// A declined caller reuses the last merged value, which stays at
    /// most one window old.
    pub fn start_refresh_at(&self, now_ms: u64) -> bool {
        let step = (MERGE_STALENESS.as_millis() as u64).max(1);
        let window = now_ms.max(1) / step;
        match self
            .claimed_window
            .compare_exchange(0, window, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => true,
            Err(0) => self.start_refresh_at(now_ms),
            Err(prev) if prev == window => false,
            Err(prev) => self
                .claimed_window
                .compare_exchange(prev, window, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
        }
    }

    /// [`Self::start_refresh_at`] on the monotonic clock.
    pub fn start_refresh(&self) -> bool {
        self.start_refresh_at(monotonic_ms())
    }

    /// Forces the next refresh (test hook: bypasses the window).
    #[doc(hidden)]
    pub fn reset(&self) {
        self.claimed_window.store(0, Ordering::Relaxed);
    }
}

/// The cluster slot of a key: Redis Cluster hashes the content between
/// the first brace pair when the key carries a hash tag (every sharded
/// key does), the whole key otherwise.
pub(crate) fn slot_of(key: &str) -> u16 {
    let tagged = match (key.find('{'), key.find('}')) {
        (Some(open), Some(close)) if close > open => &key[open + 1..close],
        _ => key,
    };
    RedisRiskStateStore::crc16(tagged.as_bytes()) & 0x3FFF
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FNV-1a 32-bit reference vectors, pinned byte-identically in the
    /// PHP mirror (`KeyspaceMode::fnv1a32`).
    #[test]
    fn fnv1a32_reference_vectors() {
        assert_eq!(fnv1a32(b""), 0x811c_9dc5);
        assert_eq!(fnv1a32(b"abc"), 0x1a47_e90b);
        assert_eq!(fnv1a32(&[0x30u8; 32]), 0xf0c8_6445);
        assert_eq!(fnv1a32(b"ffffffffffffffffffffffffffffffff"), 0xed92_8645);
        assert_eq!(fnv1a32(b"a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"), 0x1529_abe5);
    }

    #[test]
    fn scope_shards_are_deterministic_and_in_band() {
        assert_eq!(scope_shard("abc", b""), 11);
        for i in 0..64u32 {
            let id = format!("{i:064x}");
            assert!(scope_shard(&id, b"") <= 15);
            assert_eq!(scope_shard(&id, b""), scope_shard(&id, b""), "deterministic");
        }
    }

    #[test]
    fn empty_event_ids_hash_the_fallback_instead_of_one_shard() {
        // fnv1a32("") mod 16 == 5: without the fallback every dedupe-less
        // write would land on shard 5.
        assert_eq!(fnv1a32(b"") % 16, 5);
        let mut shards = std::collections::BTreeSet::new();
        for i in 0..64u32 {
            let source = format!("{i:032x}");
            shards.insert(scope_shard("", source.as_bytes()));
        }
        assert!(
            shards.len() > 8,
            "empty event ids dispersed over {} shards",
            shards.len()
        );
    }

    #[test]
    fn id_prefix_is_the_first_hex_byte() {
        assert_eq!(id_prefix("a1b2c3"), "a1");
        assert_eq!(id_prefix(&"0".repeat(32)), "00");
        assert_eq!(id_prefix("a"), "a");
        assert_eq!(id_prefix(""), "");
    }

    #[test]
    fn family_keys_match_the_contract_shapes() {
        let ns = "n1";
        assert_eq!(
            identity_state_key(ns, ShardedDimension::Source, Some(900), "a1b2"),
            "{kiwi:n1:src:a1}:risk:src:900:a1b2"
        );
        assert_eq!(
            identity_state_key(ns, ShardedDimension::Session, None, "beef"),
            "{kiwi:n1:session:be}:risk:session:beef"
        );
        assert_eq!(
            identity_marker_key(
                ns,
                ShardedDimension::Subnet,
                "c0de",
                "ab".repeat(16).as_str()
            ),
            format!("{{kiwi:n1:net:c0}}:risk:dd:{}", "ab".repeat(16))
        );
        assert_eq!(
            nonce_dedupe_key(ns, "00".repeat(16).as_str()),
            format!("{{kiwi:n1:n:00}}:risk:dedupe:{}", "00".repeat(16))
        );
        assert_eq!(
            session_tag_key(ns, "ctx", "beef"),
            "{kiwi:n1:session:be}:risk:ctx:beef"
        );
        assert_eq!(
            session_tag_key(ns, "tls", "beef"),
            "{kiwi:n1:session:be}:risk:tls:beef"
        );
        assert_eq!(
            outcome_ledger_key(ns, "ab".repeat(16).as_str()),
            format!("{{kiwi:n1:o:ab}}:outcome:{}", "ab".repeat(16))
        );
        assert_eq!(
            mark_dedupe_key(ns, "cd"),
            "mark:{kiwi:n1}:dd:cd"
        );
        assert_eq!(
            target_state_tag(ns, "5e2a"),
            "{kiwi:n1:target:5e}"
        );
        assert_eq!(
            target_state_keys(ns, "5e2a"),
            [
                "{kiwi:n1:target:5e}:risk:tgt:5e2a",
                "{kiwi:n1:target:5e}:risk:tgt:src:5e2a",
                "{kiwi:n1:target:5e}:risk:tgt:asn:5e2a",
            ]
        );
        assert_eq!(
            identity_state_key(ns, ShardedDimension::Target, None, "5e2a"),
            "{kiwi:n1:target:5e}:risk:target:5e2a"
        );
        assert_eq!(
            identity_state_key(ns, ShardedDimension::Asn, Some(3), "a6"),
            "{kiwi:n1:asn:a6}:risk:asn:3:a6"
        );
        assert_eq!(
            identity_state_key(ns, ShardedDimension::Agent, None, "0f"),
            "{kiwi:n1:agent:0f}:risk:agent:0f"
        );
        assert_eq!(
            scope_shard_key(ns, "global", 7),
            "{kiwi:n1:s:global:7}:scope:global:7"
        );
        assert_eq!(
            scope_marker_key(ns, "global", 7, "abc"),
            "{kiwi:n1:s:global:7}:dd:abc"
        );
        assert_eq!(hysteresis_key(ns), "{kiwi:n1}:risk:hyst");
        assert_eq!(mode_marker_key(ns), "{kiwi:n1}:mode");
    }

    /// Key-tag correctness: every sharded key's hash tag is its family
    /// tag, and one dimension's prefixes disperse over many slots.
    #[test]
    fn sharded_keys_carry_their_family_tag_and_disperse() {
        let ns = "disp";
        let tag_of = |key: &str| {
            let open = key.find('{').expect("hash tag");
            let close = key[open..].find('}').expect("closing brace") + open;
            key[open + 1..close].to_string()
        };
        let mut src_slots = std::collections::BTreeSet::new();
        for i in 0..64u32 {
            let id = format!("{i:02x}{}", "0".repeat(30));
            let key = identity_state_key(ns, ShardedDimension::Source, Some(1), &id);
            let expected = format!("{{kiwi:{ns}:src:{}}}", id_prefix(&id));
            let tag = tag_of(&key);
            assert!(
                key.starts_with(&expected),
                "tag {tag} must be the family tag"
            );
            src_slots.insert(slot_of(&key));
        }
        // One byte of prefix dispersion over 64 identities: the slot set
        // must spread well beyond a single slot (a fixed tag would give
        // exactly one).
        assert!(
            src_slots.len() > 16,
            "64 prefixed source keys dispersed into {} slots",
            src_slots.len()
        );

        let mut shard_slots = std::collections::BTreeSet::new();
        for shard in 0..16u8 {
            let key = scope_shard_key(ns, "global", shard);
            assert_eq!(
                tag_of(&key),
                format!("kiwi:{ns}:s:global:{shard}"),
                "each shard is its own family"
            );
            shard_slots.insert(slot_of(&key));
        }
        // 16 scope shards disperse across the cluster (no collision-free
        // guarantee, but far more than one slot).
        assert!(
            shard_slots.len() > 8,
            "16 shards hit {} slots",
            shard_slots.len()
        );
    }

    #[test]
    fn keyspace_mode_marker_values_round_trip() {
        assert_eq!(KeyspaceMode::Legacy.as_marker(), "legacy");
        assert_eq!(KeyspaceMode::Sharded.as_marker(), "sharded");
        assert_eq!(
            KeyspaceMode::from_marker("legacy"),
            Some(KeyspaceMode::Legacy)
        );
        assert_eq!(
            KeyspaceMode::from_marker("sharded"),
            Some(KeyspaceMode::Sharded)
        );
        assert_eq!(KeyspaceMode::from_marker("other"), None);
    }

    #[test]
    fn merge_gate_admits_one_refresh_per_window() {
        let gate = MergeGate::default();
        assert!(
            gate.start_refresh_at(5000),
            "the first caller owns the window"
        );
        assert!(
            !gate.start_refresh_at(5100),
            "a second caller inside the window is declined"
        );
        assert!(
            gate.start_refresh_at(6001),
            "the next window admits a refresh"
        );
    }
}
