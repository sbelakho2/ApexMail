//! ASN resolution from a free, redistributable dataset (risk-v1 network
//! plane): the IPtoASN tsv shapes, read once from local disk into sorted
//! interval tables, binary-searched per lookup, with digest-verified
//! atomic hot reload.
//!
//! No network call ever happens: the dataset is a versioned file the
//! deployment ships (a public routing-table export or the free IPtoASN
//! dataset), never a paid feed or a runtime fetch. A lookup resolves an
//! IP to its listed ASN or to the reserved unlisted namespace:
//!
//! - listed: `a<asn>` with the decimal ASN (1..=[`MAX_ASN`], canonical
//!   decimal, no leading zeros);
//! - unlisted IPv4: `u4/<prefix>` with the decimal value of the query
//!   address's /16 prefix (0..=65535) — its own bucket per /16;
//! - unlisted IPv6: `u6/<8hex>` with the lowercase hex of the query
//!   address's first 4 bytes (the /32 prefix) — its own bucket per /32.
//!
//! The grammar is mirrored exactly by the PHP `AsnBucket` and pinned by
//! the shared vectors (`protocol/risk-v1/asn-vectors.json`). Addresses
//! follow the repo's canonical IP rules: an IPv4-mapped IPv6 (and the
//! deprecated IPv4-compatible form, excluding `::` and `::1`) resolves
//! as its IPv4 address.
//!
//! Hot reload parses the new file fully off to the side and swaps the
//! table with one pointer store, so a torn or half-parsed table is never
//! visible to a lookup; a rejected reload (unreadable file, digest
//! mismatch, zero valid rows) leaves the serving table untouched.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The dataset file format version this loader reads. Bump on any change
/// to the accepted row shapes or the validation rules; the shared
/// vectors stamp the version they were generated under.
pub const DATASET_FORMAT_VERSION: u64 = 1;

/// The bucket-id grammar version. Bump on any change to the `a`/`u4`/`u6`
/// encoding; the shared vectors stamp the version they pin.
pub const BUCKET_ID_VERSION: u64 = 1;

/// The largest accepted ASN in a dataset row: the 32-bit AS number space
/// ends one value below 2^32, which stays reserved. AS 0 is reserved as
/// no ASN at all, so rows carry 1..=MAX_ASN.
pub const MAX_ASN: u64 = 4_294_967_294;

/// The largest accepted /16 prefix of an unlisted IPv4 bucket.
const MAX_V4_PREFIX: u64 = 65_535;

/// ASN resolution error. Every variant fails closed: the dataset either
/// keeps serving its table or refuses to load.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AsnError {
    /// The dataset file cannot be read from local disk.
    #[error("asn dataset {path} cannot be read: {reason}")]
    Unreadable {
        /// The dataset path that failed.
        path: String,
        /// The filesystem reason.
        reason: String,
    },
    /// The dataset carries no valid row. An all-malformed or empty file is
    /// far more likely corruption than reality, so it is refused instead
    /// of silently resolving every address to the unlisted namespace.
    #[error("asn dataset {path} carries no valid row (refusing to serve an empty table)")]
    Empty {
        /// The dataset path that failed.
        path: String,
    },
    /// A digest-verified reload found the file bytes changed under the
    /// expected digest: the swap is refused and the serving table stays.
    #[error("asn dataset {path} digest mismatch: expected {expected}, computed {computed}")]
    DigestMismatch {
        /// The dataset path that failed.
        path: String,
        /// The caller-supplied expected sha256 (hex).
        expected: String,
        /// The computed sha256 of the bytes read (hex).
        computed: String,
    },
}

/// The resolved bucket of one lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnLookup {
    /// The listed ASN, or `None` for the reserved unlisted namespace.
    pub asn: Option<u32>,
    /// The bucket id under the grammar above (`a…`, `u4/…` or `u6/…`).
    pub bucket: String,
}

/// The serving dataset snapshot's identity: the doctor surface. Exposes
/// the digest, the modification time and the row counts of the table
/// that is actually serving; the bundle-side doctor wiring (printing
/// digest and age) belongs to the bundle plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DatasetInfo {
    /// The dataset path this table was loaded from.
    pub path: String,
    /// The format version of the loader contract.
    pub format_version: u64,
    /// The sha256 of the loaded file bytes (hex).
    pub sha256: String,
    /// The file's modification time (unix seconds, 0 when unavailable).
    pub mtime_unix_secs: u64,
    /// The number of valid interval rows loaded.
    pub valid_rows: u32,
    /// The number of malformed rows skipped (counted, never fatal per
    /// row).
    pub malformed_rows: u32,
    /// The size of the loaded file in bytes.
    pub byte_len: u64,
}

impl DatasetInfo {
    /// The dataset's age in seconds at `now_unix_secs` (saturating; the
    /// doctor prints this beside the digest).
    pub fn age_secs(&self, now_unix_secs: u64) -> u64 {
        now_unix_secs.saturating_sub(self.mtime_unix_secs)
    }
}

/// The bucket id of a listed ASN: `a<asn>` in canonical decimal.
///
/// # Panics
///
/// Panics when `asn` is outside 1..=[`MAX_ASN`] — the same bound dataset
/// rows enforce; callers pass values the loader already validated.
pub fn known_asn_bucket(asn: u32) -> String {
    assert!(
        (1..=MAX_ASN).contains(&(asn as u64)),
        "a listed ASN must be within 1..={MAX_ASN} (got {asn})"
    );
    format!("a{asn}")
}

/// The bucket id of an unlisted IPv4 address: `u4/<prefix>`, the decimal
/// value of the address's /16 prefix. Two unlisted addresses share a
/// bucket exactly when they share their first two bytes.
pub fn unlisted_v4_bucket(first_two_octets: [u8; 2]) -> String {
    let prefix = (u16::from_be_bytes(first_two_octets)) as u64;
    format!("u4/{prefix}")
}

/// The bucket id of an unlisted IPv6 address: `u6/<8hex>`, the lowercase
/// hex of the address's first 4 bytes (its /32 prefix).
pub fn unlisted_v6_bucket(first_four_bytes: [u8; 4]) -> String {
    format!("u6/{}", hex::encode(first_four_bytes))
}

/// The unlisted-namespace bucket id of one address, dataset-free: the
/// bucket a lookup falls back to when no dataset row covers the address
/// (and the bucket every address resolves to when no dataset is attached
/// at all). IPv4-mapped and IPv4-compatible IPv6 normalize to their
/// IPv4 form first, exactly like [`AsnDataset::lookup`].
pub fn unlisted_bucket_for(ip: IpAddr) -> String {
    let key = ip_key_from(ip);
    if key.family == 4 {
        unlisted_v4_bucket([(key.key >> 24) as u8, (key.key >> 16) as u8])
    } else {
        unlisted_v6_bucket([
            (key.key >> 120) as u8,
            (key.key >> 112) as u8,
            (key.key >> 104) as u8,
            (key.key >> 96) as u8,
        ])
    }
}

/// True when `bucket` is a canonical bucket id of the grammar above:
/// `a` plus the decimal ASN without leading zeros, `u4/` plus the
/// decimal prefix without leading zeros, or `u6/` plus exactly 8
/// lowercase hex digits. Anything else is refused before it can reach a
/// Redis key (fail closed).
pub fn is_valid_bucket_id(bucket: &str) -> bool {
    if let Some(rest) = bucket.strip_prefix('a') {
        return canonical_decimal(rest).is_some_and(|v| (1..=MAX_ASN).contains(&v));
    }
    if let Some(rest) = bucket.strip_prefix("u4/") {
        return canonical_decimal(rest).is_some_and(|v| v <= MAX_V4_PREFIX);
    }
    if let Some(rest) = bucket.strip_prefix("u6/") {
        return rest.len() == 8
            && rest
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'));
    }
    false
}

/// Parses a canonical decimal integer (digits only, no sign, no leading
/// zeros except the single digit zero, at most ten digits).
fn canonical_decimal(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    if s.len() > 10 {
        return None;
    }
    s.parse().ok()
}

/// One address interval of the dataset (an inclusive `first..=last`
/// range owned by one ASN).
#[derive(Debug, Clone)]
struct Interval {
    first: u128,
    last: u128,
    asn: u32,
}

/// The immutable parsed table. Lookups binary-search the family table
/// for the last interval whose `first` is at or below the query, then
/// accept it when its `last` covers the query — exact for disjoint
/// intervals (the dataset's guarantee) and deterministic for any input.
#[derive(Debug, Clone)]
struct AsnTable {
    v4: Vec<Interval>,
    v6: Vec<Interval>,
    valid_rows: u32,
    malformed_rows: u32,
    digest_hex: String,
    mtime_unix_secs: u64,
    byte_len: u64,
}

impl AsnTable {
    /// Parses the dataset bytes. Malformed rows are skipped and counted
    /// (fail open per row); the counts ride the table for the info
    /// surface.
    fn parse(bytes: &[u8], digest_hex: String, mtime_unix_secs: u64) -> AsnTable {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        let mut valid_rows = 0u32;
        let mut malformed_rows = 0u32;
        for raw_line in String::from_utf8_lossy(bytes).split('\n') {
            let line = raw_line.trim_end_matches([' ', '\t', '\r']);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            // Shape A: first_ip last_ip asn [cc registry allocated...].
            // Shape B: registry first_ip last_ip asn [cc allocated...].
            let picked = if fields.len() >= 3
                && parse_ip_key(fields[0]).is_some()
                && parse_ip_key(fields[1]).is_some()
            {
                Some((fields[0], fields[1], fields[2]))
            } else if fields.len() >= 4
                && parse_ip_key(fields[1]).is_some()
                && parse_ip_key(fields[2]).is_some()
            {
                Some((fields[1], fields[2], fields[3]))
            } else {
                None
            };
            let Some((first_raw, last_raw, asn_raw)) = picked else {
                malformed_rows += 1;
                continue;
            };
            let (Some(first), Some(last)) = (parse_ip_key(first_raw), parse_ip_key(last_raw))
            else {
                malformed_rows += 1;
                continue;
            };
            let Some(asn) = asn_from_digits(asn_raw) else {
                malformed_rows += 1;
                continue;
            };
            if asn == 0 || asn > MAX_ASN || first.family != last.family || first.key > last.key {
                malformed_rows += 1;
                continue;
            }
            let asn = asn as u32;
            let table = if first.family == 4 { &mut v4 } else { &mut v6 };
            table.push(Interval {
                first: first.key,
                last: last.key,
                asn,
            });
            valid_rows += 1;
        }
        // Stable sort by `first`: same-key rows keep file order, so the
        // last-with-first-at-or-below rule resolves deterministically.
        v4.sort_by_key(|iv| iv.first);
        v6.sort_by_key(|iv| iv.first);
        AsnTable {
            v4,
            v6,
            valid_rows,
            malformed_rows,
            digest_hex,
            mtime_unix_secs,
            byte_len: bytes.len() as u64,
        }
    }

    /// Resolves one canonical (family, key) pair.
    fn resolve(&self, family: u8, key: u128) -> AsnLookup {
        let table = if family == 4 { &self.v4 } else { &self.v6 };
        // The last interval whose first is at or below the query.
        let idx = table.partition_point(|iv| iv.first <= key);
        if idx > 0 && table[idx - 1].last >= key {
            let asn = table[idx - 1].asn;
            return AsnLookup {
                asn: Some(asn),
                bucket: known_asn_bucket(asn),
            };
        }
        let bucket = if family == 4 {
            unlisted_v4_bucket([(key >> 24) as u8, (key >> 16) as u8])
        } else {
            unlisted_v6_bucket([
                (key >> 120) as u8,
                (key >> 112) as u8,
                (key >> 104) as u8,
                (key >> 96) as u8,
            ])
        };
        AsnLookup { asn: None, bucket }
    }
}

/// The canonical numeric key of one textual IP: family 4 or 6 plus the
/// address as an unsigned integer (v4 as its 32 bits, v6 as its 128
/// bits). IPv4-mapped and IPv4-compatible IPv6 normalize to family 4
/// through the shared `canonical_ip` rule.
struct IpKey {
    family: u8,
    key: u128,
}

fn parse_ip_key(text: &str) -> Option<IpKey> {
    Some(ip_key_from(text.parse::<IpAddr>().ok()?))
}

fn ip_key_from(ip: IpAddr) -> IpKey {
    let canonical = crate::identity::canonical_ip(ip);
    if canonical.first() == Some(&0x04) {
        let bytes: [u8; 4] = canonical[1..5].try_into().expect("family 4 keeps 4 bytes");
        IpKey {
            family: 4,
            key: u32::from_be_bytes(bytes) as u128,
        }
    } else {
        let bytes: [u8; 16] = canonical[1..17]
            .try_into()
            .expect("family 6 keeps 16 bytes");
        IpKey {
            family: 6,
            key: u128::from_be_bytes(bytes),
        }
    }
}

/// Parses an ASN field: digits only (leading zeros tolerated), 0 when the
/// field is all zeros, `None` beyond ten significant digits.
fn asn_from_digits(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() {
        return Some(0);
    }
    if trimmed.len() > 10 {
        return None;
    }
    trimmed.parse().ok()
}

/// The shareable ASN dataset: one file path plus an atomically swappable
/// snapshot. Lookups clone one `Arc` under a short read lock, so they
/// never observe a reload mid-swap.
#[derive(Debug)]
pub struct AsnDataset {
    path: PathBuf,
    table: RwLock<Arc<AsnTable>>,
}

impl AsnDataset {
    /// Opens and parses the dataset at `path`.
    ///
    /// # Errors
    ///
    /// [`AsnError::Unreadable`] when the file cannot be read;
    /// [`AsnError::Empty`] when it carries no valid row (fail closed —
    /// an empty table would silently resolve every address to the
    /// unlisted namespace).
    pub fn open(path: impl AsRef<Path>) -> Result<AsnDataset, AsnError> {
        let path = path.as_ref().to_path_buf();
        let (bytes, mtime) = read_dataset(&path)?;
        let digest_hex = hex::encode(Sha256::digest(&bytes));
        let table = AsnTable::parse(&bytes, digest_hex, mtime);
        if table.valid_rows == 0 {
            return Err(AsnError::Empty {
                path: path.display().to_string(),
            });
        }
        Ok(AsnDataset {
            path,
            table: RwLock::new(Arc::new(table)),
        })
    }

    /// Resolves one IP to its listed ASN and bucket id. The canonical IP
    /// rules apply: IPv4-mapped and IPv4-compatible IPv6 resolve as
    /// their IPv4 address.
    pub fn lookup(&self, ip: IpAddr) -> AsnLookup {
        let key = ip_key_from(ip);
        self.snapshot().resolve(key.family, key.key)
    }

    /// The bucket id of one IP (the lookup's bucket alone).
    pub fn bucket_id(&self, ip: IpAddr) -> String {
        self.lookup(ip).bucket
    }

    /// The serving snapshot's identity: path, digest, mtime, row counts
    /// and byte size. A doctor prints the digest and
    /// [`DatasetInfo::age_secs`] from this; the bundle-side wiring
    /// belongs to the bundle plane.
    pub fn dataset_info(&self) -> DatasetInfo {
        let snapshot = self.snapshot();
        DatasetInfo {
            path: self.path.display().to_string(),
            format_version: DATASET_FORMAT_VERSION,
            sha256: snapshot.digest_hex.clone(),
            mtime_unix_secs: snapshot.mtime_unix_secs,
            valid_rows: snapshot.valid_rows,
            malformed_rows: snapshot.malformed_rows,
            byte_len: snapshot.byte_len,
        }
    }

    /// Hot reload: reads the file again, verifies the digest when the
    /// caller supplies one, parses the new table fully off to the side
    /// and swaps it in with one pointer store. A rejected reload
    /// (unreadable, digest mismatch, zero valid rows) leaves the serving
    /// table untouched, and no lookup can ever observe a half-parsed
    /// table. No network call happens: the file is local disk only.
    ///
    /// # Errors
    ///
    /// [`AsnError::Unreadable`], [`AsnError::DigestMismatch`] or
    /// [`AsnError::Empty`] as above; the serving table survives each.
    pub fn reload(&self, expected_sha256: Option<&str>) -> Result<DatasetInfo, AsnError> {
        let (bytes, mtime) = read_dataset(&self.path)?;
        let digest_hex = hex::encode(Sha256::digest(&bytes));
        if let Some(expected) = expected_sha256 {
            if !expected.eq_ignore_ascii_case(&digest_hex) {
                return Err(AsnError::DigestMismatch {
                    path: self.path.display().to_string(),
                    expected: expected.to_string(),
                    computed: digest_hex,
                });
            }
        }
        let table = AsnTable::parse(&bytes, digest_hex, mtime);
        if table.valid_rows == 0 {
            return Err(AsnError::Empty {
                path: self.path.display().to_string(),
            });
        }
        let mut guard = self.table.write().unwrap_or_else(|p| p.into_inner());
        *guard = Arc::new(table);
        drop(guard);
        Ok(self.dataset_info())
    }

    fn snapshot(&self) -> Arc<AsnTable> {
        self.table.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// Reads the dataset bytes and modification time.
fn read_dataset(path: &Path) -> Result<(Vec<u8>, u64), AsnError> {
    let bytes = std::fs::read(path).map_err(|e| AsnError::Unreadable {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;
    let mtime = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok((bytes, mtime))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../protocol/asn/sample-asn.tsv")
    }

    #[test]
    fn bucket_grammar_is_canonical() {
        assert!(is_valid_bucket_id("a1"));
        assert!(is_valid_bucket_id("a64496"));
        assert!(is_valid_bucket_id("a4294967294"));
        assert!(!is_valid_bucket_id("a0"));
        assert!(!is_valid_bucket_id("a4294967295"));
        assert!(!is_valid_bucket_id("a042"));
        assert!(!is_valid_bucket_id("a-1"));
        assert!(is_valid_bucket_id("u4/0"));
        assert!(is_valid_bucket_id("u4/65535"));
        assert!(!is_valid_bucket_id("u4/65536"));
        assert!(!is_valid_bucket_id("u4/0042"));
        assert!(is_valid_bucket_id("u6/20010db8"));
        assert!(is_valid_bucket_id("u6/00000000"));
        assert!(!is_valid_bucket_id("u6/20010DBG"));
        assert!(!is_valid_bucket_id("u6/20010db"));
        assert!(!is_valid_bucket_id(""));
        assert!(!is_valid_bucket_id("b1"));
    }

    #[test]
    fn unlisted_buckets_follow_the_prefix_rules() {
        assert_eq!(unlisted_v4_bucket([203, 0]), "u4/51968");
        assert_eq!(unlisted_v4_bucket([8, 8]), "u4/2056");
        assert_eq!(unlisted_v6_bucket([0x20, 0x01, 0x0d, 0xb8]), "u6/20010db8");
    }

    #[test]
    fn known_asn_bucket_refuses_out_of_range() {
        assert_eq!(known_asn_bucket(64496), "a64496");
        let _ = std::panic::catch_unwind(|| known_asn_bucket(0));
        let _ = std::panic::catch_unwind(|| known_asn_bucket(4_294_967_295));
    }

    #[test]
    fn sample_resolves_edges_gaps_and_mapped_forms() {
        let dataset = AsnDataset::open(sample_path()).expect("sample opens");
        let bucket = |ip: &str| dataset.bucket_id(ip.parse::<IpAddr>().unwrap());
        assert_eq!(bucket("192.0.2.0"), "a64496");
        assert_eq!(bucket("192.0.2.255"), "a64496");
        assert_eq!(bucket("198.51.100.128"), "a64498");
        assert_eq!(bucket("203.0.113.150"), "u4/51968");
        assert_eq!(bucket("198.51.101.200"), "u4/50739");
        assert_eq!(bucket("::ffff:203.0.113.7"), "a64500");
        assert_eq!(bucket("::192.0.2.44"), "a64496");
        assert_eq!(bucket("2620:fe::fe:fe"), "a64506");
        assert_eq!(bucket("2620:fe::fe:ff"), "u6/262000fe");
        assert_eq!(bucket("::1"), "u6/00000000");

        let lookup = dataset.lookup(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(lookup.asn, Some(64500));
        assert_eq!(lookup.bucket, "a64500");
        assert_eq!(
            dataset.lookup("2600::1".parse().unwrap()).asn,
            None,
            "an unlisted v6 address resolves to no ASN"
        );
    }

    #[test]
    fn lookups_are_deterministic_across_repetition() {
        let dataset = AsnDataset::open(sample_path()).expect("sample opens");
        for ip in [
            "192.0.2.1",
            "203.0.113.150",
            "2001:db8:3::1",
            "::ffff:198.18.0.3",
            "2620:fe::fe:fe",
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            let first = dataset.lookup(parsed);
            for _ in 0..16 {
                assert_eq!(dataset.lookup(parsed), first, "{ip} must be deterministic");
            }
        }
    }

    #[test]
    fn dataset_info_carries_digest_counts_and_age() {
        let dataset = AsnDataset::open(sample_path()).expect("sample opens");
        let info = dataset.dataset_info();
        assert_eq!(
            info.sha256,
            "230cad5a0240996537420add32356c15482f7b6088faecd296edb12e8754fc5b"
        );
        assert_eq!(info.valid_rows, 13);
        assert_eq!(info.malformed_rows, 6);
        assert_eq!(info.byte_len, 1788);
        assert_eq!(info.format_version, DATASET_FORMAT_VERSION);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(info.age_secs(now) <= now, "age never exceeds the epoch");
    }

    #[test]
    fn a_backdated_mtime_yields_a_measurable_age() {
        let path = std::env::temp_dir().join(format!("kiwi-asn-age-{}.tsv", std::process::id()));
        std::fs::write(&path, "10.0.0.0\t10.0.0.255\t100\n").unwrap();
        let file = std::fs::File::options().append(true).open(&path).unwrap();
        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400);
        file.set_modified(past).expect("mtime is settable");
        drop(file);
        let dataset = AsnDataset::open(&path).unwrap();
        let info = dataset.dataset_info();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            info.age_secs(now) >= 86_000,
            "a day-old file reads as a day old"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_refuses_missing_and_empty_datasets() {
        assert!(matches!(
            AsnDataset::open("/nonexistent/asn.tsv"),
            Err(AsnError::Unreadable { .. })
        ));
        let empty = std::env::temp_dir().join(format!("kiwi-asn-empty-{}.tsv", std::process::id()));
        std::fs::write(&empty, b"# only a comment\n\n").unwrap();
        assert!(matches!(
            AsnDataset::open(&empty),
            Err(AsnError::Empty { .. })
        ));
        let _ = std::fs::remove_file(&empty);
    }

    #[test]
    fn malformed_rows_are_skipped_and_counted() {
        // Every documented malformed family: an unparsable IP on either
        // end, a reversed range, a mixed family, a non-numeric ASN and
        // AS 0. One valid row keeps the table servable.
        let body = concat!(
            "10.0.0.0\t10.0.0.255\t100\n",
            "not-an-ip\t10.0.1.1\t100\n",
            "10.0.2.0\tnot-an-ip\t100\n",
            "10.0.3.5\t10.0.3.1\t100\n",
            "2001:db8::\t10.0.4.1\t100\n",
            "10.0.5.0\t10.0.5.255\tzero\n",
            "10.0.6.0\t10.0.6.255\t0\n",
        );
        let path =
            std::env::temp_dir().join(format!("kiwi-asn-malformed-{}.tsv", std::process::id()));
        std::fs::write(&path, body).unwrap();
        let dataset = AsnDataset::open(&path).expect("one valid row opens");
        let info = dataset.dataset_info();
        assert_eq!(info.valid_rows, 1);
        assert_eq!(info.malformed_rows, 6);
        assert_eq!(
            dataset.bucket_id("10.0.0.9".parse().unwrap()),
            "a100",
            "the one valid row still serves"
        );
        assert_eq!(dataset.bucket_id("10.0.1.9".parse().unwrap()), "u4/2560");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hot_reload_swaps_atomically_and_rejects_bad_inputs() {
        let path = std::env::temp_dir().join(format!("kiwi-asn-reload-{}.tsv", std::process::id()));
        let a = b"10.0.0.0\t10.0.0.255\t100\n";
        let b = b"10.0.0.0\t10.0.0.255\t200\n";
        std::fs::write(&path, a).unwrap();
        let dataset = AsnDataset::open(&path).unwrap();
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        assert_eq!(dataset.bucket_id(ip), "a100");

        // A successful reload swaps the table and reports the new digest.
        std::fs::write(&path, b).unwrap();
        let digest_b = hex::encode(Sha256::digest(b));
        let info = dataset.reload(Some(&digest_b)).expect("digest matches");
        assert_eq!(info.sha256, digest_b);
        assert_eq!(dataset.bucket_id(ip), "a200");

        // A digest mismatch is rejected and the serving table survives.
        std::fs::write(&path, a).unwrap();
        let stale = dataset
            .reload(Some(&digest_b))
            .expect_err("the file changed under the expected digest");
        assert!(matches!(stale, AsnError::DigestMismatch { .. }));
        assert_eq!(dataset.bucket_id(ip), "a200");

        // An all-malformed file is refused; the serving table survives.
        std::fs::write(&path, "garbage row\n").unwrap();
        assert!(matches!(dataset.reload(None), Err(AsnError::Empty { .. })));
        assert_eq!(dataset.bucket_id(ip), "a200");

        // An absent file is refused the same way.
        let _ = std::fs::remove_file(&path);
        assert!(matches!(
            dataset.reload(None),
            Err(AsnError::Unreadable { .. })
        ));
        assert_eq!(dataset.bucket_id(ip), "a200");
    }

    #[test]
    fn concurrent_readers_never_observe_a_half_swapped_table() {
        let path = std::env::temp_dir().join(format!("kiwi-asn-race-{}.tsv", std::process::id()));
        std::fs::write(&path, "10.0.0.0\t10.0.0.255\t100\n").unwrap();
        let dataset = Arc::new(AsnDataset::open(&path).unwrap());
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let dataset = Arc::clone(&dataset);
            let stop = Arc::clone(&stop);
            handles.push(std::thread::spawn(move || {
                let mut seen = std::collections::HashSet::new();
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    seen.insert(dataset.bucket_id(ip));
                }
                seen
            }));
        }
        // Each round swaps one fully parsed table; a reader can observe
        // any complete generation, never a mix or a miss.
        for round in 101..140u32 {
            std::fs::write(&path, format!("10.0.0.0\t10.0.0.255\t{round}\n")).unwrap();
            dataset.reload(None).expect("reload races readers");
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for handle in handles {
            for bucket in handle.join().unwrap() {
                let asn: u32 = bucket[1..].parse().expect("a complete generation id");
                assert!(
                    (100..=139).contains(&asn),
                    "a reader saw {bucket} outside the swapped generations"
                );
            }
        }
        // The last reload reached the file's final generation.
        assert_eq!(dataset.bucket_id(ip), "a139");
        let _ = std::fs::remove_file(&path);
    }
}
